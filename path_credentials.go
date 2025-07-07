package vault_plugin_secrets_scalr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/scalr/go-scalr"
)

func pathCredentials(b *scalrBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *scalrBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	return b.createUserCreds(ctx, req, roleName)
}

func (b *scalrBackend) createUserCreds(ctx context.Context, req *logical.Request, roleName string) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if role == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	if err := role.validate(); err != nil {
		return logical.ErrorResponse("role configuration is not valid: %w", err.Error()), nil
	}

	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.Secret(scalrTokenType).Response(map[string]interface{}{
		"account_id": token.AccountID,
		"token":      token.Token,
	}, map[string]interface{}{
		"service_account_id": token.ServiceAccountID,
		"role_ids":           token.RoleIDs,
		"vault_role":         roleName,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *scalrBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *scalrRoleEntry) (*scalrToken, error) {
	c, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	return createServiceAccountToken(c, config.AccountID, roleEntry)
}

func createServiceAccountToken(c *scalr.Client, accountID string, roleEntry *scalrRoleEntry) (*scalrToken, error) {
	serviceAccountName := fmt.Sprintf("vault-%s", uuid.New())

	serviceAccount, err := c.ServiceAccounts.Create(context.Background(), scalr.ServiceAccountCreateOptions{
		Name:        scalr.String(serviceAccountName),
		Description: scalr.String("Service account created by Vault Scalr secrets plugin"),
		Account:     &scalr.Account{ID: accountID},
	})

	if err != nil {
		return nil, fmt.Errorf("error creating service account: %w", err)
	}

	accessPolicies, err := accessPoliciesStringToStruct(roleEntry.AccessPolicies)
	if err != nil {
		return nil, fmt.Errorf("error converting access policies string to struct: %w", err)
	}

	var roleIDs []string

	for _, policy := range accessPolicies {
		if len(policy.Permissions) > 0 {
			roleName := fmt.Sprintf("vault-role-%s", uuid.New())

			var permissions []*scalr.Permission

			for _, permission := range policy.Permissions {
				permissions = append(permissions, &scalr.Permission{
					ID: permission,
				})
			}

			role, err := c.Roles.Create(context.Background(), scalr.RoleCreateOptions{
				Name:        scalr.String(roleName),
				Description: scalr.String("Role created by Vault Scalr secrets plugin"),
				Permissions: permissions,
			})

			if err != nil {
				if err := deleteServiceAccountAndRoles(c, serviceAccount.ID, roleIDs); err != nil {
					return nil, fmt.Errorf("error deleting service account and roles after error creating role: %w", err)
				}
				return nil, fmt.Errorf("error creating role: %w", err)
			}

			roleIDs = append(roleIDs, role.ID)
		}

		var accessPolicyRoles []*scalr.Role
		for _, roleID := range policy.RoleIDs {
			accessPolicyRoles = append(accessPolicyRoles, &scalr.Role{
				ID: roleID,
			})
		}

		for _, roleID := range roleIDs {
			accessPolicyRoles = append(accessPolicyRoles, &scalr.Role{
				ID: roleID,
			})
		}

		accessPolicyRequest := scalr.AccessPolicyCreateOptions{
			ServiceAccount: serviceAccount,
			Roles:          accessPolicyRoles,
		}

		scopeType, err := getScopeType(policy.ScopeID)
		if err != nil {
			if err := deleteServiceAccountAndRoles(c, serviceAccount.ID, roleIDs); err != nil {
				return nil, fmt.Errorf("error deleting service account and roles after error determining scope type: %w", err)
			}
			return nil, fmt.Errorf("error determining scope type: %w", err)
		}

		switch scopeType {
		case scopeTypeAccount:
			accessPolicyRequest.Account = &scalr.Account{
				ID: policy.ScopeID,
			}
		case scopeTypeEnvironment:
			accessPolicyRequest.Environment = &scalr.Environment{
				ID: policy.ScopeID,
			}
		case scopeTypeWorkspace:
			accessPolicyRequest.Workspace = &scalr.Workspace{
				ID: policy.ScopeID,
			}
		}

		_, err = c.AccessPolicies.Create(context.Background(), accessPolicyRequest)
		if err != nil {
			if err := deleteServiceAccountAndRoles(c, serviceAccount.ID, roleIDs); err != nil {
				return nil, fmt.Errorf("error deleting service account and roles after error creating access policy: %w", err)
			}
			return nil, fmt.Errorf("error creating access policy: %w", err)
		}
	}

	accessToken, err := c.ServiceAccountTokens.Create(context.Background(), serviceAccount.ID, scalr.AccessTokenCreateOptions{
		Description: scalr.String("Token created by Vault Scalr secrets plugin"),
	})

	if err != nil {
		if err := deleteServiceAccountAndRoles(c, serviceAccount.ID, roleIDs); err != nil {
			return nil, fmt.Errorf("error deleting service account and roles after error creating service account token: %w", err)
		}
		return nil, fmt.Errorf("error creating service account token: %w", err)
	}

	return &scalrToken{
		ServiceAccountID: serviceAccount.ID,
		RoleIDs:          roleIDs,
		AccountID:        accountID,
		Token:            accessToken.Token,
	}, nil
}

func deleteServiceAccountAndRoles(c *scalr.Client, serviceAccountID string, roleIDs []string) error {
	var errs []error

	err := c.ServiceAccounts.Delete(context.Background(), serviceAccountID)

	if err != nil {
		errs = append(errs, fmt.Errorf("error deleting service account: %w", err))
	}

	for _, roleID := range roleIDs {
		err := c.Roles.Delete(context.Background(), roleID)
		if err != nil {
			errs = append(errs, fmt.Errorf("error deleting role with ID %s: %w", roleID, err))
		}
	}

	return errors.Join(errs...)
}

func accessPoliciesStringToStruct(accessPolicies string) ([]accessPolicy, error) {
	var result []accessPolicy

	if err := json.Unmarshal([]byte(accessPolicies), &result); err != nil {
		return result, fmt.Errorf("unable to unmarshall access policies string: %w", err)
	}

	return result, nil
}

const pathCredentialsHelpSyn = `
Generate a Scalr service account token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a Scalr service account token
based on a particular role.
`
