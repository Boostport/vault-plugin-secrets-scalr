package vault_plugin_secrets_scalr

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	scalrTokenType = "scalr_token"
)

type scalrToken struct {
	ServiceAccountID string   `json:"service_account_id"`
	RoleIDs          []string `json:"role_ids"`
	AccountID        string   `json:"account_id"`
	Token            string   `json:"token"`
}

func (b *scalrBackend) scalrToken() *framework.Secret {
	return &framework.Secret{
		Type: scalrTokenType,
		Fields: map[string]*framework.FieldSchema{
			"account_id": {
				Type:        framework.TypeString,
				Description: "Scalr Account ID",
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Scalr Token",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func (b *scalrBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	var roleIDs []string
	for _, roleID := range req.Secret.InternalData["role_ids"].([]interface{}) {
		roleIDs = append(roleIDs, roleID.(string))
	}

	err = deleteServiceAccountAndRoles(client, req.Secret.InternalData["service_account_id"].(string), roleIDs)
	if err != nil {
		return nil, fmt.Errorf("error deleting service account and roles: %w", err)
	}

	return nil, nil
}

func (b *scalrBackend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["vault_role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
