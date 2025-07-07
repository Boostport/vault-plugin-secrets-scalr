package vault_plugin_secrets_scalr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type scopeType string

const (
	scopeTypeAccount     scopeType = "account"
	scopeTypeEnvironment scopeType = "environment"
	scopeTypeWorkspace   scopeType = "workspace"
)

type accessPolicy struct {
	ScopeID     string   `json:"scopeID"`
	RoleIDs     []string `json:"roleIDs"`
	Permissions []string `json:"permissions"`
}

type scalrRoleEntry struct {
	AccessPolicies string        `json:"access_policies"`
	TTL            time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
}

func (r *scalrRoleEntry) validate() error {

	var accessPolicies []accessPolicy
	if err := json.Unmarshal([]byte(r.AccessPolicies), &accessPolicies); err != nil {
		return fmt.Errorf("access policies must be a valid JSON string")
	}

	for _, policy := range accessPolicies {
		_, err := getScopeType(policy.ScopeID)
		if err != nil {
			return fmt.Errorf("invalid scope id '%s': %w", policy.ScopeID, err)
		}

		for _, roleID := range policy.RoleIDs {
			if err := validateRoleID(roleID); err != nil {
				return fmt.Errorf("invalid role id '%s': %w", roleID, err)
			}
		}
	}
	return nil
}

func (r *scalrRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"access_policies": r.AccessPolicies,
		"ttl":             r.TTL.Seconds(),
		"max_ttl":         r.MaxTTL.Seconds(),
	}
	return respData

}

func pathRole(b *scalrBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"access_policies": {
					Type:        framework.TypeString,
					Description: "The access policy for the role",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Optional default TTL to apply to keys",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Optional maximum TTL to apply to keys",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *scalrBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *scalrBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *scalrBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func (b *scalrBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &scalrRoleEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if accessPolicies, ok := d.GetOk("access_policies"); ok {
		roleEntry.AccessPolicies = accessPolicies.(string)
	}

	if err := roleEntry.validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *scalrBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	err := req.Storage.Delete(ctx, "roles/"+roleName)
	if err != nil {
		return nil, fmt.Errorf("error deleting scalr role: %w", err)
	}

	return nil, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *scalrRoleEntry) error {
	entry, err := logical.StorageEntryJSON("roles/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*scalrRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role scalrRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Scalr credentials.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Scalr credentials.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Scalr backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

func getScopeType(scopeID string) (scopeType, error) {
	splitScopeID := strings.Split(scopeID, "-")
	if len(splitScopeID) != 2 {
		return "", fmt.Errorf("invalid scopeID format: %s, expected format is 'scopeType-scopeID'", scopeID)
	}
	switch splitScopeID[0] {
	case "acc":
		return scopeTypeAccount, nil
	case "env":
		return scopeTypeEnvironment, nil
	case "ws":
		return scopeTypeWorkspace, nil
	}

	return "", fmt.Errorf("unknown scope type: %s", splitScopeID[0])
}

func validateRoleID(roleID string) error {
	splitRoleID := strings.Split(roleID, "-")
	if len(splitRoleID) != 2 {
		return fmt.Errorf("invalid role id format: %s, expected format is 'role-roleID'", roleID)
	}
	if splitRoleID[0] != "role" {
		return fmt.Errorf("invalid role id prefix: %s, expected 'role'", splitRoleID[0])
	}
	return nil
}
