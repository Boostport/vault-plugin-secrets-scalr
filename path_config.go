package vault_plugin_secrets_scalr

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

type scalrConfig struct {
	Hostname  string `json:"hostname"`
	AccountID string `json:"account_id"`
	Token     string `json:"token"`
}

// Define the CRU functions for the config path
func pathConfig(b *scalrBackend) *framework.Path {
	return &framework.Path{
		Pattern:         "config",
		HelpSynopsis:    "Configure the Scalr connection.",
		HelpDescription: "Use this endpoint to set the Scalr hostname, account id and token.",

		Fields: map[string]*framework.FieldSchema{
			"hostname": {
				Type:        framework.TypeString,
				Description: "The Scalr hostname",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Hostname",
					Sensitive: false,
				},
			},
			"account_id": {
				Type:        framework.TypeString,
				Description: "The Scalr account id",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Account ID",
					Sensitive: false,
				},
			},
			"token": {
				Type:        framework.TypeString,
				Description: "The Scalr token",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token",
					Sensitive: true,
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
	}
}
func (b *scalrBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// Read the current configuration
func (b *scalrBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"hostname":   config.Hostname,
			"account_id": config.AccountID,
		},
	}, nil
}

// Update the configuration
func (b *scalrBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(scalrConfig)
	}

	if hostname, ok := data.GetOk("hostname"); ok {
		config.Hostname = hostname.(string)
	}

	if accountID, ok := data.GetOk("account_id"); ok {
		config.AccountID = accountID.(string)
	}

	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
	}

	if config.Hostname == "" || config.AccountID == "" || config.Token == "" {
		return nil, errors.New("hostname, account id and token must be set")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

func (b *scalrBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*scalrConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error reading mount configuration: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	config := new(scalrConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}
