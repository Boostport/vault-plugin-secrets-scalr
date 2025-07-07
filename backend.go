package vault_plugin_secrets_scalr

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/scalr/go-scalr"
)

func Factory(version string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := backend(version)
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

type scalrBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *scalr.Client
}

func backend(version string) *scalrBackend {
	var b scalrBackend

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.scalrToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	if version != "" {
		b.Backend.RunningVersion = fmt.Sprintf("v%s", version)
	}

	return &b
}

func (b *scalrBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *scalrBackend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}

func (b *scalrBackend) getClient(ctx context.Context, s logical.Storage) (*scalr.Client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(scalrConfig)
	}

	hostname := strings.TrimSuffix(strings.ToLower(config.Hostname), "/")

	scalrConfig := scalr.DefaultConfig()
	scalrConfig.Address = hostname
	scalrConfig.Token = config.Token

	b.client, err = scalr.NewClient(scalrConfig)

	if err != nil {
		return nil, fmt.Errorf("error creating scalr client: %w", err)
	}

	return b.client, nil
}

const backendHelp = `
The Scalr secrets backend dynamically generates Scalr roles and service account tokens.
After mounting this backend, credentials to manage Scalr tokens must be configured with the
"config/" endpoint.
`
