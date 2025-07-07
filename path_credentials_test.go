package vault_plugin_secrets_scalr

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := Factory("test")(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Token:     os.Getenv(envVarScalrToken),
		Hostname:  os.Getenv(envVarScalrHostname),
		AccountID: os.Getenv(envVarScalrAccountID),

		Backend: b,
		Context: ctx,
		Storage: &logical.InmemStorage{},
	}, nil
}

func TestCloudAcceptanceToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add role", acceptanceTestEnv.AddRole)
	t.Run("read cred", acceptanceTestEnv.ReadToken)
	t.Run("read cred", acceptanceTestEnv.ReadToken)
	t.Run("verify number of issued tokens", acceptanceTestEnv.VerifyNumberOfIssuedCredentials)
	t.Run("cleanup creds", acceptanceTestEnv.CleanupCreds)
}
