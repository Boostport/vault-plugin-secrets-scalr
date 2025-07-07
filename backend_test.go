package vault_plugin_secrets_scalr

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests    = "VAULT_ACC"
	envVarScalrHostname  = "TEST_SCALR_HOSTNAME"
	envVarScalrAccountID = "TEST_SCALR_ACCOUNT_ID"
	envVarScalrToken     = "TEST_SCALR_TOKEN"
)

func getTestBackend(tb testing.TB) (*scalrBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory("test")(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*scalrBackend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testEnv creates an object to store and track testing environment
// resources.
type testEnv struct {
	Token     string
	Hostname  string
	AccountID string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the API token, for checking rotations.
	SecretToken string

	// Tracks the generated service accounts and roles, to make sure we clean up.
	ServiceAccountIDs []string
	RoleIDs           []string
}

// AddConfig adds the configuration to the test backend.
// Make sure data includes all of the configuration
// attributes you need and the `config` path!
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"hostname":   e.Hostname,
			"account_id": e.AccountID,
			"token":      e.Token,
		},
	}

	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) AddRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"access_policies": fmt.Sprintf(`[{"scopeID": "%s", "roleIDs": [], "permissions": ["environments:*", "workspaces:*"]}]`, e.AccountID),
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Secret.InternalData["service_account_id"])
	require.NotEmpty(t, resp.Secret.InternalData["role_ids"])
	require.NotNil(t, resp.Secret)
	require.NotEmpty(t, resp.Data["token"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token"])
	}

	e.SecretToken = resp.Data["token"].(string)

	e.ServiceAccountIDs = append(e.ServiceAccountIDs, resp.Secret.InternalData["service_account_id"].(string))
	e.RoleIDs = append(e.RoleIDs, resp.Secret.InternalData["role_ids"].([]string)...)
}

func (e *testEnv) VerifyNumberOfIssuedCredentials(t *testing.T) {
	if len(e.ServiceAccountIDs) != 2 {
		t.Fatalf("expected 2 service accounts, got: %d", len(e.ServiceAccountIDs))
	}

	if len(e.RoleIDs) != 2 {
		t.Fatalf("expected 2 roles, got: %d", len(e.RoleIDs))
	}
}

func (e *testEnv) CleanupCreds(t *testing.T) {

	if len(e.RoleIDs) <= 0 && len(e.ServiceAccountIDs) <= 0 {
		return
	}

	b := e.Backend.(*scalrBackend)
	client, err := b.getClient(e.Context, e.Storage)
	if err != nil {
		t.Fatal("error getting client")
	}

	for _, id := range e.ServiceAccountIDs {
		err = client.ServiceAccounts.Delete(context.Background(), id)
		if err != nil {
			t.Fatalf("unexpected error deleting service account: %s", err)
		}
	}

	for _, id := range e.RoleIDs {
		err = client.Roles.Delete(context.Background(), id)
		if err != nil {
			t.Fatalf("unexpected error deleting role: %s", err)
		}
	}
}
