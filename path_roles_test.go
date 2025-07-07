package vault_plugin_secrets_scalr

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRoleName       = "test-role"
	testAccessPolicies = `[{"scopeID": "acc-123456", "roleIDs": ["role-123456"], "permissions": ["environments:*", "workspaces:*"]}]`
	testTTL            = int64(120)
	testMaxTTL         = int64(3600)
)

func TestRole(t *testing.T) {
	b, s := getTestBackend(t)

	err := testConfigCreate(b, s, map[string]interface{}{
		"hostname":   hostname,
		"account_id": accountID,
		"token":      token,
	})
	assert.NoError(t, err)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				testRoleName+strconv.Itoa(i),
				map[string]interface{}{
					"access_policies": testAccessPolicies,
					"ttl":             testTTL,
					"max_ttl":         testMaxTTL,
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create User Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, testRoleName, map[string]interface{}{
			"access_policies": testAccessPolicies,
			"ttl":             testTTL,
			"max_ttl":         testMaxTTL,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Create User Role - fail on invalid access policies", func(t *testing.T) {
		typeValues := map[string]interface{}{
			"Empty policies": "",
			"Invalid JSON":   "[Invalid JSON",
		}
		for d, v := range typeValues {
			t.Run(d, func(t *testing.T) {
				resp, err := testTokenRoleCreate(t, b, s, testRoleName, map[string]interface{}{
					"access_policies": v,
					"ttl":             testTTL,
					"max_ttl":         testMaxTTL,
				})

				require.Nil(t, err)
				require.NotNil(t, resp)
				require.NotNil(t, resp.Error())
			})
		}
	})

	t.Run("Read User Role - existing", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, testRoleName)

		require.Nil(t, err)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error())
		require.Equal(t, resp.Data["access_policies"], testAccessPolicies)
	})

	t.Run("Read User Role - non existent", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, "non-existent-role")

		require.Nil(t, err)
		require.Nil(t, resp)
	})

	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, testRoleName, map[string]interface{}{
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read User Role - existing", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s, testRoleName)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["access_policies"], testAccessPolicies)
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testTokenRoleDelete(t, b, s, testRoleName)

		require.NoError(t, err)
	})
}

// Utility function to create a role while, returning any response (including errors).
func testTokenRoleCreate(t *testing.T, b *scalrBackend, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Utility function to update a role while, returning any response (including errors).
func testTokenRoleUpdate(t *testing.T, b *scalrBackend, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors.
func testTokenRoleRead(t *testing.T, b *scalrBackend, s logical.Storage, vRole string) (*logical.Response, error) {
	t.Helper()

	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + vRole,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors.
func testTokenRoleList(t *testing.T, b *scalrBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors.
func testTokenRoleDelete(t *testing.T, b *scalrBackend, s logical.Storage, vRole string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + vRole,
		Storage:   s,
	})
}
