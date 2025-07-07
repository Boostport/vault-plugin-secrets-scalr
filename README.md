# Vault Plugin: Scalr Secrets Backend
[![Tests](https://github.com/Boostport/vault-plugin-secrets-scalr/actions/workflows/tests.yml/badge.svg)](https://github.com/Boostport/vault-plugin-secrets-scalr/actions/workflows/tests.yml)

This is a [HashiCorp Vault](https://www.github.com/hashicorp/vault) plugin that generates service account tokens for [Scalr](https://scalr.com/).

## Download
Binary releases are available at https://github.com/Boostport/vault-plugin-secrets-scalr/releases.

## Verify Binaries
The checksums for the binaries are signed with cosign. To verify the binaries, download the following files (where
`${VERSION}` is the version of the release):
- `vault-plugin-secrets-scalr_${VERSION}_checksums.txt`
- `vault-plugin-secrets-scalr_${VERSION}_checksums.txt.pem`
- `vault-plugin-secrets-scalr_${VERSION}_checksums.txt.sig`

Then download the release binaries you need. Here, we just download the linux amd64 binary:
-  `vault-plugin-secrets-scalr_${VERSION}_linux_amd64`

Then run the following commands to verify the checksums and signature:
```sh
# Verify checksum signature
$ cosign verify-blob --signature vault-plugin-secrets-scalr_${VERSION}_checksums.txt.sig --certificate vault-plugin-secrets-scalr_${VERSION}_checksums.txt.pem vault-plugin-secrets-scalr_${VERSION}_checksums.txt --certificate-identity "https://github.com/Boostport/vault-plugin-secrets-scalr/.github/workflows/release.yml@refs/tags/v${VERSION}" --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify checksum with binaries
$ sha256sum -c vault-plugin-secrets-scalr_${VERSION}_checksums.txt
```

## Usage
1. Once the plugin is registered with your vault instance, you can enable it
   on a particular path:
```shell
$ vault secrets enable -path=scalr vault-plugin-secrets-scalr
```
2. Configure the backend with your Scalr hostname, account id and service account token:
```shell
$ vault write scalr/config hostname=<hostname> account_id=<account id> token=<token>
```
3. Create a role:
```shell
$ vault write scalr/roles/example access_policies='[{"scopeID": "<account_id>", "roleIDs": ["<role_id>"], "permissions": ["environments:*", "workspaces:*"]}]'
```
4. Issue credentials:
```shell
$ vault read scalr/creds/example
```

## Backend Configuration
| Parameter    | Description          | Required | Default |
|--------------|----------------------|----------|---------|
| `hostname`   | The Scalr hostname   | `yes`    | `none`  |
| `account_id` | The Scalr account id | `yes`    | `none`  |
| `token`      | The Scalr token      | `yes`    | `none`  |

### Required Permissions for Service Account:
- `accounts:set-access-policies`
- `roles:*`
- `service-accounts:*`

## Role Configuration
| Parameter         | Description                                                                                                                | Required | Default  |
|-------------------|----------------------------------------------------------------------------------------------------------------------------|----------|----------|
| `access_policies` | JSON array string containing [access policies](https://docs.scalr.io/docs/identity-and-access-management#access-policies). | `yes`    | `none`   |

### Access Policy
An access policy is a JSON object with the following fields:

| Field         | Description                                                                                            | Required | Default |
|---------------|--------------------------------------------------------------------------------------------------------|----------|---------|
| `scopeID`     | The ID of the scope to which the policy applies. This can be an account, environment, or workspace ID. | `yes`    | `none`  |
| `roleIDs`     | An array of role IDs that the policy applies to.                                                       | `no`     | `none`  |
| `permissions` | An array of permissions that the policy grants.                                                        | `no`     | `none`  |

When role ids are provided, the roles are assigned to the access policy. When permissions are provided, a temporary role
is created with the provided permissions and assigned to the access policy. This temporary role is deleted when the
credentials are revoked or expired. It is valid for an access policy to have both role ids and permissions.