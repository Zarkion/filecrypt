# filecrypt-azkv

Example filecrypt key source backed by Azure Key Vault.

```
pip install ./plugins/filecrypt-azkv
az login
filecrypt keygen --store azkv:myvault/filecrypt-main
filecrypt encrypt data.csv --key azkv:myvault/filecrypt-main
filecrypt decrypt data.csv.fcx --key azkv:https://myvault.vault.azure.net/secrets/filecrypt-main
```

A specific secret version can be given as `azkv:myvault/filecrypt-main/VERSION`,
where `VERSION` is Key Vault's 32-hex-character version id. Anything else is
refused before any request is made.

Authentication uses `DefaultAzureCredential`. You need the "Key Vault Secrets
User" role to read and "Key Vault Secrets Officer" to store. Keys are stored
as `fcxkey:v1:<base64>` secrets; any other secret value is used as a passphrase.

## Choosing which Azure identity is used

`DefaultAzureCredential` tries several identities in turn (environment
variables, workload identity, managed identity, Azure CLI and others) and uses
the first that works. To pin it down, set the `AZURE_TOKEN_CREDENTIALS`
environment variable, which azure-identity reads itself:

| Value | Identities tried |
| --- | --- |
| `prod` | environment variables, workload identity, managed identity |
| `dev` | developer sign-ins such as Azure CLI, Azure Developer CLI, PowerShell, VS Code |
| a credential name, such as `ManagedIdentityCredential` or `AzureCliCredential` | only that one |

For example, on a server that should only ever use its managed identity:

```
export AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential
```

`dev` and `prod` need azure-identity 1.23 or later, and single credential names
need 1.24 or later. Older versions ignore the variable, so check with
`pip show azure-identity` if you rely on it. An unknown value is an error.

## Two `keygen --store` runs at once

Key Vault has no "create only if missing" write, so `keygen --store` checks
that the secret doesn't exist and then writes it. If two runs do this at the
same moment, both writes are kept as versions of the secret. After writing,
filecrypt lists the secret's versions and reports an error, naming them, if
any version other than its own exists. Don't encrypt with that secret until
you have checked which version is current.
