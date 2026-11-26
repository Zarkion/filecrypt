# filecrypt-azkv

Example filecrypt key source backed by Azure Key Vault.

```
pip install ./plugins/filecrypt-azkv
az login
filecrypt keygen --store azkv:myvault/filecrypt-main
filecrypt encrypt data.csv --key azkv:myvault/filecrypt-main
filecrypt decrypt data.csv.fcx --key azkv:https://myvault.vault.azure.net/secrets/filecrypt-main
```

Authentication uses `DefaultAzureCredential`. You need the "Key Vault Secrets
User" role to read and "Key Vault Secrets Officer" to store. Keys are stored
as base64 secrets; a secret holding plain text is used as a passphrase.
