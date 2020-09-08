# vault-enum-access

The pluggable nature of HashiCorp's Vault (both for authentication methods and secrets engines) combined with how Vault attaches policies to tokens after login complicates going backwards to determine which entities have access to a given secret.

This was an initial script to meet my needs. I may extend to support other authentication methods or more flexible authentication.

This script will:
* Parse a Vault path (e.g. `secrets/foo/bar`) into
  * `*`
  * `secrets/*`
  * `secrets/foo/*`
  * `secrets/foo/bar`
* Look for policies granting read or sudo access to any of those paths
* Look for LDAP groups tied to any found policies
* Look for AWS IAM roles tied to any found policies 

## Setup
* Tested on Python 3.8
```
# bash
virtualenv .env
source .env/bin/activate
pip install -r requirements.txt

# PowerShell
virtualenv .env
.env\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
# bash
export VERIFY_CERT=/path/to/cert
export VAULT_ADDR=https://vault.example.com/
vault login -method=ldap username=your_username # or other vault login
export VAULT_TOKEN=$(vault print token)
python vault_enum_access.py --path "secrets/foo/bar"

# PowerShell
$env:VERIFY_CERT="C:\\my-cert" # if you omit this https requests will be unverified
$env:VAULT_ADDR="https://vault.example.com/"
vault login -method=ldap username=your_username # or other vault login
$env:VAULT_TOKEN=$(vault print token)
python vault_enum_access.py --path "secrets/foo/bar"
```

## Output

```
Enumerating access to:
        secrets/foo/bar
        https://vault.example.com/

Looking for policies that provide read or sudo access to:
        ['*', 'secrets/*', 'secrets/foo/*', 'secrets/foo/bar']

Found these matching policies:
        ['admin', ...]

Found these ldap groups tied to one or more of the matching policies:
        ['vault_admin', ...]

Found these AWS iam roles tied to one or more of the matching policies:
        [['arn:aws:iam::REDACTED], ...]
```