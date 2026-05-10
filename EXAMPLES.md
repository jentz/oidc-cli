# Example usage of oidc-cli

Below are examples of use cases we have encountered `oidc-cli` can be of value.

## Before you start

For brevity and readability, the examples below do not contain all arguments that are required by most or all of the commands. Please review the sections below and make sure to add these arguments when executing the examples.

### Provide client id and secrets to oidc-cli

The `--client-id` and `--client-secret` command-line arguments are required by most commands. 

We do not recommend passing client secrets on the command line, but instead we advise fetching the secrets from a secret manager of choice (e.g. a password manager or secrets vault).

Using 1Password:
```sh
oidc-cli --client-id <client> --client-secret $(op read "path/to/client/password") 
```

Using Bitwarden:
```sh
oidc-cli --client-id <client> --client-secret $(bw get password "client")
```

### Provide endpoint URIs

It is mandatory to inform the `oidc-cli` about the endpoints of your authorization server. You can provide the `--issuer` argument and let the `oidc-cli` discover endpoints using the standard OIDC discovery document. If your authorization does not provide such a discovery document or it is provided in a non-standard location, it may be desired to override the endpoints explicitly using the appropriate arguments (e.g. ```--discovery-url```, ```--token-url```, ```--authorization-url``` and ```--introspection-url```).

### Add common arguments using aliases

If you often execute `oidc-cli` toward the same authorization server and using the same client id, we would recommend creating aliases. E.g.

```sh
alias oidc-cli="oidc-cli --issuer <issuer> --client-id <client id>
```

## Authenticate and retrieve access token

Run a regular authorization code flow (with or without PKCE)

```sh
oidc-cli authorization_code [--pkce]
```

Adding custom ```scope```
```sh
oidc-cli authorization_code --scope "<scope1 scope2 scopeN>"
```

Providing custom ```acr_values```
```sh
oidc-cli authorization_code --acr-values "<acr>"
```

## Obtain an access token using client credentials only

Run a client credentials flow.

```sh
oidc-cli client_credentials [--scope "<scope1 scope2 scopeN>"]
```

## Check validity and content of access token

This method can be used to check the validity and content of an access token, regardless of whether it was an opaque token or a JWT.

```sh
oidc-cli introspect --token <token>
```

The same can be executed on a refresh token to check its validity and/or expiry time:

```sh
oidc-cli introspect --token <token> --token-type refresh_token
```

In many cases, it may be preferable to read the token from stdin. This can be achieved by providing ```-``` as the value for the ```--token``` argument.

## Use a refresh token to obtain a new access token

This method can be used to obtain a new token with a refresh token.

```sh
oidc-cli token_refresh --refresh_token <refresh_token>
```

## Obtain a token and keep refreshing

This method can be used to verify rolling refresh token behavior, or refresh token idle timeouts and expiry times. In this example, we use `jq` to extract one field from the returned JSON string.

```sh
token=$(oidc-cli authorization_code | jq -r .refresh_token);

while true; do
    echo "token: ${token}"
    sleep 10;
    token=$(oidc-cli token_refresh --refresh_token ${token} | jq -r .refresh_token);
done
```

## Print out the decoded JWT token

Decoding the JWT requires an additional tool to be installed. `jwt-decode` is such a tool. If this tool is available for you, you can extract and print the decoded JWT by piping the JSON output through `jq` into `jwt-decode`.

```sh
oidc-cli authorization_code | jq -r .access_token | jwt decode -
```

## Fetch access token and introspect it

Use the following commands to fetch an access token and pipe it to another instance of the `oidc-cli` to introspect the token. This is particularly useful if a client is configured such that it receives opaque access tokens and you're interested in seeing the associated claims.
```sh
oidc-cli autorization_code | jq -r .access_token | oidc-cli introspect --token -
```
