# oidc-cli 🚀

[![Go Report Card](https://goreportcard.com/badge/github.com/jentz/oidc-cli)](https://goreportcard.com/report/github.com/jentz/oidc-cli)
[![GitHub release](https://img.shields.io/github/v/release/jentz/oidc-cli)](https://github.com/jentz/oidc-cli/releases)
[![License](https://img.shields.io/github/license/jentz/oidc-cli)](https://github.com/jentz/oidc-cli/blob/main/LICENSE)
![GitHub Downloads](https://img.shields.io/github/downloads/jentz/oidc-cli/total)

Command-line OIDC client, get a token without all the fuss

![Demo GIF](docs/static/oidc-cli-usage.gif)

## Usage 🛠️

```
oidc-cli: is a command-line OIDC and oAuth2 client

Usage:
  oidc-cli [global-flags] <command> [command-flags]

Commands:
  authorization_code: Use the Authorization Code flow to obtain tokens.
  client_credentials: Use the Client Credentials flow to obtain tokens.
  device            : Use the Device flow to obtain tokens.
  introspect        : Validate a token and retrieve associated claims.
  token_refresh     : Use a refresh token to obtain new tokens.
  token_exchange    : Exchange a token for different tokens.
  version           : Display the current version of oidc-cli.
  help              : Show help for oidc-cli or a specific command.

Run `oidc-cli <command> --help` to get help for a specific command
```

## Installing 💾

* Installing with homebrew 🍺
```bash
 brew tap jentz/oidc-cli
 brew install --cask oidc-cli
 ```
* Installing with scoop 🥄
```powershell
 scoop bucket add oidc-cli https://github.com/jentz/scoop-oidc-cli
 scoop install oidc-cli
```

* Installing with go get
```bash
# NOTE: The dev version will be in effect!
go install github.com/jentz/oidc-cli@latest
```

You can also download a suitable release for your platform from the [releases page](https://github.com/jentz/oidc-cli/releases).

## Run ▶️

```bash
go run ./ authorization_code --authorization-url <authorization-url> --token-url <token-url> --client-id <client-id> --client-secret <client-secret> --scopes "openid profile"
```

## Test

```bash
go test -v ./...
```
    
## Build

```bash
 go build -v -o oidc-cli
```
