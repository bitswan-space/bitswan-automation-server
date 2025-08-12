# Bitswan Automation Server

<div align="center">
CLI app and daemon for managing bitswan automation server and workspace deployments
<br>
<br>
<img src="https://github.com/bitswan-space/bitswan-workspaces/actions/workflows/test.yml/badge.svg" alt="drawing"/>
<img src="https://github.com/bitswan-space/bitswan-workspaces/actions/workflows/lint.yml/badge.svg" alt="drawing"/>
<img src="https://pkg.go.dev/badge/github.com/bitswan-space/bitswan-workspaces.svg" alt="drawing"/>
<img src="https://codecov.io/gh/bitswan-space/bitswan-workspaces/branch/main/graph/badge.svg" alt="drawing"/>
<img src="https://img.shields.io/github/v/release/bitswan-space/bitswan-workspaces" alt="drawing"/>
<img src="https://img.shields.io/github/downloads/bitswan-space/bitswan-workspaces/total.svg" alt="drawing"/>
</div>

# Table of Contents
<!--ts-->
   * [bitswan-workspaces](#bitswan-workspaces)
   * [Features](#features)
   * [Prerequisites](#prerequisites)
   * [Installation](#installation) 
   * [Contribute](#contribute)

<!--te-->

# Features
- Automatically set up independent bitswan workspaces deployments.
- Deployments can either connect to the bitswan.space SaaS, use the on prem bitswan management tools or operate completely independently


Prerequisites
--------------
Before installation, make sure you have installed `Docker` and `Docker compose`. Installation guides can be found on these links :

- [Docker](https://docs.docker.com/engine/install/)
- [Docker compose](https://docs.docker.com/compose/install/)

# Installation
## Linux / WSL
```
LATEST_VERSION=$(curl -sL https://api.github.com/repos/bitswan-space/bitswan-workspaces/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
curl -L "https://github.com/bitswan-space/bitswan-workspaces/releases/download/${LATEST_VERSION}/bitswan-workspaces_${LATEST_VERSION}_linux_amd64.tar.gz" | tar -xz
```
## MacOS (Apple Sillicon M1+)
```
LATEST_VERSION=$(curl -sL https://api.github.com/repos/bitswan-space/bitswan-workspaces/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
curl -L "https://github.com/bitswan-space/bitswan-workspaces/releases/download/${LATEST_VERSION}/bitswan-workspaces_${LATEST_VERSION}_darwin_arm64.tar.gz" | tar -xz
```
## MacOS (Intel-based)
```
LATEST_VERSION=$(curl -sL https://api.github.com/repos/bitswan-space/bitswan-workspaces/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
curl -L "https://github.com/bitswan-space/bitswan-workspaces/releases/download/${LATEST_VERSION}/bitswan-workspaces_${LATEST_VERSION}_darwin_amd64.tar.gz" | tar -xz
```

Move the binary to a directory in your PATH

```
sudo mv bitswan /usr/local/bin/
```

Alternatively, if you don't have sudo access or prefer a local installation:

```
mkdir -p ~/bin
mv bitswan ~/bin/

#Add to PATH if using ~/bin (add this to your ~/.bashrc or ~/.zshrc)
export PATH="$HOME/bin:$PATH"
```

# Setting up and connecting a workspace
## SaaS
```sh
bitswan workspace init my-workspace
```

## On-prem
### With public domain / DNS SSL
```sh
bitswan workspace init --domain=my-workspace.bitswan.io my-workspace
```
### With internal domain / DNS SSL
> Note:
>
> Before you initialize your workspace with an internal domain, make sure you have generated certificate for sub domain of workspace, e.g. `*.my-workspace.my-domain.local`. You have to specify path to the certificate and private key in `init` command. Certificate and private key must be in a format `full-chain.pem` and `private-key.pem`.

```sh
bitswan workspace init --domain=my-workspace.my-domain.local --certs-dir=/etc/certs my-workspace
```

### Local dev

This is for setting up a workspace locally without first setting up a domain name or connecting to the SaaS.

Create some certs for these domains using a certificate authority you setup for yourself.

```sh
mkcert --install
```

Add the CA certificate to Chrome by:
1. Navigate to chrome://settings/certificates
2. Go to "Authorities" tab
3. Click "Import" and select the ca.crt file
4. Check all trust settings and click "OK"

And finally setup the workspace.

```sh
bitswan workspace init --domain=bitswan.localhost --mkcerts dev-workspace
```

You should be able to access the editor in chrome via [https://dev-workspace-editor.bitswan.localhost](https://dev-workspace-editor.bitswan.localhost).

You can get the password to the editor using the command:

```sh
bitswan workspace list --long --passwords
```

## Remote git repository

If you wanna connect and persist your pipelines and GitOps configuration in remote git repository you can use `--remote` flag to specify your repository. `main` branch will be used to store pipelines code and each workspace will create it's own branch (e.g. `my-workspace`) to store their configurations.

```sh
bitswan workspace --remote=git@github.com:<your-name>/<your-repo>.git my-workspace
```

# Contribute

If you find issues in that setup or have some nice features / improvements, I would welcome an issue or a PR :)
