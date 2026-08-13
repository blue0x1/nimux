<img width="2736" height="754" alt="01-nimux" src="https://github.com/user-attachments/assets/105f203b-8529-4a3c-8bf6-028bd52cc6d5" />

<p align="center"><i>Pure-Nim network enumeration and remote execution toolkit</i></p>

<p align="center">
  <a href="https://github.com/blue0x1/nimux/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue"></a>
  <a href="https://nim-lang.org"><img alt="Nim" src="https://img.shields.io/badge/language-Nim-f3d400"></a>
  <a href="https://docs.nimux.wiki"><img alt="Docs" src="https://img.shields.io/badge/docs-docs.nimux.wiki-00bcd4"></a>
  <a href="https://github.com/blue0x1/nimux/releases"><img alt="Release downloads" src="https://img.shields.io/github/downloads/blue0x1/nimux/total?label=downloads"></a>
</p>

# nimux - Native Operator Toolkit

nimux is a native command surface for authorized security assessments. It combines network enumeration, lightweight web discovery, credential validation, Active Directory operations, Kerberos workflows, remote execution, file movement, secrets collection, DCSync, GPO operations, database clients, and SOCKS routing into one Pure-Nim toolkit.

Current release: `v1.0.5`

You are on the official public repository for nimux.

- Website: https://nimux.wiki
- Documentation: https://docs.nimux.wiki
- Source: https://github.com/blue0x1/nimux

## Notice

nimux is built for authorized testing only. Do not use it against third-party systems without written permission. Developers are not responsible for misuse, damage, or legal consequences.

# Documentation

Usage examples, command references, and workflow notes are maintained in the documentation:

https://docs.nimux.wiki

# Latest Release Highlights

`v1.0.5` adds the lightweight discovery layer around the existing AD/remote-ops command surface:

- HTTP directory, file, and vhost discovery with workers, recursion, link extraction, resume, and false-positive filters such as `-fs`
- DNS subdomain discovery with worker support
- Read-only SMB share spidering with depth, size, pattern, and interesting-file filters
- Anonymous/null-session SMB share enumeration fixes

It also carries the recent ADCS, BloodHound Legacy, Kerberos execution, and LDAP capture work from the `v1.0.4` line:

- Native ADCS policy get/set workflows for `EditFlags` and `DisableExtensionList`
- RPC ADCS request/auth flows with UPN/SID request support and PFX output
- BloodHound Legacy 4.x-compatible output with ACL/object-control data
- LDAP capture listener with random NTLM challenge generation and repeated connection handling

# AI Integrations

Agent guidance and MCP integration files are available in `SKILLS.md` and `integrations/`.

The core `nimux` binary remains independent. AI integrations should call `nimux` as the native execution engine, prefer `--json`, use `--dry-run` before supported writes, and require explicit approval for execution or changes.

## MCP Wrapper

`nimux-mcp` is a separate MCP stdio wrapper for AI clients.

Location:

```text
integrations/mcp/nimux-mcp
```

Build:

```bash
cd integrations/mcp/nimux-mcp
nimble build -y
```

Example MCP client config:

```json
{
  "mcpServers": {
    "nimux": {
      "command": "/path/to/nimux/integrations/mcp/nimux-mcp/nimux_mcp",
      "env": {
        "NIMUX_BIN": "/usr/local/bin/nimux",
        "NIMUX_MCP_POLICY": "/path/to/policy.json"
      }
    }
  }
}
```

The wrapper supports MCP `Content-Length` framed JSON-RPC, local newline-delimited JSON-RPC tests, policy checks, approval gates, redaction, progress notifications, and SOCKS pivot metadata.

Read more:

https://docs.nimux.wiki/mcp-integration

# Installation

## Nimble
```
nimble install nimux
```

## Download Release

Prebuilt release assets are available on GitHub:

https://github.com/blue0x1/nimux/releases

Download the latest Linux binary or Debian package from the releases page.

Install the Debian package:

```bash
sudo dpkg -i nimux_*_amd64.deb
sudo apt --fix-broken install
```

Use the standalone Linux binary:

```bash
chmod +x nimux
./nimux --help
./nimux --version
```

## Docker

The public container image is available from GitHub Container Registry:

```bash
docker run --rm -it --network host ghcr.io/blue0x1/nimux:latest --help
```

Run a scan:

```bash
docker run --rm -it --network host ghcr.io/blue0x1/nimux:latest \
  scan 10.10.10.0/24 --port 445,389,5985 --open
```

Run lightweight web discovery:

```bash
nimux http app.htb --dirs words.txt --workers 100 --status 200,301,302,403 --baseline
nimux http app.htb --dirs words.txt --auto-calibrate --recursion --depth 2 --extract-links
nimux http app.htb --files words.txt --extensions php,txt,bak --workers 100 --filter-regex 'Not Found' -fs 325
nimux http 10.10.10.10 --vhosts vhosts.txt -d app.htb --workers 100 --resume seen.jsonl --json
nimux dns app.htb --subdomains subdomains.txt --workers 200 --json
```

Run read-only SMB spidering:

```bash
nimux smb files01.corp.local --shares
nimux smb files01.corp.local --spider --share Public --max-depth 3
nimux smb files01.corp.local --spider --interesting --size-limit 10485760
```

Run the MCP wrapper:

```bash
docker run --rm -i --network host --entrypoint nimux_mcp \
  ghcr.io/blue0x1/nimux:latest
```

## Arch Linux AUR

nimux is available on the AUR:

https://aur.archlinux.org/packages/nimux

Install with an AUR helper:

```bash
yay -S nimux
```

Or build manually:

```bash
git clone https://aur.archlinux.org/nimux.git
cd nimux
makepkg -si
```

## BlackArch

nimux is available in BlackArch:

```bash
sudo pacman -S nimux
```

## Build From Source

```bash
git clone https://github.com/blue0x1/nimux
cd nimux
nimble build -y
```

Requirements:

- Nim 1.6.10 or newer
- OpenSSL development libraries
- Kerberos libraries
- MinGW-w64 for Windows helper builds used by some execution paths

## Debian Package

Build a local Debian package from source:

```bash
dpkg-buildpackage -us -uc -b
sudo apt install ../nimux_*.deb
```

# Quick Examples

```bash
nimux scan 10.10.10.0/24 --port 445,389,5985 --open
nimux smb dc01.corp.local -u operator -H <nt_hash> -d corp.local --shares --users
nimux smb files01.corp.local -u operator -p '<password>' -d corp.local --spider --max-depth 3 --interesting
nimux ldap dc01.corp.local -u operator -p '<password>' -d corp.local --bloodhound --legacy --bloodhound-out bh-legacy.zip
nimux winrm host.corp.local -u operator -p '<password>' -d corp.local --cmd whoami
nimux kerberos dc01.corp.local -u operator -p '<password>' -d corp.local --request kinit --out operator.ccache
nimux scan 10.10.10.0/24 --port 445,389,5985 --proxy socks5://127.0.0.1:1080
```

ADCS policy and certificate workflow examples:

```bash
nimux ldap dc01.corp.local -u 'gMSA_CA_prod$' -H <nt_hash> -d CORP.LOCAL \
  --adcs-policy --ca CORP-CA --adcs-get-disable-extension-list

nimux ldap dc01.corp.local -u 'gMSA_CA_prod$' -H <nt_hash> -d CORP.LOCAL \
  --adcs-policy --ca CORP-CA \
  --adcs-set-disable-extension-list 1.3.6.1.4.1.311.25.2

nimux ldap dc01.corp.local -u svc_infra -p '<password>' -d CORP.LOCAL \
  --adcs-request --adcs-rpc --ca CORP-CA --template User \
  --upn Administrator@corp.local \
  --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --out administrator.pfx
```

LDAP capture listener:

```bash
nimux ldap --server
nimux ldap --server --srvhost 0.0.0.0 --srvport 2222
nimux ldap --server --srvhost 0.0.0.0 --srvport 2222 --challenge 1122334455667788
```

# Features

- TCP and UDP scanning with protocol-aware probes
- Lightweight HTTP directory/file/vhost discovery and DNS subdomain discovery
- SMB authentication, enumeration, read-only share spidering, file operations, coercion, and ticket capture workflows
- LDAP and Active Directory enumeration, writes, ACL paths, roasting, RBCD, shadow credentials, and ADCS support
- BloodHound Legacy 4.x-compatible LDAP export mode
- Kerberos TGT, TGS, S4U, ccache, kirbi, renewal, purge, and ticket forge workflows
- WinRM, WMI, SCM, DCOM, scheduled task, and helper-service execution modes
- MSSQL, PostgreSQL, MySQL, HTTP, HTTPS, WebDAV, FTP, SSH, RDP, VNC, NFS, and AFP clients
- SAM, LSA, cached credentials, DPAPI material, and native DCSync operations
- GPO discovery, backup, file operations, linking, and policy modification workflows
- SOCKS helper deployment and global SOCKS5 routing with `--proxy`
- JSON output for automation

# Command Families

| Command | Purpose |
| --- | --- |
| `scan` | TCP and UDP service discovery |
| `smb` | SMB enumeration, auth checks, file operations, and coercion |
| `ldap` | AD queries, writes, roasting, ACLs, RBCD, shadow credentials, ADCS |
| `http`, `https`, `dns` | Lightweight web and DNS discovery |
| `kerberos` | TGT, TGS, S4U, ticket conversion, renewal, purge, forge |
| `winrm` | WinRM command execution, shell, and file helpers |
| `scm`, `bin`, `cim`, `tsch`, `mmc` | Remote execution transports |
| `mssql`, `postgres`, `mysql` | Database protocol clients |
| `secrets`, `dcsync` | Credential material and replication workflows |
| `socks` | SOCKS helper deployment |
| `put`, `get`, `ls`, `mkdir`, `rm` | SMB file operations |

# Development

Build locally:

```bash
nimble build -y
```

Run command help:

```bash
./nimux --help
./nimux smb --help
./nimux kerberos --help
```
# Credits 
Chokri Hammedi

<a href="https://www.buymeacoffee.com/blue0x1" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>


# License

nimux is released under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
