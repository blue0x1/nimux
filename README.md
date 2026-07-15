<img width="1368" height="377" alt="01-nimux" src="https://github.com/user-attachments/assets/a2463702-6969-442a-822e-868b28409021" />

<p align="center"><i></i>Pure-Nim network enumeration and remote execution toolkit</i></p>

<p align="center">
  <a href="https://github.com/blue0x1/nimux/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue"></a>
  <a href="https://nim-lang.org"><img alt="Nim" src="https://img.shields.io/badge/language-Nim-f3d400"></a>
  <a href="https://docs.nimux.wiki"><img alt="Docs" src="https://img.shields.io/badge/docs-docs.nimux.wiki-00bcd4"></a>
  <a href="https://github.com/blue0x1/nimux/releases"><img alt="Release downloads" src="https://img.shields.io/github/downloads/blue0x1/nimux/total?label=downloads"></a>
</p>

# nimux - Native Operator Toolkit

nimux is a native command surface for authorized security assessments. It combines network enumeration, credential validation, Active Directory operations, Kerberos workflows, remote execution, file movement, secrets collection, DCSync, GPO operations, database clients, and SOCKS routing into one Pure-Nim toolkit.

You are on the official public repository for nimux.

- Website: https://nimux.wiki
- Documentation: https://docs.nimux.wiki
- Source: https://github.com/blue0x1/nimux

## Notice

nimux is built for authorized testing only. Do not use it against third-party systems without written permission. Developers are not responsible for misuse, damage, or legal consequences.

# Documentation

Usage examples, command references, and workflow notes are maintained in the documentation:

https://docs.nimux.wiki

# Installation

## Download Release

Prebuilt release assets are available on GitHub:

https://github.com/blue0x1/nimux/releases

Download the latest Linux binary or Debian package from the releases page.

Install the Debian package:

```bash
sudo dpkg -i nimux_1.0_amd64.deb
sudo apt --fix-broken install
```

Use the standalone Linux binary:

```bash
chmod +x nimux
./nimux --help
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
nimux scan 10.10.10.0/24 --ports 445,389,5985 --open
nimux smb dc01.corp.local -u operator -H <nt_hash> -d corp.local --shares --users
nimux winrm host.corp.local -u operator -p '<password>' -d corp.local --cmd whoami
nimux kerberos dc01.corp.local -u operator -p '<password>' -d corp.local --request kinit --out operator.ccache
nimux scan 10.10.10.0/24 --ports 445,389,5985 --proxy socks5://127.0.0.1:1080
```

# Features

- TCP and UDP scanning with protocol-aware probes
- SMB authentication, enumeration, file operations, coercion, and ticket capture workflows
- LDAP and Active Directory enumeration, writes, ACL paths, roasting, RBCD, shadow credentials, and ADCS support
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

# License

nimux is released under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
