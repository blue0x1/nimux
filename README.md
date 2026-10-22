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

Current release: `v1.0.7`

You are on the official public repository for nimux.

- Website: https://nimux.wiki
- Documentation: https://docs.nimux.wiki
- Source: https://github.com/blue0x1/nimux

## Notice

nimux is built for authorized testing only. Do not use it against third-party systems without written permission. Developers are not responsible for misuse, damage, or legal consequences.

# Documentation

Usage examples, command references, and workflow notes are maintained in the documentation:

https://docs.nimux.wiki

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

Nimble builds nimux from source, so native development libraries must be
installed first. On Kali, Debian, or Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential ca-certificates git libssl-dev libkrb5-dev
nimble install nimux
```

Do not run Nimble with `sudo`. If Nimble reports an SSL certificate error,
refresh the system CA store before retrying:

```bash
sudo apt install --reinstall ca-certificates
sudo update-ca-certificates
nimble refresh
```

MinGW-w64 is optional for the base installation, but is required by execution
paths that build Windows helper binaries:

```bash
sudo apt install -y mingw-w64
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
nimux http app.example.local --dirs words.txt --workers 100 --status 200,301,302,403 --baseline
nimux http app.example.local --dirs words.txt --auto-calibrate --recursion --depth 2 --extract-links
nimux http app.example.local --files words.txt --extensions php,txt,bak --workers 100 --filter-regex 'Not Found' -fs 325
nimux http 192.0.2.10 --vhosts vhosts.txt -d app.example.local --workers 100 --resume seen.jsonl --json
nimux dns app.example.local --subdomains subdomains.txt --workers 200 --json
```

Run read-only SMB spidering:

```bash
nimux smb files01.example.local --shares
nimux smb files01.example.local --spider --share Public --max-depth 3
nimux smb files01.example.local --spider --interesting --size-limit 10485760
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

## Offline BloodHound inspection

`bh` reads saved BloodHound ZIPs locally. It provides inventory, collection
coverage, object search, and direct/nested group membership inspection:

```bash
nimux bh collection.zip --summary
nimux bh collection.zip --interesting
nimux bh collection.zip --high-value
nimux bh collection.zip --search alice
nimux bh collection.zip --inspect 'ALICE@EXAMPLE.TEST'
nimux bh collection.zip --summary --json
nimux bh collection.zip --graph --high-value
nimux bh collection.zip --graph --interesting
nimux bh --help
```

`--interesting` combines critical-object inventory, privileged account membership
review, disabled privileged accounts, password-policy exceptions, activity older
than 90 days, and collection gaps. Staleness uses the latest collection filename
timestamp with UTC assumed; missing, zero, or future logon timestamps remain
unknown. Without a collection timestamp, stale-activity checks are skipped.
These observations include evidence and administrator review guidance.

`--high-value` shows recorded `highvalue=true` flags and classifications inferred
from domain objects or exact well-known administrative group SIDs. It does not
classify objects by display name or treat missing flags as false evidence.
The SID classifications follow Microsoft's
[security identifier reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
Both reports bound displayed lists to 100 objects/accounts and retain totals.

Both text reports include a static directed graph of recorded relationships.
For compatibility, JSON retains the membership trees and explicit source/target
identifiers: each tree is limited to six levels and 60 nodes, with omissions
reported. These are snapshot relationships, not calculated effective access.

### Native terminal graph

`--interesting` and `--high-value` print their reports and a graph, then exit.
Add `--graph` to print **only the graph**, including with `--search` or `--inspect`.
There is no keyboard interaction, alternate screen, raw terminal mode, browser,
new window, database, subprocess, or network service. Output stays in the normal
terminal scrollback and can be redirected to a file. `--graph --json` is rejected;
omit `--graph` for the existing JSON reports.

Results are presented one finding at a time: a short title, a named left-to-right
path, a plain-language explanation of each relationship, and collection evidence.
For example (fictional data):

```text
Finding 1 · Connected recorded relationships

ALICE ──MemberOf──▶ HELP DESK ──AdminTo──▶ SERVER01

ALICE belongs to HELP DESK.
HELP DESK has recorded local administrator rights on SERVER01.
Evidence: 2 graph relationships · Members; LocalAdmins.
```

Native reverse BFS and a shortest-path DAG retain equal-length alternatives,
parallel-edge evidence, shared intermediate nodes, and paths longer than three
relationships. Shortest paths do not repeat nodes, so cycles cannot cause loops.
The default depth is unbounded; `--depth N` explicitly bounds it. `--limit 50` is
the default **output** limit, not an input-edge sample. `--limit 0` requests all
results (maximum 100,000 paths); truncation is explicit. Other safety limits are
1,000 targets, 2 million reachable source/target pairs and 20 million reverse edge
visits; overly broad queries fail with an explanation instead of silently sampling.

```bash
nimux bh collection.zip --interesting --graph --limit 0
nimux bh collection.zip --graph --from 'ALICE@EXAMPLE.TEST' --to 'DOMAIN ADMINS@EXAMPLE.TEST' --limit 0
nimux bh collection.zip --graph --inspect 'ALICE@EXAMPLE.TEST' --limit 0
```

`--from` and `--to` accept exact names or identifiers. Without `--to`, the targets
are high-value objects; without `--from`, the applicable preset selects sources.
Plain `--graph`, `--search ... --graph`, and `--inspect ... --graph` list individual
recorded edges rather than arbitrarily joining them. `--limit 0` prints all matching
edges in those modes. Path queries are text-only; existing JSON inventory/hygiene
reports retain their previous meaning.

Scope results to a single object with `--user`, `--computer`, or `--group`:

```bash
nimux bh collection.zip --user alice --interesting
nimux bh collection.zip --computer dc01 --interesting
nimux bh collection.zip --group 'HELP DESK' --interesting
nimux bh collection.zip --user 'ALICE@EXAMPLE.TEST' --high-value --limit 0
nimux bh collection.zip --user alice --to 'SERVER01.EXAMPLE.TEST' --limit 0
nimux bh collection.zip --computer dc01
```

Names are case-insensitive. Exact short user/group names, computer short names
(including `DC01$`), full names/FQDNs and identifiers are accepted; substring
matches are not. Ambiguous short names require a full name or identifier.
Choose only one typed selector. Combining it with `--from`, `--summary`,
`--search`, `--inspect` or `--json` is rejected explicitly.


- `DCSync`: the same principal reaches the same domain through both
  `MemberOf|GetChanges` and `MemberOf|GetChangesAll` permission paths.
- `SyncLAPSPassword`: `GetChanges` and `GetChangesInFilteredSet` reach the same
  domain, and the destination computer has that exact `domainsid` and a typed
  `haslaps=true` property. Missing metadata does not satisfy the rule.



Developer checks (after installing the Nimble dependencies):

```bash
nim c -r tests/test_bloodhound.nim
nim c -r tests/check_bloodhound_archives.nim /path/to/collection.zip
# Optional developer-only static-output test (standalone inspector binary):
nim c -o:/tmp/nimux-bh-inspect src/bloodhound/inspect.nim
python3 tests/check_bloodhound_output.py /tmp/nimux-bh-inspect /path/to/collection.zip
```

# Quick Examples

```bash
nimux scan 10.10.10.0/24 --port 445,389,5985 --open
nimux smb dc01.example.local -u operator -H <nt_hash> -d example.local --shares --users
nimux smb files01.example.local -u operator -p '<password>' -d example.local --spider --max-depth 3 --interesting
nimux ldap dc01.example.local -u operator -p '<password>' -d example.local --bloodhound --legacy --bloodhound-out bh-legacy.zip
nimux winrm host.example.local -u operator -p '<password>' -d example.local --cmd whoami
nimux kerberos dc01.example.local -u operator -p '<password>' -d example.local --request kinit --out <ccache>
nimux scan 10.10.10.0/24 --port 445,389,5985 --proxy socks5://127.0.0.1:1080
```

ADCS policy and certificate workflow examples:

```bash
nimux ldap dc01.example.local -u '<gmsa-account>$' -H <nt_hash> -d EXAMPLE.LOCAL \
  --adcs-policy --ca CORP-CA --adcs-get-disable-extension-list

nimux ldap dc01.example.local -u '<gmsa-account>$' -H <nt_hash> -d EXAMPLE.LOCAL \
  --adcs-policy --ca CORP-CA \
  --adcs-set-disable-extension-list 1.3.6.1.4.1.311.25.2

nimux ldap dc01.example.local -u <service-user> -p '<password>' -d EXAMPLE.LOCAL \
  --adcs-request --adcs-rpc --ca CORP-CA --template User \
  --upn <admin>@example.local \
  --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --out <admin>.pfx
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
