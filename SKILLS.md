# nimux Agent Skill

Use this skill when an AI coding or operator agent needs to work with `nimux` in an authorized security assessment.

For the full command-family map, read `integrations/COMMAND_SURFACE.md`.

## Role

`nimux` is the execution engine. The agent is the planner, parser, and reporting layer.

The agent should:

- Read the local `nimux --help` output before assuming command syntax.
- Read `integrations/COMMAND_SURFACE.md` before planning multi-step usage across command families.
- Prefer `--json` when command output will be parsed.
- Prefer hostnames for Kerberos workflows because SPNs are hostname based.
- Generate `krb5.conf` with `nimux krb5conf` before Kerberos WinRM, SMB, LDAP, or MSSQL workflows when DNS or realm settings are uncertain.
- Use `--dry-run` before LDAP, ACL, GPO, certificate mapping, or other write operations where supported.
- Use `--rollback-out <file>` for supported AD write paths.
- Treat `nimux socks` as a native pivoting feature. After approved deployment, record the local SOCKS URL and use the same `nimux` binary again with `--proxy socks5://host:port`.
- Keep credentials, hashes, tickets, and secrets out of logs, summaries, and final answers unless the user explicitly asks to display them.
- Stop and ask for confirmation before destructive changes, persistence changes, password resets, GPO links, DCSync, secrets extraction, pivot helper deployment, or command execution against a new host.

The agent must not:

- Invent flags or workflows that are not present in `nimux --help` or the local docs.
- Run `nimux` outside the authorized scope supplied by the user.
- Hide errors from the user.
- Continue brute force or spraying if lockout risk is detected.
- Exfiltrate secrets or write payloads without explicit authorization.

## Required Context

Before running commands, collect:

```text
authorized scope
target domain and hosts
allowed protocols
credential material available
allowed write operations
output directory for evidence
rollback file path for supported writes
pivot listener IP and ports when internal routing is required
```

If any of these are missing, use read-only discovery first or ask the user.

## Command Patterns

The full command surface includes:

```text
scan, smb, ldap, kerberos, krb5conf, winrm, scm, bin, cim, tsch, mmc,
socks, secrets, dcsync, mssql, postgres, mysql, ssh, ftp, vnc, nfs,
afp, webdav, http, rdp, put, get, ls, mkdir, rm
```

Discovery:

```bash
nimux scan <target-or-cidr> --port 445,389,5985 --open --json
nimux smb <host> --json
```

Authenticated SMB enumeration:

```bash
nimux smb <host> -u <user> -p '<password>' -d <domain> --shares --users --groups --pass-pol --json
nimux smb <host> -u <user> -H <nt_hash> -d <domain> --shares --json
```

LDAP enumeration:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> \
  --query dcs --query trusts --query admins --query kerberoast --json
```

BloodHound output:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> \
  --bloodhound --bloodhound-out bloodhound.zip
```

Kerberos setup:

```bash
nimux krb5conf <dc> -d <domain> --out <domain>.krb5.conf
nimux kerberos <dc> -u <user> -p '<password>' -d <domain> --request kinit --out <user>.ccache
```

WinRM Kerberos command:

```bash
nimux winrm <host> -k --ccache <user>.ccache --krb5-config <domain>.krb5.conf \
  -u <user> -d <domain> --spn WSMAN --cmd whoami --json
```

Proxy-aware enumeration:

```bash
nimux scan <internal-cidr> --port 445,389,5985 --open --proxy socks5://127.0.0.1:1080 --json
```

Native pivot deployment:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081
```

Native pivot deployment with Kerberos:

```bash
nimux socks <pivot-host> -k --ccache <admin>.ccache --krb5-config <domain>.krb5.conf \
  -d <domain> --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081
```

After deployment, keep the SOCKS helper running in the background and reuse `nimux` with the printed proxy endpoint:

```bash
nimux scan <internal-cidr> --port 445,389,5985 --open \
  --proxy socks5://127.0.0.1:1080 --json

nimux smb <internal-host> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --shares --json

nimux ldap <internal-dc> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --query dcs --query trusts --json
```

Pivot cleanup:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --kill --pid <pid> --socks-task <task-name> --remote <remote-helper-path>
```

GPO write preview:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> \
  --gpo --link '<gpo-name>' --target '<target-dn>' --dry-run
```

GPO write with rollback:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> \
  --gpo --link '<gpo-name>' --target '<target-dn>' --rollback-out gpo-rollback.jsonl
```

## Output Handling

When summarizing results:

- Separate confirmed facts from assumptions.
- Include exact commands only when they do not reveal secrets.
- Redact passwords, NT hashes, AES keys, tickets, cookies, and private keys.
- Preserve target names, ports, status codes, and error messages.
- Report files created locally.

## Safety Defaults

Default to read-only operations unless the user explicitly requests writes.

Use this progression:

```text
scan -> protocol probe -> authenticated enum -> path validation -> dry-run write -> approved write -> verify -> cleanup
```

For internal network pivoting, use this progression:

```text
confirm pivot host is in scope
deploy nimux socks only after approval
record socks URL, pid, task name, and remote helper path
reuse nimux with --proxy for internal scan and enumeration
avoid direct commands until the routed path is verified
cleanup the pivot helper when finished
```

For write-capable workflows, include rollback:

```text
LDAP ACL edits
GPO links and file writes
RBCD writes
shadow credentials
certificate mappings
password changes
group membership changes
```
