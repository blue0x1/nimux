# nimux Skill for Codex

Use this skill when Codex is asked to operate, document, test, or integrate `nimux`.

## Objective

Help the user use `nimux` safely and accurately. Prefer reading local source, help output, and docs before suggesting commands.

For full command coverage, read `integrations/COMMAND_SURFACE.md`.

## Command Discipline

Before suggesting a command, verify the syntax from one of:

- `nimux --help`
- `nimux <command> --help`
- `src/nimux.nim`
- `docs/gitbook`

Do not invent flags.

Codex should understand all command families:

```text
scan, smb, ldap, kerberos, krb5conf, winrm, scm, bin, cim, tsch, mmc,
socks, secrets, dcsync, mssql, postgres, mysql, ssh, ftp, vnc, nfs,
afp, webdav, http, rdp, put, get, ls, mkdir, rm
```

## Defaults

Use:

```text
--json for machine parsing
--dry-run before supported writes
--rollback-out for supported AD changes
--krb5-config with Kerberos where realm resolution may fail
--proxy socks5://host:port when routing through SOCKS
nimux socks for native background pivot deployment
```

## Approval Gates

Ask for explicit user approval before commands that:

- execute code remotely
- deploy a helper
- dump secrets
- run DCSync
- modify LDAP
- modify ACLs
- modify GPOs
- change passwords
- add certificate mappings
- add shadow credentials
- coerce authentication
- deploy SOCKS pivot helpers
- route into a new internal segment through a pivot
- start spraying

## Reporting

When returning results:

- lead with confirmed findings
- include command outcomes
- mention errors and partial failures
- redact sensitive values
- list created files
- suggest the next concrete step

## Common Safe Reads

```bash
nimux scan <target> --port 445,389,5985 --open --json
nimux smb <host> --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query dcs --query trusts --json
nimux kerberos <dc> --request describe --ccache <file>
```

## Native Pivot Pattern

`nimux` can deploy its own SOCKS pivot helper and then reuse the same command families through `--proxy`.

Use this pattern:

```text
verify pivot host is authorized
ask approval to deploy helper
run nimux socks in reverse mode
record SOCKS URL and cleanup values
reuse nimux scan/smb/ldap/winrm/mssql with --proxy
cleanup helper after the routed workflow
```

Deploy:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081
```

Use:

```bash
nimux scan <internal-cidr> --port 445,389,5985 --open \
  --proxy socks5://127.0.0.1:1080 --json

nimux ldap <internal-dc> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --query dcs --query trusts --json
```

Cleanup:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --kill --pid <pid> --socks-task <task-name> --remote <remote-helper-path>
```

## Write Pattern

Use this order:

```text
read current state
dry-run planned change
request approval
run change with rollback file
verify result
document cleanup
```
