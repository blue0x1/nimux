import std/[json, os, osproc, streams, strutils, times]

const ServerName = "nimux-mcp"
const ServerVersion = "0.2.0"

var framedOutput = false

type
  Risk = enum
    riskRead, riskWritePreview, riskWrite, riskExecute, riskSecrets, riskDeploy, riskCleanup

  ToolDef = object
    name: string
    description: string
    risk: Risk
    schema: JsonNode

  Policy = object
    hosts: seq[string]
    domains: seq[string]
    cidrs: seq[string]
    allowReadOnly: bool
    allowRemoteExecution: bool
    allowSecrets: bool
    allowDcsync: bool
    allowLdapWrites: bool
    allowGpoWrites: bool
    allowSocksDeploy: bool
    allowProxyReuse: bool
    requireApproval: bool
    redact: bool
    evidenceDir: string
    rollbackDir: string

  ExecResult = object
    exitCode: int
    stdout: string
    stderr: string
    argv: seq[string]
    durationMs: int
    timedOut: bool

  McpMessage = object
    body: string
    framed: bool
    eof: bool

proc `%`(s: seq[string]): JsonNode =
  result = newJArray()
  for item in s:
    result.add(%item)

proc getStr(n: JsonNode; key: string; default = ""): string =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JString:
    n[key].getStr
  else:
    default

proc getBool(n: JsonNode; key: string; default = false): bool =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JBool:
    n[key].getBool
  else:
    default

proc getInt(n: JsonNode; key: string; default = 0): int =
  if n.kind == JObject and n.hasKey(key) and n[key].kind in {JInt, JFloat}:
    n[key].getInt
  else:
    default

proc getSeq(n: JsonNode; key: string): seq[string] =
  result = @[]
  if n.kind != JObject or not n.hasKey(key):
    return
  let v = n[key]
  case v.kind
  of JArray:
    for item in v.items:
      if item.kind == JString:
        result.add(item.getStr)
  of JString:
    if v.getStr.len > 0:
      result.add(v.getStr)
  else:
    discard

proc hasText(n: JsonNode; key: string): bool =
  n.kind == JObject and n.hasKey(key) and n[key].kind == JString and n[key].getStr.len > 0

proc prop(kind: string; desc = ""): JsonNode =
  result = %*{"type": kind}
  if desc.len > 0:
    result["description"] = %desc

proc schema(required: seq[string]; props: openArray[(string, JsonNode)]): JsonNode =
  var p = newJObject()
  for (k, v) in props:
    p[k] = v
  %*{
    "type": "object",
    "required": required,
    "properties": p,
    "additionalProperties": false
  }

proc riskName(r: Risk): string =
  case r
  of riskRead: "read"
  of riskWritePreview: "write-preview"
  of riskWrite: "write"
  of riskExecute: "execute"
  of riskSecrets: "secrets"
  of riskDeploy: "deploy"
  of riskCleanup: "cleanup"

proc boolPolicy(n: JsonNode; key: string; default: bool): bool =
  if n.kind == JObject and n.hasKey(key):
    case n[key].kind
    of JBool: n[key].getBool
    else: default
  else:
    default

proc loadPolicy(): Policy =
  result = Policy(
    allowReadOnly: true,
    allowRemoteExecution: false,
    allowSecrets: false,
    allowDcsync: false,
    allowLdapWrites: false,
    allowGpoWrites: false,
    allowSocksDeploy: false,
    allowProxyReuse: true,
    requireApproval: true,
    redact: true,
    evidenceDir: "./evidence",
    rollbackDir: "./rollback"
  )

  let path = getEnv("NIMUX_MCP_POLICY")
  if path.len == 0 or not fileExists(path):
    return

  let root = parseFile(path)
  if root.hasKey("scope"):
    let scope = root["scope"]
    result.hosts = getSeq(scope, "hosts")
    result.domains = getSeq(scope, "domains")
    result.cidrs = getSeq(scope, "cidrs")

  if root.hasKey("defaults"):
    let d = root["defaults"]
    result.requireApproval = boolPolicy(d, "require_approval", result.requireApproval)
    result.redact = boolPolicy(d, "redact", result.redact)
    result.evidenceDir = getStr(d, "evidence_dir", result.evidenceDir)
    result.rollbackDir = getStr(d, "rollback_dir", result.rollbackDir)

  if root.hasKey("allow"):
    let a = root["allow"]
    result.allowReadOnly = boolPolicy(a, "read_only", result.allowReadOnly)
    result.allowRemoteExecution = boolPolicy(a, "remote_execution", result.allowRemoteExecution)
    result.allowSecrets = boolPolicy(a, "secrets", result.allowSecrets)
    result.allowDcsync = boolPolicy(a, "dcsync", result.allowDcsync)
    result.allowLdapWrites = boolPolicy(a, "ldap_writes", result.allowLdapWrites)
    result.allowGpoWrites = boolPolicy(a, "gpo_writes", result.allowGpoWrites)
    result.allowSocksDeploy = boolPolicy(a, "socks_deploy", result.allowSocksDeploy)
    result.allowProxyReuse = boolPolicy(a, "proxy_reuse", result.allowProxyReuse)

proc targetAllowed(policy: Policy; target: string): bool =
  if policy.hosts.len == 0 and policy.domains.len == 0 and policy.cidrs.len == 0:
    return true
  let t = target.toLowerAscii
  for h in policy.hosts:
    if t == h.toLowerAscii:
      return true
  for d in policy.domains:
    let dn = d.toLowerAscii
    if t == dn or t.endsWith("." & dn):
      return true
  for c in policy.cidrs:
    if t == c.toLowerAscii:
      return true
  false

proc riskAllowed(policy: Policy; risk: Risk; toolName: string): bool =
  case risk
  of riskRead:
    policy.allowReadOnly
  of riskWritePreview:
    policy.allowReadOnly
  of riskWrite:
    if toolName.startsWith("nimux.gpo_"): policy.allowGpoWrites
    else: policy.allowLdapWrites
  of riskExecute:
    policy.allowRemoteExecution
  of riskSecrets:
    policy.allowSecrets
  of riskDeploy:
    policy.allowSocksDeploy
  of riskCleanup:
    policy.allowSocksDeploy

proc approvalOk(policy: Policy; risk: Risk; args: JsonNode): bool =
  if not policy.requireApproval:
    return true
  if risk in {riskRead, riskWritePreview}:
    return true
  getStr(args, "approval_id").len > 0

proc redactText(s: string): string =
  var outp = s
  let markers = [
    "password", "passwd", "pwd", "hash", "nt_hash", "nthash", "aes", "aes_key",
    "ticket", "ccache", "kirbi", "private_key", "pfx", "dpapi", "secret",
    "cookie", "token", "authorization", "plain_password_hex"
  ]
  for line in outp.splitLines:
    discard line
  var redactedLines: seq[string] = @[]
  for line in outp.splitLines:
    let low = line.toLowerAscii
    var shouldRedact = false
    for m in markers:
      if m in low:
        shouldRedact = true
        break
    if shouldRedact:
      let idx = line.find(":")
      if idx >= 0:
        redactedLines.add(line[0 .. idx] & " <redacted>")
      else:
        redactedLines.add("<redacted>")
    else:
      redactedLines.add(line)
  redactedLines.join("\n")

proc redactionKey(key: string): bool =
  let low = key.toLowerAscii
  for marker in [
    "password", "passwd", "pwd", "hash", "nt_hash", "nthash", "aes", "aes_key",
    "ticket", "ccache", "kirbi", "private_key", "pfx", "dpapi", "secret",
    "cookie", "token", "authorization", "plain_password_hex"
  ]:
    if marker in low:
      return true
  false

proc redactJson(n: JsonNode): JsonNode =
  case n.kind
  of JObject:
    result = newJObject()
    for k, v in n.pairs:
      if redactionKey(k):
        result[k] = %"<redacted>"
      else:
        result[k] = redactJson(v)
  of JArray:
    result = newJArray()
    for item in n.items:
      result.add(redactJson(item))
  else:
    result = n

proc parseJsonOutput(s: string; redact: bool): JsonNode =
  let stripped = s.strip
  if stripped.len == 0:
    return newJNull()
  try:
    result = parseJson(stripped)
    if redact:
      result = redactJson(result)
    return
  except CatchableError:
    discard

  result = newJArray()
  for line in s.splitLines:
    let item = line.strip
    if item.len == 0:
      continue
    try:
      var parsed = parseJson(item)
      if redact:
        parsed = redactJson(parsed)
      result.add(parsed)
    except CatchableError:
      discard
  if result.len == 0:
    result = newJNull()

proc nimuxBin(): string =
  let envBin = getEnv("NIMUX_BIN")
  if envBin.len > 0: envBin else: "nimux"

proc publicArgv(argv: seq[string]): seq[string] =
  result = @[]
  var skipNext = false
  let sensitive = ["-p", "--password", "-H", "--hash", "--new-hash", "--cert", "--key", "--pfx"]
  for a in argv:
    if skipNext:
      result.add("<redacted>")
      skipNext = false
    elif a in sensitive:
      result.add(a)
      skipNext = true
    else:
      result.add(a)

proc writeJson(n: JsonNode; framed: bool) =
  if n.kind == JNull:
    return
  let body = $n
  if framed:
    stdout.write("Content-Length: " & $body.len & "\r\n\r\n")
    stdout.write(body)
  else:
    stdout.writeLine(body)
  flushFile(stdout)

proc emitProgress(token: string; message: string; progress: int) =
  if token.len == 0:
    return
  writeJson(%*{
    "jsonrpc": "2.0",
    "method": "notifications/progress",
    "params": {
      "progressToken": token,
      "progress": progress,
      "message": message
    }
  }, framedOutput)

proc emitLog(message: string) =
  if not framedOutput:
    return
  writeJson(%*{
    "jsonrpc": "2.0",
    "method": "notifications/message",
    "params": {
      "level": "info",
      "logger": ServerName,
      "data": message
    }
  }, framedOutput)

proc runNimux(argv: seq[string]; timeoutMs = 120000; progressToken = ""): ExecResult =
  result.argv = @[nimuxBin()] & argv
  let started = epochTime()
  emitProgress(progressToken, "starting nimux command", 0)
  emitLog("starting " & publicArgv(result.argv).join(" "))
  let p = startProcess(nimuxBin(), args = argv, options = {poUsePath, poStdErrToStdOut})
  var lastProgress = started
  while p.peekExitCode == -1:
    sleep(50)
    let nowTs = epochTime()
    if progressToken.len > 0 and nowTs - lastProgress >= 5.0:
      emitProgress(progressToken, "nimux command still running", int((nowTs - started) * 1000))
      lastProgress = nowTs
    if int((epochTime() - started) * 1000) > timeoutMs:
      p.terminate()
      result.exitCode = -1
      result.stderr = "timeout"
      result.timedOut = true
      result.stdout = p.outputStream.readAll()
      result.durationMs = int((epochTime() - started) * 1000)
      p.close()
      emitProgress(progressToken, "nimux command timed out", result.durationMs)
      return
  result.exitCode = p.waitForExit()
  result.stdout = p.outputStream.readAll()
  result.durationMs = int((epochTime() - started) * 1000)
  p.close()
  emitProgress(progressToken, "nimux command completed", result.durationMs)

proc addAuth(argv: var seq[string]; args: JsonNode) =
  let user = getStr(args, "username", getStr(args, "user"))
  let pass = getStr(args, "password")
  let hash = getStr(args, "hash")
  let domain = getStr(args, "domain")
  let ccache = getStr(args, "ccache")
  let krb5 = getStr(args, "krb5_config")
  if user.len > 0: argv.add(@["-u", user])
  if pass.len > 0: argv.add(@["-p", pass])
  if hash.len > 0: argv.add(@["-H", hash])
  if domain.len > 0: argv.add(@["-d", domain])
  if getBool(args, "kerberos") or ccache.len > 0:
    argv.add("-k")
  if ccache.len > 0: argv.add(@["--ccache", ccache])
  if krb5.len > 0: argv.add(@["--krb5-config", krb5])
  if getBool(args, "local_auth"): argv.add("--local-auth")

proc addCommon(argv: var seq[string]; args: JsonNode) =
  let proxy = getStr(args, "proxy")
  let port = getInt(args, "port")
  let timeout = getInt(args, "timeout_ms", getInt(args, "timeout"))
  if proxy.len > 0: argv.add(@["--proxy", proxy])
  if port > 0: argv.add(@["--port", $port])
  if timeout > 0: argv.add(@["--timeout", $timeout])

proc statePath(): string =
  let p = getEnv("NIMUX_MCP_STATE")
  if p.len > 0: p else: getTempDir() / "nimux-mcp-pivots.json"

proc loadState(): JsonNode =
  let path = statePath()
  if fileExists(path):
    try: return parseFile(path)
    except CatchableError: discard
  %*{"pivots": {}}

proc saveState(state: JsonNode) =
  writeFile(statePath(), pretty(state))

proc toolDefs(): seq[ToolDef] =
  let authProps = @[
    ("username", prop("string")),
    ("password", prop("string")),
    ("hash", prop("string")),
    ("domain", prop("string")),
    ("kerberos", prop("boolean")),
    ("ccache", prop("string")),
    ("krb5_config", prop("string")),
    ("proxy", prop("string"))
  ]
  result = @[
    ToolDef(name: "nimux.scan", risk: riskRead, description: "Run nimux scan with JSON output.",
      schema: schema(@["target"], {
        "target": prop("string"), "ports": prop("string"), "udp": prop("boolean"),
        "open_only": prop("boolean"), "proxy": prop("string"), "timeout_ms": prop("integer")
      })),
    ToolDef(name: "nimux.smb_enum", risk: riskRead, description: "Run SMB enumeration.",
      schema: schema(@["target"], authProps & @[
        ("target", prop("string")), ("shares", prop("boolean")), ("users", prop("boolean")),
        ("groups", prop("boolean")), ("sessions", prop("boolean")), ("pass_policy", prop("boolean")),
        ("local_admins", prop("boolean"))
      ])),
    ToolDef(name: "nimux.ldap_query", risk: riskRead, description: "Run LDAP named queries or a filter.",
      schema: schema(@["dc"], authProps & @[
        ("dc", prop("string")), ("queries", %*{"type": "array", "items": {"type": "string"}}),
        ("filter", prop("string")), ("attrs", prop("string")), ("bloodhound_out", prop("string"))
      ])),
    ToolDef(name: "nimux.kerberos_request", risk: riskRead, description: "Run Kerberos ticket operations.",
      schema: schema(@["kdc", "request"], authProps & @[
        ("kdc", prop("string")), ("request", prop("string")), ("out", prop("string")),
        ("spn", prop("string")), ("service", prop("string")), ("user", prop("string")),
        ("kirbi", prop("string"))
      ])),
    ToolDef(name: "nimux.winrm_command", risk: riskExecute, description: "Run an approved WinRM command.",
      schema: schema(@["target", "command", "approval_id"], authProps & @[
        ("target", prop("string")), ("command", prop("string")), ("approval_id", prop("string")),
        ("spn", prop("string")), ("ssl", prop("boolean"))
      ])),
    ToolDef(name: "nimux.remote_exec", risk: riskExecute, description: "Run an approved remote execution method.",
      schema: schema(@["method", "target", "command", "approval_id"], authProps & @[
        ("method", prop("string")), ("target", prop("string")), ("command", prop("string")),
        ("approval_id", prop("string"))
      ])),
    ToolDef(name: "nimux.socks_deploy", risk: riskDeploy, description: "Deploy native nimux SOCKS pivot helper.",
      schema: schema(@["target", "listener", "approval_id"], authProps & @[
        ("target", prop("string")), ("listener", prop("string")), ("approval_id", prop("string")),
        ("socks_port", prop("integer")), ("control_port", prop("integer")), ("reverse", prop("boolean"))
      ])),
    ToolDef(name: "nimux.socks_status", risk: riskRead, description: "Return stored pivot metadata.",
      schema: schema(@["pivot_id"], {"pivot_id": prop("string")})),
    ToolDef(name: "nimux.socks_cleanup", risk: riskCleanup, description: "Cleanup native nimux SOCKS pivot helper.",
      schema: schema(@["pivot_id", "approval_id"], authProps & @[
        ("pivot_id", prop("string")), ("approval_id", prop("string"))
      ])),
    ToolDef(name: "nimux.proxy_scan", risk: riskRead, description: "Run scan through a stored pivot.",
      schema: schema(@["pivot_id", "target"], {
        "pivot_id": prop("string"), "target": prop("string"), "ports": prop("string"),
        "udp": prop("boolean"), "open_only": prop("boolean"), "timeout_ms": prop("integer")
      })),
    ToolDef(name: "nimux.gpo_dry_run", risk: riskWritePreview, description: "Preview a GPO operation with --dry-run.",
      schema: schema(@["dc", "operation"], authProps & @[
        ("dc", prop("string")), ("operation", prop("string")), ("name", prop("string")),
        ("target_dn", prop("string")), ("principal", prop("string")), ("rights", prop("string"))
      ])),
    ToolDef(name: "nimux.gpo_apply", risk: riskWrite, description: "Apply an approved GPO operation.",
      schema: schema(@["dc", "operation", "approval_id", "rollback_out"], authProps & @[
        ("dc", prop("string")), ("operation", prop("string")), ("approval_id", prop("string")),
        ("rollback_out", prop("string")), ("name", prop("string")), ("target_dn", prop("string")),
        ("local_file", prop("string")), ("remote_path", prop("string"))
      ])),
    ToolDef(name: "nimux.file_operation", risk: riskWrite, description: "Run approved SMB file operation.",
      schema: schema(@["operation", "target", "share"], authProps & @[
        ("operation", prop("string")), ("target", prop("string")), ("share", prop("string")),
        ("local_path", prop("string")), ("remote_path", prop("string")), ("recursive", prop("boolean")),
        ("approval_id", prop("string"))
      ])),
    ToolDef(name: "nimux.database_query", risk: riskRead, description: "Run database query or auth check.",
      schema: schema(@["db_type", "target"], authProps & @[
        ("db_type", prop("string")), ("target", prop("string")), ("query", prop("string")),
        ("database", prop("string"))
      ])),
    ToolDef(name: "nimux.secrets", risk: riskSecrets, description: "Run approved secrets or DCSync workflow.",
      schema: schema(@["operation", "target", "approval_id"], authProps & @[
        ("operation", prop("string")), ("target", prop("string")), ("approval_id", prop("string")),
        ("user", prop("string")), ("trust_keys", prop("boolean"))
      ])),
    ToolDef(name: "nimux.protocol_probe", risk: riskRead, description: "Run read-only protocol probe.",
      schema: schema(@["protocol", "target"], authProps & @[
        ("protocol", prop("string")), ("target", prop("string")), ("path", prop("string")),
        ("ssl", prop("boolean"))
      ])),
    ToolDef(name: "nimux.report_summary", risk: riskRead, description: "Summarize local evidence files with redaction.",
      schema: schema(@["evidence_files"], {
        "evidence_files": %*{"type": "array", "items": {"type": "string"}},
        "redact": prop("boolean")
      }))
  ]

proc findTool(name: string): ToolDef =
  for t in toolDefs():
    if t.name == name:
      return t
  raise newException(ValueError, "unknown tool: " & name)

proc runWrapped(argv: seq[string]; args: JsonNode; policy: Policy): JsonNode =
  let timeout = getInt(args, "timeout_ms", 120000)
  let shouldRedact = policy.redact or getBool(args, "redact", true)
  let r = runNimux(argv, timeout, getStr(args, "progress_token"))
  let outText = if shouldRedact: redactText(r.stdout) else: r.stdout
  let parsed = parseJsonOutput(r.stdout, shouldRedact)
  %*{
    "exit_code": r.exitCode,
    "argv": publicArgv(r.argv),
    "stdout": outText,
    "stderr": r.stderr,
    "duration_ms": r.durationMs,
    "timed_out": r.timedOut,
    "json": parsed
  }

proc requireTarget(policy: Policy; target: string) =
  if target.len == 0:
    raise newException(ValueError, "target is required")
  if not targetAllowed(policy, target):
    raise newException(ValueError, "target outside MCP policy scope: " & target)

proc pivotProxy(pivotId: string): string =
  let state = loadState()
  if not state["pivots"].hasKey(pivotId):
    raise newException(ValueError, "unknown pivot_id: " & pivotId)
  state["pivots"][pivotId].getStr("local_proxy_url")

proc buildGpo(argv: var seq[string]; args: JsonNode; apply: bool) =
  argv.add("ldap")
  argv.add(getStr(args, "dc"))
  addAuth(argv, args)
  argv.add("--gpo")
  let op = getStr(args, "operation")
  case op
  of "create", "create-gpo":
    argv.add("--create-gpo")
    argv.add(@["--name", getStr(args, "name")])
  of "link":
    argv.add(@["--link", getStr(args, "name"), "--target", getStr(args, "target_dn")])
  of "unlink":
    argv.add(@["--unlink", getStr(args, "name"), "--target", getStr(args, "target_dn")])
  of "startup":
    argv.add(@["--startup", "--name", getStr(args, "name"), "--put", getStr(args, "local_file")])
  of "put":
    argv.add(@["--put", getStr(args, "local_file"), "--name", getStr(args, "name"), "--remote", getStr(args, "remote_path")])
  else:
    raise newException(ValueError, "unsupported gpo operation: " & op)
  if not apply:
    argv.add("--dry-run")
  let rollback = getStr(args, "rollback_out")
  if rollback.len > 0:
    argv.add(@["--rollback-out", rollback])

proc toolCall(name: string; args: JsonNode; policy: Policy): JsonNode =
  let tool = findTool(name)
  if not riskAllowed(policy, tool.risk, name):
    raise newException(ValueError, "tool blocked by MCP policy: " & name)
  if not approvalOk(policy, tool.risk, args):
    raise newException(ValueError, "approval_id is required for " & name)

  var argv: seq[string] = @[]
  case name
  of "nimux.scan":
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @["scan", target]
    let ports = getStr(args, "ports")
    if ports.len > 0: argv.add(@["--port", ports])
    if getBool(args, "udp"): argv.add("--udp")
    if getBool(args, "open_only", true): argv.add("--open")
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.proxy_scan":
    let proxy = pivotProxy(getStr(args, "pivot_id"))
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @["scan", target]
    let ports = getStr(args, "ports")
    if ports.len > 0: argv.add(@["--port", ports])
    if getBool(args, "udp"): argv.add("--udp")
    if getBool(args, "open_only", true): argv.add("--open")
    argv.add(@["--proxy", proxy, "--json"])
    runWrapped(argv, args, policy)
  of "nimux.smb_enum":
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @["smb", target]
    addAuth(argv, args)
    for flag in ["shares", "users", "groups", "sessions", "local_admins"]:
      if getBool(args, flag):
        argv.add("--" & flag.replace("_", "-"))
    if getBool(args, "pass_policy"):
      argv.add("--pass-pol")
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.ldap_query":
    let dc = getStr(args, "dc")
    requireTarget(policy, dc)
    argv = @["ldap", dc]
    addAuth(argv, args)
    for q in getSeq(args, "queries"):
      argv.add(@["--query", q])
    let filter = getStr(args, "filter")
    if filter.len > 0: argv.add(@["--filter", filter])
    let attrs = getStr(args, "attrs")
    if attrs.len > 0: argv.add(@["--attrs", attrs])
    let bh = getStr(args, "bloodhound_out")
    if bh.len > 0: argv.add(@["--bloodhound", "--bloodhound-out", bh])
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.kerberos_request":
    let kdc = getStr(args, "kdc")
    requireTarget(policy, kdc)
    argv = @["kerberos", kdc]
    addAuth(argv, args)
    argv.add(@["--request", getStr(args, "request")])
    for opt in ["out", "spn", "service", "user", "kirbi", "ccache"]:
      let v = getStr(args, opt)
      if v.len > 0: argv.add(@["--" & opt.replace("_", "-"), v])
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.winrm_command":
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @["winrm", target]
    addAuth(argv, args)
    let spn = getStr(args, "spn")
    if spn.len > 0: argv.add(@["--spn", spn])
    if getBool(args, "ssl"): argv.add("--ssl")
    addCommon(argv, args)
    argv.add(@["--cmd", getStr(args, "command"), "--json"])
    runWrapped(argv, args, policy)
  of "nimux.remote_exec":
    let execMethod = getStr(args, "method")
    if execMethod notin ["winrm", "scm", "bin", "cim", "tsch", "mmc", "ssh", "mssql", "postgres"]:
      raise newException(ValueError, "unsupported remote exec method: " & execMethod)
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @[execMethod, target]
    addAuth(argv, args)
    addCommon(argv, args)
    argv.add(@["--cmd", getStr(args, "command"), "--json"])
    runWrapped(argv, args, policy)
  of "nimux.socks_deploy":
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @["socks", target]
    addAuth(argv, args)
    if getBool(args, "reverse", true): argv.add("--reverse")
    argv.add(@["--listener", getStr(args, "listener")])
    let sp = getInt(args, "socks_port", 1080)
    let cp = getInt(args, "control_port", 1081)
    argv.add(@["--socks-port", $sp, "--control-port", $cp])
    let wrapped = runWrapped(argv, args, policy)
    let pivotId = "pivot-" & $epochTime().int
    let proxy = "socks5://127.0.0.1:" & $sp
    var state = loadState()
    state["pivots"][pivotId] = %*{
      "pivot_id": pivotId,
      "target": target,
      "local_proxy_url": proxy,
      "listener": getStr(args, "listener"),
      "socks_port": sp,
      "control_port": cp,
      "created_at": $now(),
      "raw": wrapped
    }
    saveState(state)
    %*{"pivot_id": pivotId, "local_proxy_url": proxy, "result": wrapped}
  of "nimux.socks_status":
    let state = loadState()
    let pivotId = getStr(args, "pivot_id")
    if not state["pivots"].hasKey(pivotId):
      raise newException(ValueError, "unknown pivot_id: " & pivotId)
    state["pivots"][pivotId]
  of "nimux.socks_cleanup":
    let state = loadState()
    let pivotId = getStr(args, "pivot_id")
    if not state["pivots"].hasKey(pivotId):
      raise newException(ValueError, "unknown pivot_id: " & pivotId)
    let p = state["pivots"][pivotId]
    let target = p.getStr("target")
    argv = @["socks", target]
    addAuth(argv, args)
    if p.hasKey("pid"): argv.add(@["--kill", "--pid", p["pid"].getStr])
    if p.hasKey("socks_task"): argv.add(@["--socks-task", p["socks_task"].getStr])
    if p.hasKey("remote_helper_path"): argv.add(@["--remote", p["remote_helper_path"].getStr])
    let wrapped = runWrapped(argv, args, policy)
    state["pivots"].delete(pivotId)
    saveState(state)
    %*{"pivot_id": pivotId, "cleaned": true, "result": wrapped}
  of "nimux.gpo_dry_run":
    buildGpo(argv, args, false)
    runWrapped(argv, args, policy)
  of "nimux.gpo_apply":
    buildGpo(argv, args, true)
    runWrapped(argv, args, policy)
  of "nimux.file_operation":
    let op = getStr(args, "operation")
    if op notin ["put", "get", "ls", "mkdir", "rm"]:
      raise newException(ValueError, "unsupported file operation: " & op)
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @[op, target]
    addAuth(argv, args)
    argv.add(@["--share", getStr(args, "share")])
    let localPath = getStr(args, "local_path")
    if localPath.len > 0: argv.add(@["--local", localPath])
    let remotePath = getStr(args, "remote_path")
    if remotePath.len > 0: argv.add(@["--remote", remotePath])
    if getBool(args, "recursive"): argv.add("--recursive")
    addCommon(argv, args)
    runWrapped(argv, args, policy)
  of "nimux.database_query":
    let db = getStr(args, "db_type")
    if db notin ["mssql", "postgres", "mysql"]:
      raise newException(ValueError, "unsupported database type: " & db)
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @[db, target]
    addAuth(argv, args)
    let database = getStr(args, "database")
    if database.len > 0: argv.add(@["--database", database])
    let query = getStr(args, "query")
    if query.len > 0 and db != "mysql": argv.add(@["--query", query])
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.secrets":
    let op = getStr(args, "operation")
    if op notin ["secrets", "dcsync"]:
      raise newException(ValueError, "operation must be secrets or dcsync")
    if op == "dcsync" and not policy.allowDcsync:
      raise newException(ValueError, "dcsync blocked by MCP policy")
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @[op, target]
    addAuth(argv, args)
    let user = getStr(args, "user")
    if user.len > 0: argv.add(@["--user", user])
    if getBool(args, "trust_keys"): argv.add("--trust-keys")
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.protocol_probe":
    let proto = getStr(args, "protocol")
    if proto notin ["http", "rdp", "ftp", "vnc", "nfs", "afp", "webdav", "ssh", "mysql", "postgres", "mssql"]:
      raise newException(ValueError, "unsupported protocol: " & proto)
    let target = getStr(args, "target")
    requireTarget(policy, target)
    argv = @[proto, target]
    addAuth(argv, args)
    let path = getStr(args, "path")
    if path.len > 0: argv.add(@["--path", path])
    if getBool(args, "ssl"): argv.add("--ssl")
    addCommon(argv, args)
    argv.add("--json")
    runWrapped(argv, args, policy)
  of "nimux.report_summary":
    var chunks: seq[string] = @[]
    for f in getSeq(args, "evidence_files"):
      if fileExists(f):
        chunks.add("## " & f & "\n" & redactText(readFile(f)))
    %*{"summary": chunks.join("\n\n")}
  else:
    raise newException(ValueError, "unhandled tool: " & name)

proc response(id: JsonNode; payload: JsonNode): JsonNode =
  %*{"jsonrpc": "2.0", "id": id, "result": payload}

proc errorResponse(id: JsonNode; code: int; msg: string): JsonNode =
  %*{"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}

proc toolList(): JsonNode =
  var arr = newJArray()
  for t in toolDefs():
    arr.add(%*{
      "name": t.name,
      "description": t.description & " Risk: " & riskName(t.risk) & ".",
      "inputSchema": t.schema
    })
  %*{"tools": arr}

proc textContent(n: JsonNode): JsonNode =
  %*{"content": [{"type": "text", "text": pretty(n)}]}

proc handle(req: JsonNode; policy: Policy): JsonNode =
  let id = if req.hasKey("id"): req["id"] else: newJNull()
  let meth = getStr(req, "method")
  try:
    case meth
    of "initialize":
      return response(id, %*{
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": ServerName, "version": ServerVersion}
      })
    of "notifications/initialized":
      return newJNull()
    of "tools/list":
      return response(id, toolList())
    of "tools/call":
      let params = req["params"]
      let name = getStr(params, "name")
      let args = if params.hasKey("arguments"): params["arguments"] else: newJObject()
      let r = toolCall(name, args, policy)
      return response(id, textContent(r))
    of "ping":
      return response(id, %*{})
    else:
      return errorResponse(id, -32601, "method not found: " & meth)
  except CatchableError as e:
    return errorResponse(id, -32000, e.msg)

proc parseContentLength(line: string): int =
  let idx = line.find(":")
  if idx < 0:
    raise newException(ValueError, "invalid Content-Length header")
  parseInt(line[idx + 1 .. ^1].strip)

proc readMessage(): McpMessage =
  var line: string
  while true:
    try:
      line = stdin.readLine()
    except EOFError:
      result.eof = true
      return
    if line.strip.len == 0:
      continue
    break

  if line.toLowerAscii.startsWith("content-length:"):
    var contentLength = parseContentLength(line)
    while true:
      let h = stdin.readLine()
      if h.strip.len == 0:
        break
      if h.toLowerAscii.startsWith("content-length:"):
        contentLength = parseContentLength(h)
    var body = newString(contentLength)
    let got =
      if contentLength > 0:
        stdin.readChars(toOpenArray(body, 0, contentLength - 1))
      else:
        0
    if got < contentLength:
      body.setLen(got)
    return McpMessage(body: body, framed: true, eof: false)

  McpMessage(body: line, framed: false, eof: false)

when isMainModule:
  let policy = loadPolicy()
  while true:
    let msg = readMessage()
    if msg.eof:
      break
    framedOutput = msg.framed
    if msg.body.strip.len == 0:
      continue
    var req: JsonNode
    try:
      req = parseJson(msg.body)
    except CatchableError as e:
      writeJson(errorResponse(newJNull(), -32700, "parse error: " & e.msg), framedOutput)
      continue
    let resp = handle(req, policy)
    writeJson(resp, framedOutput)
