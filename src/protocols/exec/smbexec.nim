## SMBexec (impacket-style) command execution.
##
## Flow:
##   1. SMB negotiate + NTLM session-setup via the shared establishSmbSession
##      helper (gives us IPC$ + ADMIN$ tree IDs ready to use).
##   2. Open the \pipe\svcctl pipe over IPC$.
##   3. DCE/RPC bind to SVCCTL (interface 367ABB81-9844-35F1-AD32-98F038001003 v2.0).
##   4. ROpenSCManagerW (opnum 15) → SC_HANDLE.
##   5. RCreateServiceW (opnum 12) with binary path
##        %COMSPEC% /Q /c <cmd> > %SYSTEMROOT%\Temp\<rand>.out 2>&1
##      Service type/start/error tuned so the SCM starts the process but
##      returns ERROR_SERVICE_REQUEST_TIMEOUT — that's fine, the command has
##      already executed by the time the timeout fires.
##   6. RStartServiceW (opnum 19) — return code irrelevant for us.
##   7. RDeleteService (opnum 2) + RCloseServiceHandle (opnum 0) cleanup.
##   8. Open the output file on ADMIN$\Temp\<rand>.out, read its contents,
##      then delete it via SMB2 SET_INFO disposition.
##
## Output retrieval uses the existing SmbRpcCtx (same socket / session) — we
## just switch its `treeId` to the ADMIN$ tree.

import std/[asyncdispatch, asyncnet, strutils, random, times]

import ../smb/client as smb
import ./output as execio

type
  SmbExecResult* = object
    host*: string
    port*: int
    username*: string
    domain*: string
    authenticated*: bool
    serviceCreated*: bool
    serviceStarted*: bool
    output*: string
    bytesRead*: int
    message*: string
    error*: string
    success*: bool
    rpcStatus*: uint32
    scmStatus*: uint32

  SmbExecSession* = ref object
    session*: smb.SmbSession
    pipe*: smb.SmbPipeInfo
    scmHandle*: string
    message*: string
    ready*: bool

const
  SvcCtlUuidBytes* = [
    byte 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
    0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03
  ]
  ScManagerAllAccess = 0x000F003F'u32
  ServiceAllAccess   = 0x000F01FF'u32
  ServiceWin32OwnProcess = 0x00000010'u32
  ServiceDemandStart = 0x00000003'u32
  ServiceErrorIgnore = 0x00000000'u32


proc addU16Le(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc padNdr4(data: var string) =
  while data.len mod 4 != 0: data.add char(0)

proc ndrUniqueWString(text: string; refId = 0x00020000'u32): string =
  result.addU32Le refId
  let utf = smb.toUtf16Le(text) & "\x00\x00"
  let charCount = uint32(utf.len div 2)
  result.addU32Le charCount
  result.addU32Le 0'u32
  result.addU32Le charCount
  result.add utf
  padNdr4(result)

proc ndrNullPointer(): string =
  result.addU32Le 0'u32

proc readU32Le(data: string; offset: int): uint32 =
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc randomTempName(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))



proc buildROpenSCManagerWStub(host: string;
                              dwDesiredAccess: uint32): string =
  result.add ndrUniqueWString("\\\\" & host)
  result.add ndrUniqueWString("ServicesActive")
  result.addU32Le dwDesiredAccess

proc buildRCreateServiceWStub(scmHandle: string; serviceName, binaryPath: string;
                              dwDesiredAccess = ServiceAllAccess;
                              dwServiceType = ServiceWin32OwnProcess;
                              dwStartType = ServiceDemandStart;
                              dwErrorControl = ServiceErrorIgnore): string =
  if scmHandle.len != 20:
    raise newException(ValueError, "SCManager handle must be 20 bytes")
  result.add scmHandle
  let nameUtf = smb.toUtf16Le(serviceName) & "\x00\x00"
  let nameChars = uint32(nameUtf.len div 2)
  result.addU32Le nameChars
  result.addU32Le 0'u32
  result.addU32Le nameChars
  result.add nameUtf
  padNdr4(result)
  result.add ndrUniqueWString(serviceName)
  result.addU32Le dwDesiredAccess
  result.addU32Le dwServiceType
  result.addU32Le dwStartType
  result.addU32Le dwErrorControl
  let binUtf = smb.toUtf16Le(binaryPath) & "\x00\x00"
  let binChars = uint32(binUtf.len div 2)
  result.addU32Le binChars
  result.addU32Le 0'u32
  result.addU32Le binChars
  result.add binUtf
  padNdr4(result)
  result.add ndrNullPointer()
  result.add ndrNullPointer()
  result.add ndrNullPointer()
  result.addU32Le 0'u32
  result.add ndrNullPointer()
  result.add ndrNullPointer()
  result.addU32Le 0'u32

proc buildRStartServiceWStub(serviceHandle: string): string =
  if serviceHandle.len != 20:
    raise newException(ValueError, "service handle must be 20 bytes")
  result.add serviceHandle
  result.addU32Le 0'u32
  result.add ndrNullPointer()

proc buildRCloseServiceHandleStub(handle: string): string =
  if handle.len != 20:
    raise newException(ValueError, "service handle must be 20 bytes")
  result.add handle

proc buildRDeleteServiceStub(handle: string): string =
  if handle.len != 20:
    raise newException(ValueError, "service handle must be 20 bytes")
  result.add handle

proc parseScmHandle(stub: string): tuple[handle: string; status: uint32] =
  if stub.len < 24:
    return ("", 0xffffffff'u32)
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc parseStatusOnly(stub: string; offset = 0): uint32 =
  if stub.len < offset + 4:
    return 0xffffffff'u32
  readU32Le(stub, offset)


proc smbExec*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain, command: string;
              waitMs = 1500;
              authMethod: smb.SmbAuthMethod = smb.samNtlm;
              ccache = ""): Future[SmbExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  result.domain = domain
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain,
    ccache: ccache)
  let session = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  result.authenticated = true
  let ctx = session.ctx
  try:
    let pipe = await smb.openSmbPipe(ctx, "svcctl")
    if not pipe.opened:
      result.message = "svcctl pipe open failed 0x" & pipe.status.toHex(8)
      return
    let bindAck = await smb.rpcBindPipe(ctx, pipe,
      smb.buildDceRpcBind(SvcCtlUuidBytes, 2'u16, 0'u16, 1'u32))
    if not bindAck.bound:
      result.message = "SVCCTL bind failed"
      return
    let outName     = randomTempName() & ".out"
    let batName     = randomTempName() & ".bat"
    let outputPath  = "Temp\\" & outName
    let batSmbPath  = "Temp\\" & batName
    let serviceName = "ne" & randomTempName()
    let outPath     = "C:\\Windows\\Temp\\" & outName
    let sep         = command.find(" && ")
    let batContent  =
      if sep >= 0: command[0 ..< sep] & "\r\ncmd /c \"" & command[sep+4..^1] & " > " & outPath & " 2>&1\"\r\n"
      else: "cmd /c \"" & command & " > " & outPath & " 2>&1\"\r\n"
    let binaryPath  = "C:\\Windows\\System32\\cmd.exe /Q /c C:\\Windows\\Temp\\" & batName
    if session.adminTreeId == 0:
      result.message = "ADMIN$ tree not connected"
      return
    discard await execio.writeSmbFile(ctx, session.adminTreeId, batSmbPath, batContent)

    let openSt = await smb.rpcCall(ctx, pipe, 15'u16,
      buildROpenSCManagerWStub(host, ScManagerAllAccess), 2'u32)
    let scm = parseScmHandle(openSt)
    result.scmStatus = scm.status
    if scm.handle.len != 20 or scm.status != 0:
      result.message = "ROpenSCManagerW failed status 0x" & scm.status.toHex(8)
      return
    let createSt = await smb.rpcCall(ctx, pipe, 12'u16,
      buildRCreateServiceWStub(scm.handle, serviceName, binaryPath), 3'u32)
    if createSt.len < 28:
      result.message = "RCreateServiceW short reply"
      return
    let svcHandle = createSt[4 ..< 24]
    let createStatus = readU32Le(createSt, createSt.len - 4)
    result.rpcStatus = createStatus
    if createStatus != 0 or svcHandle.len != 20:
      result.message = "RCreateServiceW failed status 0x" & createStatus.toHex(8)
      discard await smb.rpcCall(ctx, pipe, 0'u16,
        buildRCloseServiceHandleStub(scm.handle), 4'u32)
      return
    result.serviceCreated = true
    let startSt = await smb.rpcCall(ctx, pipe, 19'u16,
      buildRStartServiceWStub(svcHandle), 5'u32)
    result.serviceStarted = true
    discard startSt
    await sleepAsync(3000)
    discard await smb.rpcCall(ctx, pipe, 2'u16,
      buildRDeleteServiceStub(svcHandle), 6'u32)
    discard await smb.rpcCall(ctx, pipe, 0'u16,
      buildRCloseServiceHandleStub(svcHandle), 7'u32)
    discard await smb.rpcCall(ctx, pipe, 0'u16,
      buildRCloseServiceHandleStub(scm.handle), 8'u32)
    discard await execio.readSmbFile(ctx, session.adminTreeId, batSmbPath, true)
    let polled = await execio.pollOutputFile(ctx, session.adminTreeId, outputPath,
      attempts = 18, initialDelayMs = 250, backoffMs = 150, preDelayMs = waitMs)
    result.output = polled.data
    result.bytesRead = result.output.len
    result.success = true
    result.message = if result.output.len > 0: "command executed" else: "service ran but output file was empty"
  except CatchableError as error:
    result.error = error.msg.splitLines()[0]
    result.message = "smbexec error"

proc openSmbExecSession*(host: string; port, timeoutMs: int;
                         username, password, ntlmHash, domain: string;
                         authMethod: smb.SmbAuthMethod = smb.samNtlm;
                         ccache = ""): Future[SmbExecSession] {.async.} =
  result = SmbExecSession()
  let cred = smb.SmbCredential(username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache)
  let session = await smb.establishSmbSession(host, port, timeoutMs, cred, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  if session.adminTreeId == 0:
    result.message = if session.message.len > 0: "ADMIN$ not available: " & session.message
                     else: "ADMIN$ not available"
    return
  result.session = session
  let pipe = await smb.openSmbPipe(session.ctx, "svcctl")
  if not pipe.opened:
    result.message = "svcctl pipe open failed 0x" & pipe.status.toHex(8)
    return
  let bindAck = await smb.rpcBindPipe(session.ctx, pipe,
    smb.buildDceRpcBind(SvcCtlUuidBytes, 2'u16, 0'u16, 1'u32))
  if not bindAck.bound:
    result.message = "SVCCTL bind failed"
    return
  let openSt = await smb.rpcCall(session.ctx, pipe, 15'u16,
    buildROpenSCManagerWStub(host, ScManagerAllAccess), 2'u32)
  let scm = parseScmHandle(openSt)
  if scm.handle.len != 20 or scm.status != 0:
    result.message = "ROpenSCManagerW failed 0x" & scm.status.toHex(8)
    return
  result.pipe = pipe
  result.scmHandle = scm.handle
  result.ready = true

proc runSmbExecShellCommand*(s: SmbExecSession; command: string): Future[tuple[output, err: string]] {.async.} =
  let ctx = s.session.ctx
  let outName     = randomTempName() & ".out"
  let batName     = randomTempName() & ".bat"
  let outputPath  = "Temp\\" & outName
  let batSmbPath  = "Temp\\" & batName
  let serviceName = "ne" & randomTempName()
  let outPath     = "C:\\Windows\\Temp\\" & outName
  let sep         = command.find(" && ")
  let batContent  =
    if sep >= 0: command[0 ..< sep] & "\r\ncmd /c \"" & command[sep+4..^1] & " > " & outPath & " 2>&1\"\r\n"
    else: "cmd /c \"" & command & " > " & outPath & " 2>&1\"\r\n"
  let binaryPath  = "C:\\Windows\\System32\\cmd.exe /Q /c C:\\Windows\\Temp\\" & batName
  discard await execio.writeSmbFile(ctx, s.session.adminTreeId, batSmbPath, batContent)
  let createSt = await smb.rpcCall(ctx, s.pipe, 12'u16,
    buildRCreateServiceWStub(s.scmHandle, serviceName, binaryPath), 3'u32)
  if createSt.len < 28:
    result.err = "RCreateServiceW short reply"
    return
  let svcHandle = createSt[4 ..< 24]
  let createStatus = readU32Le(createSt, createSt.len - 4)
  if createStatus != 0:
    result.err = "RCreateServiceW failed 0x" & createStatus.toHex(8)
    return
  discard await smb.rpcCall(ctx, s.pipe, 19'u16,
    buildRStartServiceWStub(svcHandle), 4'u32)
  discard await smb.rpcCall(ctx, s.pipe, 2'u16,
    buildRDeleteServiceStub(svcHandle), 5'u32)
  discard await smb.rpcCall(ctx, s.pipe, 0'u16,
    buildRCloseServiceHandleStub(svcHandle), 6'u32)
  discard await execio.readSmbFile(ctx, s.session.adminTreeId, batSmbPath, true)
  let polled = await execio.pollOutputFile(ctx, s.session.adminTreeId, outputPath,
    attempts = 18, initialDelayMs = 250, backoffMs = 150, preDelayMs = 1500)
  result.output = polled.data

proc closeSmbExecSession*(s: SmbExecSession): Future[void] {.async.} =
  if s == nil or s.session == nil: return
  if s.scmHandle.len == 20:
    try:
      discard await smb.rpcCall(s.session.ctx, s.pipe, 0'u16,
        buildRCloseServiceHandleStub(s.scmHandle), 99'u32)
    except CatchableError: discard
  try: s.session.ctx.socket.close()
  except CatchableError: discard
