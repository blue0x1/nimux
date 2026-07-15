import std/[asyncdispatch, asyncnet, strutils, random, times]

import ../smb/client as smb
import ./output as execio

type
  AtExecResult* = object
    host*: string
    port*: int
    username*: string
    domain*: string
    authenticated*: bool
    taskCreated*: bool
    taskStarted*: bool
    output*: string
    bytesRead*: int
    message*: string
    error*: string
    success*: bool

  AtExecSession* = ref object
    session*: smb.SmbSession
    pipe*: smb.SmbPipeInfo
    sealCtx*: smb.NtlmSealContext
    kerbSealCtx*: smb.KerbSealContext
    useKerb*: bool
    message*: string
    ready*: bool

const
  TschUuidBytes = [
    byte 0x49, 0x59, 0xD3, 0x86, 0xC9, 0x83, 0x44, 0x40,
    byte 0xB4, 0x24, 0xDB, 0x36, 0x32, 0x31, 0xFD, 0x0C
  ]

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

proc ndrUniqueWString(text: string): string =
  result.addU32Le 0x00020000'u32
  let utf = smb.toUtf16Le(text) & "\x00\x00"
  let n = uint32(utf.len div 2)
  result.addU32Le n
  result.addU32Le 0'u32
  result.addU32Le n
  result.add utf
  padNdr4(result)

proc ndrWString(text: string): string =
  let utf = smb.toUtf16Le(text) & "\x00\x00"
  let n = uint32(utf.len div 2)
  result.addU32Le n
  result.addU32Le 0'u32
  result.addU32Le n
  result.add utf
  padNdr4(result)

proc ndrNull(): string =
  result.addU32Le 0'u32

proc randomToken(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 8:
    let c = rng.rand(25)
    result.add chr(ord('a') + c)

proc xmlEscape(s: string): string =
  for c in s:
    case c
    of '&': result.add "&amp;"
    of '<': result.add "&lt;"
    of '>': result.add "&gt;"
    of '"': result.add "&quot;"
    else: result.add c

proc buildTaskXml(command, outPath: string): string =
  let args = xmlEscape("/Q /c " & command & " > " & outPath & " 2>&1")
  result = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>""" & args & """</Arguments>
    </Exec>
  </Actions>
</Task>"""

proc buildSchRpcRegisterTaskStub(taskPath, xml: string): string =
  result.add ndrUniqueWString(taskPath)
  result.add ndrWString(xml)
  result.addU32Le 0x00000002'u32
  result.add ndrNull()
  result.addU32Le 5'u32
  result.addU32Le 0'u32
  result.add ndrNull()

proc buildSchRpcDeleteStub(taskPath: string): string =
  result.add ndrWString(taskPath)
  result.addU32Le 0'u32

proc atexecSealedCall(ctx: smb.SmbRpcCtx; pipe: smb.SmbPipeInfo;
                       sealCtx: smb.NtlmSealContext; kerbSealCtx: smb.KerbSealContext;
                       useKerb: bool; opnum: uint16; stub: string; callId: uint32):
                       Future[smb.DceRpcCallResult] {.async.} =
  if useKerb:
    result = await smb.rpcCallExKerbSealed(ctx, pipe, kerbSealCtx, opnum, stub, callId)
  else:
    result = await smb.rpcCallExSealed(ctx, pipe, sealCtx, opnum, stub, callId)

proc atExec*(host: string; port, timeoutMs: int;
             username, password, ntlmHash, domain, command: string;
             authMethod: smb.SmbAuthMethod = smb.samNtlm;
             ccache = "";
             krb5Config = "";
             outputPreDelayMs = 0): Future[AtExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  result.domain = domain
  let cred = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain,
    ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, cred, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  result.authenticated = true
  if session.adminTreeId == 0:
    result.message = "ADMIN$ not available — needed to read task output"
    return

  let token    = randomToken()
  let taskName = "\\" & token
  let outFile  = token & ".out"
  let outPath  = "C:\\Windows\\Temp\\" & outFile
  let smhPath  = "Temp\\" & outFile
  let ctx      = session.ctx
  let useKerb  = authMethod == smb.samKerberos

  try:
    let pipe = await smb.openSmbPipe(ctx, "atsvc")
    if not pipe.opened:
      result.message = "atsvc pipe open failed 0x" & pipe.status.toHex(8)
      return

    var sealCtx: smb.NtlmSealContext
    var kerbSealCtx: smb.KerbSealContext
    if useKerb:
      let (bindAck, ksc) = await smb.rpcBindPipeKerb(ctx, pipe,
        @TschUuidBytes, 1'u16, 0'u16, host, domain, 1'u32,
        ccache = ccache, krb5Config = krb5Config)
      if not bindAck.bound:
        result.message = "TSCH Kerberos bind failed: " & bindAck.message
        return
      kerbSealCtx = ksc
    else:
      let (bindAck, sc) = await smb.rpcBindPipeNtlm(ctx, pipe,
        @TschUuidBytes, 1'u16, 0'u16, cred, 1'u32)
      if not bindAck.bound:
        result.message = "TSCH NTLM bind failed: " & bindAck.message
        return
      sealCtx = sc

    let xml = buildTaskXml(command, outPath)
    let regRpc = await atexecSealedCall(ctx, pipe, sealCtx, kerbSealCtx, useKerb,
      1'u16, buildSchRpcRegisterTaskStub(taskName, xml), 1'u32)
    let regStatus = if regRpc.stub.len >= 4: readU32Le(regRpc.stub, regRpc.stub.len - 4) else: 0xffffffff'u32
    if regStatus != 0:
      let detail = if regRpc.faultStatus != 0: " fault=0x" & regRpc.faultStatus.toHex(8) else: ""
      result.message = "SchRpcRegisterTask failed 0x" & regStatus.toHex(8) & detail
      return
    result.taskCreated = true
    result.taskStarted = true

    let polled = await execio.pollOutputFile(ctx, session.adminTreeId, smhPath,
      preDelayMs = outputPreDelayMs)
    result.output   = polled.data
    result.bytesRead = polled.data.len
    result.success  = true
    result.message  = if polled.data.len > 0: "command executed" else: "task ran but produced no output"

    discard await atexecSealedCall(ctx, pipe, sealCtx, kerbSealCtx, useKerb,
      13'u16, buildSchRpcDeleteStub(taskName), 4'u32)
  except CatchableError as e:
    result.error = e.msg.splitLines()[0]
    if result.message.len == 0:
      result.message = "atexec error"

proc openAtExecSession*(host: string; port, timeoutMs: int;
                        username, password, ntlmHash, domain: string;
                        authMethod: smb.SmbAuthMethod = smb.samNtlm;
                        ccache = "";
                        krb5Config = ""): Future[AtExecSession] {.async.} =
  result = AtExecSession()
  let cred = smb.SmbCredential(username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, cred, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  if session.adminTreeId == 0:
    result.message = "ADMIN$ not available"
    return
  result.session = session
  result.useKerb = authMethod == smb.samKerberos
  let pipe = await smb.openSmbPipe(session.ctx, "atsvc")
  if not pipe.opened:
    result.message = "atsvc pipe open failed 0x" & pipe.status.toHex(8)
    return
  if result.useKerb:
    let (bindAck, ksc) = await smb.rpcBindPipeKerb(session.ctx, pipe,
      @TschUuidBytes, 1'u16, 0'u16, host, domain, 1'u32,
      ccache = ccache, krb5Config = krb5Config)
    if not bindAck.bound:
      result.message = "TSCH Kerberos bind failed: " & bindAck.message
      return
    result.kerbSealCtx = ksc
  else:
    let (bindAck, sc) = await smb.rpcBindPipeNtlm(session.ctx, pipe,
      @TschUuidBytes, 1'u16, 0'u16, cred, 1'u32)
    if not bindAck.bound:
      result.message = "TSCH NTLM bind failed: " & bindAck.message
      return
    result.sealCtx = sc
  result.pipe = pipe
  result.ready = true

proc runAtExecShellCommand*(s: AtExecSession; command: string): Future[tuple[output, err: string]] {.async.} =
  let ctx = s.session.ctx
  let token   = randomToken()
  let taskName = "\\" & token
  let outFile  = token & ".out"
  let outPath  = "C:\\Windows\\Temp\\" & outFile
  let smhPath  = "Temp\\" & outFile
  let xml = buildTaskXml(command, outPath)
  let regRpc = await atexecSealedCall(ctx, s.pipe, s.sealCtx, s.kerbSealCtx, s.useKerb,
    1'u16, buildSchRpcRegisterTaskStub(taskName, xml), 1'u32)
  let regStatus = if regRpc.stub.len >= 4: readU32Le(regRpc.stub, regRpc.stub.len - 4) else: 0xffffffff'u32
  if regStatus != 0:
    result.err = "SchRpcRegisterTask failed 0x" & regStatus.toHex(8)
    return
  let polled = await execio.pollOutputFile(ctx, s.session.adminTreeId, smhPath)
  result.output = polled.data
  discard await atexecSealedCall(ctx, s.pipe, s.sealCtx, s.kerbSealCtx, s.useKerb,
    13'u16, buildSchRpcDeleteStub(taskName), 4'u32)

proc closeAtExecSession*(s: AtExecSession) =
  if s == nil or s.session == nil: return
  try: asyncnet.close(s.session.ctx.socket)
  except CatchableError: discard
