import std/[asyncdispatch, asyncnet, net, os, strutils, times, unicode]

import ../../core/scanner as scannercore
import ../../core/proxy as netproxy
import ../smb/client as smbntlm
import ../kerberos/gssapi as krb

when defined(ssl):
  import wrappers/openssl

type
  MsSqlProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksMsSql*: bool
    encryptionMode*: int
    version*: string
    message*: string

  MsSqlColumn* = object
    name*: string
    typeId*: int
    maxLen*: int

  MsSqlMessage* = object
    number*: int
    severity*: int
    state*: int
    text*: string
    isError*: bool

  MsSqlResultSet* = object
    columns*: seq[MsSqlColumn]
    rows*: seq[seq[string]]

  MsSqlExecResult* = object
    host*: string
    port*: int
    authenticated*: bool
    authMessage*: string
    serverVersion*: string
    resultSets*: seq[MsSqlResultSet]
    messages*: seq[MsSqlMessage]
    rowsAffected*: int64
    success*: bool
    error*: string

when defined(ssl):
  type MssTlsCtx = ref object
    ssl: SslPtr
    rbio, wbio: BIO
    sslCtx: SslContext

type MsSqlSession* = ref object
  socket*: AsyncSocket
  when defined(ssl):
    tls: MssTlsCtx
  packetId*: int
  authenticated*: bool
  authMessage*: string
  serverVersion*: string
  timeoutMs*: int

const
  TdsPacketSqlBatch* = 1
  TdsPacketLogin7*   = 16
  TdsPacketSspi*     = 17
  TdsPacketPrelogin* = 18
  TdsPacketStatusNormal* = 0
  TdsPacketStatusEom*   = 1

  TdsPreloginVersion    = 0
  TdsPreloginEncryption = 1
  TdsPreloginTerminator = 255

  TdsTokenColMetadata = 0x81
  TdsTokenError       = 0xAA
  TdsTokenInfo        = 0xAB
  TdsTokenLoginAck    = 0xAD
  TdsTokenRow         = 0xD1
  TdsTokenNbcRow      = 0xD2
  TdsTokenSspi        = 0xED
  TdsTokenEnvChange   = 0xE3
  TdsTokenDone        = 0xFD
  TdsTokenDoneProc    = 0xFE
  TdsTokenDoneInProc  = 0xFF

  TdsVersion71 = 0x71000001'u32
  DefaultPacketSize = 4096'u32

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc addU16Be(data: var string; value: uint16) =
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc addU16Le(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc readU16Le(data: string; offset: int): uint16 =
  uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

proc readU32Le(data: string; offset: int): uint32 =
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc readU64Le(data: string; offset: int): uint64 =
  var value: uint64 = 0
  for i in 0 ..< 8:
    value = value or (uint64(ord(data[offset + i])) shl (8 * i))
  value

proc readI32Le(data: string; offset: int): int32 =
  cast[int32](readU32Le(data, offset))

proc formatSqlDateTime(raw: string): string =
  if raw.len < 8: return raw.toHex()
  let days = int(readI32Le(raw, 0))
  let ticks = int(readU32Le(raw, 4))
  try:
    let base = dateTime(1900, mJan, 1, 0, 0, 0, zone = utc())
    let dt = base + initDuration(days = days, milliseconds = (ticks * 1000) div 300)
    return dt.format("yyyy-MM-dd HH:mm:ss")
  except CatchableError:
    return raw.toHex()

proc toUcs2Le*(text: string): string =
  for rune in text.runes:
    var code = int(rune)
    if code > 0xFFFF: code = 0xFFFD
    result.add char(code and 0xff)
    result.add char((code shr 8) and 0xff)

proc scramblePassword(plain: string): string =
  let encoded = toUcs2Le(plain)
  for ch in encoded:
    let b = ord(ch)
    let swapped = ((b and 0x0f) shl 4) or ((b and 0xf0) shr 4)
    result.add char(swapped xor 0xa5)

proc buildMsSqlPreloginRequest*(encryptionMode = 0): string =
  var payload = ""
  let versionOffset = 11
  let encryptionOffset = versionOffset + 6
  payload.add char(TdsPreloginVersion)
  payload.addU16Be versionOffset.uint16
  payload.addU16Be 6
  payload.add char(TdsPreloginEncryption)
  payload.addU16Be encryptionOffset.uint16
  payload.addU16Be 1
  payload.add char(TdsPreloginTerminator)
  payload.add "\x00\x00\x00\x00\x00\x00"
  payload.add char(encryptionMode)
  result.add char(TdsPacketPrelogin)
  result.add char(TdsPacketStatusEom)
  result.addU16Be (8 + payload.len).uint16
  result.add "\x00\x00\x00\x00"
  result.add payload

proc parseMsSqlPreloginResponse*(response: string): MsSqlProbe =
  if response.len < 8 or ord(response[0]) != TdsPacketPrelogin:
    result.message = "non-MSSQL response"
    return
  result.speaksMsSql = true
  result.message = "TDS prelogin response"
  let packetLen = (ord(response[2]) shl 8) or ord(response[3])
  if packetLen > response.len: return
  var pos = 8
  while pos + 4 < response.len and ord(response[pos]) != TdsPreloginTerminator:
    let token  = ord(response[pos])
    let offset = (ord(response[pos + 1]) shl 8) or ord(response[pos + 2])
    let length = (ord(response[pos + 3]) shl 8) or ord(response[pos + 4])
    let absolute = 8 + offset
    if absolute + length <= response.len:
      case token
      of TdsPreloginEncryption:
        if length >= 1: result.encryptionMode = ord(response[absolute])
      of TdsPreloginVersion:
        if length >= 6:
          result.version = $ord(response[absolute]) & "." &
            $ord(response[absolute + 1]) & "." &
            $ord(response[absolute + 2]) & "." &
            $ord(response[absolute + 3])
      else: discard
    pos += 5

proc parsePreloginEncryption(payload: string): int =
  var pos = 0
  while pos + 4 < payload.len and ord(payload[pos]) != TdsPreloginTerminator:
    let token  = ord(payload[pos])
    let offset = (ord(payload[pos + 1]) shl 8) or ord(payload[pos + 2])
    let length = (ord(payload[pos + 3]) shl 8) or ord(payload[pos + 4])
    if token == TdsPreloginEncryption and offset < payload.len and length >= 1:
      return ord(payload[offset])
    pos += 5
  return 0

proc recvOneTdsPacket(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.}

proc probeMsSql*(host: string; port, timeoutMs: int; encryptionMode = 0): Future[MsSqlProbe] {.async.} =
  var socket = newTcpAsyncSocket(host)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      return MsSqlProbe(host: host, port: port, reachable: false, message: "timeout")
    await socket.send(buildMsSqlPreloginRequest(encryptionMode))
    let payload = await recvOneTdsPacket(socket, timeoutMs)
    if payload.len == 0:
      return MsSqlProbe(host: host, port: port, reachable: true, message: "connected, receive timeout")
    var response = ""
    response.add char(TdsPacketPrelogin)
    response.add char(TdsPacketStatusEom)
    response.addU16Be uint16(8 + payload.len)
    response.add "\x00\x00\x00\x00"
    response.add payload
    result = parseMsSqlPreloginResponse(response)
    result.host = host
    result.port = port
    result.reachable = true
  except CatchableError as error:
    result = MsSqlProbe(host: host, port: port, reachable: false, message: cleanError(error))
  finally:
    try: socket.close()
    except CatchableError: discard

proc wrapTdsPacket(packetType: int; packetId: int; payload: string): string =
  result.add char(packetType)
  result.add char(TdsPacketStatusEom)
  result.addU16Be uint16(8 + payload.len)
  result.add "\x00\x00"
  result.add char(packetId and 0xff)
  result.add char(0)
  result.add payload

proc recvOneTdsPacket(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  var stitched = ""
  while true:
    var header = ""
    while header.len < 8:
      let chunkFut = socket.recv(8 - header.len)
      if not await withTimeout(chunkFut, timeoutMs): return stitched
      let chunk = await chunkFut
      if chunk.len == 0: return stitched
      header.add chunk
    let status = ord(header[1])
    let total  = (ord(header[2]) shl 8) or ord(header[3])
    let bodyLen = total - 8
    var body = ""
    while body.len < bodyLen:
      let chunkFut = socket.recv(bodyLen - body.len)
      if not await withTimeout(chunkFut, timeoutMs): return stitched
      let chunk = await chunkFut
      if chunk.len == 0: return stitched
      body.add chunk
    stitched.add body
    if (status and TdsPacketStatusEom) != 0: break
  return stitched

when defined(ssl):
  proc bioReadAll(b: BIO): string =
    var buf = newString(32768)
    while true:
      let n = bioRead(b, cast[cstring](addr buf[0]), cint(buf.len))
      if n <= 0: break
      result.add buf[0..<int(n)]

  proc doMssqlTls(socket: AsyncSocket; timeoutMs: int): Future[MssTlsCtx] {.async.} =
    let ctx = newContext(verifyMode = CVerifyNone)
    let ssl = SSL_new(ctx.context)
    let rb  = bioNew(bioSMem())
    let wb  = bioNew(bioSMem())
    sslSetBio(ssl, rb, wb)
    result = MssTlsCtx(ssl: ssl, rbio: rb, wbio: wb, sslCtx: ctx)
    while true:
      let ret = SSL_connect(ssl)
      let pending = bioReadAll(wb)
      if pending.len > 0:
        await socket.send(wrapTdsPacket(TdsPacketPrelogin, 1, pending))
      if ret == 1: break
      let err = SSL_get_error(ssl, ret)
      case err
      of SSL_ERROR_WANT_READ:
        let raw = await recvOneTdsPacket(socket, timeoutMs)
        if raw.len == 0:
          raise newException(IOError, "MSSQL TLS: server closed during handshake")
        discard bioWrite(rb, cast[cstring](unsafeAddr raw[0]), cint(raw.len))
      of SSL_ERROR_WANT_WRITE:
        discard
      else:
        raise newException(IOError, "MSSQL TLS handshake failed (err=" & $err & ")")

proc sessionSendPacket(s: MsSqlSession; packetType: int; payload: string) {.async.} =
  let maxBody = int(DefaultPacketSize) - 8
  var offset = 0
  while offset < payload.len or payload.len == 0:
    let chunkEnd = min(offset + maxBody, payload.len)
    let chunk = payload[offset ..< chunkEnd]
    let isLast = chunkEnd >= payload.len
    let pktId = s.packetId
    s.packetId = (s.packetId + 1) and 0xff
    var hdr = ""
    hdr.add char(packetType)
    hdr.add char(if isLast: TdsPacketStatusEom else: 0)
    hdr.addU16Be uint16(8 + chunk.len)
    hdr.add "\x00\x00"
    hdr.add char(pktId and 0xff)
    hdr.add char(0)
    let data = hdr & chunk
    when defined(ssl):
      if s.tls != nil:
        var off2 = 0
        while off2 < data.len:
          let n = SSL_write(s.tls.ssl, cast[cstring](unsafeAddr data[off2]), data.len - off2)
          if n <= 0:
            raise newException(IOError, "SSL_write failed err=" & $SSL_get_error(s.tls.ssl, n))
          off2 += n
        let raw = bioReadAll(s.tls.wbio)
        if raw.len > 0:
          await s.socket.send(raw)
        if isLast: return
        offset = chunkEnd
        continue
    await s.socket.send(data)
    if isLast: return
    offset = chunkEnd

proc sessionRecvExact(s: MsSqlSession; n: int): Future[string] {.async.} =
  when defined(ssl):
    if s.tls != nil:
      var got = ""
      while got.len < n:
        var buf = newString(n - got.len + 4096)
        let nr = SSL_read(s.tls.ssl, addr buf[0], buf.len)
        if nr > 0:
          got.add buf[0..<int(nr)]
        else:
          let err = SSL_get_error(s.tls.ssl, nr.cint)
          if err == SSL_ERROR_WANT_READ:
            let raw = await recvOneTdsPacket(s.socket, s.timeoutMs)
            if raw.len == 0: return got
            discard bioWrite(s.tls.rbio, cast[cstring](unsafeAddr raw[0]), cint(raw.len))
          else:
            return got
      return got
  var got = ""
  while got.len < n:
    let chunkFut = s.socket.recv(n - got.len)
    if not await withTimeout(chunkFut, s.timeoutMs): return got
    let chunk = await chunkFut
    if chunk.len == 0: return got
    got.add chunk
  return got

proc sessionRecvTdsPacket(s: MsSqlSession): Future[string] {.async.} =
  var stitched = ""
  while true:
    let header = await s.sessionRecvExact(8)
    if header.len < 8: return stitched
    let status  = ord(header[1])
    let total   = (ord(header[2]) shl 8) or ord(header[3])
    let bodyLen = total - 8
    if bodyLen > 0:
      let body = await s.sessionRecvExact(bodyLen)
      stitched.add body
    if (status and TdsPacketStatusEom) != 0: break
  return stitched

type Login7Field = tuple[offset, length: int]

proc buildLogin7*(host, username, password, database, appName, serverName: string;
                  sspiToken = ""): string =
  let workstation = if host.len > 0: host else: "nimux"
  let appLit      = if appName.len > 0: appName else: "nimux"
  let serverLit   = if serverName.len > 0: serverName else: ""
  let libName     = "nimux-tds"
  let useSspi     = sspiToken.len > 0

  let hostUtf  = toUcs2Le(workstation)
  let userUtf  = if useSspi: "" else: toUcs2Le(username)
  let passEnc  = if useSspi: "" else: scramblePassword(password)
  let appUtf   = toUcs2Le(appLit)
  let serverUtf = toUcs2Le(serverLit)
  let libUtf   = toUcs2Le(libName)
  let langUtf  = toUcs2Le("")
  let dbUtf    = toUcs2Le(database)

  let fixedHeaderLen = 36
  let offsetTableLen = 9 * 4
  let clientIdLen    = 6
  let extraIblfeLen  = 3 * 4
  let sspiLongLen    = 4
  let varDataStart   =
    fixedHeaderLen + offsetTableLen + clientIdLen + extraIblfeLen + sspiLongLen

  var cursor = varDataStart
  proc place(data: string): Login7Field =
    let off = cursor
    cursor += data.len
    (offset: off, length: data.len div 2)

  let fHost   = place(hostUtf)
  let fUser   = place(userUtf)
  let fPass   = (offset: cursor, length: passEnc.len div 2)
  cursor += passEnc.len
  let fApp    = place(appUtf)
  let fServer = place(serverUtf)
  let fExt    = (offset: 0, length: 0)
  let fLib    = place(libUtf)
  let fLang   = place(langUtf)
  let fDb     = place(dbUtf)
  var fSspi: Login7Field = (offset: 0, length: 0)
  if useSspi:
    fSspi = (offset: cursor, length: sspiToken.len)
    cursor += sspiToken.len

  let totalLength = cursor

  result.addU32Le uint32(totalLength)
  result.addU32Le TdsVersion71
  result.addU32Le DefaultPacketSize
  result.addU32Le 0x07000000'u32
  result.addU32Le 0x00001000'u32
  result.addU32Le 0'u32
  result.add char(0xe0)
  result.add (if useSspi: char(0x83) else: char(0x03))
  result.add char(0x00)
  result.add char(0x00)
  result.addU32Le 0xffffffc4'u32
  result.addU32Le 0x00000409'u32

  template addField(f: Login7Field) =
    result.addU16Le uint16(f.offset)
    result.addU16Le uint16(f.length)

  addField fHost; addField fUser; addField fPass; addField fApp
  addField fServer; addField fExt; addField fLib; addField fLang; addField fDb
  for _ in 0 ..< 6: result.add char(0)
  addField fSspi
  addField (offset: 0, length: 0)
  addField (offset: 0, length: 0)
  result.addU32Le 0'u32

  result.add hostUtf; result.add userUtf; result.add passEnc
  result.add appUtf; result.add serverUtf; result.add libUtf
  result.add langUtf; result.add dbUtf
  if useSspi: result.add sspiToken

type
  TokenWalker = object
    data: string
    pos: int

proc remaining(w: TokenWalker): int = w.data.len - w.pos
proc ensure(w: TokenWalker; n: int): bool = w.remaining >= n

proc readBytes(w: var TokenWalker; n: int): string =
  if not w.ensure(n):
    w.pos = w.data.len
    return ""
  result = w.data[w.pos ..< w.pos + n]
  w.pos += n

proc readU8(w: var TokenWalker): int =
  if not w.ensure(1): return 0
  result = ord(w.data[w.pos]); inc w.pos

proc readU16le(w: var TokenWalker): int =
  if not w.ensure(2): return 0
  result = int(readU16Le(w.data, w.pos)); w.pos += 2

proc readU32le(w: var TokenWalker): int =
  if not w.ensure(4): return 0
  result = int(readU32Le(w.data, w.pos)); w.pos += 4

proc readU64le(w: var TokenWalker): uint64 =
  if not w.ensure(8): return 0
  result = readU64Le(w.data, w.pos); w.pos += 8

proc readUcs2(w: var TokenWalker; chars: int): string =
  if chars <= 0: return ""
  let bytes = chars * 2
  if not w.ensure(bytes):
    w.pos = w.data.len
    return ""
  for i in 0 ..< chars:
    let code = int(readU16Le(w.data, w.pos + i * 2))
    if code <= 0xFFFF: result.add toUTF8(Rune(code))
  w.pos += bytes

proc readBVarchar(w: var TokenWalker): string =
  let charCount = w.readU8()
  result = w.readUcs2(charCount)

proc readUsVarchar(w: var TokenWalker): string =
  let charCount = w.readU16le()
  result = w.readUcs2(charCount)

proc fixedTypeLen(typeId: int): int =
  case typeId
  of 0x1F, 0x30: 1
  of 0x32: 1
  of 0x34: 2
  of 0x38: 4
  of 0x3A: 4
  of 0x3B: 4
  of 0x3C: 8
  of 0x3D: 8
  of 0x3E: 8
  of 0x7A: 4
  of 0x7F: 8
  else: -1

proc readTypeInfo(w: var TokenWalker): tuple[typeId, maxLen: int; collation: string] =
  result.typeId = w.readU8()
  let fixed = fixedTypeLen(result.typeId)
  if fixed > 0:
    result.maxLen = fixed
    return
  case result.typeId
  of 0x26, 0x37, 0x68, 0x6D, 0x6F, 0x7A, 0x7F:
    result.maxLen = w.readU8()
  of 0xA5, 0xAD:
    result.maxLen = w.readU16le()
  of 0xA7, 0xAF:
    result.maxLen = w.readU16le()
    result.collation = w.readBytes(5)
  of 0xE7, 0xEF:
    result.maxLen = w.readU16le()
    result.collation = w.readBytes(5)
  of 0x22, 0x23, 0x62:
    result.maxLen = w.readU32le()
  of 0x63:
    result.maxLen = w.readU32le()
    result.collation = w.readBytes(5)
  of 0xF1:
    discard w.readU8()
  else:
    result.maxLen = w.readU16le()

proc readValue(w: var TokenWalker; info: tuple[typeId, maxLen: int; collation: string]): string =
  let fixed = fixedTypeLen(info.typeId)
  if fixed > 0:
    let raw = w.readBytes(fixed)
    case info.typeId
    of 0x30: return $cast[int8](ord(raw[0]))
    of 0x32: return (if ord(raw[0]) != 0: "1" else: "0")
    of 0x34:
      var v = int16(uint16(ord(raw[0])) or (uint16(ord(raw[1])) shl 8))
      return $v
    of 0x38: return $cast[int32](readU32Le(raw, 0))
    of 0x3D: return formatSqlDateTime(raw)
    of 0x7F: return $cast[int64](readU64Le(raw, 0))
    else: return raw.toHex()

  let typeId = info.typeId
  case typeId
  of 0x26, 0x37, 0x68, 0x6A, 0x6C, 0x6D, 0x6F, 0x7A:
    let n = w.readU8()
    if n == 0: return ""
    let raw = w.readBytes(n)
    case typeId
    of 0x26:
      case n
      of 1: return $ord(raw[0])
      of 2: return $cast[int16](uint16(ord(raw[0])) or (uint16(ord(raw[1])) shl 8))
      of 4: return $cast[int32](readU32Le(raw, 0))
      of 8: return $cast[int64](readU64Le(raw, 0))
      else: return raw.toHex()
    of 0x68: return (if ord(raw[0]) != 0: "1" else: "0")
    else: return raw.toHex()
  of 0xA5, 0xAD:
    let length = w.readU16le()
    if length == 0xffff: return ""
    return "0x" & w.readBytes(length).toHex()
  of 0xA7, 0xAF:
    let length = w.readU16le()
    if length == 0xffff: return ""
    return w.readBytes(length)
  of 0xE7, 0xEF:
    if info.maxLen == 0xFFFF:
      let totalLen = w.readU64le()
      if totalLen == 0xFFFFFFFFFFFFFFFF'u64: return ""
      var data = ""
      while true:
        let chunkLen = w.readU32le()
        if chunkLen == 0: break
        data.add w.readBytes(chunkLen)
      for i in 0 ..< (data.len div 2):
        let code = int(readU16Le(data, i * 2))
        if code <= 0xFFFF: result.add toUTF8(Rune(code))
    else:
      let length = w.readU16le()
      if length == 0xffff: return ""
      let bytes = w.readBytes(length)
      for i in 0 ..< (bytes.len div 2):
        let code = int(readU16Le(bytes, i * 2))
        if code <= 0xFFFF: result.add toUTF8(Rune(code))
  of 0x22:
    let tpLen = w.readU8()
    if tpLen == 0: return ""
    discard w.readBytes(tpLen)
    discard w.readBytes(8)
    let dataLen = w.readU32le()
    return "0x" & w.readBytes(dataLen).toHex()
  of 0x23:
    let tpLen = w.readU8()
    if tpLen == 0: return ""
    discard w.readBytes(tpLen)
    discard w.readBytes(8)
    let dataLen = w.readU32le()
    return w.readBytes(dataLen)
  of 0x63:
    let tpLen = w.readU8()
    if tpLen == 0: return ""
    discard w.readBytes(tpLen)
    discard w.readBytes(8)
    let dataLen = w.readU32le()
    let bytes = w.readBytes(dataLen)
    for i in 0 ..< (bytes.len div 2):
      let code = int(readU16Le(bytes, i * 2))
      if code <= 0xFFFF: result.add toUTF8(Rune(code))
  of 0x62:
    let cbLen = w.readU32le()
    if cbLen == 0: return ""
    let varData = w.readBytes(cbLen)
    if varData.len < 2: return varData.toHex()
    var vw = TokenWalker(data: varData, pos: 0)
    let baseType = vw.readU8()
    let cbPropBytes = vw.readU8()
    discard vw.readBytes(cbPropBytes)
    let info2 = (typeId: baseType, maxLen: 0, collation: "")
    return readValue(vw, info2)
  else:
    let length = w.readU16le()
    if length == 0xffff: return ""
    return w.readBytes(length).toHex()

proc parseEnvChange(w: var TokenWalker): tuple[kind: int; newValue, oldValue: string] =
  let totalLen = w.readU16le()
  let endPos   = w.pos + totalLen
  if endPos > w.data.len:
    w.pos = w.data.len; return
  result.kind = w.readU8()
  case result.kind
  of 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 17, 18:
    result.newValue = w.readBVarchar()
    result.oldValue = w.readBVarchar()
  else:
    w.pos = endPos; return
  w.pos = endPos

proc parseInfoOrError(w: var TokenWalker; isError: bool): MsSqlMessage =
  let totalLen = w.readU16le()
  let endPos   = w.pos + totalLen
  result.isError = isError
  if endPos > w.data.len:
    w.pos = w.data.len; return
  result.number   = w.readU32le()
  result.state    = w.readU8()
  result.severity = w.readU8()
  result.text     = w.readUsVarchar()
  discard w.readBVarchar()
  discard w.readBVarchar()
  discard w.readU16le()
  w.pos = endPos

proc parseLoginAck(w: var TokenWalker): string =
  let totalLen = w.readU16le()
  let endPos   = w.pos + totalLen
  if endPos > w.data.len:
    w.pos = w.data.len; return ""
  discard w.readU8()
  discard w.readU32le()
  let progName = w.readBVarchar()
  let major    = w.readU8()
  let minor    = w.readU8()
  let buildHi  = w.readU8()
  let buildLo  = w.readU8()
  w.pos = endPos
  return progName.replace("\0", "") & " " & $major & "." & $minor & "." &
    $((buildHi shl 8) or buildLo)

proc parseColMetadata(w: var TokenWalker): seq[MsSqlColumn] =
  let count = w.readU16le()
  if count == 0xffff: return
  for _ in 0 ..< count:
    discard w.readU16le()
    discard w.readU16le()
    let info = readTypeInfo(w)
    if info.typeId in [0x22, 0x23, 0x63]:
      discard w.readUsVarchar()
    let name = w.readBVarchar()
    result.add MsSqlColumn(name: name, typeId: info.typeId, maxLen: info.maxLen)

proc parseRow(w: var TokenWalker; columns: seq[MsSqlColumn]): seq[string] =
  for col in columns:
    let info = (typeId: col.typeId, maxLen: col.maxLen, collation: "")
    result.add readValue(w, info)

proc parseDone(w: var TokenWalker): tuple[status, curCmd: int; rowCount: int64] =
  result.status  = w.readU16le()
  result.curCmd  = w.readU16le()
  if w.ensure(4):
    result.rowCount = int64(w.readU32le())

proc walkTokens*(stream: string; loginAck: var string;
                 messages: var seq[MsSqlMessage];
                 sets: var seq[MsSqlResultSet];
                 doneRows: var int64;
                 sspiToken: var string) =
  var w = TokenWalker(data: stream, pos: 0)
  var current    = MsSqlResultSet()
  var inResultSet = false
  while w.remaining > 0:
    let tokenType = w.readU8()
    case tokenType
    of TdsTokenEnvChange:
      discard parseEnvChange(w)
    of TdsTokenSspi:
      let length = w.readU16le()
      sspiToken = w.readBytes(length)
    of TdsTokenInfo:
      messages.add parseInfoOrError(w, false)
    of TdsTokenError:
      messages.add parseInfoOrError(w, true)
    of TdsTokenLoginAck:
      loginAck = parseLoginAck(w)
    of TdsTokenColMetadata:
      if inResultSet: sets.add current
      current = MsSqlResultSet(columns: parseColMetadata(w))
      inResultSet = true
    of TdsTokenRow:
      current.rows.add parseRow(w, current.columns)
    of TdsTokenNbcRow:
      let bitmapBytes = (current.columns.len + 7) div 8
      let bitmap = w.readBytes(bitmapBytes)
      var row: seq[string]
      for ci, col in current.columns:
        let bit = (ord(bitmap[ci div 8]) shr (ci mod 8)) and 1
        if bit == 1:
          row.add ""
        else:
          let info = (typeId: col.typeId, maxLen: col.maxLen, collation: "")
          row.add readValue(w, info)
      current.rows.add row
    of TdsTokenDone, TdsTokenDoneProc, TdsTokenDoneInProc:
      let done = parseDone(w)
      if done.rowCount > 0: doneRows += done.rowCount
      if inResultSet:
        sets.add current
        current = MsSqlResultSet()
        inResultSet = false
    of 0x79:
      discard w.readBytes(4)
    of 0x88, 0xA9, 0xAC:
      let length = w.readU16le()
      discard w.readBytes(length)
    else:
      w.pos = w.data.len
  if inResultSet: sets.add current

proc walkTokens*(stream: string; loginAck: var string;
                 messages: var seq[MsSqlMessage];
                 sets: var seq[MsSqlResultSet];
                 doneRows: var int64) =
  var ignored = ""
  walkTokens(stream, loginAck, messages, sets, doneRows, ignored)

proc sendSqlBatch*(session: MsSqlSession; sql: string) {.async.} =
  var payload = ""
  payload.addU32Le 22'u32
  payload.addU32Le 18'u32
  payload.addU16Le 2'u16
  for _ in 0 ..< 8: payload.add char(0)
  payload.addU32Le 1'u32
  payload.add toUcs2Le(sql)
  await session.sessionSendPacket(TdsPacketSqlBatch, payload)

proc readResponse*(session: MsSqlSession): Future[tuple[loginAck: string;
                  messages: seq[MsSqlMessage]; sets: seq[MsSqlResultSet];
                  rowCount: int64; sspiToken: string]] {.async.} =
  let stream = await session.sessionRecvTdsPacket()
  walkTokens(stream, result.loginAck, result.messages, result.sets,
    result.rowCount, result.sspiToken)

proc openMsSqlSession*(host: string; port, timeoutMs: int;
                      username, password, database: string;
                      ntlmHash = ""; domain = "";
                      kerberos = false; ccache = ""; spnOverride = ""): Future[MsSqlSession] {.async.} =
  let oldCcache =
    if kerberos and ccache.len > 0: getEnv("KRB5CCNAME")
    else: ""
  let restoreCcache = kerberos and ccache.len > 0
  if restoreCcache:
    if ccache.contains(":"): putEnv("KRB5CCNAME", ccache)
    else: putEnv("KRB5CCNAME", "FILE:" & ccache)
  defer:
    if restoreCcache:
      if oldCcache.len > 0: putEnv("KRB5CCNAME", oldCcache)
      else: delEnv("KRB5CCNAME")
  let socket = newTcpAsyncSocket(host)
  let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
  if not connected:
    socket.close()
    raise newException(IOError, "connection timed out")

  await socket.send(buildMsSqlPreloginRequest(0))
  let preloginPayload = await recvOneTdsPacket(socket, timeoutMs)
  if preloginPayload.len == 0:
    socket.close()
    raise newException(IOError, "no TDS prelogin response")

  result = MsSqlSession(socket: socket, packetId: 1, timeoutMs: timeoutMs)
  var loginOnlyTls = false

  when defined(ssl):
    let encMode = parsePreloginEncryption(preloginPayload)
    if encMode != 2:
      result.tls = await doMssqlTls(socket, timeoutMs)
      loginOnlyTls = encMode == 0

  let forceWindowsAuth = kerberos or ntlmHash.len > 0 or domain.len > 0 or '\\' in username

  if kerberos:
    let tok =
      if spnOverride.len > 0: krb.initKerberosSpnToken(spnOverride, domain)
      else: krb.initKerberosToken("MSSQLSvc", host, domain)
    if tok.token.len == 0:
      result.authenticated = false
      return
    let login = buildLogin7(host, "", "", database, "nimux", host, sspiToken = tok.token)
    await result.sessionSendPacket(TdsPacketLogin7, login)
    when defined(ssl):
      if loginOnlyTls:
        result.tls = nil
    let response = await result.readResponse()
    result.serverVersion = response.loginAck
    for m in response.messages:
      if m.isError:
        result.authenticated = false
        return
    result.authenticated = response.loginAck.len > 0
    return

  var ntlmUser   = username
  var ntlmDomain = domain
  if '\\' in ntlmUser:
    let parts = ntlmUser.split('\\', 1)
    if ntlmDomain.len == 0: ntlmDomain = parts[0]
    ntlmUser = parts[1]
  let type1 = smbntlm.buildNtlmType1Rpc()
  let ntlmLogin = buildLogin7(host, "", "", database, "nimux", host, sspiToken = type1)
  await result.sessionSendPacket(TdsPacketLogin7, ntlmLogin)
  when defined(ssl):
    if loginOnlyTls:
      result.tls = nil
  let challengeResp = await result.readResponse()
  if challengeResp.sspiToken.len == 0:
    if forceWindowsAuth:
      result.authenticated = false
      if challengeResp.loginAck.len > 0:
        result.serverVersion = challengeResp.loginAck
        result.authenticated = true
      return
    result.socket.close()
    let sqlSocket = newTcpAsyncSocket(host)
    let sqlConn = await netproxy.connectTcp(sqlSocket, host, port, timeoutMs)
    if not sqlConn:
      sqlSocket.close()
      result.authenticated = false
      return
    await sqlSocket.send(buildMsSqlPreloginRequest(0))
    let sqlPre = await recvOneTdsPacket(sqlSocket, timeoutMs)
    result.socket = sqlSocket
    result.packetId = 1
    when defined(ssl):
      if sqlPre.len > 0:
        let sqlEnc = parsePreloginEncryption(sqlPre)
        if sqlEnc != 2:
          result.tls = await doMssqlTls(sqlSocket, timeoutMs)
          loginOnlyTls = sqlEnc == 0
    let sqlLogin = buildLogin7(host, username, password, database, "nimux", host)
    await result.sessionSendPacket(TdsPacketLogin7, sqlLogin)
    when defined(ssl):
      if loginOnlyTls:
        result.tls = nil
    let sqlResp = await result.readResponse()
    result.serverVersion = sqlResp.loginAck
    for m in sqlResp.messages:
      if m.isError:
        result.authMessage = m.text
        result.authenticated = false
        return
    result.authenticated = sqlResp.loginAck.len > 0
    return
  let challenge = smbntlm.parseNtlmChallenge(challengeResp.sspiToken)
  if ntlmDomain.len == 0:
    if challenge.netbiosComputer.len > 0: ntlmDomain = challenge.netbiosComputer
    elif challenge.targetName.len > 0: ntlmDomain = challenge.targetName
  let cred = smbntlm.SmbCredential(
    username: ntlmUser, password: password,
    ntlmHash: ntlmHash, domain: ntlmDomain)
  let type3Bundle = smbntlm.buildNtlmType3Tds(
    cred, challenge, smbntlm.randomBytes(8), type1, challengeResp.sspiToken)
  await result.sessionSendPacket(TdsPacketSspi, type3Bundle.token)
  let finalResp = await result.readResponse()
  result.serverVersion = finalResp.loginAck
  for m in finalResp.messages:
    if m.isError:
      result.authMessage = m.text
      result.authenticated = false
      return
  result.authenticated = finalResp.loginAck.len > 0

proc runQuery*(host: string; port, timeoutMs: int;
              username, password, database, sql: string;
              ntlmHash = ""; domain = "";
              kerberos = false; linkedServer = ""; ccache = ""; spnOverride = ""): Future[MsSqlExecResult] {.async.} =
  result.host = host
  result.port = port
  try:
    let session = await openMsSqlSession(host, port, timeoutMs,
      username, password, database,
      ntlmHash = ntlmHash, domain = domain, kerberos = kerberos, ccache = ccache,
      spnOverride = spnOverride)
    result.authenticated  = session.authenticated
    result.serverVersion  = session.serverVersion
    if not session.authenticated:
      result.authMessage = "Login7 rejected"
      session.socket.close()
      return
    let finalSql =
      if linkedServer.len > 0:
        "EXEC ('" & sql.replace("'", "''") & "') AT [" & linkedServer.replace("]", "]]") & "]"
      else:
        sql
    await session.sendSqlBatch(finalSql)
    let response = await session.readResponse()
    result.resultSets   = response.sets
    result.messages     = response.messages
    result.rowsAffected = response.rowCount
    result.success      = true
    for m in response.messages:
      if m.isError:
        result.success = false
        result.error   = m.text
        break
    session.socket.close()
  except CatchableError as error:
    result.success = false
    result.error   = cleanError(error)

proc runXpCmdshell*(host: string; port, timeoutMs: int;
                   username, password, command: string;
                   ntlmHash = ""; domain = "";
                   kerberos = false; linkedServer = ""; ccache = ""; spnOverride = ""): Future[MsSqlExecResult] {.async.} =
  let escaped = command.replace("'", "''")
  result = await runQuery(host, port, timeoutMs, username, password, "master",
    "EXEC xp_cmdshell '" & escaped & "'",
    ntlmHash = ntlmHash, domain = domain, kerberos = kerberos,
    linkedServer = linkedServer, ccache = ccache, spnOverride = spnOverride)
  if result.success: return
  if result.error.toLowerAscii().contains("xp_cmdshell"):
    let enableSql =
      "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; " &
      "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; " &
      "EXEC xp_cmdshell '" & escaped & "'"
    result = await runQuery(host, port, timeoutMs, username, password, "master", enableSql,
      ntlmHash = ntlmHash, domain = domain, kerberos = kerberos,
      linkedServer = linkedServer, ccache = ccache, spnOverride = spnOverride)
