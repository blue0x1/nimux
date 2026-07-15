import std/[asyncdispatch, asyncnet, net, strutils]
import ../../core/proxy as netproxy

proc SHA1(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}
proc SHA256(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}

proc sha1(data: string): string =
  result = newString(20)
  let p = if data.len > 0: unsafeAddr data[0] else: nil
  discard SHA1(p, data.len.csize_t, addr result[0])

proc sha256m(data: string): string =
  result = newString(32)
  let p = if data.len > 0: unsafeAddr data[0] else: nil
  discard SHA256(p, data.len.csize_t, addr result[0])

proc readU8(s: string; pos: int): uint8 = uint8(ord(s[pos]))
proc readU16Le(s: string; pos: int): uint16 =
  uint16(ord(s[pos])) or (uint16(ord(s[pos+1])) shl 8)
proc readU32Le(s: string; pos: int): uint32 =
  uint32(ord(s[pos])) or (uint32(ord(s[pos+1])) shl 8) or
  (uint32(ord(s[pos+2])) shl 16) or (uint32(ord(s[pos+3])) shl 24)

proc addU8(s: var string; v: uint8) = s.add char(v)
proc addU24Le(s: var string; v: uint32) =
  s.add char(v and 0xff); s.add char((v shr 8) and 0xff); s.add char((v shr 16) and 0xff)
proc addU32Le(s: var string; v: uint32) =
  s.add char(v and 0xff); s.add char((v shr 8) and 0xff)
  s.add char((v shr 16) and 0xff); s.add char((v shr 24) and 0xff)

proc readNulStr(s: string; pos: var int): string =
  while pos < s.len and s[pos] != '\x00':
    result.add s[pos]; inc pos
  inc pos

proc readFixedStr(s: string; pos: var int; n: int): string =
  let e = min(pos + n, s.len)
  result = s[pos ..< e]; pos = e

proc readLenencInt(s: string; pos: var int): int64 =
  if pos >= s.len: return -1
  let b = uint8(ord(s[pos])); inc pos
  case b
  of 0xfb'u8: return -1
  of 0xfc'u8:
    if pos + 1 >= s.len: return -1
    let v = int64(readU16Le(s, pos)); pos += 2; return v
  of 0xfd'u8:
    if pos + 2 >= s.len: return -1
    let v = int64(ord(s[pos])) or (int64(ord(s[pos+1])) shl 8) or (int64(ord(s[pos+2])) shl 16)
    pos += 3; return v
  of 0xfe'u8:
    if pos + 7 >= s.len: return -1
    let v = int64(readU32Le(s, pos)) or (int64(readU32Le(s, pos+4)) shl 32)
    pos += 8; return v
  else: return int64(b)

proc readLenencStr(s: string; pos: var int): string =
  let n = readLenencInt(s, pos)
  if n <= 0: return ""
  let e = min(pos + int(n), s.len)
  result = s[pos ..< e]; pos = e

proc nativePasswordScramble(password, salt: string): string =
  if password.len == 0: return ""
  let h1 = sha1(password)
  let h2 = sha1(h1)
  let combined = sha1(salt & h2)
  result = newString(20)
  for i in 0..19:
    result[i] = char(ord(h1[i]) xor ord(combined[i]))

proc cachingSha2Scramble(password, salt: string): string =
  if password.len == 0: return ""
  let h1 = sha256m(password)
  let h2 = sha256m(h1)
  let combined = sha256m(h2 & salt)
  result = newString(32)
  for i in 0..31:
    result[i] = char(ord(h1[i]) xor ord(combined[i]))

proc recvExact(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let f = sock.recv(n - buf.len)
    if not await withTimeout(f, timeoutMs):
      raise newException(IOError, "MySQL: timeout")
    let chunk = await f
    if chunk.len == 0:
      raise newException(IOError, "MySQL: connection closed")
    buf.add chunk
  result = buf

proc recvPacket(sock: AsyncSocket; timeoutMs: int): Future[tuple[seq: uint8; payload: string]] {.async.} =
  let hdr = await recvExact(sock, 4, timeoutMs)
  let pktLen = int(readU32Le(hdr, 0) and 0x00FFFFFF'u32)
  result.seq = readU8(hdr, 3)
  result.payload = await recvExact(sock, pktLen, timeoutMs)

proc sendPacket(sock: AsyncSocket; seqNo: uint8; payload: string): Future[void] {.async.} =
  var pkt = ""
  pkt.addU24Le uint32(payload.len)
  pkt.addU8 seqNo
  pkt.add payload
  await sock.send(pkt)

type
  MysqlResult* = object
    host*:          string
    port*:          int
    reachable*:     bool
    serverVersion*: string
    authenticated*: bool
    authMessage*:   string
    authPlugin*:    string
    databases*:     seq[string]
    currentUser*:   string

  MysqlQueryResult* = object
    columns*:  seq[string]
    rows*:     seq[seq[string]]
    affected*: int64
    insertId*: int64
    err*:      string
    ok*:       bool

  MysqlSession* = ref object
    sock*:          AsyncSocket
    host*:          string
    port*:          int
    username*:      string
    database*:      string
    currentUser*:   string
    serverVersion*: string
    timeoutMs*:     int

proc doHandshake(sock: AsyncSocket; timeoutMs: int;
                 username, password: string): Future[tuple[ok: bool; version, user, msg: string]] {.async.} =
  let (_, handshake) = await recvPacket(sock, timeoutMs)
  if handshake.len < 5:
    return (false, "", "", "short handshake")
  let proto = readU8(handshake, 0)
  if proto == 0xff:
    var p = 3
    return (false, "", "", handshake[p .. ^1])

  var pos = 1
  let serverVersion = readNulStr(handshake, pos)
  pos += 4
  var salt = readFixedStr(handshake, pos, 8)
  pos += 1
  var capLo = readU16Le(handshake, pos); pos += 2
  pos += 1; pos += 2
  let capHi = readU16Le(handshake, pos); pos += 2
  let capabilities = uint32(capLo) or (uint32(capHi) shl 16)
  let authPluginDataLen =
    if (capabilities and 0x00080000'u32) != 0: max(13, int(readU8(handshake, pos)) - 8)
    else: 13
  pos += 1; pos += 10
  let salt2 = readFixedStr(handshake, pos, authPluginDataLen)
  pos += authPluginDataLen
  salt.add salt2[0 ..< salt2.len - 1]
  var authPlugin = ""
  if (capabilities and 0x00080000'u32) != 0:
    authPlugin = readNulStr(handshake, pos)

  let useCachingSha2 = authPlugin == "caching_sha2_password"
  let scramble =
    if useCachingSha2: cachingSha2Scramble(password, salt)
    else: nativePasswordScramble(password, salt)

  const
    ClientLongPassword = 0x00000001'u32
    ClientProtocol41   = 0x00000200'u32
    ClientSecureConn   = 0x00008000'u32
    ClientPluginAuth   = 0x00080000'u32

  var clientCaps = (ClientLongPassword or ClientProtocol41 or ClientSecureConn or ClientPluginAuth) and capabilities
  var resp = ""
  resp.addU32Le clientCaps
  resp.addU32Le 16777216'u32
  resp.addU8 33'u8
  for _ in 0..22: resp.addU8 0
  resp.add username & "\x00"
  if scramble.len > 0:
    resp.addU8 uint8(scramble.len)
    resp.add scramble
  else:
    resp.addU8 0
  let pluginName = if useCachingSha2: "caching_sha2_password" else: "mysql_native_password"
  resp.add pluginName & "\x00"
  await sendPacket(sock, 1, resp)

  var pkt = await recvPacket(sock, timeoutMs)

  if useCachingSha2 and pkt.payload.len > 0 and readU8(pkt.payload, 0) == 0x01:
    let subtype = readU8(pkt.payload, 1)
    if subtype == 0x04:
      await sendPacket(sock, pkt.seq + 1, password & "\x00")
      pkt = await recvPacket(sock, timeoutMs)
    elif subtype == 0x02 or subtype == 0x03:
      await sendPacket(sock, pkt.seq + 1, "\x02")
      pkt = await recvPacket(sock, timeoutMs)

  let status = readU8(pkt.payload, 0)
  if status == 0x00:
    return (true, serverVersion, "", "")
  elif status == 0xfe and pkt.payload.len > 1:
    var p = 1
    let switchPlugin = readNulStr(pkt.payload, p)
    let switchSalt = pkt.payload[p .. ^2]
    let newScramble =
      if switchPlugin == "caching_sha2_password": cachingSha2Scramble(password, switchSalt)
      else: nativePasswordScramble(password, switchSalt)
    await sendPacket(sock, pkt.seq + 1, newScramble)
    let finalPkt = await recvPacket(sock, timeoutMs)
    if readU8(finalPkt.payload, 0) == 0x00:
      return (true, serverVersion, "", "")
    var ep = 3
    return (false, serverVersion, "", readNulStr(finalPkt.payload, ep))
  elif status == 0xff:
    var ep = 3
    return (false, serverVersion, "", readNulStr(pkt.payload, ep))
  return (false, serverVersion, "", "unexpected status 0x" & status.toHex(2))

proc mysqlQuery*(sess: MysqlSession; sql: string): Future[MysqlQueryResult] {.async.} =
  result.ok = false
  try:
    await sendPacket(sess.sock, 0, "\x03" & sql)
    let first = await recvPacket(sess.sock, sess.timeoutMs)
    let status = readU8(first.payload, 0)
    if status == 0x00:
      var p = 1
      result.affected = readLenencInt(first.payload, p)
      result.insertId = readLenencInt(first.payload, p)
      result.ok = true
      return
    if status == 0xff:
      var p = 3
      if p < first.payload.len and first.payload[p] == '#': inc p
      p += 5
      result.err = if p < first.payload.len: first.payload[p .. ^1] else: "error"
      return
    var p = 0
    let colCount = int(readLenencInt(first.payload, p))
    if colCount <= 0: return
    for _ in 0 ..< colCount:
      let colPkt = await recvPacket(sess.sock, sess.timeoutMs)
      var cp = 0
      discard readLenencStr(colPkt.payload, cp)
      discard readLenencStr(colPkt.payload, cp)
      discard readLenencStr(colPkt.payload, cp)
      discard readLenencStr(colPkt.payload, cp)
      let colName = readLenencStr(colPkt.payload, cp)
      result.columns.add colName
    discard await recvPacket(sess.sock, sess.timeoutMs)
    while true:
      let row = await recvPacket(sess.sock, sess.timeoutMs)
      let rowStatus = readU8(row.payload, 0)
      if rowStatus == 0xfe or rowStatus == 0xff: break
      var rp = 0
      var cols: seq[string]
      for _ in 0 ..< colCount:
        if rp >= row.payload.len: break
        let flen = readLenencInt(row.payload, rp)
        if flen < 0:
          cols.add "NULL"
        else:
          cols.add row.payload[rp ..< min(rp + int(flen), row.payload.len)]
          rp += int(flen)
      result.rows.add cols
    result.ok = true
  except Exception as e:
    result.err = e.msg.splitLines()[0]

proc mysqlClose*(sess: MysqlSession) =
  try:
    waitFor sendPacket(sess.sock, 0, "\x01")
  except: discard
  try: sess.sock.close() except: discard

proc openMysqlSession*(host: string; port, timeoutMs: int;
                       username, password: string): Future[MysqlSession] {.async.} =
  let sess = MysqlSession(host: host, port: port, username: username, timeoutMs: timeoutMs)
  sess.sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sess.sock, host, port, timeoutMs)
    if not ok: sess.sock.close(); return nil
  except: sess.sock.close(); return nil
  try:
    let (authed, version, _, msg) = await doHandshake(sess.sock, timeoutMs, username, password)
    if not authed:
      sess.sock.close()
      return nil
    sess.serverVersion = version
    let userRes = await mysqlQuery(sess, "SELECT CURRENT_USER(), DATABASE()")
    if userRes.rows.len > 0:
      if userRes.rows[0].len > 0: sess.currentUser = userRes.rows[0][0]
      if userRes.rows[0].len > 1 and userRes.rows[0][1] != "NULL":
        sess.database = userRes.rows[0][1]
    if sess.database.len == 0: sess.database = "(none)"
    return sess
  except:
    try: sess.sock.close() except: discard
    return nil

proc probeMySQL*(host: string; port, timeoutMs: int;
                 username, password: string): Future[MysqlResult] {.async.} =
  result.host = host
  result.port = port
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok: sock.close(); return
  except: sock.close(); return
  result.reachable = true
  try:
    let (authed, version, _, msg) = await doHandshake(sock, timeoutMs, username, password)
    result.serverVersion = version
    result.authenticated = authed
    result.authMessage = msg
    if authed:
      let sess = MysqlSession(sock: sock, host: host, port: port, username: username,
                              database: "", timeoutMs: timeoutMs)
      let userRes = await mysqlQuery(sess, "SELECT CURRENT_USER()")
      if userRes.rows.len > 0 and userRes.rows[0].len > 0:
        result.currentUser = userRes.rows[0][0]
      let dbRes = await mysqlQuery(sess, "SHOW DATABASES")
      for row in dbRes.rows:
        if row.len > 0: result.databases.add row[0]
  except Exception as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sock.close()
