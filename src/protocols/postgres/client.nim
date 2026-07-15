import std/[asyncdispatch, asyncnet, base64, net, random, strutils, tables]
import ../../core/proxy as netproxy

proc SHA256(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}
proc HMAC(evp_md: pointer; key: pointer; key_len: cint; d: pointer; n: csize_t;
          md: pointer; md_len: ptr cuint): pointer {.cdecl, importc, header: "<openssl/hmac.h>".}
proc EVP_sha256(): pointer {.cdecl, importc, header: "<openssl/evp.h>".}
proc PKCS5_PBKDF2_HMAC(pass: cstring; passlen: cint; salt: pointer; saltlen: cint;
                       iter: cint; digest: pointer; keylen: cint; outbuf: pointer): cint
                       {.cdecl, importc, header: "<openssl/evp.h>".}

type
  PgResult* = object
    host*: string
    port*: int
    ssl*: bool
    reachable*: bool
    authenticated*: bool
    authMessage*: string
    serverVersion*: string
    currentUser*: string
    currentDatabase*: string
    databases*: seq[string]
    parameterStatus*: Table[string, string]

  PgQueryResult* = object
    columns*: seq[string]
    rows*: seq[seq[string]]
    commandTag*: string
    ok*: bool
    err*: string

  PgSession* = ref object
    sock*: AsyncSocket
    host*: string
    port*: int
    ssl*: bool
    username*: string
    database*: string
    currentUser*: string
    serverVersion*: string
    timeoutMs*: int
    parameterStatus*: Table[string, string]

proc sha256Raw(data: string): string =
  result = newString(32)
  let p = if data.len > 0: unsafeAddr data[0] else: nil
  discard SHA256(p, data.len.csize_t, addr result[0])

proc hmacSha256(key, data: string): string =
  result = newString(32)
  var outLen: cuint = 0
  let keyPtr = if key.len > 0: unsafeAddr key[0] else: nil
  let dataPtr = if data.len > 0: unsafeAddr data[0] else: nil
  discard HMAC(EVP_sha256(), keyPtr, key.len.cint, dataPtr, data.len.csize_t,
    addr result[0], addr outLen)
  result.setLen(int(outLen))

proc xorStrings(a, b: string): string =
  let n = min(a.len, b.len)
  result = newString(n)
  for i in 0 ..< n:
    result[i] = char(ord(a[i]) xor ord(b[i]))

proc scramNonce(): string =
  randomize()
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  for _ in 0 ..< 18:
    result.add alphabet[rand(alphabet.len - 1)]

proc recvExact(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  while result.len < n:
    let f = sock.recv(n - result.len)
    if not await withTimeout(f, timeoutMs):
      raise newException(IOError, "PostgreSQL: timeout")
    let chunk = await f
    if chunk.len == 0:
      raise newException(IOError, "PostgreSQL: connection closed")
    result.add chunk

proc readU32Be(s: string; pos: int): uint32 =
  (uint32(ord(s[pos])) shl 24) or (uint32(ord(s[pos + 1])) shl 16) or
  (uint32(ord(s[pos + 2])) shl 8) or uint32(ord(s[pos + 3]))

proc addU32Be(s: var string; v: uint32) =
  s.add char((v shr 24) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 8) and 0xff)
  s.add char(v and 0xff)

proc recvMsg(sock: AsyncSocket; timeoutMs: int): Future[tuple[kind: char; payload: string]] {.async.} =
  let head = await recvExact(sock, 5, timeoutMs)
  let kind = head[0]
  let msgLen = int(readU32Be(head, 1))
  if msgLen < 4:
    raise newException(IOError, "PostgreSQL: invalid message length")
  let payload = await recvExact(sock, msgLen - 4, timeoutMs)
  result = (kind, payload)

proc sendStartup(sock: AsyncSocket; username, database: string): Future[void] {.async.} =
  var body = ""
  body.addU32Be 196608'u32
  body.add "user" & "\x00" & username & "\x00"
  body.add "database" & "\x00" & database & "\x00"
  body.add "client_encoding" & "\x00" & "UTF8" & "\x00"
  body.add "\x00"
  var pkt = ""
  pkt.addU32Be uint32(body.len + 4)
  pkt.add body
  await sock.send(pkt)

proc sendPasswordMessage(sock: AsyncSocket; passwordText: string): Future[void] {.async.} =
  var payload = passwordText & "\x00"
  var pkt = "p"
  pkt.addU32Be uint32(payload.len + 4)
  pkt.add payload
  await sock.send(pkt)

proc parseError(payload: string): string =
  var pos = 0
  var fields = initTable[char, string]()
  while pos < payload.len and payload[pos] != '\x00':
    let code = payload[pos]
    inc pos
    let start = pos
    while pos < payload.len and payload[pos] != '\x00':
      inc pos
    fields[code] = payload[start ..< pos]
    inc pos
  if fields.hasKey('M'):
    result = fields['M']
  elif fields.hasKey('S'):
    result = fields['S']
  else:
    result = "server error"
  if fields.hasKey('C'):
    result.add " (" & fields['C'] & ")"

proc pgMd5Hex(data: string): string =
  proc MD5(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}
  var raw = newString(16)
  let p = if data.len > 0: unsafeAddr data[0] else: nil
  discard MD5(p, data.len.csize_t, addr raw[0])
  for ch in raw:
    result.add toHex(ord(ch), 2).toLowerAscii()

proc md5Password(password, username: string; salt: string): string =
  "md5" & pgMd5Hex(pgMd5Hex(password & username) & salt)

proc maybeUpgradeSsl(sock: AsyncSocket; timeoutMs: int): Future[bool] {.async.} =
  var req = ""
  req.addU32Be 8'u32
  req.addU32Be 80877103'u32
  await sock.send(req)
  let resp = await recvExact(sock, 1, timeoutMs)
  if resp.len == 1 and resp[0] == 'S':
    let ctx = newContext(verifyMode = CVerifyNone)
    ctx.wrapSocket(sock)
    return true
  result = false

proc parseSaslFields(text: string): Table[string, string] =
  for part in text.split(','):
    let eq = part.find('=')
    if eq > 0:
      result[part[0 ..< eq]] = part[eq + 1 .. ^1]

proc sendSaslInitial(sock: AsyncSocket; mechanism, initialResponse: string): Future[void] {.async.} =
  var payload = mechanism & "\x00"
  payload.addU32Be uint32(initialResponse.len)
  payload.add initialResponse
  var pkt = "p"
  pkt.addU32Be uint32(payload.len + 4)
  pkt.add payload
  await sock.send(pkt)

proc sendSaslResponse(sock: AsyncSocket; data: string): Future[void] {.async.} =
  var pkt = "p"
  pkt.addU32Be uint32(data.len + 4)
  pkt.add data
  await sock.send(pkt)

proc doAuth(sock: AsyncSocket; timeoutMs: int; username, password, database: string;
            useSsl: bool): Future[tuple[ok: bool; msg, serverVersion, currentUser, currentDb: string;
                                        params: Table[string, string]]] {.async.} =
  result.params = initTable[string, string]()
  if useSsl:
    discard await maybeUpgradeSsl(sock, timeoutMs)
  await sendStartup(sock, username, database)
  while true:
    let (kind, payload) = await recvMsg(sock, timeoutMs)
    case kind
    of 'R':
      if payload.len < 4:
        return (false, "short authentication packet", "", "", "", result.params)
      let authType = int(readU32Be(payload, 0))
      case authType
      of 0:
        discard
      of 3:
        await sendPasswordMessage(sock, password)
      of 5:
        if payload.len < 8:
          return (false, "short md5 auth packet", "", "", "", result.params)
        await sendPasswordMessage(sock, md5Password(password, username, payload[4 ..< 8]))
      of 10:
        var mechs: seq[string] = @[]
        var pos = 4
        while pos < payload.len and payload[pos] != '\x00':
          let start = pos
          while pos < payload.len and payload[pos] != '\x00':
            inc pos
          mechs.add payload[start ..< pos]
          inc pos
        if "SCRAM-SHA-256" notin mechs:
          return (false, "unsupported SASL mechanisms: " & mechs.join(", "), "", "", "", result.params)
        let nonce = scramNonce()
        let bare = "n=" & username.replace("=", "=3D").replace(",", "=2C") & ",r=" & nonce
        let initial = "n,," & bare
        await sendSaslInitial(sock, "SCRAM-SHA-256", initial)
        let (contKind, contPayload) = await recvMsg(sock, timeoutMs)
        if contKind != 'R' or contPayload.len < 4 or int(readU32Be(contPayload, 0)) != 11:
          return (false, "unexpected SCRAM continuation", "", "", "", result.params)
        let serverFirst = contPayload[4 .. ^1]
        let fields = parseSaslFields(serverFirst)
        if not fields.hasKey("r") or not fields.hasKey("s") or not fields.hasKey("i"):
          return (false, "malformed SCRAM server-first", "", "", "", result.params)
        let combinedNonce = fields["r"]
        if not combinedNonce.startsWith(nonce):
          return (false, "SCRAM nonce mismatch", "", "", "", result.params)
        let salt = base64.decode(fields["s"])
        let iterations = parseInt(fields["i"])
        var salted = newString(32)
        if PKCS5_PBKDF2_HMAC(password, password.len.cint,
            if salt.len > 0: unsafeAddr salt[0] else: nil,
            salt.len.cint, iterations.cint, EVP_sha256(), 32, addr salted[0]) != 1:
          return (false, "SCRAM PBKDF2 failed", "", "", "", result.params)
        let clientKey = hmacSha256(salted, "Client Key")
        let storedKey = sha256Raw(clientKey)
        let finalWithoutProof = "c=biws,r=" & combinedNonce
        let authMessage = bare & "," & serverFirst & "," & finalWithoutProof
        let clientSignature = hmacSha256(storedKey, authMessage)
        let proof = base64.encode(xorStrings(clientKey, clientSignature))
        await sendSaslResponse(sock, finalWithoutProof & ",p=" & proof)
        let (finalKind, finalPayload) = await recvMsg(sock, timeoutMs)
        if finalKind != 'R' or finalPayload.len < 4:
          return (false, "unexpected SCRAM final", "", "", "", result.params)
        let finalType = int(readU32Be(finalPayload, 0))
        if finalType == 12:
          discard
        elif finalType != 0:
          return (false, "unexpected SCRAM result type " & $finalType, "", "", "", result.params)
      else:
        return (false, "unsupported auth method " & $authType, "", "", "", result.params)
    of 'S':
      let zero = payload.find('\x00')
      if zero > 0:
        let key = payload[0 ..< zero]
        let rest = payload[zero + 1 .. ^1]
        let zero2 = rest.find('\x00')
        let val = if zero2 >= 0: rest[0 ..< zero2] else: rest
        result.params[key] = val
    of 'K':
      discard
    of 'Z':
      result.serverVersion = result.params.getOrDefault("server_version")
      result.currentUser = username
      result.currentDb = database
      return (true, "", result.serverVersion, result.currentUser, result.currentDb, result.params)
    of 'E':
      return (false, parseError(payload), "", "", "", result.params)
    of 'N':
      discard
    else:
      discard

proc postgresQuery*(sess: PgSession; sql: string): Future[PgQueryResult] {.async.} =
  var pkt = "Q"
  let payload = sql & "\x00"
  pkt.addU32Be uint32(payload.len + 4)
  pkt.add payload
  await sess.sock.send(pkt)
  while true:
    let (kind, payload) = await recvMsg(sess.sock, sess.timeoutMs)
    case kind
    of 'T':
      if payload.len < 2: continue
      let count = (ord(payload[0]) shl 8) or ord(payload[1])
      var pos = 2
      for _ in 0 ..< count:
        let start = pos
        while pos < payload.len and payload[pos] != '\x00':
          inc pos
        result.columns.add payload[start ..< pos]
        inc pos
        pos += 18
      discard
    of 'D':
      if payload.len < 2: continue
      let count = (ord(payload[0]) shl 8) or ord(payload[1])
      var pos = 2
      var row: seq[string] = @[]
      for _ in 0 ..< count:
        if pos + 4 > payload.len:
          row.add ""
          continue
        let l = int(readU32Be(payload, pos))
        pos += 4
        if l < 0:
          row.add "NULL"
        else:
          let e = min(pos + l, payload.len)
          row.add payload[pos ..< e]
          pos = e
      result.rows.add row
    of 'C':
      result.commandTag = payload.strip(chars = {'\x00'})
    of 'E':
      result.err = parseError(payload)
    of 'Z':
      result.ok = result.err.len == 0
      return
    of 'S', 'N':
      discard
    else:
      discard

proc postgresClose*(sess: PgSession) =
  try:
    var pkt = "X"
    pkt.addU32Be 4'u32
    waitFor sess.sock.send(pkt)
  except:
    discard
  try:
    sess.sock.close()
  except:
    discard

proc openPostgresSession*(host: string; port, timeoutMs: int;
                          username, password, database: string;
                          useSsl: bool): Future[PgSession] {.async.} =
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok:
      sock.close()
      return nil
  except:
    try: sock.close() except: discard
    return nil
  let db = if database.len > 0: database else: "postgres"
  try:
    let auth = await doAuth(sock, timeoutMs, username, password, db, useSsl)
    if not auth.ok:
      sock.close()
      return nil
    let sess = PgSession(sock: sock, host: host, port: port, ssl: useSsl,
      username: username, database: db, currentUser: auth.currentUser,
      serverVersion: auth.serverVersion, timeoutMs: timeoutMs,
      parameterStatus: auth.params)
    let ctx = await postgresQuery(sess, "SELECT CURRENT_USER, current_database()")
    if ctx.ok and ctx.rows.len > 0:
      if ctx.rows[0].len > 0: sess.currentUser = ctx.rows[0][0]
      if ctx.rows[0].len > 1: sess.database = ctx.rows[0][1]
    return sess
  except:
    try: sock.close() except: discard
    return nil

proc probePostgres*(host: string; port, timeoutMs: int;
                    username, password, database: string;
                    useSsl: bool): Future[PgResult] {.async.} =
  result.host = host
  result.port = port
  result.ssl = useSsl
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok:
      sock.close()
      return
  except:
    try: sock.close() except: discard
    return
  result.reachable = true
  let db = if database.len > 0: database else: "postgres"
  try:
    let auth = await doAuth(sock, timeoutMs, username, password, db, useSsl)
    result.parameterStatus = auth.params
    result.serverVersion = auth.serverVersion
    result.authenticated = auth.ok
    result.authMessage = auth.msg
    result.currentUser = auth.currentUser
    result.currentDatabase = auth.currentDb
    if auth.ok:
      let sess = PgSession(sock: sock, host: host, port: port, ssl: useSsl,
        username: username, database: db, currentUser: auth.currentUser,
        serverVersion: auth.serverVersion, timeoutMs: timeoutMs,
        parameterStatus: auth.params)
      let ctx = await postgresQuery(sess, "SELECT CURRENT_USER, current_database()")
      if ctx.ok and ctx.rows.len > 0:
        if ctx.rows[0].len > 0: result.currentUser = ctx.rows[0][0]
        if ctx.rows[0].len > 1: result.currentDatabase = ctx.rows[0][1]
      let dbs = await postgresQuery(sess, "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY 1")
      if dbs.ok:
        for row in dbs.rows:
          if row.len > 0:
            result.databases.add row[0]
  except Exception as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    try: sock.close() except: discard
