import std/[asyncdispatch, asyncnet, net, os, sequtils, strutils]
import ../../core/proxy as netproxy

type BigNum = distinct pointer
type BnCtx  = distinct pointer

proc BN_new(): BigNum {.importc, header: "<openssl/bn.h>".}
proc BN_free(a: BigNum) {.importc, header: "<openssl/bn.h>".}
proc BN_bin2bn(s: pointer; len: cint; ret: BigNum): BigNum {.importc, header: "<openssl/bn.h>".}
proc BN_bn2bin(a: BigNum; to: pointer): cint {.importc, header: "<openssl/bn.h>".}
proc BN_set_word(a: BigNum; w: culong): cint {.importc, header: "<openssl/bn.h>".}
proc BN_mod_exp(r, a, p, m: BigNum; ctx: BnCtx): cint {.importc, header: "<openssl/bn.h>".}
proc BN_CTX_new(): BnCtx {.importc, header: "<openssl/bn.h>".}
proc BN_CTX_free(ctx: BnCtx) {.importc, header: "<openssl/bn.h>".}
proc BN_num_bytes(a: BigNum): cint {.importc, header: "<openssl/bn.h>".}

proc RAND_bytes(buf: pointer; num: cint): cint {.importc, header: "<openssl/rand.h>".}

type OsslProvider = distinct pointer
proc OSSL_PROVIDER_load(libctx: pointer; name: cstring): OsslProvider {.importc, header: "<openssl/provider.h>".}

proc ensureCast5() =
  var loaded {.global.} = false
  if not loaded:
    loaded = true
    discard OSSL_PROVIDER_load(nil, "legacy")
    discard OSSL_PROVIDER_load(nil, "default")

type EvpCipher = distinct pointer
type EvpCipherCtx = distinct pointer
proc EVP_cast5_ecb(): EvpCipher {.importc, header: "<openssl/evp.h>".}
proc EVP_cast5_cbc(): EvpCipher {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_new(): EvpCipherCtx {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_free(ctx: EvpCipherCtx) {.importc, header: "<openssl/evp.h>".}
proc EVP_CipherInit_ex(ctx: EvpCipherCtx; cipher: EvpCipher; engine: pointer;
                       key, iv: pointer; enc: cint): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_set_padding(ctx: EvpCipherCtx; padding: cint): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_CipherUpdate(ctx: EvpCipherCtx; outbuf: pointer; outl: ptr cint;
                      inbuf: pointer; inl: cint): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_CipherFinal_ex(ctx: EvpCipherCtx; outbuf: pointer; outl: ptr cint): cint {.importc, header: "<openssl/evp.h>".}

proc castCrypt(data, key, iv: string; enc: bool): string =
  let ctx = EVP_CIPHER_CTX_new()
  defer: EVP_CIPHER_CTX_free(ctx)
  result = newString(data.len)
  let kp = if key.len > 0: unsafeAddr key[0] else: nil
  let dp = if data.len > 0: unsafeAddr data[0] else: nil
  let rp = if result.len > 0: addr result[0] else: nil
  let ivp = if iv.len > 0: unsafeAddr iv[0] else: nil
  discard EVP_CipherInit_ex(ctx, EVP_cast5_cbc(), nil, kp, ivp, if enc: 1 else: 0)
  discard EVP_CIPHER_CTX_set_padding(ctx, 0)
  var outl = 0.cint
  discard EVP_CipherUpdate(ctx, rp, addr outl, dp, data.len.cint)
  var finall = 0.cint
  discard EVP_CipherFinal_ex(ctx, if rp != nil: cast[pointer](cast[int](rp) + outl) else: nil, addr finall)
  result.setLen(int(outl) + int(finall))

proc randBytes(n: int): string =
  result = newString(n)
  discard RAND_bytes(addr result[0], n.cint)

proc bnModExp(base: string; exp: string; modulus: string): string =
  let bnBase = BN_bin2bn(unsafeAddr base[0], base.len.cint, BN_new())
  let bnExp  = BN_bin2bn(unsafeAddr exp[0],  exp.len.cint,  BN_new())
  let bnMod  = BN_bin2bn(unsafeAddr modulus[0], modulus.len.cint, BN_new())
  let bnRes  = BN_new()
  let ctx    = BN_CTX_new()
  defer:
    BN_free(bnBase); BN_free(bnExp); BN_free(bnMod); BN_free(bnRes); BN_CTX_free(ctx)
  discard BN_mod_exp(bnRes, bnBase, bnExp, bnMod, ctx)
  let nbytes = int(BN_num_bytes(bnRes))
  result = newString(nbytes)
  discard BN_bn2bin(bnRes, addr result[0])

proc wordToBytes(v: uint32): string =
  result = newString(4)
  result[0] = char((v shr 24) and 0xff)
  result[1] = char((v shr 16) and 0xff)
  result[2] = char((v shr 8)  and 0xff)
  result[3] = char(v and 0xff)

proc incBytes(s: string): string =
  result = s
  var i = result.len - 1
  while i >= 0:
    let v = uint8(ord(result[i])) + 1
    result[i] = char(v)
    if v != 0: break
    dec i

type
  AfpEntry* = object
    name*: string
    isDirectory*: bool
    nodeId*: uint32
    size*: uint64

  AfpSession* = ref object
    sock*: AsyncSocket
    host*: string
    port*: int
    timeoutMs*: int
    username*: string
    afpVersion*: string
    uam*: string
    nextReqId*: uint16

  AfpResult* = object
    host*:          string
    port*:          int
    reachable*:     bool
    serverName*:    string
    machineType*:   string
    afpVersions*:   seq[string]
    uams*:          seq[string]
    authenticated*: bool
    authMessage*:   string

proc recvExact(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let f = sock.recv(n - buf.len)
    if not await withTimeout(f, timeoutMs):
      raise newException(IOError, "AFP: timeout")
    let chunk = await f
    if chunk.len == 0:
      raise newException(IOError, "AFP: connection closed")
    buf.add chunk
  result = buf

proc readU8(s: string; pos: int): uint8 = uint8(ord(s[pos]))
proc readU16Be(s: string; pos: int): uint16 =
  (uint16(ord(s[pos])) shl 8) or uint16(ord(s[pos+1]))
proc readU32Be(s: string; pos: int): uint32 =
  (uint32(ord(s[pos])) shl 24) or (uint32(ord(s[pos+1])) shl 16) or
  (uint32(ord(s[pos+2])) shl 8) or uint32(ord(s[pos+3]))
proc readU64Be(s: string; pos: int): uint64 =
  (uint64(readU32Be(s, pos)) shl 32) or uint64(readU32Be(s, pos + 4))

proc addU8(s: var string; v: uint8) = s.add char(v)
proc addU16Be(s: var string; v: uint16) =
  s.add char((v shr 8) and 0xff); s.add char(v and 0xff)
proc addU32Be(s: var string; v: uint32) =
  s.add char((v shr 24) and 0xff); s.add char((v shr 16) and 0xff)
  s.add char((v shr 8) and 0xff); s.add char(v and 0xff)
proc addU64Be(s: var string; v: uint64) =
  s.addU32Be uint32(v shr 32)
  s.addU32Be uint32(v and 0xffffffff'u64)

proc sendDsi(sock: AsyncSocket; cmd: uint8; reqId: uint16; payload: string;
             dataOffset: uint32 = 0'u32): Future[void] {.async.} =
  var hdr = ""
  hdr.addU8 0
  hdr.addU8 cmd
  hdr.addU16Be reqId
  hdr.addU32Be dataOffset
  hdr.addU32Be uint32(payload.len)
  hdr.addU32Be 0
  await sock.send(hdr & payload)

proc recvDsi(sock: AsyncSocket; timeoutMs: int): Future[tuple[cmd: uint8; err: int32; payload: string]] {.async.} =
  let hdr = await recvExact(sock, 16, timeoutMs)
  let dataLen = int(readU32Be(hdr, 8))
  let errCode = cast[int32](readU32Be(hdr, 4))
  let payload = if dataLen > 0: await recvExact(sock, dataLen, timeoutMs) else: ""
  result = (readU8(hdr, 1), errCode, payload)

proc readPStr(s: string; pos: var int): string =
  if pos >= s.len: return ""
  let n = int(readU8(s, pos)); inc pos
  let e = min(pos + n, s.len)
  result = s[pos ..< e]; pos = e

proc pStr(s: string): string =
  result.addU8 uint8(s.len)
  result.add s

proc afpEncodePathUtf8(path: string): string =
  result.addU8 3
  result.addU32Be 0x08000103'u32
  result.addU16Be uint16(path.len)
  result.add path

proc afpNextReqId(sess: AfpSession): uint16 =
  result = sess.nextReqId
  inc sess.nextReqId
  if sess.nextReqId == 0'u16:
    sess.nextReqId = 1

proc chooseAfpVersion(versions: seq[string]): string =
  if "AFP3.4" in versions: "AFP3.4"
  elif "AFP3.3" in versions: "AFP3.3"
  elif "AFP3.2" in versions: "AFP3.2"
  elif "AFP3.1" in versions: "AFP3.1"
  else: "AFP2.2"

proc chooseAfpUam(uams: seq[string]): string =
  for u in ["DHCAST128", "DHX2", "Cleartxt Passwrd", "No User Authent"]:
    if uams.anyIt(it == u):
      return u

proc afpParseShareList(payload: string): seq[string] =
  if payload.len < 5:
    return
  var pos = 5
  let count = int(readU8(payload, 4))
  for _ in 0 ..< count:
    if pos >= payload.len:
      break
    inc pos
    result.add readPStr(payload, pos)

proc afpDoLogin(sock: AsyncSocket; timeoutMs: int;
                afpVersion, uam, username, password: string): Future[tuple[ok: bool; msg: string]] {.async.} =
  try:
    await sendDsi(sock, 4, 1, "")
    let (_, openErr, _) = await recvDsi(sock, timeoutMs)
    if openErr != 0:
      return (false, "DSIOpenSession error " & $openErr)
    case uam
    of "No User Authent":
      var cmd = "\x12"
      cmd.add pStr(afpVersion)
      cmd.add pStr(uam)
      if (cmd.len + username.len + 1) mod 2 != 0:
        cmd.add username & "\x00\x00"
      else:
        cmd.add username & "\x00"
      await sendDsi(sock, 2, 2, cmd)
      let (_, loginErr, _) = await recvDsi(sock, timeoutMs)
      return (loginErr == 0, if loginErr == -5023: "user not auth / bad password"
                              elif loginErr != 0: "FPLogin error " & $loginErr else: "")
    of "Cleartxt Passwrd":
      var pass8 = newString(8)
      for i in 0..7: pass8[i] = if i < password.len: password[i] else: '\x00'
      var cmd = "\x12"
      cmd.add pStr(afpVersion)
      cmd.add pStr(uam)
      if (cmd.len - 1) mod 2 != 0: cmd.add '\x00'
      cmd.add username & "\x00" & pass8
      await sendDsi(sock, 2, 2, cmd)
      let (_, loginErr, _) = await recvDsi(sock, timeoutMs)
      return (loginErr == 0, if loginErr == -5023: "user not auth / bad password"
                              elif loginErr != 0: "FPLogin error " & $loginErr else: "")
    of "DHCAST128":
      ensureCast5()
      const dhxP = "\xBA\x28\x73\xDF\xB0\x60\x57\xD4\x3F\x20\x24\x74\x4C\xEE\xE7\x5B"
      const dhxG = "\x07"
      let Ra = randBytes(16)
      let MaRaw = bnModExp(dhxG, Ra, dhxP)
      let Ma = repeat('\x00', 16 - MaRaw.len) & MaRaw
      var cmd = "\x12"
      cmd.add pStr(afpVersion)
      cmd.add pStr(uam)
      cmd.add char(username.len)
      cmd.add username
      if username.len mod 2 == 0: cmd.add '\x00'
      cmd.add Ma
      await sendDsi(sock, 2, 2, cmd)
      let (_, loginErr, challenge) = await recvDsi(sock, timeoutMs)
      if loginErr != -5001:
        return (false, if loginErr == -5023: "user not auth / bad password"
                       else: "FPLogin error " & $loginErr)
      if challenge.len < 50:
        return (false, "challenge too short (" & $challenge.len & ")")
      let sessId = readU16Be(challenge, 0)
      let Mb = challenge[2..17]
      let encBlock = challenge[18..49]
      let Kraw = bnModExp(Mb, Ra, dhxP)
      let K = repeat('\x00', 16 - Kraw.len) & Kraw
      let dec = castCrypt(encBlock, K, "CJalbert", false)
      let Rb = dec[0..15]
      let RbInc = incBytes(Rb)
      var plain = RbInc
      for i in 0..63: plain.add(if i < password.len: password[i] else: '\x00')
      let response = castCrypt(plain, K, "LWallace", true)
      var cont = ""
      cont.add '\x00'
      cont.addU16Be sessId
      cont.add response
      await sendDsi(sock, 2, 3, "\x13" & cont)
      let (_, contErr, _) = await recvDsi(sock, timeoutMs)
      return (contErr == 0, if contErr == -5023: "user not auth / bad password"
                             elif contErr != 0: "DHCAST128 auth failed (" & $contErr & ")" else: "")
    else:
      return (false, "UAM not supported: " & uam)
  except Exception as e:
    return (false, e.msg.splitLines()[0])

proc connectSock(host: string; port, timeoutMs: int): Future[AsyncSocket] {.async.} =
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if ok: return sock
    sock.close()
  except: sock.close()
  return nil

proc readPStrAt(s: string; off: int): string =
  if off >= s.len: return ""
  var pos = off
  readPStr(s, pos)

proc readPStrListAt(s: string; off: int): seq[string] =
  if off >= s.len: return
  let count = int(readU8(s, off))
  var pos = off + 1
  for _ in 0 ..< count:
    result.add readPStr(s, pos)

proc getServerInfo(host: string; port, timeoutMs: int): Future[tuple[name, machine: string; versions, uams: seq[string]]] {.async.} =
  let sock = await connectSock(host, port, timeoutMs)
  if sock.isNil: return
  defer: sock.close()
  try:
    await sendDsi(sock, 3, 1, "")
    let (_, err, payload) = await recvDsi(sock, timeoutMs)
    if err != 0 or payload.len < 10: return
    let offMachine = int(readU16Be(payload, 0))
    let offAfpVer  = int(readU16Be(payload, 2))
    let offUam     = int(readU16Be(payload, 4))
    var pos = 10
    result.name    = readPStr(payload, pos)
    result.machine = readPStrAt(payload, offMachine)
    result.versions = readPStrListAt(payload, offAfpVer)
    result.uams     = readPStrListAt(payload, offUam)
  except: discard

proc tryLogin(host: string; port, timeoutMs: int;
              afpVersion, uam, username, password: string): Future[tuple[ok: bool; msg: string]] {.async.} =
  let sock = await connectSock(host, port, timeoutMs)
  if sock.isNil: return (false, "connection failed")
  defer: sock.close()
  return await afpDoLogin(sock, timeoutMs, afpVersion, uam, username, password)

proc probeAfp*(host: string; port, timeoutMs: int;
               username, password: string): Future[AfpResult] {.async.} =
  result.host = host
  result.port = port
  let testSock = await connectSock(host, port, timeoutMs)
  if testSock.isNil: return
  testSock.close()
  result.reachable = true

  let info = await getServerInfo(host, port, timeoutMs)
  result.serverName  = info.name
  result.machineType = info.machine
  result.afpVersions = info.versions
  result.uams        = info.uams

  if username.len == 0: return

  let afpVersion =
    if "AFP3.4" in result.afpVersions: "AFP3.4"
    elif "AFP3.3" in result.afpVersions: "AFP3.3"
    elif "AFP3.2" in result.afpVersions: "AFP3.2"
    elif "AFP3.1" in result.afpVersions: "AFP3.1"
    else: "AFP2.2"

  let uamPriority = ["DHCAST128", "Cleartxt Passwrd", "No User Authent"]
  var chosenUam = ""
  for u in uamPriority:
    if result.uams.anyIt(it == u):
      chosenUam = u
      break

  if chosenUam.len == 0:
    result.authMessage = "no supported UAM (server has: " & result.uams.join(", ") & ")"
    return

  let (ok, msg) = await tryLogin(host, port, timeoutMs, afpVersion, chosenUam, username, password)
  result.authenticated = ok
  if not ok:
    result.authMessage = "[" & chosenUam & "] " & msg

const
  afpFileBmNodeId = 0x0100'u16
  afpFileBmLongName = 0x0040'u16
  afpFileBmExtSize = 0x0800'u16
  afpDirBmNodeId = 0x0100'u16
  afpDirBmLongName = 0x0040'u16
  afpRootDid = 2'u32

proc openAfpSession*(host: string; port, timeoutMs: int;
                     username, password: string): Future[AfpSession] {.async.} =
  let info = await getServerInfo(host, port, timeoutMs)
  let afpVersion = chooseAfpVersion(info.versions)
  let uam = chooseAfpUam(info.uams)
  if uam.len == 0:
    return nil
  let sock = await connectSock(host, port, timeoutMs)
  if sock.isNil:
    return nil
  let (ok, _) = await afpDoLogin(sock, timeoutMs, afpVersion, uam, username, password)
  if not ok:
    try: sock.close() except: discard
    return nil
  result = AfpSession(sock: sock, host: host, port: port, timeoutMs: timeoutMs,
    username: username, afpVersion: afpVersion, uam: uam, nextReqId: 10)

proc closeAfpSession*(sess: AfpSession) =
  if sess.isNil or sess.sock.isNil:
    return
  try:
    waitFor sendDsi(sess.sock, 2, afpNextReqId(sess), "\x14\x00")
    discard waitFor recvDsi(sess.sock, sess.timeoutMs)
  except CatchableError:
    discard
  try:
    sess.sock.close()
  except CatchableError:
    discard

proc afpListShares*(sess: AfpSession): Future[seq[string]] {.async.} =
  var cmd = ""
  cmd.add '\x10'
  cmd.add '\x00'
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0:
    return
  result = afpParseShareList(payload)

proc afpOpenVolume*(sess: AfpSession; volumeName: string): Future[uint16] {.async.} =
  var cmd = ""
  cmd.add '\x18'
  cmd.add '\x00'
  cmd.addU16Be 0x0020'u16
  cmd.add pStr(volumeName)
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0 or payload.len < 4:
    return 0'u16
  result = readU16Be(payload, 2)

proc afpCloseVolume*(sess: AfpSession; volumeId: uint16): Future[bool] {.async.} =
  var cmd = ""
  cmd.add '\x02'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, _) = await recvDsi(sess.sock, sess.timeoutMs)
  result = err == 0

proc afpDecodeName(data: string; pos, offset: int): string =
  if offset <= 0 or pos + offset >= data.len:
    return ""
  var p = pos + offset
  if p >= data.len:
    return ""
  result = readPStr(data, p)

proc afpDecodeEntry(isDir: bool; payload: string; pos: int): AfpEntry =
  var cur = pos
  let orig = pos
  if isDir:
    if cur + 6 > payload.len:
      return
    let nameOff = int(readU16Be(payload, cur)); cur += 2
    result.name = afpDecodeName(payload, orig, nameOff)
    result.nodeId = readU32Be(payload, cur); cur += 4
    result.isDirectory = true
  else:
    if cur + 14 > payload.len:
      return
    let nameOff = int(readU16Be(payload, cur)); cur += 2
    result.name = afpDecodeName(payload, orig, nameOff)
    result.nodeId = readU32Be(payload, cur); cur += 4
    result.size = readU64Be(payload, cur)
    result.isDirectory = false

proc afpLookupEntry*(sess: AfpSession; volumeId: uint16; did: uint32;
                     name: string): Future[tuple[ok: bool; entry: AfpEntry; message: string]] {.async.} =
  var cmd = ""
  cmd.add '\x22'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  cmd.addU32Be did
  cmd.addU16Be afpFileBmLongName or afpFileBmNodeId or afpFileBmExtSize
  cmd.addU16Be afpDirBmLongName or afpDirBmNodeId
  cmd.add afpEncodePathUtf8(name)
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0:
    return (false, AfpEntry(), "lookup failed (" & $err & ")")
  if payload.len < 7:
    return (false, AfpEntry(), "short reply")
  let fileType = readU8(payload, 4)
  if fileType == 0x80'u8:
    return (true, afpDecodeEntry(true, payload, 6), "")
  result = (true, afpDecodeEntry(false, payload, 6), "")

proc afpListDirectory*(sess: AfpSession; volumeId: uint16; did: uint32): Future[seq[AfpEntry]] {.async.} =
  var cmd = ""
  cmd.add '\x44'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  cmd.addU32Be did
  cmd.addU16Be afpFileBmLongName or afpFileBmNodeId or afpFileBmExtSize
  cmd.addU16Be afpDirBmLongName or afpDirBmNodeId
  cmd.addU16Be 128'u16
  cmd.addU32Be 1'u32
  cmd.addU32Be 65535'u32
  cmd.add afpEncodePathUtf8("")
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0 or payload.len < 6:
    return
  let fileBm = readU16Be(payload, 0)
  let dirBm = readU16Be(payload, 2)
  let count = int(readU16Be(payload, 4))
  var pos = 6
  for _ in 0 ..< count:
    if pos + 4 > payload.len:
      break
    var recLen = int(readU16Be(payload, pos))
    let recType = readU8(payload, pos + 3)
    if recLen <= 0 or pos + recLen > payload.len:
      break
    let recData = payload[pos ..< pos + recLen]
    let entryPos = 4
    try:
      let entry =
        if recType == 0x80'u8:
          afpDecodeEntry(true, recData, entryPos)
        elif fileBm != 0'u16:
          afpDecodeEntry(false, recData, entryPos)
        else:
          AfpEntry()
      if entry.name.len > 0:
        result.add entry
    except IndexDefect:
      discard
    if (recLen mod 2) != 0:
      inc recLen
    pos += recLen

proc afpGetDirEntryNames*(sess: AfpSession; volumeId: uint16; did: uint32): Future[seq[string]] {.async.} =
  var cmd = ""
  cmd.add '\x44'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  cmd.addU32Be did
  cmd.addU16Be 0'u16
  cmd.addU16Be afpDirBmLongName or afpDirBmNodeId
  cmd.addU16Be 128'u16
  cmd.addU32Be 1'u32
  cmd.addU32Be 65535'u32
  cmd.add afpEncodePathUtf8("")
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0 or payload.len < 6:
    return
  let count = int(readU16Be(payload, 4))
  var pos = 6
  for _ in 0 ..< count:
    if pos + 4 > payload.len:
      break
    var recLen = int(readU16Be(payload, pos))
    if recLen <= 0 or pos + recLen > payload.len:
      break
    let recType = readU8(payload, pos + 3)
    if recType == 0x80'u8:
      let recData = payload[pos ..< pos + recLen]
      try:
        let entry = afpDecodeEntry(true, recData, 4)
        if entry.name.len > 0:
          result.add entry.name
      except IndexDefect:
        discard
    if (recLen mod 2) != 0:
      inc recLen
    pos += recLen

proc afpCreateDir*(sess: AfpSession; volumeId: uint16; did: uint32; name: string): Future[tuple[ok: bool; message: string]] {.async.} =
  var cmd = ""
  cmd.add '\x06'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  cmd.addU32Be did
  cmd.add afpEncodePathUtf8(name)
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, _) = await recvDsi(sess.sock, sess.timeoutMs)
  result = (err == 0, if err == 0: "" else: "mkdir failed (" & $err & ")")

proc afpOpenFork(sess: AfpSession; volumeId: uint16; did: uint32; accessMode: uint16;
                 name: string): Future[tuple[ok: bool; forkId: uint16; message: string]] {.async.} =
  var cmd = ""
  cmd.add '\x1a'
  cmd.add '\x00'
  cmd.addU16Be volumeId
  cmd.addU32Be did
  cmd.addU16Be afpFileBmExtSize
  cmd.addU16Be accessMode
  cmd.add afpEncodePathUtf8(name)
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
  if err != 0 or payload.len < 4:
    return (false, 0'u16, "open fork failed (" & $err & ")")
  result = (true, readU16Be(payload, 2), "")

proc afpCloseFork(sess: AfpSession; forkId: uint16): Future[void] {.async.} =
  var cmd = ""
  cmd.add '\x04'
  cmd.add '\x00'
  cmd.addU16Be forkId
  await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
  discard await recvDsi(sess.sock, sess.timeoutMs)

proc afpReadFile*(sess: AfpSession; volumeId: uint16; did: uint32; name, localPath: string): Future[tuple[ok: bool; bytesRead: int; message: string]] {.async.} =
  let opened = await afpOpenFork(sess, volumeId, did, 0x0001'u16, name)
  if not opened.ok:
    return (false, 0, opened.message)
  defer:
    try: waitFor afpCloseFork(sess, opened.forkId)
    except CatchableError: discard
  let info = await afpLookupEntry(sess, volumeId, did, name)
  if not info.ok:
    return (false, 0, info.message)
  var outBuf = ""
  var offset = 0'u64
  while offset < info.entry.size:
    let want = min(65536'u64, info.entry.size - offset)
    var cmd = ""
    cmd.add '\x3c'
    cmd.add '\x00'
    cmd.addU16Be opened.forkId
    cmd.addU64Be offset
    cmd.addU64Be want
    await sendDsi(sess.sock, 2, afpNextReqId(sess), cmd)
    let (_, err, payload) = await recvDsi(sess.sock, sess.timeoutMs)
    if err != 0 and err != -5009:
      return (false, outBuf.len, "read failed (" & $err & ")")
    if payload.len == 0:
      break
    outBuf.add payload
    offset += uint64(payload.len)
    if payload.len < int(want):
      break
  writeFile(localPath, outBuf)
  result = (true, outBuf.len, "")

proc afpWriteFile*(sess: AfpSession; volumeId: uint16; did: uint32;
                   localPath, remoteName: string): Future[tuple[ok: bool; bytesWritten: int; message: string]] {.async.} =
  if not fileExists(localPath):
    return (false, 0, "local file not found")
  let data = readFile(localPath)
  var create = ""
  create.add '\x07'
  create.add '\x00'
  create.addU16Be volumeId
  create.addU32Be did
  create.add afpEncodePathUtf8(remoteName)
  await sendDsi(sess.sock, 2, afpNextReqId(sess), create)
  let (_, createErr, _) = await recvDsi(sess.sock, sess.timeoutMs)
  if createErr != 0 and createErr != -5017:
    return (false, 0, "create failed (" & $createErr & ")")
  let opened = await afpOpenFork(sess, volumeId, did, 0x0002'u16, remoteName)
  if not opened.ok:
    return (false, 0, opened.message)
  defer:
    try: waitFor afpCloseFork(sess, opened.forkId)
    except CatchableError: discard
  var offset = 0
  while offset < data.len:
    let chunkLen = min(65536, data.len - offset)
    var cmd = ""
    cmd.add '\x3d'
    cmd.add '\x00'
    cmd.addU16Be opened.forkId
    cmd.addU64Be uint64(offset)
    cmd.addU64Be uint64(chunkLen)
    cmd.add data[offset ..< offset + chunkLen]
    await sendDsi(sess.sock, 6, afpNextReqId(sess), cmd, 20'u32)
    let (_, err, _) = await recvDsi(sess.sock, sess.timeoutMs)
    if err != 0:
      return (false, offset, "write failed (" & $err & ")")
    offset += chunkLen
  result = (true, data.len, "")
