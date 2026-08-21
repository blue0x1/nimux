import std/[asyncdispatch, asyncnet, net, strutils, random, posix]
import ../../core/proxy as netproxy

type
  EvpPkeyCtxObj {.importc: "EVP_PKEY_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpPkeyObj {.importc: "EVP_PKEY", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpCipherObj {.importc: "EVP_CIPHER", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpCipherCtxObj {.importc: "EVP_CIPHER_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpMdObj {.importc: "EVP_MD", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpMdCtxObj {.importc: "EVP_MD_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object

  EvpPkeyCtxPtr = ptr EvpPkeyCtxObj
  EvpPkeyPtr    = ptr EvpPkeyObj
  EvpCipherPtr  = ptr EvpCipherObj
  EvpCipherCtxPtr = ptr EvpCipherCtxObj
  EvpMdPtr      = ptr EvpMdObj
  EvpMdCtxPtr   = ptr EvpMdCtxObj

  BioObj {.importc: "BIO", header: "<openssl/bio.h>", incompleteStruct.} = object
  RsaObj {.importc: "RSA", header: "<openssl/rsa.h>", incompleteStruct.} = object
  BnObj {.importc: "BIGNUM", header: "<openssl/bn.h>", incompleteStruct.} = object

const EVP_PKEY_X25519 = 1034.cint

proc EVP_PKEY_CTX_new_id(id: cint; e: pointer): EvpPkeyCtxPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_new(pkey: EvpPkeyPtr; e: pointer): EvpPkeyCtxPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_free(ctx: EvpPkeyCtxPtr) {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_keygen_init(ctx: EvpPkeyCtxPtr): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_keygen(ctx: EvpPkeyCtxPtr; ppkey: ptr EvpPkeyPtr): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_derive_init(ctx: EvpPkeyCtxPtr): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_derive_set_peer(ctx: EvpPkeyCtxPtr; peer: EvpPkeyPtr): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_derive(ctx: EvpPkeyCtxPtr; key: pointer; keylen: ptr csize_t): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_free(pkey: EvpPkeyPtr) {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_new_raw_public_key(typ: cint; e: pointer; key: pointer; keylen: csize_t): EvpPkeyPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_get_raw_public_key(pkey: EvpPkeyPtr; pub: pointer; publen: ptr csize_t): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_get1_RSA(pkey: EvpPkeyPtr): ptr RsaObj {.cdecl, importc, header: "<openssl/evp.h>".}

proc EVP_aes_128_ctr(): EvpCipherPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_sha256(): EvpMdPtr {.cdecl, importc, header: "<openssl/evp.h>".}

proc EVP_CIPHER_CTX_new(): EvpCipherCtxPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_EncryptInit_ex(ctx: EvpCipherCtxPtr; cipher: EvpCipherPtr; impl, key, iv: pointer): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_EncryptUpdate(ctx: EvpCipherCtxPtr; outbuf: pointer; outl: ptr cint; inbuf: pointer; inl: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DecryptInit_ex(ctx: EvpCipherCtxPtr; cipher: EvpCipherPtr; impl, key, iv: pointer): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DecryptUpdate(ctx: EvpCipherCtxPtr; outbuf: pointer; outl: ptr cint; inbuf: pointer; inl: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_MD_CTX_new(): EvpMdCtxPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_MD_CTX_free(ctx: EvpMdCtxPtr) {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DigestSignInit(ctx: EvpMdCtxPtr; pctx: ptr EvpPkeyCtxPtr; typ: EvpMdPtr;
                        e: pointer; pkey: EvpPkeyPtr): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DigestSignUpdate(ctx: EvpMdCtxPtr; d: pointer; cnt: csize_t): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DigestSignFinal(ctx: EvpMdCtxPtr; sig: pointer; siglen: ptr csize_t): cint {.cdecl, importc, header: "<openssl/evp.h>".}

proc SHA256(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc, header: "<openssl/sha.h>".}

proc HMAC(evp_md: EvpMdPtr; key: pointer; key_len: cint;
          d: cstring; n: csize_t; md: cstring; mdlen: ptr cuint): cstring {.cdecl, importc, header: "<openssl/hmac.h>".}
proc BIO_new_mem_buf(buf: pointer; len: cint): ptr BioObj {.cdecl, importc, header: "<openssl/bio.h>".}
proc BIO_free(a: ptr BioObj): cint {.cdecl, importc, header: "<openssl/bio.h>".}
proc PEM_read_bio_PrivateKey(bp: ptr BioObj; x: ptr EvpPkeyPtr; cb: pointer; u: pointer): EvpPkeyPtr {.cdecl, importc, header: "<openssl/pem.h>".}
proc RSA_free(rsa: ptr RsaObj) {.cdecl, importc, header: "<openssl/rsa.h>".}
proc BN_num_bytes(a: ptr BnObj): cint {.cdecl, importc: "BN_num_bytes", header: "<openssl/bn.h>".}
proc BN_bn2bin(a: ptr BnObj; to: pointer): cint {.cdecl, importc, header: "<openssl/bn.h>".}

{.emit: """
static void nimux_RSA_get0_key_compat(RSA *r, void **n, void **e, void **d) {
  const BIGNUM *cn = NULL, *ce = NULL, *cd = NULL;
  RSA_get0_key(r, &cn, &ce, &cd);
  if (n) *n = (void *)cn;
  if (e) *e = (void *)ce;
  if (d) *d = (void *)cd;
}
""".}
proc RSA_get0_key_compat(r: ptr RsaObj; n, e, d: ptr pointer) {.cdecl, importc: "nimux_RSA_get0_key_compat", nodecl.}

type
  SshSession* = ref object
    socket*:        AsyncSocket
    serverBanner*:  string
    clientBanner:   string
    sessionId:      string
    sendSeq:        uint32
    recvSeq:        uint32
    encrypted:      bool
    encCtx:         EvpCipherCtxPtr
    decCtx:         EvpCipherCtxPtr
    sendMacKey:     string
    recvMacKey:     string
    sendBlockSize:  int
    recvBlockSize:  int
    macLen:         int
    timeoutMs:      int

  SshExecResult* = object
    host*:          string
    port*:          int
    reachable*:     bool
    banner*:        string
    authenticated*: bool
    username*:      string
    isRoot*:        bool
    authMessage*:   string
    output*:        string
    stderrOut*:     string
    exitCode*:      int

const
  MsgDisconnect       = 1'u8
  MsgIgnore           = 2'u8
  MsgServiceRequest   = 5'u8
  MsgServiceAccept    = 6'u8
  MsgKexinit          = 20'u8
  MsgNewkeys          = 21'u8
  MsgKexEcdhInit      = 30'u8
  MsgKexEcdhReply     = 31'u8
  MsgUserauthRequest  = 50'u8
  MsgUserauthFailure  = 51'u8
  MsgUserauthSuccess  = 52'u8
  MsgUserauthBanner   = 53'u8
  MsgChannelOpen      = 90'u8
  MsgChannelOpenConf  = 91'u8
  MsgChannelOpenFail  = 92'u8
  MsgChannelWindowAdj = 93'u8
  MsgChannelData      = 94'u8
  MsgChannelExtData   = 95'u8
  MsgChannelEof       = 96'u8
  MsgChannelClose     = 97'u8
  MsgChannelRequest   = 98'u8
  MsgChannelSuccess   = 99'u8
  MsgChannelFailure   = 100'u8

proc addU32Be(s: var string; v: uint32) =
  s.add char((v shr 24) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 8)  and 0xff)
  s.add char(v and 0xff)

proc readU32Be(s: string; pos: int): uint32 =
  (uint32(ord(s[pos])) shl 24) or (uint32(ord(s[pos+1])) shl 16) or
  (uint32(ord(s[pos+2])) shl 8) or uint32(ord(s[pos+3]))

proc readU8(s: string; pos: int): uint8 = uint8(ord(s[pos]))

proc sshStr(s: string): string =
  result.addU32Be uint32(s.len)
  result.add s

proc sshBool(b: bool): string = (if b: "\x01" else: "\x00")

proc readSshStr(s: string; pos: var int): string =
  if pos + 4 > s.len: return ""
  let ln = int(readU32Be(s, pos))
  pos += 4
  if pos + ln > s.len: return ""
  result = s[pos ..< pos + ln]
  pos += ln

proc sshMpint(data: string): string =
  var stripped = data
  var i = 0
  while i < stripped.len - 1 and stripped[i] == '\x00':
    inc i
  stripped = stripped[i .. ^1]
  if stripped.len > 0 and (uint8(stripped[0]) and 0x80) != 0:
    stripped = "\x00" & stripped
  result.addU32Be uint32(stripped.len)
  result.add stripped

proc randomBytes(n: int): string =
  result = newString(n)
  for i in 0 ..< n:
    result[i] = char(rand(255))

proc sha256(data: string): string =
  result = newString(32)
  let p = if data.len > 0: unsafeAddr data[0] else: nil
  discard SHA256(p, data.len.csize_t, addr result[0])

proc hmacSha256(key, data: string): string =
  result = newString(32)
  var outLen: cuint = 0
  let kp = if key.len > 0: unsafeAddr key[0] else: nil
  let dp = if data.len > 0: cast[cstring](unsafeAddr data[0]) else: nil
  discard HMAC(EVP_sha256(), kp, key.len.cint, dp, data.len.csize_t,
               cast[cstring](addr result[0]), addr outLen)
  result.setLen int(outLen)

proc bnToRaw(bn: ptr BnObj): string =
  let n = int(BN_num_bytes(bn))
  if n <= 0: return ""
  result = newString(n)
  discard BN_bn2bin(bn, addr result[0])

proc loadPrivateKey(path: string; err: var string): EvpPkeyPtr =
  let keyPem =
    try:
      readFile(path)
    except CatchableError as e:
      err = "failed to read private key: " & e.msg
      return nil
  if keyPem.len == 0:
    err = "private key file is empty"
    return nil
  let bio = BIO_new_mem_buf(unsafeAddr keyPem[0], keyPem.len.cint)
  if bio == nil:
    err = "failed to open private key buffer"
    return nil
  defer: discard BIO_free(bio)
  result = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
  if result == nil:
    err = "failed to parse private key (native key auth currently supports OpenSSL-readable RSA keys)"

proc rsaPublicBlob(pkey: EvpPkeyPtr; err: var string): string =
  let rsa = EVP_PKEY_get1_RSA(pkey)
  if rsa == nil:
    err = "only RSA private keys are supported for native SSH key auth"
    return ""
  defer: RSA_free(rsa)
  var nRaw, eRaw, dRaw: pointer
  RSA_get0_key_compat(rsa, addr nRaw, addr eRaw, addr dRaw)
  let n = cast[ptr BnObj](nRaw)
  let e = cast[ptr BnObj](eRaw)
  if n == nil or e == nil:
    err = "failed to extract RSA public key components"
    return ""
  result = sshStr("ssh-rsa") & sshMpint(bnToRaw(e)) & sshMpint(bnToRaw(n))

proc rsaSignSha256(pkey: EvpPkeyPtr; data: string; err: var string): string =
  let mdctx = EVP_MD_CTX_new()
  if mdctx == nil:
    err = "failed to allocate OpenSSL digest context"
    return ""
  defer: EVP_MD_CTX_free(mdctx)
  var pctx: EvpPkeyCtxPtr = nil
  if EVP_DigestSignInit(mdctx, addr pctx, EVP_sha256(), nil, pkey) != 1:
    err = "EVP_DigestSignInit failed"
    return ""
  if data.len > 0 and EVP_DigestSignUpdate(mdctx, unsafeAddr data[0], data.len.csize_t) != 1:
    err = "EVP_DigestSignUpdate failed"
    return ""
  var sigLen: csize_t = 0
  if EVP_DigestSignFinal(mdctx, nil, addr sigLen) != 1 or sigLen == 0:
    err = "EVP_DigestSignFinal sizing failed"
    return ""
  result = newString(int(sigLen))
  if EVP_DigestSignFinal(mdctx, addr result[0], addr sigLen) != 1:
    err = "EVP_DigestSignFinal failed"
    return ""
  result.setLen(int(sigLen))

proc sshKdf(kmpint, h, letter: string; sessionId: string; need: int): string =
  var k1 = sha256(kmpint & h & letter & sessionId)
  result = k1
  while result.len < need:
    let kn = sha256(kmpint & h & result)
    result.add kn
  result.setLen need

proc x25519GenPkey(): tuple[pub: string; pkey: EvpPkeyPtr] =
  let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nil)
  discard EVP_PKEY_keygen_init(pctx)
  result.pkey = nil
  discard EVP_PKEY_keygen(pctx, addr result.pkey)
  EVP_PKEY_CTX_free(pctx)
  result.pub = newString(32)
  var pubLen: csize_t = 32
  discard EVP_PKEY_get_raw_public_key(result.pkey, addr result.pub[0], addr pubLen)

proc x25519Derive(pkey: EvpPkeyPtr; peerPub: string): string =
  let peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nil,
                  unsafeAddr peerPub[0], 32.csize_t)
  let dctx = EVP_PKEY_CTX_new(pkey, nil)
  discard EVP_PKEY_derive_init(dctx)
  discard EVP_PKEY_derive_set_peer(dctx, peerKey)
  var secLen: csize_t = 32
  result = newString(32)
  discard EVP_PKEY_derive(dctx, addr result[0], addr secLen)
  result.setLen int(secLen)
  EVP_PKEY_CTX_free(dctx)
  EVP_PKEY_free(peerKey)
  EVP_PKEY_free(pkey)

proc newAesCtr(key, iv: string; encrypt: bool): EvpCipherCtxPtr =
  result = EVP_CIPHER_CTX_new()
  if encrypt:
    discard EVP_EncryptInit_ex(result, EVP_aes_128_ctr(), nil,
              unsafeAddr key[0], unsafeAddr iv[0])
  else:
    discard EVP_DecryptInit_ex(result, EVP_aes_128_ctr(), nil,
              unsafeAddr key[0], unsafeAddr iv[0])

proc aesCtrProcess(ctx: EvpCipherCtxPtr; data: string; encrypt: bool): string =
  if data.len == 0: return ""
  result = newString(data.len)
  var outLen: cint = 0
  if encrypt:
    discard EVP_EncryptUpdate(ctx, addr result[0], addr outLen,
              unsafeAddr data[0], data.len.cint)
  else:
    discard EVP_DecryptUpdate(ctx, addr result[0], addr outLen,
              unsafeAddr data[0], data.len.cint)
  result.setLen int(outLen)

proc buildSshPacket(sess: SshSession; payload: string): string =
  let bs = if sess.encrypted: sess.sendBlockSize else: 8
  let needed = 4 + 1 + payload.len
  var padLen = bs - (needed mod bs)
  if padLen < 4: padLen += bs
  let pktLen = uint32(1 + payload.len + padLen)
  var plain = ""
  plain.addU32Be pktLen
  plain.add char(padLen)
  plain.add payload
  for _ in 0 ..< padLen:
    plain.add char(rand(255))
  if not sess.encrypted:
    return plain
  let encrypted = aesCtrProcess(sess.encCtx, plain, true)
  let mac = hmacSha256(sess.sendMacKey,
    block:
      var s = ""
      s.addU32Be sess.sendSeq
      s.add plain
      s)
  result = encrypted & mac

proc sendPacket(sess: SshSession; payload: string): Future[void] {.async.} =
  let wire = buildSshPacket(sess, payload)
  inc sess.sendSeq
  await sess.socket.send(wire)

proc recvExact(sess: SshSession; n: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let chunk = await sess.socket.recv(n - buf.len)
    if chunk.len == 0:
      raise newException(IOError, "SSH: connection closed")
    buf.add chunk
  result = buf

proc recvPacket(sess: SshSession): Future[string] {.async.} =
  let bs = if sess.encrypted: sess.recvBlockSize else: 8
  let firstBlock = await sess.recvExact(bs)
  let plain0 =
    if sess.encrypted: aesCtrProcess(sess.decCtx, firstBlock, false)
    else: firstBlock
  let pktLen = int(readU32Be(plain0, 0))
  let remaining = pktLen + 4 - bs
  var rest = if remaining > 0: await sess.recvExact(remaining) else: ""
  let plain1 =
    if sess.encrypted and rest.len > 0: aesCtrProcess(sess.decCtx, rest, false)
    else: rest
  if sess.encrypted:
    let macBytes = await sess.recvExact(sess.macLen)
    let plainAll = plain0 & plain1
    let expected = hmacSha256(sess.recvMacKey,
      block:
        var s = ""
        s.addU32Be sess.recvSeq
        s.add plainAll
        s)
    if macBytes != expected:
      raise newException(IOError, "SSH: MAC mismatch")
  inc sess.recvSeq
  let fullPlain = plain0 & plain1
  let padLen = int(readU8(fullPlain, 4))
  let payloadLen = pktLen - 1 - padLen
  result = fullPlain[5 ..< 5 + payloadLen]

proc recvPacketSkipIgnore(sess: SshSession): Future[string] {.async.} =
  while true:
    let p = await sess.recvPacket()
    if p.len == 0: return p
    let t = readU8(p, 0)
    if t != MsgIgnore and t != MsgUserauthBanner:
      return p

proc recvLine(sock: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  while true:
    let ch = await sock.recv(1)
    if ch.len == 0: return result
    if ch == "\n": return result
    if ch != "\r": result.add ch

proc doVersionExchange(sess: SshSession): Future[void] {.async.} =
  sess.clientBanner = "SSH-2.0-nimux"
  while true:
    let line = await recvLine(sess.socket, sess.timeoutMs)
    if line.startsWith("SSH-"):
      sess.serverBanner = line
      break
  await sess.socket.send(sess.clientBanner & "\r\n")

proc buildKexinit(cookie: string): string =
  result.add char(MsgKexinit)
  result.add cookie
  let algos = [
    "curve25519-sha256",
    "ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512,ssh-ed25519,ssh-rsa",
    "aes128-ctr",
    "aes128-ctr",
    "hmac-sha2-256",
    "hmac-sha2-256",
    "none",
    "none",
    "",
    ""
  ]
  for a in algos:
    result.add sshStr(a)
  result.add sshBool(false)
  result.addU32Be 0'u32

proc parseKexinitAlgo(payload: string; field: int): string =
  var pos = 17
  for _ in 0 ..< field:
    discard readSshStr(payload, pos)
  result = readSshStr(payload, pos)

proc doKex(sess: SshSession; clientKexInit, serverKexInit: string): Future[string] {.async.} =
  await sess.sendPacket(clientKexInit)

  let myKeypair = x25519GenPkey()
  let myPub = myKeypair.pub

  var ecdh = ""
  ecdh.add char(MsgKexEcdhInit)
  ecdh.add sshStr(myPub)
  await sess.sendPacket(ecdh)

  let replyRaw = await sess.recvPacketSkipIgnore()
  if replyRaw.len < 1 or readU8(replyRaw, 0) != MsgKexEcdhReply:
    raise newException(IOError, "SSH: expected ECDH reply got " & $readU8(replyRaw, 0))

  var pos = 1
  let hostKey = readSshStr(replyRaw, pos)
  let serverPub = readSshStr(replyRaw, pos)

  let sharedSecret = x25519Derive(myKeypair.pkey, serverPub)

  let kMpint = sshMpint(sharedSecret)
  let hash = sha256(
    sshStr(sess.clientBanner) &
    sshStr(sess.serverBanner) &
    sshStr(clientKexInit) &
    sshStr(serverKexInit) &
    sshStr(hostKey) &
    sshStr(myPub) &
    sshStr(serverPub) &
    kMpint)

  let newkeys = "" & char(MsgNewkeys)
  await sess.sendPacket(newkeys)

  let nkReply = await sess.recvPacketSkipIgnore()
  if nkReply.len < 1 or readU8(nkReply, 0) != MsgNewkeys:
    raise newException(IOError, "SSH: expected NEWKEYS")

  let sessionId = hash

  let ivC2s  = sshKdf(kMpint, hash, "A", sessionId, 16)
  let ivS2c  = sshKdf(kMpint, hash, "B", sessionId, 16)
  let ekC2s  = sshKdf(kMpint, hash, "C", sessionId, 16)
  let ekS2c  = sshKdf(kMpint, hash, "D", sessionId, 16)
  let macC2s = sshKdf(kMpint, hash, "E", sessionId, 32)
  let macS2c = sshKdf(kMpint, hash, "F", sessionId, 32)

  sess.encCtx       = newAesCtr(ekC2s, ivC2s, true)
  sess.decCtx       = newAesCtr(ekS2c, ivS2c, false)
  sess.sendMacKey   = macC2s
  sess.recvMacKey   = macS2c
  sess.sendBlockSize = 16
  sess.recvBlockSize = 16
  sess.macLen        = 32
  sess.encrypted     = true

  result = sessionId

proc serviceRequest(sess: SshSession; name: string): Future[void] {.async.} =
  var p = "" & char(MsgServiceRequest)
  p.add sshStr(name)
  await sess.sendPacket(p)
  let r = await sess.recvPacketSkipIgnore()
  if readU8(r, 0) != MsgServiceAccept:
    raise newException(IOError, "SSH: service " & name & " rejected")

proc authPassword*(sess: SshSession; username, password: string): Future[bool] {.async.} =
  var p = "" & char(MsgUserauthRequest)
  p.add sshStr(username)
  p.add sshStr("ssh-connection")
  p.add sshStr("password")
  p.add sshBool(false)
  p.add sshStr(password)
  await sess.sendPacket(p)
  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len == 0: return false
    case readU8(r, 0)
    of MsgUserauthSuccess: return true
    of MsgUserauthFailure: return false
    else: discard

proc authPublicKey*(sess: SshSession; username, keyPath: string): Future[bool] {.async.} =
  var err = ""
  let pkey = loadPrivateKey(keyPath, err)
  if pkey == nil:
    raise newException(IOError, "SSH key auth: " & err)
  defer: EVP_PKEY_free(pkey)

  let alg = "rsa-sha2-256"
  let pubBlob = rsaPublicBlob(pkey, err)
  if pubBlob.len == 0:
    raise newException(IOError, "SSH key auth: " & err)

  var signedData = sshStr(sess.sessionId)
  signedData.add char(MsgUserauthRequest)
  signedData.add sshStr(username)
  signedData.add sshStr("ssh-connection")
  signedData.add sshStr("publickey")
  signedData.add sshBool(true)
  signedData.add sshStr(alg)
  signedData.add sshStr(pubBlob)

  let signature = rsaSignSha256(pkey, signedData, err)
  if signature.len == 0:
    raise newException(IOError, "SSH key auth: " & err)

  let sigBlob = sshStr(alg) & sshStr(signature)

  var p = "" & char(MsgUserauthRequest)
  p.add sshStr(username)
  p.add sshStr("ssh-connection")
  p.add sshStr("publickey")
  p.add sshBool(true)
  p.add sshStr(alg)
  p.add sshStr(pubBlob)
  p.add sshStr(sigBlob)
  await sess.sendPacket(p)

  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len == 0: return false
    case readU8(r, 0)
    of MsgUserauthSuccess: return true
    of MsgUserauthFailure: return false
    else: discard

type SshChannel = ref object
  localId:     uint32
  remoteId:    uint32
  remoteWindow: uint32

proc openChannel(sess: SshSession): Future[SshChannel] {.async.} =
  let ch = SshChannel(localId: 0, remoteWindow: 0)
  var p = "" & char(MsgChannelOpen)
  p.add sshStr("session")
  p.addU32Be ch.localId
  p.addU32Be 1048576'u32
  p.addU32Be 32768'u32
  await sess.sendPacket(p)
  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len < 1: raise newException(IOError, "SSH: no channel response")
    case readU8(r, 0)
    of MsgChannelOpenConf:
      ch.remoteId    = readU32Be(r, 5)
      ch.remoteWindow = readU32Be(r, 9)
      return ch
    of MsgChannelOpenFail:
      raise newException(IOError, "SSH: channel open failed")
    of MsgChannelWindowAdj: discard
    else: discard

proc channelExec(sess: SshSession; ch: SshChannel; command: string): Future[void] {.async.} =
  var p = "" & char(MsgChannelRequest)
  p.addU32Be ch.remoteId
  p.add sshStr("exec")
  p.add sshBool(true)
  p.add sshStr(command)
  await sess.sendPacket(p)
  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len < 1: return
    case readU8(r, 0)
    of MsgChannelSuccess: return
    of MsgChannelFailure: raise newException(IOError, "SSH: exec request failed")
    of MsgChannelWindowAdj: discard
    else: return

proc channelRequestPty(sess: SshSession; ch: SshChannel): Future[void] {.async.} =
  var p = "" & char(MsgChannelRequest)
  p.addU32Be ch.remoteId
  p.add sshStr("pty-req")
  p.add sshBool(true)
  p.add sshStr("xterm")
  p.addU32Be 80'u32
  p.addU32Be 24'u32
  p.addU32Be 0'u32
  p.addU32Be 0'u32
  p.add sshStr("")
  await sess.sendPacket(p)
  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len < 1: return
    case readU8(r, 0)
    of MsgChannelSuccess, MsgChannelFailure: return
    of MsgChannelWindowAdj: discard
    else: return

proc channelShellReq(sess: SshSession; ch: SshChannel): Future[void] {.async.} =
  var p = "" & char(MsgChannelRequest)
  p.addU32Be ch.remoteId
  p.add sshStr("shell")
  p.add sshBool(true)
  await sess.sendPacket(p)
  while true:
    let r = await sess.recvPacketSkipIgnore()
    if r.len < 1: return
    case readU8(r, 0)
    of MsgChannelSuccess, MsgChannelFailure: return
    of MsgChannelWindowAdj: discard
    else: return

proc windowAdjust(sess: SshSession; ch: SshChannel; n: uint32): Future[void] {.async.} =
  var p = "" & char(MsgChannelWindowAdj)
  p.addU32Be ch.remoteId
  p.addU32Be n
  await sess.sendPacket(p)

proc channelSendData(sess: SshSession; ch: SshChannel; data: string): Future[void] {.async.} =
  const maxChunk = 16384
  var offset = 0
  while offset < data.len:
    let chunkLen = min(maxChunk, data.len - offset)
    let chunk = data[offset ..< offset + chunkLen]
    var p = "" & char(MsgChannelData)
    p.addU32Be ch.remoteId
    p.add sshStr(chunk)
    await sess.sendPacket(p)
    offset += chunkLen

proc channelSendEof(sess: SshSession; ch: SshChannel): Future[void] {.async.} =
  var p = "" & char(MsgChannelEof)
  p.addU32Be ch.remoteId
  await sess.sendPacket(p)

proc channelReadAll(sess: SshSession; ch: SshChannel; timeoutMs: int):
    Future[tuple[stdout, stderr: string; exitCode: int]] {.async.} =
  result.exitCode = -1
  var eofSeen = false
  var closeSeen = false
  while not (eofSeen and closeSeen):
    let rf = sess.recvPacket()
    if not await withTimeout(rf, timeoutMs):
      break
    let r = await rf
    if r.len < 1: break
    case readU8(r, 0)
    of MsgChannelData:
      var pos = 5
      let data = readSshStr(r, pos)
      result.stdout.add data
      await windowAdjust(sess, ch, uint32(data.len))
    of MsgChannelExtData:
      var pos = 9
      let data = readSshStr(r, pos)
      result.stderr.add data
    of MsgChannelEof:
      eofSeen = true
    of MsgChannelClose:
      closeSeen = true
      var cls = "" & char(MsgChannelClose)
      cls.addU32Be ch.remoteId
      await sess.sendPacket(cls)
    of MsgChannelRequest:
      var pos = 5
      let reqType = readSshStr(r, pos)
      let wantReply = readU8(r, pos) != 0
      pos += 1
      if reqType == "exit-status" and pos + 4 <= r.len:
        result.exitCode = int(readU32Be(r, pos))
      if wantReply:
        var rep = "" & char(MsgChannelSuccess)
        rep.addU32Be ch.remoteId
        await sess.sendPacket(rep)
    of MsgChannelWindowAdj: discard
    of MsgIgnore: discard
    else: discard

proc openSshSession*(host: string; port, timeoutMs: int): Future[SshSession] {.async.} =
  randomize()
  let sock = newAsyncSocket(buffered = false)
  let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
  if not ok:
    sock.close()
    return nil
  result = SshSession(socket: sock, timeoutMs: timeoutMs, sendBlockSize: 8, recvBlockSize: 8)
  let bannerFut = doVersionExchange(result)
  if not await withTimeout(bannerFut, timeoutMs):
    sock.close()
    return nil
  await bannerFut

  let clientKexInit = buildKexinit(randomBytes(16))
  let serverKexRaw = await result.recvPacketSkipIgnore()
  if serverKexRaw.len < 1 or readU8(serverKexRaw, 0) != MsgKexinit:
    raise newException(IOError, "SSH: expected KEXINIT got " & $readU8(serverKexRaw, 0))

  result.sessionId = await result.doKex(clientKexInit, serverKexRaw)

  await result.serviceRequest("ssh-userauth")

proc probeSsh*(host: string; port, timeoutMs: int): Future[tuple[reachable: bool; banner: string]] {.async.} =
  let sock = newAsyncSocket(buffered = false)
  var ok = false
  try: ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
  except: sock.close(); return (false, "")
  if not ok:
    sock.close()
    return (false, "")
  let sess = SshSession(socket: sock, timeoutMs: timeoutMs)
  let bf = doVersionExchange(sess)
  if not await withTimeout(bf, timeoutMs):
    sock.close()
    return (true, "")
  await bf
  sock.close()
  result = (true, sess.serverBanner)

proc sshExecKey*(host: string; port, timeoutMs: int;
                 username, keyPath, command: string): Future[SshExecResult] {.async.}

proc sshExecInputKey*(host: string; port, timeoutMs: int;
                      username, keyPath, command, stdinData: string): Future[SshExecResult] {.async.}

proc sshExec*(host: string; port, timeoutMs: int;
              username, password, command: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  let probe = await probeSsh(host, port, timeoutMs)
  result.reachable = probe.reachable
  result.banner = probe.banner
  if not result.reachable: return
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner = sess.serverBanner
  let authed = await authPassword(sess, username, password)
  result.authenticated = authed
  if not authed:
    result.authMessage = "authentication failed"
    sess.socket.close()
    return
  let ch = await openChannel(sess)
  await channelExec(sess, ch, command)
  let (stdout, stderr, exitCode) = await channelReadAll(sess, ch, timeoutMs * 3)
  result.output    = stdout
  result.stderrOut = stderr
  result.exitCode  = exitCode
  result.isRoot    = exitCode == 0 and (stdout.contains("uid=0") or stdout.contains("root"))
  sess.socket.close()

proc sshShell*(host: string; port, timeoutMs: int;
               username, password: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner    = sess.serverBanner
  result.reachable = true
  let authed = await authPassword(sess, username, password)
  result.authenticated = authed
  if not authed:
    result.authMessage = "authentication failed"
    sess.socket.close()
    return

  let ch = await openChannel(sess)
  await channelRequestPty(sess, ch)
  await channelShellReq(sess, ch)

  let idRes = await sshExec(host, port, timeoutMs, username, password, "id")
  result.isRoot = idRes.isRoot

  let sock = sess.socket
  let fd = sock.getFd()
  discard fcntl(fd.cint, F_SETFL, O_NONBLOCK)

  proc writeAll(data: string) =
    var written = 0
    while written < data.len:
      let n = write(STDOUT_FILENO, unsafeAddr data[written], data.len - written)
      if n <= 0: break
      written += n

  var stdinBuf = newString(4096)
  while true:
    var rfds: TFdSet
    FD_ZERO(rfds)
    FD_SET(STDIN_FILENO.cint, rfds)
    FD_SET(fd.cint, rfds)
    let maxFd = max(STDIN_FILENO.cint, fd.cint) + 1
    var tv: Timeval
    tv.tv_sec = 1.Time
    tv.tv_usec = 0
    let ret = select(maxFd, addr rfds, nil, nil, addr tv)
    if ret < 0: break

    if FD_ISSET(STDIN_FILENO.cint, rfds) != 0:
      let n = read(STDIN_FILENO, addr stdinBuf[0], stdinBuf.len)
      if n <= 0: break
      let data = stdinBuf[0 ..< n]
      waitFor channelSendData(sess, ch, data)

    if FD_ISSET(fd.cint, rfds) != 0:
      try:
        let pkt = waitFor sess.recvPacket()
        if pkt.len < 1: break
        case readU8(pkt, 0)
        of MsgChannelData:
          var pos = 5
          let data = readSshStr(pkt, pos)
          writeAll(data)
          waitFor windowAdjust(sess, ch, uint32(data.len))
        of MsgChannelExtData:
          var pos = 9
          let data = readSshStr(pkt, pos)
          writeAll(data)
        of MsgChannelEof, MsgChannelClose: break
        of MsgChannelWindowAdj: discard
        else: discard
      except: break

  sock.close()

proc sshShellKey*(host: string; port, timeoutMs: int;
                  username, keyPath: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner = sess.serverBanner
  result.reachable = true
  try:
    let authed = await authPublicKey(sess, username, keyPath)
    result.authenticated = authed
    if not authed:
      result.authMessage = "authentication failed"
      sess.socket.close()
      return
    let ch = await openChannel(sess)
    await channelRequestPty(sess, ch)
    await channelShellReq(sess, ch)

    let idRes = await sshExecKey(host, port, timeoutMs, username, keyPath, "id")
    result.isRoot = idRes.isRoot

    let sock = sess.socket
    let fd = sock.getFd()
    discard fcntl(fd.cint, F_SETFL, O_NONBLOCK)

    proc writeAll(data: string) =
      var written = 0
      while written < data.len:
        let n = write(STDOUT_FILENO, unsafeAddr data[written], data.len - written)
        if n <= 0: break
        written += n

    var stdinBuf = newString(4096)
    while true:
      var rfds: TFdSet
      FD_ZERO(rfds)
      FD_SET(STDIN_FILENO.cint, rfds)
      FD_SET(fd.cint, rfds)
      let maxFd = max(STDIN_FILENO.cint, fd.cint) + 1
      var tv: Timeval
      tv.tv_sec = 1.Time
      tv.tv_usec = 0
      let ret = select(maxFd, addr rfds, nil, nil, addr tv)
      if ret < 0: break

      if FD_ISSET(STDIN_FILENO.cint, rfds) != 0:
        let n = read(STDIN_FILENO, addr stdinBuf[0], stdinBuf.len)
        if n <= 0: break
        let data = stdinBuf[0 ..< n]
        waitFor channelSendData(sess, ch, data)

      if FD_ISSET(fd.cint, rfds) != 0:
        try:
          let pkt = waitFor sess.recvPacket()
          if pkt.len < 1: break
          case readU8(pkt, 0)
          of MsgChannelData:
            var pos = 5
            let data = readSshStr(pkt, pos)
            writeAll(data)
            waitFor windowAdjust(sess, ch, uint32(data.len))
          of MsgChannelExtData:
            var pos = 9
            let data = readSshStr(pkt, pos)
            writeAll(data)
          of MsgChannelEof, MsgChannelClose: break
          of MsgChannelWindowAdj: discard
          else: discard
        except: break

    sock.close()
  except CatchableError as e:
    result.authMessage = e.msg.splitLines()[0]
    sess.socket.close()

proc sshExecInput*(host: string; port, timeoutMs: int;
                   username, password, command, stdinData: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  let probe = await probeSsh(host, port, timeoutMs)
  result.reachable = probe.reachable
  result.banner = probe.banner
  if not result.reachable: return
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner = sess.serverBanner
  let authed = await authPassword(sess, username, password)
  result.authenticated = authed
  if not authed:
    result.authMessage = "authentication failed"
    sess.socket.close()
    return
  let ch = await openChannel(sess)
  await channelExec(sess, ch, command)
  if stdinData.len > 0:
    await channelSendData(sess, ch, stdinData)
  await channelSendEof(sess, ch)
  let (stdout, stderr, exitCode) = await channelReadAll(sess, ch, timeoutMs * 3)
  result.output = stdout
  result.stderrOut = stderr
  result.exitCode = exitCode
  result.isRoot = exitCode == 0 and (stdout.contains("uid=0") or stdout.contains("root"))
  sess.socket.close()

proc sshExecKey*(host: string; port, timeoutMs: int;
                 username, keyPath, command: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  let probe = await probeSsh(host, port, timeoutMs)
  result.reachable = probe.reachable
  result.banner = probe.banner
  if not result.reachable: return
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner = sess.serverBanner
  try:
    let authed = await authPublicKey(sess, username, keyPath)
    result.authenticated = authed
    if not authed:
      result.authMessage = "authentication failed"
      sess.socket.close()
      return
    let ch = await openChannel(sess)
    await channelExec(sess, ch, command)
    let (stdout, stderr, exitCode) = await channelReadAll(sess, ch, timeoutMs * 3)
    result.output = stdout
    result.stderrOut = stderr
    result.exitCode = exitCode
    result.isRoot = exitCode == 0 and (stdout.contains("uid=0") or stdout.contains("root"))
  except CatchableError as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sess.socket.close()

proc sshExecInputKey*(host: string; port, timeoutMs: int;
                      username, keyPath, command, stdinData: string): Future[SshExecResult] {.async.} =
  result.host = host
  result.port = port
  result.username = username
  let probe = await probeSsh(host, port, timeoutMs)
  result.reachable = probe.reachable
  result.banner = probe.banner
  if not result.reachable: return
  var sess: SshSession
  try:
    sess = await openSshSession(host, port, timeoutMs)
  except:
    result.authMessage = getCurrentExceptionMsg().splitLines()[0]
    return
  if sess.isNil:
    result.authMessage = "connection failed"
    return
  result.banner = sess.serverBanner
  try:
    let authed = await authPublicKey(sess, username, keyPath)
    result.authenticated = authed
    if not authed:
      result.authMessage = "authentication failed"
      sess.socket.close()
      return
    let ch = await openChannel(sess)
    await channelExec(sess, ch, command)
    if stdinData.len > 0:
      await channelSendData(sess, ch, stdinData)
    await channelSendEof(sess, ch)
    let (stdout, stderr, exitCode) = await channelReadAll(sess, ch, timeoutMs * 3)
    result.output = stdout
    result.stderrOut = stderr
    result.exitCode = exitCode
    result.isRoot = exitCode == 0 and (stdout.contains("uid=0") or stdout.contains("root"))
  except CatchableError as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sess.socket.close()
