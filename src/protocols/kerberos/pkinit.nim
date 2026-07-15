import std/[net, os, random, strutils, times]
import ../../core/proxy as netproxy
import ../smb/client as smbclient

when defined(linux):
  const krb5Lib = "libkrb5.so.3"
else:
  const krb5Lib = "libkrb5.so.3"

const
  cryptoLib = "libcrypto.so.3"
  nidSha1 = 64
  oidSignedData = "1.2.840.113549.1.7.2"
  oidPkinitAuthData = "1.3.6.1.5.2.3.1"
  oidPkinitDhKeyData = "1.3.6.1.5.2.3.2"
  oidDhKeyAgreement = "1.2.840.10046.2.1"
  oidSha1 = "1.3.14.3.2.26"
  oidSha1Rsa = "1.2.840.113549.1.1.5"
  oidContentType = "1.2.840.113549.1.9.3"
  oidMessageDigest = "1.2.840.113549.1.9.4"
  dhPrimeHex = "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea6" &
    "3b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e4" &
    "85b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b" &
    "1fe649286651ece65381ffffffffffffffff"

type
  Krb5Int32 = int32
  Krb5ErrorCode = int32
  Krb5Magic = int32
  Krb5Timestamp = int32
  Krb5Deltat = int32
  Krb5Boolean = cuint
  Krb5Flags = int32
  Krb5Enctype = int32
  Krb5Kvno = cuint
  Krb5Context = pointer
  Krb5Principal = pointer
  Krb5Ccache = pointer
  Krb5GetInitCredsOpt = pointer
  Krb5Prompter = proc(ctx: Krb5Context; data: pointer; name, banner: cstring;
                      numPrompts: cint; prompts: pointer): Krb5ErrorCode {.cdecl.}

  Krb5Data {.bycopy.} = object
    magic: Krb5Magic
    length: cuint
    data: cstring

  Krb5Keyblock {.bycopy.} = object
    magic: Krb5Magic
    enctype: Krb5Enctype
    length: cuint
    contents: pointer

  Krb5EncData {.bycopy.} = object
    magic: Krb5Magic
    enctype: Krb5Enctype
    kvno: Krb5Kvno
    ciphertext: Krb5Data

  Krb5TicketTimes {.bycopy.} = object
    authtime: Krb5Timestamp
    starttime: Krb5Timestamp
    endtime: Krb5Timestamp
    renewTill: Krb5Timestamp

  Krb5Creds {.bycopy.} = object
    magic: Krb5Magic
    client: Krb5Principal
    server: Krb5Principal
    keyblock: Krb5Keyblock
    times: Krb5TicketTimes
    isSkey: Krb5Boolean
    ticketFlags: Krb5Flags
    addresses: pointer
    ticket: Krb5Data
    secondTicket: Krb5Data
    authdata: pointer

  PkinitResult* = object
    success*: bool
    principal*: string
    ccache*: string
    identity*: string
    message*: string

  Tlv = object
    tag: int
    body: string
    next: int

  BioObj {.importc: "BIO", header: "<openssl/bio.h>".} = object
  X509Obj {.importc: "X509", header: "<openssl/x509.h>".} = object
  X509NameObj {.importc: "X509_NAME", header: "<openssl/x509.h>".} = object
  Asn1Integer {.importc: "ASN1_INTEGER", header: "<openssl/asn1.h>".} = object
  EvpPkey {.importc: "EVP_PKEY", header: "<openssl/evp.h>".} = object
  RsaObj {.importc: "RSA", header: "<openssl/rsa.h>".} = object
  BnObj {.importc: "BIGNUM", header: "<openssl/bn.h>".} = object
  BnCtxObj {.importc: "BN_CTX", header: "<openssl/bn.h>".} = object

proc krb5_init_context(ctx: ptr Krb5Context): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_context(ctx: Krb5Context) {.importc, dynlib: krb5Lib.}
proc krb5_parse_name(ctx: Krb5Context; name: cstring; princ: ptr Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_principal(ctx: Krb5Context; princ: Krb5Principal) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_alloc(ctx: Krb5Context; opt: ptr Krb5GetInitCredsOpt): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_free(ctx: Krb5Context; opt: Krb5GetInitCredsOpt) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_set_pa(ctx: Krb5Context; opt: Krb5GetInitCredsOpt; attr, value: cstring): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_set_pac_request(ctx: Krb5Context; opt: Krb5GetInitCredsOpt;
                                             reqPac: cint): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_password(ctx: Krb5Context; creds: ptr Krb5Creds; client: Krb5Principal;
                                  password: cstring; prompter: Krb5Prompter; data: pointer;
                                  startTime: Krb5Deltat; inTktService: cstring;
                                  opt: Krb5GetInitCredsOpt): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_resolve(ctx: Krb5Context; name: cstring; cache: ptr Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_default(ctx: Krb5Context; cache: ptr Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_get_principal(ctx: Krb5Context; cache: Krb5Ccache; princ: ptr Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_initialize(ctx: Krb5Context; cache: Krb5Ccache; principal: Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_store_cred(ctx: Krb5Context; cache: Krb5Ccache; creds: ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_close(ctx: Krb5Context; cache: Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_cred_contents(ctx: Krb5Context; creds: ptr Krb5Creds) {.importc, dynlib: krb5Lib.}
proc krb5_unparse_name(ctx: Krb5Context; princ: Krb5Principal; name: ptr cstring): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_unparsed_name(ctx: Krb5Context; name: cstring) {.importc, dynlib: krb5Lib.}
proc krb5_get_error_message(ctx: Krb5Context; code: Krb5ErrorCode): cstring {.importc, dynlib: krb5Lib.}
proc krb5_free_error_message(ctx: Krb5Context; msg: cstring) {.importc, dynlib: krb5Lib.}
proc krb5_c_decrypt(ctx: Krb5Context; key: ptr Krb5Keyblock; usage: Krb5Int32;
                    cipherState: pointer; input: ptr Krb5EncData;
                    output: ptr Krb5Data): Krb5ErrorCode {.importc, dynlib: krb5Lib.}

proc BIO_new_mem_buf(buf: pointer; len: cint): ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc BIO_free(a: ptr BioObj): cint {.importc, header: "<openssl/bio.h>".}
proc PEM_read_bio_X509(bp: ptr BioObj; x: ptr ptr X509Obj; cb: pointer; u: pointer): ptr X509Obj {.importc, header: "<openssl/pem.h>".}
proc PEM_read_bio_PrivateKey(bp: ptr BioObj; x: ptr ptr EvpPkey; cb: pointer; u: pointer): ptr EvpPkey {.importc, header: "<openssl/pem.h>".}
proc X509_free(x: ptr X509Obj) {.importc, header: "<openssl/x509.h>".}
proc EVP_PKEY_free(pkey: ptr EvpPkey) {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_get1_RSA(pkey: ptr EvpPkey): ptr RsaObj {.importc, header: "<openssl/evp.h>".}
proc RSA_size(rsa: ptr RsaObj): cint {.importc, header: "<openssl/rsa.h>".}
proc RSA_sign(`type`: cint; m: pointer; mLen: cuint; sigret: pointer; siglen: ptr cuint;
              rsa: ptr RsaObj): cint {.importc, header: "<openssl/rsa.h>".}
proc RSA_free(rsa: ptr RsaObj) {.importc, header: "<openssl/rsa.h>".}
proc X509_get_issuer_name(x: ptr X509Obj): ptr X509NameObj {.importc, header: "<openssl/x509.h>".}
proc X509_get_serialNumber(x: ptr X509Obj): ptr Asn1Integer {.importc, header: "<openssl/x509.h>".}
proc i2d_X509(a: ptr X509Obj; pp: ptr ptr byte): cint {.importc, header: "<openssl/x509.h>".}
proc i2d_X509_NAME(a: ptr X509NameObj; pp: ptr ptr byte): cint {.importc, header: "<openssl/x509.h>".}
proc i2d_ASN1_INTEGER(a: ptr Asn1Integer; pp: ptr ptr byte): cint {.importc, header: "<openssl/asn1.h>".}
proc SHA1(d: pointer; n: csize_t; md: pointer): pointer {.importc, header: "<openssl/sha.h>".}
proc BN_new(): ptr BnObj {.importc, header: "<openssl/bn.h>".}
proc BN_free(a: ptr BnObj) {.importc, header: "<openssl/bn.h>".}
proc BN_CTX_new(): ptr BnCtxObj {.importc, header: "<openssl/bn.h>".}
proc BN_CTX_free(c: ptr BnCtxObj) {.importc, header: "<openssl/bn.h>".}
proc BN_hex2bn(a: ptr ptr BnObj; str: cstring): cint {.importc, header: "<openssl/bn.h>".}
proc BN_bin2bn(s: pointer; len: cint; ret: ptr BnObj): ptr BnObj {.importc, header: "<openssl/bn.h>".}
proc BN_set_word(a: ptr BnObj; w: culong): cint {.importc, header: "<openssl/bn.h>".}
proc BN_mod_exp(r: ptr BnObj; a, p, m: ptr BnObj; ctx: ptr BnCtxObj): cint {.importc, header: "<openssl/bn.h>".}
proc BN_num_bits(a: ptr BnObj): cint {.importc, header: "<openssl/bn.h>".}
proc BN_num_bytes(a: ptr BnObj): cint {.importc: "BN_num_bytes", header: "<openssl/bn.h>".}
proc BN_bn2bin(a: ptr BnObj; to: pointer): cint {.importc, header: "<openssl/bn.h>".}

proc krb5Error(ctx: Krb5Context; code: Krb5ErrorCode): string =
  let msg = krb5_get_error_message(ctx, code)
  if msg != nil:
    result = $msg
  if result.len == 0:
    result = "krb5 error " & $code

proc noPrompt(ctx: Krb5Context; data: pointer; name, banner: cstring;
              numPrompts: cint; prompts: pointer): Krb5ErrorCode {.cdecl.} =
  -1765328254'i32

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
proc setT(body: string): string = tlv(0x31, body)
proc ctx(n: int; body: string): string = tlv(0xa0 + n, body)
proc ctxImplicit(n: int; body: string): string = tlv(0xa0 + n, body)
proc app(n: int; body: string): string = tlv(0x60 + n, body)
proc genStr(value: string): string = tlv(0x1b, value)
proc octet(value: string): string = tlv(0x04, value)
proc derNull(): string = "\x05\x00"

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
  tlv(0x02, cast[string](bytes))

proc derBigInt(rawIn: string): string =
  var raw = rawIn
  while raw.len > 1 and raw[0] == '\x00' and (ord(raw[1]) and 0x80) == 0:
    raw.delete(0..0)
  if raw.len == 0:
    raw = "\x00"
  if (ord(raw[0]) and 0x80) != 0:
    raw = "\x00" & raw
  tlv(0x02, raw)

proc hexToRaw(hex: string): string =
  var i = 0
  while i + 1 < hex.len:
    if hex[i] in {' ', '\n', '\r', '\t'}:
      inc i
      continue
    result.add char(parseHexInt(hex[i .. i + 1]))
    i += 2

proc boolT(value: bool): string = tlv(0x01, if value: "\xff" else: "\x00")

proc kerberosTimeFromUnix(ts: int64): string =
  let utcTime = fromUnix(ts).utc
  tlv(0x18, utcTime.format("yyyyMMddHHmmss") & "Z")

proc bitString(bytes: openArray[byte]): string =
  result.add char(0x03)
  result.add derLen(bytes.len + 1)
  result.add char(0)
  result.addBytes bytes

proc bitStringUnused(unusedBits: byte; bytes: openArray[byte]): string =
  result.add char(0x03)
  result.add derLen(bytes.len + 1)
  result.add char(unusedBits)
  result.addBytes bytes

proc bitStringDer(value: string): string =
  tlv(0x03, "\x00" & value)

proc principal(nameType: int; parts: seq[string]): string =
  var names = ""
  for part in parts:
    names.add genStr(part)
  seqT(ctx(0, derInt(nameType)) & ctx(1, seqT(names)))

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

proc fieldBody(seqBody: string; tag: int): string =
  for field in children(seqBody):
    if field.tag == tag:
      return field.body

proc innerSeq(data: string): string =
  let top = readTlv(data)
  if top.tag == 0x30: top.body else: data

proc sha1Raw(data: string): string =
  result = newString(20)
  if data.len > 0:
    discard SHA1(unsafeAddr data[0], csize_t(data.len), addr result[0])
  else:
    discard SHA1(nil, 0, addr result[0])

proc truncatePkinitKey(value: string; keySize: int): string =
  var current = 0
  while result.len < keySize:
    let digest = sha1Raw(char(current and 0xff) & value)
    let take = min(digest.len, keySize - result.len)
    result.add digest[0 ..< take]
    inc current

proc oidBody(oid: string): string =
  let parts = oid.split('.')
  if parts.len < 2: return ""
  result.add char(parseInt(parts[0]) * 40 + parseInt(parts[1]))
  for p in parts[2 .. ^1]:
    var v = parseInt(p)
    var stack: seq[byte]
    stack.add byte(v and 0x7f)
    v = v shr 7
    while v > 0:
      stack.insert(byte((v and 0x7f) or 0x80), 0)
      v = v shr 7
    result.addBytes stack

proc oid(oidText: string): string = tlv(0x06, oidBody(oidText))

proc algId(oidText: string; params = derNull()): string =
  seqT(oid(oidText) & params)

proc rawDerX509(cert: ptr X509Obj): string =
  let n = i2d_X509(cert, nil)
  if n <= 0: return ""
  result = newString(n)
  var p = cast[ptr byte](addr result[0])
  discard i2d_X509(cert, addr p)

proc rawDerName(name: ptr X509NameObj): string =
  let n = i2d_X509_NAME(name, nil)
  if n <= 0: return ""
  result = newString(n)
  var p = cast[ptr byte](addr result[0])
  discard i2d_X509_NAME(name, addr p)

proc rawDerInteger(i: ptr Asn1Integer): string =
  let n = i2d_ASN1_INTEGER(i, nil)
  if n <= 0: return ""
  result = newString(n)
  var p = cast[ptr byte](addr result[0])
  discard i2d_ASN1_INTEGER(i, addr p)

proc rsaSignSha1(key: ptr EvpPkey; data: string; err: var string): string =
  let rsa = EVP_PKEY_get1_RSA(key)
  if rsa == nil:
    err = "private key is not RSA"
    return ""
  defer: RSA_free(rsa)
  let digest = sha1Raw(data)
  var sigLen: cuint = cuint(RSA_size(rsa))
  result = newString(int(sigLen))
  let ok = RSA_sign(nidSha1.cint, unsafeAddr digest[0], cuint(digest.len),
    addr result[0], addr sigLen, rsa)
  if ok != 1:
    err = "RSA_sign failed"
    return ""
  result.setLen(int(sigLen))

proc loadPemPair(certPath, keyPath: string; err: var string): tuple[cert: ptr X509Obj; key: ptr EvpPkey] =
  let certPem = readFile(certPath)
  let keyPem = readFile(keyPath)
  let certBio = BIO_new_mem_buf(unsafeAddr certPem[0], certPem.len.cint)
  if certBio == nil:
    err = "failed to read certificate"
    return
  defer: discard BIO_free(certBio)
  result.cert = PEM_read_bio_X509(certBio, nil, nil, nil)
  if result.cert == nil:
    err = "failed to parse PEM certificate"
    return
  let keyBio = BIO_new_mem_buf(unsafeAddr keyPem[0], keyPem.len.cint)
  if keyBio == nil:
    err = "failed to read private key"
    return
  defer: discard BIO_free(keyBio)
  result.key = PEM_read_bio_PrivateKey(keyBio, nil, nil, nil)
  if result.key == nil:
    err = "failed to parse PEM private key"

proc bnToRaw(bn: ptr BnObj): string =
  let n = int(BN_num_bytes(bn))
  if n <= 0: return ""
  result = newString(n)
  discard BN_bn2bin(bn, addr result[0])

proc dhPublic(privateRaw: string; err: var string): string =
  var p: ptr BnObj = nil
  let g = BN_new()
  let priv = BN_bin2bn(unsafeAddr privateRaw[0], privateRaw.len.cint, nil)
  let pub = BN_new()
  let ctxBn = BN_CTX_new()
  defer:
    if p != nil: BN_free(p)
    if g != nil: BN_free(g)
    if priv != nil: BN_free(priv)
    if pub != nil: BN_free(pub)
    if ctxBn != nil: BN_CTX_free(ctxBn)
  if BN_hex2bn(addr p, dhPrimeHex.cstring) == 0 or
      BN_set_word(g, 2) != 1 or priv == nil or pub == nil or ctxBn == nil:
    err = "failed to initialize DH parameters"
    return ""
  if BN_mod_exp(pub, g, priv, p, ctxBn) != 1:
    err = "failed to calculate DH public key"
    return ""
  bnToRaw(pub)

proc dhShared(peerPublic, privateRaw: string; err: var string): string =
  var p: ptr BnObj = nil
  let peer = BN_bin2bn(unsafeAddr peerPublic[0], peerPublic.len.cint, nil)
  let priv = BN_bin2bn(unsafeAddr privateRaw[0], privateRaw.len.cint, nil)
  let shared = BN_new()
  let ctxBn = BN_CTX_new()
  defer:
    if p != nil: BN_free(p)
    if peer != nil: BN_free(peer)
    if priv != nil: BN_free(priv)
    if shared != nil: BN_free(shared)
    if ctxBn != nil: BN_CTX_free(ctxBn)
  if BN_hex2bn(addr p, dhPrimeHex.cstring) == 0 or peer == nil or priv == nil or shared == nil or ctxBn == nil:
    err = "failed to initialize DH exchange"
    return ""
  if BN_mod_exp(shared, peer, priv, p, ctxBn) != 1:
    err = "failed to calculate DH shared key"
    return ""
  bnToRaw(shared)

proc buildDhSpki(publicRaw: string): string =
  let params = seqT(
    derBigInt(hexToRaw(dhPrimeHex)) &
    derInt(2) &
    derInt(0)
  )
  seqT(
    algId(oidDhKeyAgreement, params) &
    bitStringDer(derBigInt(publicRaw))
  )

proc signedAttrsDer(authPack: string): string =
  let contentTypeAttr = seqT(oid(oidContentType) & setT(oid(oidPkinitAuthData)))
  let messageDigestAttr = seqT(oid(oidMessageDigest) & setT(octet(sha1Raw(authPack))))
  setT(contentTypeAttr & messageDigestAttr)

proc signAuthPack(authPack: string; cert: ptr X509Obj; key: ptr EvpPkey;
                  err: var string): string =
  let attrs = signedAttrsDer(authPack)
  let signature = rsaSignSha1(key, attrs, err)
  if signature.len == 0:
    return ""
  let certDer = rawDerX509(cert)
  let issuer = rawDerName(X509_get_issuer_name(cert))
  let serial = rawDerInteger(X509_get_serialNumber(cert))
  if certDer.len == 0 or issuer.len == 0 or serial.len == 0:
    err = "failed to encode certificate"
    return ""
  let signerInfo = seqT(
    derInt(1) &
    seqT(issuer & serial) &
    algId(oidSha1) &
    ctxImplicit(0, attrs[2 .. ^1]) &
    algId(oidSha1Rsa) &
    octet(signature)
  )
  let signedData = seqT(
    derInt(3) &
    setT(algId(oidSha1)) &
    seqT(oid(oidPkinitAuthData) & ctx(0, octet(authPack))) &
    ctxImplicit(0, certDer) &
    setT(signerInfo)
  )
  seqT(oid(oidSignedData) & ctx(0, signedData))

proc kdcRequestTcp(kdc: string; payload: string; timeoutMs: int): string =
  let dialHost = netproxy.proxySocketHost(kdc)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  var sock = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  try:
    netproxy.connectTcpSync(sock, kdc, 88, timeoutMs)
    var framed = ""
    framed.addU32Be(payload.len.uint32)
    framed.add payload
    sock.send(framed)
    var header = newString(4)
    var got = sock.recv(header, 4, timeoutMs)
    if got != 4:
      return ""
    let total = int(readU32Be(header, 0))
    if total <= 0:
      return ""
    var chunk = newString(min(4096, total))
    while result.len < total:
      got = sock.recv(chunk, min(chunk.len, total - result.len), timeoutMs)
      if got <= 0:
        return ""
      result.add chunk[0 ..< got]
  except CatchableError:
    result = ""
  finally:
    try: sock.close()
    except CatchableError: discard

proc parseKrbError(data: string): string =
  let top = readTlv(data)
  if top.tag != 0x7e:
    return "KDC returned an unexpected Kerberos response"
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return "KDC returned malformed KRB-ERROR"
  var code = -1
  var text = ""
  for field in children(seq.body):
    case field.tag
    of 0xa6: code = intValue(field.body)
    of 0xa9:
      let t = readTlv(field.body)
      if t.tag in [0x1b, 0x1c, 0x18]:
        text = t.body
    else:
      discard
  if text.len > 0:
    "KDC error " & $code & ": " & text
  else:
    "KDC error " & $code

proc parseEncryptedDataFull(data: string): tuple[etype: int; kvno: int; cipher: string] =
  let body = innerSeq(data)
  for field in children(body):
    case field.tag
    of 0xa0:
      result.etype = intValue(field.body)
    of 0xa1:
      result.kvno = intValue(field.body)
    of 0xa2:
      let c = readTlv(field.body)
      if c.tag == 0x04:
        result.cipher = c.body
    else:
      discard

proc decryptWithKrb5Key(ctxp: Krb5Context; key: ptr Krb5Keyblock; usage: int;
                        enc: Krb5EncData; err: var string): string =
  result = newString(int(enc.ciphertext.length))
  if result.len == 0:
    err = "empty encrypted payload"
    return ""
  var output = Krb5Data(magic: 0, length: cuint(result.len),
    data: cast[cstring](addr result[0]))
  var encCopy = enc
  let code = krb5_c_decrypt(ctxp, key, Krb5Int32(usage), nil, addr encCopy, addr output)
  if code != 0:
    err = krb5Error(ctxp, code)
    result = ""
    return
  result.setLen(int(output.length))

proc parseKerberosTime(data: string): int32 =
  let t = readTlv(data)
  if t.tag notin [0x18, 0x17] or t.body.len < 15:
    return int32(getTime().toUnix())
  try:
    let s = t.body
    let dt = dateTime(
      parseInt(s[0 .. 3]), Month(parseInt(s[4 .. 5])),
      parseInt(s[6 .. 7]), parseInt(s[8 .. 9]),
      parseInt(s[10 .. 11]), parseInt(s[12 .. 13]),
      zone = utc())
    result = int32(dt.toTime().toUnix())
  except CatchableError:
    result = int32(getTime().toUnix())

proc parseBitStringInt(data: string): int =
  let t = readTlv(data)
  if t.tag != 0x03 or t.body.len < 2:
    return 0
  for i in 1 ..< t.body.len:
    result = (result shl 8) or ord(t.body[i])

proc principalName(user, realm: string): string =
  if "@" in user: user else: user & "@" & realm.toUpperAscii()

proc serviceName(spn, realm: string): string =
  if "@" in spn: spn else: spn & "@" & realm.toUpperAscii()

proc parseEncAsRepPart(plain: string): tuple[keyType: int; key: string; flags: int;
    authtime, starttime, endtime, renewTill: int32; srealm: string; snameParts: seq[string]] =
  let top = readTlv(plain)
  let seq = if top.tag == 0x79: readTlv(top.body) else: top
  let body = if seq.tag == 0x30: seq.body else: plain
  for field in children(body):
    case field.tag
    of 0xa0:
      let keySeq = readTlv(field.body)
      let keyBody = if keySeq.tag == 0x30: keySeq.body else: field.body
      for kf in children(keyBody):
        case kf.tag
        of 0xa0: result.keyType = intValue(kf.body)
        of 0xa1:
          let k = readTlv(kf.body)
          if k.tag == 0x04: result.key = k.body
        else: discard
    of 0xa4: result.flags = parseBitStringInt(field.body)
    of 0xa5: result.authtime = parseKerberosTime(field.body)
    of 0xa6: result.starttime = parseKerberosTime(field.body)
    of 0xa7: result.endtime = parseKerberosTime(field.body)
    of 0xa8: result.renewTill = parseKerberosTime(field.body)
    of 0xa9:
      let r = readTlv(field.body)
      if r.tag in [0x1b, 0x1c]: result.srealm = r.body
    of 0xaa:
      let pnSeq = readTlv(field.body)
      let pnBody = if pnSeq.tag == 0x30: pnSeq.body else: field.body
      for pf in children(pnBody):
        if pf.tag == 0xa1:
          let names = readTlv(pf.body)
          if names.tag == 0x30:
            for n in children(names.body):
              if n.tag in [0x1b, 0x1c]:
                result.snameParts.add n.body
    else:
      discard
  if result.starttime == 0:
    result.starttime = result.authtime

proc findOidContent(data, oidText: string): string =
  let needle = oid(oidText)
  let pos = data.find(needle)
  if pos < 0:
    return ""
  var p = pos + needle.len
  while p < data.len:
    let t = readTlv(data, p)
    if t.tag < 0:
      return ""
    if t.tag == 0xa0:
      let inner = readTlv(t.body)
      if inner.tag == 0x04:
        return inner.body
      return t.body
    p = t.next

proc parsePaPkAsRep(data: string): tuple[dhSigned: string; serverNonce: string] =
  let top = readTlv(data)
  if top.tag != 0xa0:
    return
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return
  for field in children(seq.body):
    case field.tag
    of 0x80:
      result.dhSigned = field.body
    of 0xa1:
      let o = readTlv(field.body)
      if o.tag == 0x04: result.serverNonce = o.body
    else:
      discard

proc parseKdcDhKeyInfo(data: string): string =
  let seq = readTlv(data)
  let body = if seq.tag == 0x30: seq.body else: data
  for field in children(body):
    if field.tag == 0xa0:
      let bs = readTlv(field.body)
      if bs.tag == 0x03 and bs.body.len > 1:
        var pub = bs.body[1 .. ^1]
        let pubInt = readTlv(pub)
        if pubInt.tag == 0x02:
          pub = pubInt.body
          while pub.len > 1 and pub[0] == '\x00':
            pub.delete(0..0)
        return pub

proc buildPkinitAsReq(username, realm: string; cert: ptr X509Obj; key: ptr EvpPkey;
                      privateRaw, dhNonce: string; err: var string): tuple[req: string; body: string] =
  let upperRealm = realm.toUpperAscii()
  let now = getTime()
  let nowUnix = now.toUnix()
  let kdcOptions = bitStringUnused(4, [byte 0x40, 0x80, 0x00, 0x10])
  let nonceBody = rand(0x7fffffff)
  let body = seqT(
    ctx(0, kdcOptions) &
    ctx(1, principal(1, @[username])) &
    ctx(2, genStr(upperRealm)) &
    ctx(3, principal(2, @["krbtgt", upperRealm])) &
    ctx(5, kerberosTimeFromUnix(nowUnix + 86400)) &
    ctx(6, kerberosTimeFromUnix(nowUnix + 86400)) &
    ctx(7, derInt(nonceBody)) &
    ctx(8, seqT(derInt(18) & derInt(17)))
  )
  let dhPub = dhPublic(privateRaw, err)
  if dhPub.len == 0:
    return
  let auth = seqT(
    ctx(0, derInt(int((now.toUnixFloat() - float(nowUnix)) * 1000000))) &
    ctx(1, kerberosTimeFromUnix(nowUnix)) &
    ctx(2, derInt(rand(0x7fffffff))) &
    ctx(3, octet(sha1Raw(body)))
  )
  let authPack = seqT(
    ctx(0, auth) &
    ctx(1, buildDhSpki(dhPub)) &
    ctx(3, octet(dhNonce))
  )
  let signed = signAuthPack(authPack, cert, key, err)
  if signed.len == 0:
    return
  let paPk = seqT(tlv(0x80, signed))
  let paPac = seqT(ctx(1, derInt(128)) & ctx(2, octet(seqT(ctx(0, boolT(true))))))
  let paPkData = seqT(ctx(1, derInt(16)) & ctx(2, octet(paPk)))
  result.body = body
  result.req = app(10, seqT(
    ctx(1, derInt(5)) &
    ctx(2, derInt(10)) &
    ctx(3, seqT(paPac & paPkData)) &
    ctx(4, body)
  ))

proc parseAsRep(response: string): tuple[ticket, encPart, paPk: string] =
  let top = readTlv(response)
  if top.tag != 0x6b:
    return
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return
  for field in children(seq.body):
    case field.tag
    of 0xa2:
      let paSeq = readTlv(field.body)
      if paSeq.tag == 0x30:
        for pa in children(paSeq.body):
          let paBody = if pa.tag == 0x30: pa.body else: pa.body
          var paType = -1
          var paVal = ""
          for pf in children(paBody):
            case pf.tag
            of 0xa1: paType = intValue(pf.body)
            of 0xa2:
              let o = readTlv(pf.body)
              if o.tag == 0x04: paVal = o.body
            else: discard
          if paType == 17:
            result.paPk = paVal
    of 0xa5:
      let t = readTlv(field.body)
      if t.tag == 0x61: result.ticket = field.body
    of 0xa6:
      result.encPart = field.body
    else:
      discard

proc storeTgtCcache(principal, realm, ccachePath, ticket, sessionKey: string;
                    sessionEtype, flags: int; authtime, starttime, endtime,
                    renewTill: int32; err: var string): bool =
  var ctxp: Krb5Context = nil
  var client: Krb5Principal = nil
  var server: Krb5Principal = nil
  var cache: Krb5Ccache = nil
  var creds = Krb5Creds()
  let cacheName = if ccachePath.startsWith("FILE:") or ccachePath.startsWith("MEMORY:"):
      ccachePath
    else:
      "FILE:" & ccachePath
  try:
    var code = krb5_init_context(addr ctxp)
    if code != 0:
      err = "krb5_init_context failed"
      return false
    code = krb5_parse_name(ctxp, principalName(principal, realm).cstring, addr client)
    if code != 0:
      err = "client principal: " & krb5Error(ctxp, code)
      return false
    code = krb5_parse_name(ctxp, serviceName("krbtgt/" & realm.toUpperAscii(), realm).cstring, addr server)
    if code != 0:
      err = "server principal: " & krb5Error(ctxp, code)
      return false
    code = krb5_cc_resolve(ctxp, cacheName.cstring, addr cache)
    if code != 0:
      err = "ccache resolve: " & krb5Error(ctxp, code)
      return false
    code = krb5_cc_initialize(ctxp, cache, client)
    if code != 0:
      err = "ccache initialize: " & krb5Error(ctxp, code)
      return false
    creds.client = client
    creds.server = server
    creds.keyblock.enctype = Krb5Enctype(sessionEtype)
    creds.keyblock.length = sessionKey.len.cuint
    creds.keyblock.contents = cast[pointer](unsafeAddr sessionKey[0])
    creds.times.authtime = authtime
    creds.times.starttime = starttime
    creds.times.endtime = endtime
    creds.times.renewTill = renewTill
    creds.ticketFlags = Krb5Flags(flags)
    creds.ticket.length = ticket.len.cuint
    creds.ticket.data = cast[cstring](unsafeAddr ticket[0])
    code = krb5_cc_store_cred(ctxp, cache, addr creds)
    if code != 0:
      err = "ccache store TGT: " & krb5Error(ctxp, code)
      return false
    true
  finally:
    if cache != nil: discard krb5_cc_close(ctxp, cache)
    if client != nil and ctxp != nil: krb5_free_principal(ctxp, client)
    if server != nil and ctxp != nil: krb5_free_principal(ctxp, server)
    if ctxp != nil: krb5_free_context(ctxp)

proc pkinitGetTgtNative*(kdc, realm, principal, certPath, keyPath, ccache: string;
                         timeoutMs = 5000): PkinitResult =
  result = PkinitResult(principal: principalName(principal, realm),
    identity: certPath, ccache: ccache)
  var err = ""
  let pair = loadPemPair(certPath, keyPath, err)
  if err.len > 0:
    result.message = err
    if pair.cert != nil: X509_free(pair.cert)
    if pair.key != nil: EVP_PKEY_free(pair.key)
    return
  defer:
    if pair.cert != nil: X509_free(pair.cert)
    if pair.key != nil: EVP_PKEY_free(pair.key)
  randomize()
  let privateRaw = smbclient.randomBytes(32)
  let dhNonce = smbclient.randomBytes(32)
  let user = if "@" in principal: principal.split('@')[0] else: principal
  let built = buildPkinitAsReq(user, realm, pair.cert, pair.key, privateRaw, dhNonce, err)
  if built.req.len == 0:
    result.message = err
    return
  if existsEnv("NIMUX_PKINIT_DUMP"):
    try:
      writeFile(getEnv("NIMUX_PKINIT_DUMP"), built.req)
    except CatchableError:
      discard
  let response = kdcRequestTcp(kdc, built.req, timeoutMs)
  if response.len == 0:
    result.message = "no response from KDC"
    return
  if existsEnv("NIMUX_PKINIT_RESP_DUMP"):
    try:
      writeFile(getEnv("NIMUX_PKINIT_RESP_DUMP"), response)
    except CatchableError:
      discard
  if readTlv(response).tag == 0x7e:
    result.message = parseKrbError(response)
    return
  let asrep = parseAsRep(response)
  if asrep.ticket.len == 0 or asrep.encPart.len == 0 or asrep.paPk.len == 0:
    result.message = "KDC did not return a complete PKINIT AS-REP"
    return
  let pkrep = parsePaPkAsRep(asrep.paPk)
  if pkrep.dhSigned.len == 0:
    result.message = "PA-PK-AS-REP missing DH signed data"
    return
  let kdcDhInfo = findOidContent(pkrep.dhSigned, oidPkinitDhKeyData)
  if kdcDhInfo.len == 0:
    result.message = "PKINIT DH reply missing key data"
    return
  let serverPub = parseKdcDhKeyInfo(kdcDhInfo)
  if serverPub.len == 0:
    result.message = "PKINIT DH reply missing public key"
    return
  let shared = dhShared(serverPub, privateRaw, err)
  if shared.len == 0:
    result.message = err
    return
  let encParsed = parseEncryptedDataFull(asrep.encPart)
  if encParsed.cipher.len == 0:
    result.message = "AS-REP missing encrypted part"
    return
  let keySize = if encParsed.etype == 18: 32 elif encParsed.etype == 17: 16 else: 0
  if keySize == 0:
    result.message = "unexpected AS-REP enctype " & $encParsed.etype
    return
  var replyKeyRaw = truncatePkinitKey(shared & dhNonce & pkrep.serverNonce, keySize)
  var replyKey = Krb5Keyblock(magic: 0, enctype: Krb5Enctype(encParsed.etype),
    length: replyKeyRaw.len.cuint, contents: cast[pointer](addr replyKeyRaw[0]))
  var cipherCopy = encParsed.cipher
  var enc = Krb5EncData(magic: 0, enctype: Krb5Enctype(encParsed.etype),
    kvno: Krb5Kvno(encParsed.kvno),
    ciphertext: Krb5Data(magic: 0, length: cipherCopy.len.cuint,
      data: cast[cstring](addr cipherCopy[0])))
  var ctxp: Krb5Context = nil
  var code = krb5_init_context(addr ctxp)
  if code != 0:
    result.message = "krb5_init_context failed"
    return
  var plain = ""
  try:
    plain = decryptWithKrb5Key(ctxp, addr replyKey, 3, enc, err)
  finally:
    krb5_free_context(ctxp)
  if plain.len == 0:
    result.message = "AS-REP decrypt failed: " & err
    return
  let encPart = parseEncAsRepPart(plain)
  if encPart.key.len == 0:
    result.message = "decrypted AS-REP missing session key"
    return
  if not storeTgtCcache(user, realm, ccache, asrep.ticket, encPart.key,
      encPart.keyType, encPart.flags, encPart.authtime, encPart.starttime,
      encPart.endtime, encPart.renewTill, err):
    result.message = err
    return
  result.success = true
  result.message = "PKINIT TGT stored"

proc currentCachePrincipal*(cacheName = ""): string =
  var ctx: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var princ: Krb5Principal = nil
  var name: cstring = nil
  var code = krb5_init_context(addr ctx)
  if code != 0:
    return ""
  try:
    if cacheName.len > 0:
      code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    else:
      code = krb5_cc_default(ctx, addr cache)
    if code != 0:
      return ""
    code = krb5_cc_get_principal(ctx, cache, addr princ)
    if code != 0:
      return ""
    code = krb5_unparse_name(ctx, princ, addr name)
    if code != 0 or name == nil:
      return ""
    result = $name
  finally:
    if name != nil: krb5_free_unparsed_name(ctx, name)
    if princ != nil: krb5_free_principal(ctx, princ)
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if ctx != nil: krb5_free_context(ctx)

proc pkinitGetTgt*(principal, identity, ccache: string; password = "";
                   krb5Config = ""): PkinitResult =
  result = PkinitResult(principal: principal, identity: identity, ccache: ccache)
  var ctx: Krb5Context = nil
  var princ: Krb5Principal = nil
  var opt: Krb5GetInitCredsOpt = nil
  var cache: Krb5Ccache = nil
  var creds = Krb5Creds()
  var gotCreds = false
  let oldConfig =
    if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG")
    else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  if krb5Config.len > 0:
    putEnv("KRB5_CONFIG", krb5Config)
  var code = krb5_init_context(addr ctx)
  if code != 0:
    result.message = "krb5_init_context failed"
    return
  try:
    let principalC = principal.cstring
    let identityC = identity.cstring
    let paNameC = "X509_user_identity".cstring
    let passwordValue = password
    let passwordC =
      if passwordValue.len > 0: passwordValue.cstring
      else: "".cstring
    code = krb5_parse_name(ctx, principalC, addr princ)
    if code != 0:
      result.message = "krb5_parse_name: " & krb5Error(ctx, code)
      return
    code = krb5_get_init_creds_opt_alloc(ctx, addr opt)
    if code != 0:
      result.message = "krb5_get_init_creds_opt_alloc: " & krb5Error(ctx, code)
      return
    code = krb5_get_init_creds_opt_set_pa(ctx, opt, paNameC, identityC)
    if code != 0:
      result.message = "set X509_user_identity: " & krb5Error(ctx, code)
      return
    discard krb5_get_init_creds_opt_set_pac_request(ctx, opt, 1)
    code = krb5_get_init_creds_password(ctx, addr creds, princ,
      passwordC, noPrompt, nil, 0, nil, opt)
    if code != 0:
      result.message = "PKINIT get credentials failed: " & krb5Error(ctx, code)
      return
    gotCreds = true
    code = krb5_cc_resolve(ctx, ("FILE:" & ccache).cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, cache, princ)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctx, code)
      return
    code = krb5_cc_store_cred(ctx, cache, addr creds)
    if code != 0:
      result.message = "ccache store: " & krb5Error(ctx, code)
      return
    result.success = true
    result.message = "PKINIT TGT stored"
  finally:
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if opt != nil: krb5_get_init_creds_opt_free(ctx, opt)
    if gotCreds:
      krb5_free_cred_contents(ctx, addr creds)
    if princ != nil: krb5_free_principal(ctx, princ)
    if ctx != nil: krb5_free_context(ctx)
    if krb5Config.len > 0:
      if hadOldConfig:
        putEnv("KRB5_CONFIG", oldConfig)
      else:
        delEnv("KRB5_CONFIG")
