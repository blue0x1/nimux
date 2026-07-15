import std/[strutils]

when defined(linux):
  const gssLib = "libgssapi_krb5.so.2"
elif defined(macosx):
  const gssLib = "libgssapi_krb5.dylib"
else:
  const gssLib = "libgssapi_krb5.so.2"

{.emit: "/*INCLUDESECTION*/\ntypedef void* gss_ctx_id_t;\ntypedef void* gss_cred_id_t;\ntypedef void* gss_name_t;".}

type
  GssUint32 = uint32
  GssOidDesc {.bycopy.} = object
    length*: GssUint32
    elements*: pointer
  GssOid = ptr GssOidDesc
  GssBufferDesc {.bycopy.} = object
    length*: csize_t
    value*: pointer
  GssBuffer = ptr GssBufferDesc
  GssBufferSetDesc {.bycopy.} = object
    count*: csize_t
    elements*: ptr UncheckedArray[GssBufferDesc]
  GssBufferSet = ptr GssBufferSetDesc
  GssCtxId = pointer
  GssCredId = pointer
  GssNameT = pointer

  GssKrb5LucidKey {.bycopy.} = object
    typ*: GssUint32
    length*: GssUint32
    data*: pointer

  GssKrb5Rfc1964KeyData {.bycopy.} = object
    signAlg*: GssUint32
    sealAlg*: GssUint32
    ctxKey*: GssKrb5LucidKey

  GssKrb5CfxKeyData {.bycopy.} = object
    haveAcceptorSubkey*: GssUint32
    ctxKey*: GssKrb5LucidKey
    acceptorSubkey*: GssKrb5LucidKey

  GssKrb5LucidContextV1 {.bycopy.} = object
    version*: GssUint32
    initiate*: GssUint32
    endtime*: GssUint32
    sendSeq*: uint64
    recvSeq*: uint64
    protocol*: GssUint32
    rfc1964Kd*: GssKrb5Rfc1964KeyData
    cfxKd*: GssKrb5CfxKeyData

  KerberosToken* = object
    token*: string
    sessionKey*: string
    complete*: bool

  KerberosContext* = ref object
    ctx*: GssCtxId
    target: GssNameT

  GssIovBufferDesc* {.bycopy.} = object
    typ*: GssUint32
    buffer*: GssBufferDesc

const
  GSS_S_COMPLETE = 0'u32
  GSS_S_CONTINUE_NEEDED = 1'u32
  GssIovTypeEmpty*    = 0'u32
  GssIovTypeData*     = 1'u32
  GssIovTypeHeader*   = 2'u32
  GssIovTypePadding*  = 9'u32
  GssIovTypeSignOnly* = 11'u32
  GssIovFlagAllocate* = 0x00010000'u32

var
  GSS_C_NO_CREDENTIAL: GssCredId = nil
  GSS_C_NO_OID: GssOid = nil

var GSS_C_INQ_SSPI_SESSION_KEY {.importc, dynlib: gssLib.}: GssOid

var krb5MechBytes = [0x2a'u8, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
var krb5Mech = GssOidDesc(length: 9, elements: addr krb5MechBytes[0])

proc gss_import_name(
  minor: ptr GssUint32,
  input: GssBuffer,
  nameType: GssOid,
  output: ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_init_sec_context(
  minor: ptr GssUint32,
  cred: GssCredId,
  ctx: ptr GssCtxId,
  target: GssNameT,
  mechType: GssOid,
  reqFlags: GssUint32,
  timeReq: GssUint32,
  chanBindings: pointer,
  input: GssBuffer,
  actualMech: ptr GssOid,
  output: GssBuffer,
  retFlags: ptr GssUint32,
  timeRec: ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_buffer(
  minor: ptr GssUint32,
  buf: GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_name(
  minor: ptr GssUint32,
  name: ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_delete_sec_context(
  minor: ptr GssUint32,
  ctx: ptr GssCtxId,
  buf: GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_display_status(
  minor: ptr GssUint32,
  status: GssUint32,
  statusType: cint,
  mechType: GssOid,
  msgCtx: ptr GssUint32,
  output: GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_inquire_sec_context_by_oid(
  minor: ptr GssUint32,
  context: GssCtxId,
  desiredObject: GssOid,
  dataSet: ptr GssBufferSet
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_buffer_set(
  minor: ptr GssUint32,
  dataSet: ptr GssBufferSet
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_krb5_export_lucid_sec_context(
  minor: ptr GssUint32,
  context: ptr GssCtxId,
  version: GssUint32,
  kctx: ptr pointer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_krb5_free_lucid_sec_context(
  minor: ptr GssUint32,
  kctx: pointer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap_iov(
  minor: ptr GssUint32;
  ctx: GssCtxId;
  confReq: cint;
  qop: GssUint32;
  confState: ptr cint;
  iov: ptr UncheckedArray[GssIovBufferDesc];
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap_iov(
  minor: ptr GssUint32;
  ctx: GssCtxId;
  confState: ptr cint;
  qopState: ptr GssUint32;
  iov: ptr UncheckedArray[GssIovBufferDesc];
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap(
  minor: ptr GssUint32;
  ctx: GssCtxId;
  confReq: cint;
  qop: GssUint32;
  input: GssBuffer;
  confState: ptr cint;
  output: GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap(
  minor: ptr GssUint32;
  ctx: GssCtxId;
  input: GssBuffer;
  output: GssBuffer;
  confState: ptr cint;
  qopState: ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_iov_buffer(
  minor: ptr GssUint32;
  iov: ptr UncheckedArray[GssIovBufferDesc];
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap_iov_length(
  minor: ptr GssUint32;
  ctx: GssCtxId;
  confReq: cint;
  qop: GssUint32;
  confState: ptr cint;
  iov: ptr UncheckedArray[GssIovBufferDesc];
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc bufferToString(buf: GssBufferDesc): string =
  if buf.value == nil or buf.length == 0:
    return ""
  let p = cast[ptr UncheckedArray[byte]](buf.value)
  for i in 0 ..< int(buf.length):
    result.add char(p[i])

proc lucidKeyToString(key: GssKrb5LucidKey): string =
  if key.data == nil or key.length == 0:
    return ""
  let p = cast[ptr UncheckedArray[byte]](key.data)
  for i in 0 ..< int(key.length):
    result.add char(p[i])

proc exportLucidSessionKey(ctx: var GssCtxId): string =
  if ctx == nil:
    return ""
  var minor: GssUint32
  var raw: pointer = nil
  let maj = gss_krb5_export_lucid_sec_context(addr minor, addr ctx, 1'u32, addr raw)
  if maj != GSS_S_COMPLETE or raw == nil:
    return ""
  let lucid = cast[ptr GssKrb5LucidContextV1](raw)
  if lucid.protocol == 1'u32:
    if lucid.cfxKd.haveAcceptorSubkey != 0'u32:
      result = lucidKeyToString(lucid.cfxKd.acceptorSubkey)
    if result.len == 0:
      result = lucidKeyToString(lucid.cfxKd.ctxKey)
  else:
    result = lucidKeyToString(lucid.rfc1964Kd.ctxKey)
  discard gss_krb5_free_lucid_sec_context(addr minor, raw)

proc gssError(major, minor: GssUint32): string =
  var m2, ctx: GssUint32
  var buf = GssBufferDesc()
  discard gss_display_status(addr m2, major, 1.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil:
    result.add bufferToString(buf)
    discard gss_release_buffer(addr m2, addr buf)
  ctx = 0
  discard gss_display_status(addr m2, minor, 2.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil:
    if result.len > 0: result.add " / "
    result.add bufferToString(buf)
    discard gss_release_buffer(addr m2, addr buf)
  if result.len == 0:
    result = "major=" & $major & " minor=" & $minor

proc normalizeHost(host: string): string =
  result = host.strip()
  if result.len > 0 and result[^1] == '.':
    result.setLen(result.len - 1)
  if ':' in result:
    result = result.split(':')[0]

proc importSpn(service, host, realm: string): GssNameT =
  var minor: GssUint32
  let hostOnly = normalizeHost(host)
  let serviceNorm = service.strip()
  if serviceNorm.len == 0 or hostOnly.len == 0:
    raise newException(ValueError, "Kerberos SPN needs service and host")

  var svcElems: array[6, byte] = [0x2b'u8, 0x06, 0x01, 0x05, 0x06, 0x02]
  var svcDesc = GssOidDesc(length: 6, elements: addr svcElems[0])
  var krbElems: array[10, byte] = [0x2a'u8, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01]
  var krbDesc = GssOidDesc(length: 10, elements: addr krbElems[0])

  var candidates: seq[tuple[name: string; typ: GssOid]]
  let realmNorm = realm.strip().toUpperAscii()
  if realmNorm.len > 0:
    candidates.add((serviceNorm & "/" & hostOnly & "@" & realmNorm, addr krbDesc))
  candidates.add((serviceNorm & "/" & hostOnly, addr krbDesc))
  candidates.add((serviceNorm & "/" & hostOnly, addr svcDesc))
  candidates.add((serviceNorm & "@" & hostOnly, addr svcDesc))
  if serviceNorm != serviceNorm.toLowerAscii():
    let lc = serviceNorm.toLowerAscii()
    if realmNorm.len > 0:
      candidates.add((lc & "/" & hostOnly & "@" & realmNorm, addr krbDesc))
    candidates.add((lc & "/" & hostOnly, addr krbDesc))
    candidates.add((lc & "@" & hostOnly, addr svcDesc))

  var lastMaj, lastMin: GssUint32
  for candidate in candidates:
    var ibuf = GssBufferDesc(
      length: csize_t(candidate.name.len),
      value: if candidate.name.len > 0: cast[pointer](unsafeAddr candidate.name[0]) else: nil)
    let maj = gss_import_name(addr minor, addr ibuf, candidate.typ, addr result)
    if maj == GSS_S_COMPLETE:
      return
    if lastMaj == 0:
      lastMaj = maj
      lastMin = minor
  raise newException(OSError, "gss_import_name failed: " & gssError(lastMaj, lastMin))

proc newKerberosContext*(service, host, realm: string): KerberosContext =
  KerberosContext(target: importSpn(service, host, realm))

proc newKerberosSpnContext*(spn, realm: string): KerberosContext =
  let trimmed = spn.strip()
  if trimmed.len == 0:
    raise newException(ValueError, "Kerberos SPN must not be empty")
  let slash = trimmed.find('/')
  if slash <= 0 or slash >= trimmed.len - 1:
    raise newException(ValueError, "Kerberos SPN must look like service/host")
  KerberosContext(target: importSpn(trimmed[0 ..< slash], trimmed[slash + 1 .. ^1], realm))

proc close*(kc: KerberosContext) =
  if kc == nil:
    return
  var minor: GssUint32
  if kc.target != nil:
    discard gss_release_name(addr minor, addr kc.target)
    kc.target = nil
  if kc.ctx != nil:
    discard gss_delete_sec_context(addr minor, addr kc.ctx, nil)
    kc.ctx = nil

proc sessionKey*(kc: KerberosContext): string =
  if kc == nil or kc.ctx == nil:
    return ""
  var minor: GssUint32
  var keySet: GssBufferSet = nil
  let keyMaj = gss_inquire_sec_context_by_oid(
    addr minor, kc.ctx, GSS_C_INQ_SSPI_SESSION_KEY, addr keySet)
  if keyMaj == GSS_S_COMPLETE and keySet != nil and keySet.count > 0:
    result = bufferToString(keySet.elements[0])
  if keySet != nil:
    discard gss_release_buffer_set(addr minor, addr keySet)

proc step*(kc: KerberosContext; inputToken = ""): KerberosToken =
  if kc == nil or kc.target == nil:
    raise newException(OSError, "Kerberos context is closed")
  var minor: GssUint32
  var outBuf = GssBufferDesc()
  var retFlags, timeRec: GssUint32
  var inBuf = GssBufferDesc(
    length: csize_t(inputToken.len),
    value: if inputToken.len > 0: cast[pointer](unsafeAddr inputToken[0]) else: nil)
  let inPtr = if inputToken.len > 0: addr inBuf else: nil
  let maj = gss_init_sec_context(
    addr minor, GSS_C_NO_CREDENTIAL, addr kc.ctx, kc.target, addr krb5Mech,
    0x38'u32, 0, nil, inPtr, nil, addr outBuf, addr retFlags, addr timeRec)
  if maj != GSS_S_COMPLETE and maj != GSS_S_CONTINUE_NEEDED:
    raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj, minor))
  result.token = bufferToString(outBuf)
  result.complete = maj == GSS_S_COMPLETE
  if outBuf.value != nil:
    discard gss_release_buffer(addr minor, addr outBuf)

proc stepWithFlags*(kc: KerberosContext; inputToken = ""; reqFlags = 0x3e'u32): KerberosToken =
  if kc == nil or kc.target == nil:
    raise newException(OSError, "Kerberos context is closed")
  var minor: GssUint32
  var outBuf = GssBufferDesc()
  var retFlags, timeRec: GssUint32
  var inBuf = GssBufferDesc(
    length: csize_t(inputToken.len),
    value: if inputToken.len > 0: cast[pointer](unsafeAddr inputToken[0]) else: nil)
  let inPtr = if inputToken.len > 0: addr inBuf else: nil
  let maj = gss_init_sec_context(
    addr minor, GSS_C_NO_CREDENTIAL, addr kc.ctx, kc.target, addr krb5Mech,
    reqFlags, 0, nil, inPtr, nil, addr outBuf, addr retFlags, addr timeRec)
  if maj != GSS_S_COMPLETE and maj != GSS_S_CONTINUE_NEEDED:
    raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj, minor))
  result.token = bufferToString(outBuf)
  result.complete = maj == GSS_S_COMPLETE
  if outBuf.value != nil:
    discard gss_release_buffer(addr minor, addr outBuf)

proc wrapToken*(kc: KerberosContext; data: string; confidential = false): string =
  if kc == nil or kc.ctx == nil:
    raise newException(OSError, "Kerberos context not established")
  var minor: GssUint32
  var inBuf = GssBufferDesc(
    length: csize_t(data.len),
    value: if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil)
  var outBuf = GssBufferDesc()
  var confState: cint
  let maj = gss_wrap(addr minor, kc.ctx, (if confidential: 1.cint else: 0.cint),
    0'u32, addr inBuf, addr confState, addr outBuf)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_wrap failed: " & gssError(maj, minor))
  result = bufferToString(outBuf)
  if outBuf.value != nil:
    discard gss_release_buffer(addr minor, addr outBuf)

proc unwrapToken*(kc: KerberosContext; data: string): string =
  if kc == nil or kc.ctx == nil:
    raise newException(OSError, "Kerberos context not established")
  var minor: GssUint32
  var inBuf = GssBufferDesc(
    length: csize_t(data.len),
    value: if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil)
  var outBuf = GssBufferDesc()
  var confState: cint
  var qopState: GssUint32
  let maj = gss_unwrap(addr minor, kc.ctx, addr inBuf, addr outBuf,
    addr confState, addr qopState)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_unwrap failed: " & gssError(maj, minor))
  result = bufferToString(outBuf)
  if outBuf.value != nil:
    discard gss_release_buffer(addr minor, addr outBuf)

proc wrapDce*(kc: KerberosContext; data: string): tuple[header, encrypted: string] =
  if kc == nil or kc.ctx == nil:
    raise newException(OSError, "Kerberos context not established")
  var iovArr: array[2, GssIovBufferDesc]
  var dataBuf = data
  iovArr[0].typ = GssIovTypeHeader or GssIovFlagAllocate
  iovArr[0].buffer.length = 0
  iovArr[0].buffer.value = nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(dataBuf.len)
  iovArr[1].buffer.value = if dataBuf.len > 0: cast[pointer](addr dataBuf[0]) else: nil
  var minor: GssUint32
  var confState: cint = 0
  let maj = gss_wrap_iov(addr minor, kc.ctx, 1, 0, addr confState,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 2)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_wrap_iov failed: major=" & $maj)
  result.header = bufferToString(iovArr[0].buffer)
  result.encrypted = dataBuf
  discard gss_release_iov_buffer(addr minor,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 2)

proc unwrapDce*(kc: KerberosContext; header, encrypted: string): string =
  if kc == nil or kc.ctx == nil:
    return ""
  var iovArr: array[2, GssIovBufferDesc]
  var hdr = header
  var enc = encrypted
  iovArr[0].typ = GssIovTypeHeader
  iovArr[0].buffer.length = csize_t(hdr.len)
  iovArr[0].buffer.value = if hdr.len > 0: cast[pointer](addr hdr[0]) else: nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(enc.len)
  iovArr[1].buffer.value = if enc.len > 0: cast[pointer](addr enc[0]) else: nil
  var minor: GssUint32
  var confState: cint = 0
  var qopState: GssUint32 = 0
  let maj = gss_unwrap_iov(addr minor, kc.ctx, addr confState, addr qopState,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 2)
  if maj != GSS_S_COMPLETE:
    return ""
  result = enc

proc getDce2TokenSize*(kc: KerberosContext; dataLen: int): int =
  var iovArr: array[2, GssIovBufferDesc]
  iovArr[0].typ = GssIovTypeHeader or GssIovFlagAllocate
  iovArr[0].buffer.length = 0
  iovArr[0].buffer.value = nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(dataLen)
  iovArr[1].buffer.value = nil
  var minor, confState: GssUint32
  let cs = cast[ptr cint](addr confState)
  discard gss_wrap_iov_length(addr minor, kc.ctx, 1, 0, cs,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 2)
  result = int(iovArr[0].buffer.length)

proc getDceTokenSize*(kc: KerberosContext; dataLen: int): int =
  var iovArr: array[4, GssIovBufferDesc]
  iovArr[0].typ = GssIovTypeSignOnly
  iovArr[0].buffer.length = 24
  iovArr[0].buffer.value = nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(dataLen)
  iovArr[1].buffer.value = nil
  iovArr[2].typ = GssIovTypeSignOnly
  iovArr[2].buffer.length = 8
  iovArr[2].buffer.value = nil
  iovArr[3].typ = GssIovTypeHeader or GssIovFlagAllocate
  iovArr[3].buffer.length = 0
  iovArr[3].buffer.value = nil
  var minor, confState: GssUint32
  let cs = cast[ptr cint](addr confState)
  discard gss_wrap_iov_length(addr minor, kc.ctx, 1, 0, cs,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 4)
  result = int(iovArr[3].buffer.length)

proc wrapDce4*(kc: KerberosContext; signOnly0, data, signOnly2: string): tuple[header, encrypted: string] =
  if kc == nil or kc.ctx == nil:
    raise newException(OSError, "Kerberos context not established")
  var s0 = signOnly0
  var dataBuf = data
  var s2 = signOnly2
  var iovArr: array[4, GssIovBufferDesc]
  iovArr[0].typ = GssIovTypeSignOnly
  iovArr[0].buffer.length = csize_t(s0.len)
  iovArr[0].buffer.value = if s0.len > 0: cast[pointer](addr s0[0]) else: nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(dataBuf.len)
  iovArr[1].buffer.value = if dataBuf.len > 0: cast[pointer](addr dataBuf[0]) else: nil
  iovArr[2].typ = GssIovTypeSignOnly
  iovArr[2].buffer.length = csize_t(s2.len)
  iovArr[2].buffer.value = if s2.len > 0: cast[pointer](addr s2[0]) else: nil
  iovArr[3].typ = GssIovTypeHeader or GssIovFlagAllocate
  iovArr[3].buffer.length = 0
  iovArr[3].buffer.value = nil
  var minor: GssUint32
  var confState: cint = 0
  let maj = gss_wrap_iov(addr minor, kc.ctx, 1, 0, addr confState,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 4)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_wrap_iov (4-buf) failed: major=" & $maj & " minor=" & $minor)
  result.header = bufferToString(iovArr[3].buffer)
  result.encrypted = dataBuf
  discard gss_release_iov_buffer(addr minor,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 4)

proc unwrapDce4*(kc: KerberosContext; signOnly0, encrypted, signOnly2, token: string): string =
  if kc == nil or kc.ctx == nil:
    return ""
  var s0 = signOnly0
  var enc = encrypted
  var s2 = signOnly2
  var hdr = token
  var iovArr: array[4, GssIovBufferDesc]
  iovArr[0].typ = GssIovTypeSignOnly
  iovArr[0].buffer.length = csize_t(s0.len)
  iovArr[0].buffer.value = if s0.len > 0: cast[pointer](addr s0[0]) else: nil
  iovArr[1].typ = GssIovTypeData
  iovArr[1].buffer.length = csize_t(enc.len)
  iovArr[1].buffer.value = if enc.len > 0: cast[pointer](addr enc[0]) else: nil
  iovArr[2].typ = GssIovTypeSignOnly
  iovArr[2].buffer.length = csize_t(s2.len)
  iovArr[2].buffer.value = if s2.len > 0: cast[pointer](addr s2[0]) else: nil
  iovArr[3].typ = GssIovTypeHeader
  iovArr[3].buffer.length = csize_t(hdr.len)
  iovArr[3].buffer.value = if hdr.len > 0: cast[pointer](addr hdr[0]) else: nil
  var minor: GssUint32
  var confState: cint = 0
  var qopState: GssUint32 = 0
  let maj = gss_unwrap_iov(addr minor, kc.ctx, addr confState, addr qopState,
    cast[ptr UncheckedArray[GssIovBufferDesc]](addr iovArr[0]), 4)
  if maj != GSS_S_COMPLETE:
    return ""
  result = enc

proc initKerberosToken*(service, host, realm: string; inputToken = ""): KerberosToken =
  let kc = newKerberosContext(service, host, realm)
  try:
    result = kc.step(inputToken)
    if result.sessionKey.len == 0:
      result.sessionKey = kc.sessionKey()
  finally:
    kc.close()

proc initKerberosSpnToken*(spn, realm: string; inputToken = ""): KerberosToken =
  let kc = newKerberosSpnContext(spn, realm)
  try:
    result = kc.step(inputToken)
    if result.sessionKey.len == 0:
      result.sessionKey = kc.sessionKey()
  finally:
    kc.close()
