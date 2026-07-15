import std/[os, strutils]
import ./tgs

when defined(linux):
  const gssLib = "libgssapi_krb5.so.2"
elif defined(macosx):
  const gssLib = "libgssapi_krb5.dylib"
else:
  const gssLib = "libgssapi_krb5.so.2"

{.emit: "/*INCLUDESECTION*/\ntypedef void* gss_cred_id_t;\ntypedef void* gss_name_t;".}

type
  GssUint32 = uint32
  GssOidDesc = object
    length*: GssUint32
    elements*: pointer
  GssOid = ptr GssOidDesc
  GssBufferDesc = object
    length*: csize_t
    value*: pointer
  GssBuffer = ptr GssBufferDesc
  GssCredId = pointer
  GssNameT = pointer
  GssKeyValueElementDesc = object
    key*: cstring
    value*: cstring
  GssKeyValueSetDesc = object
    count*: GssUint32
    elements*: ptr GssKeyValueElementDesc
  GssCredUsage = int32

const
  GSS_S_COMPLETE = 0'u32
  GSS_C_INITIATE = 1'i32

var
  GSS_C_NO_OID*: GssOid = nil
  GSS_C_NO_CREDENTIAL*: GssCredId = nil
  GSS_KRB5_NT_PRINCIPAL_NAME {.importc, dynlib: gssLib.}: GssOid
  gss_mech_krb5 {.importc, dynlib: gssLib.}: GssOid

proc gss_import_name(minor: ptr GssUint32; input: GssBuffer; nameType: GssOid;
                     output: ptr GssNameT): GssUint32 {.importc, dynlib: gssLib.}
proc gss_acquire_cred(minor: ptr GssUint32; desiredName: GssNameT; timeReq: GssUint32;
                      desiredMechs: pointer; credUsage: GssCredUsage;
                      outputCred: ptr GssCredId; actualMechs: pointer;
                      timeRec: ptr GssUint32): GssUint32 {.importc, dynlib: gssLib.}
proc gss_acquire_cred_impersonate_name(minor: ptr GssUint32; impersonatorCred: GssCredId;
                                       desiredName: GssNameT; timeReq: GssUint32;
                                       desiredMechs: pointer; credUsage: GssCredUsage;
                                       outputCred: ptr GssCredId; actualMechs: pointer;
                                       timeRec: ptr GssUint32): GssUint32 {.importc, dynlib: gssLib.}
proc gss_store_cred_into(minor: ptr GssUint32; inputCred: GssCredId;
                         inputUsage: GssCredUsage; desiredMech: GssOid;
                         overwriteCred: GssUint32; defaultCred: GssUint32;
                         credStore: ptr GssKeyValueSetDesc; elementsStored: pointer;
                         credUsageStored: ptr GssCredUsage): GssUint32 {.importc, dynlib: gssLib.}
proc gss_release_cred(minor: ptr GssUint32; cred: ptr GssCredId): GssUint32 {.importc, dynlib: gssLib.}
proc gss_release_name(minor: ptr GssUint32; name: ptr GssNameT): GssUint32 {.importc, dynlib: gssLib.}
proc gss_release_buffer(minor: ptr GssUint32; buf: GssBuffer): GssUint32 {.importc, dynlib: gssLib.}
proc gss_display_status(minor: ptr GssUint32; status: GssUint32; statusType: cint;
                        mechType: GssOid; msgCtx: ptr GssUint32;
                        output: GssBuffer): GssUint32 {.importc, dynlib: gssLib.}

proc gssError(major, minor: GssUint32): string =
  var ctx: GssUint32 = 0
  var m2: GssUint32 = 0
  var buf = GssBufferDesc()
  discard gss_display_status(addr m2, major, 1.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    result.add $cast[cstring](buf.value)
    discard gss_release_buffer(addr m2, addr buf)
  ctx = 0
  discard gss_display_status(addr m2, minor, 2.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    if result.len > 0: result.add ": "
    result.add $cast[cstring](buf.value)
    discard gss_release_buffer(addr m2, addr buf)
  if result.len == 0:
    result = "GSS error major=" & $major & " minor=" & $minor

proc cacheName(path: string): string =
  if path.len == 0:
    ""
  elif path.startsWith("FILE:") or path.startsWith("MEMORY:"):
    path
  else:
    "FILE:" & path

proc s4u2Self*(impersonateUser, sourceCcache, outCcache: string): TicketRequestResult =
  result = TicketRequestResult(operation: "s4u2self", principal: impersonateUser,
    ccache: outCcache)
  if impersonateUser.len == 0:
    result.message = "S4U2Self requires --user <principal>"
    return
  if outCcache.len == 0:
    result.message = "S4U2Self requires --out <ccache>"
    return

  let oldCcache = if existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME") else: ""
  let hadOldCcache = existsEnv("KRB5CCNAME")
  let src = cacheName(sourceCcache)
  if src.len > 0:
    putEnv("KRB5CCNAME", src)

  var minor: GssUint32 = 0
  var impersonator: GssCredId = nil
  var delegated: GssCredId = nil
  var name: GssNameT = nil
  try:
    var maj = gss_acquire_cred(addr minor, nil, 0, nil, GSS_C_INITIATE,
      addr impersonator, nil, nil)
    if maj != GSS_S_COMPLETE:
      result.message = "acquire source cred failed: " & gssError(maj, minor)
      return

    var userBuf = GssBufferDesc(length: impersonateUser.len.csize_t,
      value: cast[pointer](unsafeAddr impersonateUser[0]))
    maj = gss_import_name(addr minor, addr userBuf, GSS_KRB5_NT_PRINCIPAL_NAME,
      addr name)
    if maj != GSS_S_COMPLETE:
      result.message = "import impersonated name failed: " & gssError(maj, minor)
      return

    maj = gss_acquire_cred_impersonate_name(addr minor, impersonator, name, 0,
      nil, GSS_C_INITIATE, addr delegated, nil, nil)
    if maj != GSS_S_COMPLETE:
      result.message = "S4U2Self failed: " & gssError(maj, minor)
      return

    var outName = cacheName(outCcache)
    var item = GssKeyValueElementDesc(key: "ccache".cstring, value: outName.cstring)
    var store = GssKeyValueSetDesc(count: 1, elements: addr item)
    var storedUsage: GssCredUsage = 0
    maj = gss_store_cred_into(addr minor, delegated, GSS_C_INITIATE,
      gss_mech_krb5, 1, 0, addr store, nil, addr storedUsage)
    if maj != GSS_S_COMPLETE:
      result.message = "store S4U ccache failed: " & gssError(maj, minor)
      return

    result.success = true
    result.ccache = outName
    result.message = "S4U2Self credential stored"
  finally:
    if delegated != nil: discard gss_release_cred(addr minor, addr delegated)
    if impersonator != nil: discard gss_release_cred(addr minor, addr impersonator)
    if name != nil: discard gss_release_name(addr minor, addr name)
    if hadOldCcache:
      putEnv("KRB5CCNAME", oldCcache)
    elif src.len > 0:
      delEnv("KRB5CCNAME")
