import std/[asyncdispatch, strutils]

import ../smb/client as smb
import ../dcerpc/client as rpc
import ../dcom/client as dcom

const
  CLSIDCertAdminBytes* = [
    byte 0x73, 0x6e, 0x9e, 0xd9, 0x88, 0xfc, 0xd0, 0x11,
         0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03, 0x12, 0xf3
  ]
  ICertAdminD2UuidBytes* = [
    byte 0x35, 0xd9, 0xe0, 0x7f, 0xa6, 0xdd, 0x3f, 0x44,
         0x85, 0xd0, 0x1c, 0xfb, 0x58, 0xfe, 0x41, 0xdd
  ]
  OpGetConfigEntry* = 44'u16
  OpSetConfigEntry* = 45'u16
  ICertAdminD2Major* = 0'u16
  ICertAdminD2Minor* = 0'u16
  VtI4 = 3'u16
  VtBstr = 8'u16
  VtArray = 0x2000'u16

type
  CertAdminValueKind* = enum
    cavI4, cavBstrArray

  CertAdminValue* = object
    case kind*: CertAdminValueKind
    of cavI4:
      i4*: int32
    of cavBstrArray:
      strings*: seq[string]

  CertAdminResult* = object
    host*: string
    success*: bool
    transport*: string
    authority*: string
    nodePath*: string
    entry*: string
    hresult*: uint32
    faultStatus*: uint32
    message*: string
    valueI4*: int32
    valueKind*: string

proc addU16Le(d: var string; v: uint16) =
  d.add char(int(v) and 0xff)
  d.add char((int(v) shr 8) and 0xff)

proc addU32Le(d: var string; v: uint32) =
  d.add char(int(v) and 0xff)
  d.add char((int(v) shr 8) and 0xff)
  d.add char((int(v) shr 16) and 0xff)
  d.add char((int(v) shr 24) and 0xff)

proc readU32Le(data: string; off: int): uint32 =
  if off + 3 >= data.len:
    return 0xffffffff'u32
  uint32(ord(data[off])) or (uint32(ord(data[off+1])) shl 8) or
    (uint32(ord(data[off+2])) shl 16) or (uint32(ord(data[off+3])) shl 24)

proc pad4(d: var string) =
  while d.len mod 4 != 0:
    d.add char(0)

proc pad8(d: var string) =
  while d.len mod 8 != 0:
    d.add char(0)

proc toUtf16Le(s: string): string =
  for c in s:
    result.add c
    result.add char(0)

proc bytesToStrLocal(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b:
    result[i] = chr(int(x))

proc hexString(data: string): string =
  const digits = "0123456789abcdef"
  for c in data:
    let v = ord(c)
    result.add digits[(v shr 4) and 0xf]
    result.add digits[v and 0xf]

proc addOrpcThis(d: var string) =
  d.addU16Le 5
  d.addU16Le 7
  d.addU32Le 0
  d.addU32Le 0
  for _ in 0 ..< 16:
    d.add char(0)
  d.addU32Le 0

proc addWStringBody(d: var string; value: string) =
  let utf = toUtf16Le(value & "\x00")
  let count = uint32(utf.len div 2)
  d.addU32Le count
  d.addU32Le 0'u32
  d.addU32Le count
  d.add utf
  pad4(d)

proc addUniqueWString(d: var string; value: string; referent: uint32) =
  if value.len == 0:
    d.addU32Le 0'u32
    return
  d.addU32Le referent
  d.addWStringBody(value)

proc addRefWString(d: var string; value: string; referent: uint32) =
  discard referent
  d.addWStringBody(value)

proc addWireVariantI4(d: var string; value: int32) =
  d.addU32Le 5'u32
  d.addU32Le 0'u32
  d.addU16Le VtI4
  d.addU16Le 0'u16
  d.addU16Le 0'u16
  d.addU16Le 0'u16
  d.addU32Le uint32(VtI4)
  d.addU32Le cast[uint32](value)

proc addBstrData(d: var string; value: string) =
  let utf = toUtf16Le(value)
  d.addU32Le uint32(value.len)
  d.addU32Le uint32(utf.len)
  d.addU32Le uint32(value.len)
  d.add utf
  pad4(d)

proc addBstrPointer(d: var string; value: string; referent: uint32) =
  d.addU32Le referent
  addBstrData(d, value)

proc addWireVariantBstrArray(d: var string; values: seq[string]) =
  d.addU32Le 0'u32
  d.addU32Le 0'u32
  d.addU16Le (VtArray or VtBstr)
  d.addU16Le 0'u16
  d.addU16Le 0'u16
  d.addU16Le 0'u16
  d.addU32Le uint32(VtArray)
  d.addU32Le 1'u32
  d.addU16Le 1'u16
  d.addU16Le 0x0100'u16
  d.addU32Le 8'u32
  d.addU32Le 0'u32
  d.addU32Le uint32(VtBstr)
  d.addU32Le uint32(values.len)
  d.addU32Le 0x00020040'u32
  d.addU32Le uint32(values.len)
  d.addU32Le 0'u32
  d.addU32Le uint32(values.len)
  for i, value in values:
    d.addU32Le 0x00030000'u32 + uint32(i * 4)
  for i, value in values:
    discard i
    addBstrData(d, value)

proc addVariantRef(d: var string; value: CertAdminValue) =
  d.addU32Le 0x0002000c'u32
  case value.kind
  of cavI4:
    addWireVariantI4(d, value.i4)
  of cavBstrArray:
    addWireVariantBstrArray(d, value.strings)

proc buildSetConfigEntryStub(authority, nodePath, entry: string;
                             value: CertAdminValue): string =
  result.addOrpcThis()
  result.addUniqueWString(authority, 0x00020000'u32)
  result.addUniqueWString(nodePath, 0x00020004'u32)
  result.addRefWString(entry, 0x00020008'u32)
  result.addVariantRef(value)

proc buildGetConfigEntryStub(authority, nodePath, entry: string): string =
  result.addOrpcThis()
  result.addUniqueWString(authority, 0x00020000'u32)
  result.addUniqueWString(nodePath, 0x00020004'u32)
  result.addRefWString(entry, 0x00020008'u32)

proc parseReturnedVariantI4(stub: string; value: var int32; vtName: var string): bool =
  var start = 0
  dcom.parseOrpcThat(stub, start)
  var i = start
  while i + 20 <= stub.len:
    let clSize = readU32Le(stub, i)
    if (clSize == 5'u32 or clSize == 3'u32) and readU32Le(stub, i + 4) == 0'u32:
      let vt = uint16(readU32Le(stub, i + 8) and 0xffff'u32)
      let unionOrValue = readU32Le(stub, i + 16)
      if vt == VtI4 and unionOrValue == uint32(VtI4) and i + 24 <= stub.len:
        value = cast[int32](readU32Le(stub, i + 20))
        vtName = "VT_I4"
        return true
      if vt == VtI4:
        value = cast[int32](unionOrValue)
        vtName = "VT_I4"
        return true
      vtName = "VT_" & $vt
    inc i, 4
  return false

proc parseDcomHresult(stub: string): uint32 =
  var offset = 0
  dcom.parseOrpcThat(stub, offset)
  if offset + 4 <= stub.len:
    return readU32Le(stub, offset)
  if stub.len >= 4:
    return readU32Le(stub, stub.len - 4)
  return 0xffffffff'u32

proc parseDcomTrailingHresult(stub: string): uint32 =
  if stub.len < 4:
    return 0xffffffff'u32
  let last = readU32Le(stub, stub.len - 4)
  if last != 0'u32:
    return last
  var start = 0
  dcom.parseOrpcThat(stub, start)
  var i = stub.len - 8
  while i >= start:
    let v = readU32Le(stub, i)
    if (v and 0x80000000'u32) != 0'u32:
      return v
    dec i, 4
  return last

proc setConfigEntry*(host: string; timeoutMs: int; credential: smb.SmbCredential;
                     authMethod: smb.SmbAuthMethod; authority, nodePath, entry: string;
                     value: CertAdminValue): Future[CertAdminResult] {.async.} =
  result.host = host
  result.authority = authority
  result.nodePath = nodePath
  result.entry = entry
  result.transport = "certadmin-dcom-tcp"

  var scm: rpc.DceRpcClient
  try:
    scm =
      if authMethod == smb.samKerberos:
        await rpc.connectAndBindKerb(host, 135, max(timeoutMs, 8000),
          @(dcom.IRemoteSCMActivatorUuidBytes), dcom.IRemoteSCMActivatorMajor,
          dcom.IRemoteSCMActivatorMinor, credential.domain)
      else:
        await rpc.connectAndBind(host, 135, max(timeoutMs, 8000),
          @(dcom.IRemoteSCMActivatorUuidBytes), dcom.IRemoteSCMActivatorMajor,
          dcom.IRemoteSCMActivatorMinor, credential)
    let createStub = dcom.buildRemoteCreateInstanceStub(
      bytesToStrLocal(CLSIDCertAdminBytes),
      bytesToStrLocal(ICertAdminD2UuidBytes))
    let createResp = await scm.call(4'u16, createStub)
    scm.close()
    if not createResp.ok:
      result.faultStatus = createResp.faultStatus
      result.message = "RemoteCreateInstance fault 0x" & createResp.faultStatus.toHex(8)
      return
    let reply = dcom.parseActivationReply(createResp.stub)
    if reply.iwbemObjRef.std.ipid.len != 16:
      result.hresult = reply.comError
      result.message =
        if reply.comError != 0'u32:
          "RemoteCreateInstance returned HRESULT 0x" & reply.comError.toHex(8)
        else:
          "RemoteCreateInstance returned no ICertAdminD2 OBJREF"
      return

    var dynamicPort = dcom.tcpPortFromBindings(reply.bindings)
    if dynamicPort == 0:
      dynamicPort = dcom.tcpPortFromBindings(reply.iwbemObjRef.bindings)
    if dynamicPort == 0 and reply.oxid.len == 8 and authMethod != smb.samKerberos:
      let resolved = await dcom.resolveOxid2(host, 135, max(timeoutMs, 8000),
        reply.oxid, credential)
      dynamicPort = dcom.tcpPortFromBindings(resolved.bindings)
    if dynamicPort == 0:
      result.message = "could not determine dynamic DCOM port for CertAdmin"
      return

    let cli =
      if authMethod == smb.samKerberos:
        await rpc.connectAndBindKerb(host, dynamicPort, max(timeoutMs, 8000),
          @(ICertAdminD2UuidBytes), ICertAdminD2Major, ICertAdminD2Minor, credential.domain,
          rpc.AuthLevelPktPrivacy)
      else:
        await rpc.connectAndBind(host, dynamicPort, max(timeoutMs, 8000),
          @(ICertAdminD2UuidBytes), ICertAdminD2Major, ICertAdminD2Minor, credential,
          rpc.AuthLevelPktPrivacy)
    let callRes = await cli.call(OpSetConfigEntry,
      buildSetConfigEntryStub(authority, nodePath, entry, value),
      reply.iwbemObjRef.std.ipid)
    cli.close()
    if not callRes.ok:
      result.faultStatus = callRes.faultStatus
      result.message = "ICertAdminD2 SetConfigEntry faulted"
      return
    result.hresult = parseDcomHresult(callRes.stub)
    result.success = result.hresult == 0'u32
    result.message =
      if result.success: "ICertAdminD2 SetConfigEntry returned S_OK"
      else: "ICertAdminD2 SetConfigEntry returned HRESULT 0x" & result.hresult.toHex(8)
  except CatchableError as error:
    if scm != nil:
      scm.close()
    result.message = error.msg
    return

proc getConfigEntryI4*(host: string; timeoutMs: int; credential: smb.SmbCredential;
                       authMethod: smb.SmbAuthMethod; authority, nodePath, entry: string):
                       Future[CertAdminResult] {.async.} =
  result.host = host
  result.authority = authority
  result.nodePath = nodePath
  result.entry = entry
  result.transport = "certadmin-dcom-tcp"

  var scm: rpc.DceRpcClient
  try:
    scm =
      if authMethod == smb.samKerberos:
        await rpc.connectAndBindKerb(host, 135, max(timeoutMs, 8000),
          @(dcom.IRemoteSCMActivatorUuidBytes), dcom.IRemoteSCMActivatorMajor,
          dcom.IRemoteSCMActivatorMinor, credential.domain)
      else:
        await rpc.connectAndBind(host, 135, max(timeoutMs, 8000),
          @(dcom.IRemoteSCMActivatorUuidBytes), dcom.IRemoteSCMActivatorMajor,
          dcom.IRemoteSCMActivatorMinor, credential)
    let createStub = dcom.buildRemoteCreateInstanceStub(
      bytesToStrLocal(CLSIDCertAdminBytes),
      bytesToStrLocal(ICertAdminD2UuidBytes))
    let createResp = await scm.call(4'u16, createStub)
    scm.close()
    if not createResp.ok:
      result.faultStatus = createResp.faultStatus
      result.message = "RemoteCreateInstance fault 0x" & createResp.faultStatus.toHex(8)
      return
    let reply = dcom.parseActivationReply(createResp.stub)
    if reply.iwbemObjRef.std.ipid.len != 16:
      result.hresult = reply.comError
      result.message =
        if reply.comError != 0'u32:
          "RemoteCreateInstance returned HRESULT 0x" & reply.comError.toHex(8)
        else:
          "RemoteCreateInstance returned no ICertAdminD2 OBJREF"
      return

    var dynamicPort = dcom.tcpPortFromBindings(reply.bindings)
    if dynamicPort == 0:
      dynamicPort = dcom.tcpPortFromBindings(reply.iwbemObjRef.bindings)
    if dynamicPort == 0 and reply.oxid.len == 8 and authMethod != smb.samKerberos:
      let resolved = await dcom.resolveOxid2(host, 135, max(timeoutMs, 8000),
        reply.oxid, credential)
      dynamicPort = dcom.tcpPortFromBindings(resolved.bindings)
    if dynamicPort == 0:
      result.message = "could not determine dynamic DCOM port for CertAdmin"
      return

    let cli =
      if authMethod == smb.samKerberos:
        await rpc.connectAndBindKerb(host, dynamicPort, max(timeoutMs, 8000),
          @(ICertAdminD2UuidBytes), ICertAdminD2Major, ICertAdminD2Minor, credential.domain,
          rpc.AuthLevelPktPrivacy)
      else:
        await rpc.connectAndBind(host, dynamicPort, max(timeoutMs, 8000),
          @(ICertAdminD2UuidBytes), ICertAdminD2Major, ICertAdminD2Minor, credential,
          rpc.AuthLevelPktPrivacy)
    let callRes = await cli.call(OpGetConfigEntry,
      buildGetConfigEntryStub(authority, nodePath, entry),
      reply.iwbemObjRef.std.ipid)
    cli.close()
    if not callRes.ok:
      result.faultStatus = callRes.faultStatus
      result.message = "ICertAdminD2 GetConfigEntry faulted"
      return
    result.hresult = parseDcomTrailingHresult(callRes.stub)
    var vtName = ""
    var i4 = 0'i32
    result.success = result.hresult == 0'u32 and parseReturnedVariantI4(callRes.stub, i4, vtName)
    result.valueI4 = i4
    result.valueKind = vtName
    result.message =
      if result.success: "ICertAdminD2 GetConfigEntry succeeded"
      elif result.hresult != 0'u32: "ICertAdminD2 GetConfigEntry returned HRESULT 0x" & result.hresult.toHex(8)
      else: "ICertAdminD2 GetConfigEntry returned unsupported variant: " & hexString(callRes.stub)
  except CatchableError as error:
    if scm != nil:
      scm.close()
    result.message = error.msg
    return
