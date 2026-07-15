import std/[asyncdispatch, asyncfutures, strutils]
import ../smb/client as smb

const
  RrpUuidBytes* = [
    byte 0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31,
    0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03
  ]
  ScmrUuidBytes = [
    byte 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
    0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03
  ]
  MaxAllowed = 0x02000000'u32
  ServiceStopped = 0x00000001'u32

proc addU16Le(s: var string; v: uint16) =
  s.add char(v and 0xff); s.add char((v shr 8) and 0xff)

proc addU32Le(s: var string; v: uint32) =
  s.add char(v and 0xff)
  s.add char((v shr 8) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 24) and 0xff)

proc readU16Le(data: string; off: int): uint16 =
  uint16(ord(data[off])) or (uint16(ord(data[off+1])) shl 8)

proc readU32Le*(data: string; off: int): uint32 =
  uint32(ord(data[off])) or (uint32(ord(data[off+1])) shl 8) or
  (uint32(ord(data[off+2])) shl 16) or (uint32(ord(data[off+3])) shl 24)

proc pad4(s: var string) =
  while s.len mod 4 != 0: s.add char(0)

proc ndrUnicodeStr(text: string; refId: uint32): string =
  let utf = smb.toUtf16Le(text) & "\x00\x00"
  let byteLen = utf.len
  let charCount = uint32(byteLen div 2)
  result.addU16Le uint16(byteLen)
  result.addU16Le uint16(byteLen)
  result.addU32Le refId
  result.addU32Le charCount
  result.addU32Le 0'u32
  result.addU32Le charCount
  result.add utf
  pad4(result)

proc ndrEmptyUnicodeStr(maxChars: uint32; refId: uint32): string =
  result.addU16Le 0'u16
  result.addU16Le uint16(maxChars * 2)
  result.addU32Le refId
  result.addU32Le maxChars
  result.addU32Le 0'u32
  result.addU32Le 0'u32

proc buildDceRpcBindRrp*(callId = 1'u32): string =
  smb.buildDceRpcBind(RrpUuidBytes, 1'u16, 0'u16, callId)

proc buildOpenHklm*(): string =
  result.addU32Le 0'u32
  result.addU32Le MaxAllowed

proc buildOpenHive*(): string =
  result.addU32Le 0'u32
  result.addU32Le MaxAllowed

proc parseHKey*(stub: string): string =
  if stub.len < 24: return ""
  let code = readU32Le(stub, 20)
  if code != 0: return ""
  result = stub[0 ..< 20]

proc parseHKeyStatus*(stub: string): uint32 =
  if stub.len < 24: return 0xffffffff'u32
  readU32Le(stub, 20)

proc buildCloseKey*(hKey: string): string =
  if hKey.len >= 20: result.add hKey[0 ..< 20]

proc buildOpenKey*(hKey: string; subKey: string; samDesired = MaxAllowed): string =
  result.add hKey[0 ..< 20]
  result.add ndrUnicodeStr(subKey, 0x00020014'u32)
  result.addU32Le 0'u32
  result.addU32Le samDesired

proc parseHKeyResponse*(stub: string): string =
  if stub.len < 24: return ""
  let code = readU32Le(stub, stub.len - 4)
  if code != 0: return ""
  if stub.len >= 28:
    result = stub[4 ..< 24]
  else:
    result = stub[0 ..< 20]

proc buildQueryInfoKey*(hKey: string): string =
  result.add hKey[0 ..< 20]
  result.add ndrEmptyUnicodeStr(512, 0x00020014'u32)

proc parseQueryInfoKeyClass*(stub: string): string =
  if stub.len < 8: return ""
  let length  = int(readU16Le(stub, 0))
  let refId   = readU32Le(stub, 4)
  if refId == 0 or length == 0: return ""
  var off = 8
  if off + 12 > stub.len: return ""
  let actCount = int(readU32Le(stub, off + 8))
  off += 12
  if actCount == 0 or off + actCount * 2 > stub.len: return ""
  let rawUtf = stub[off ..< off + actCount * 2]
  var i = 0
  while i + 1 < rawUtf.len:
    let cp = uint32(ord(rawUtf[i])) or (uint32(ord(rawUtf[i+1])) shl 8)
    i += 2
    if cp == 0: break
    if cp < 0x80: result.add char(cp)
    else: result.add char(0x3f)

proc buildQueryValue*(hKey: string; valueName: string; dataLen = 512'u32): string =
  result.add hKey[0 ..< 20]
  result.add ndrUnicodeStr(valueName, 0x00020014'u32)
  result.addU32Le 0x00020018'u32
  result.addU32Le 0'u32
  result.addU32Le 0x0002001c'u32
  result.addU32Le dataLen
  result.addU32Le 0'u32
  result.addU32Le dataLen
  result.add repeat(' ', int(dataLen))
  pad4(result)
  result.addU32Le 0x00020020'u32
  result.addU32Le dataLen
  result.addU32Le 0x00020024'u32
  result.addU32Le dataLen

proc buildSaveKey*(hKey: string; fileName: string): string =
  result.add hKey[0 ..< 20]
  result.add ndrUnicodeStr(fileName, 0x00020014'u32)
  result.addU32Le 0'u32

proc parseStatus*(stub: string): uint32 =
  if stub.len < 4: return 0xffffffff'u32
  result = readU32Le(stub, stub.len - 4)

proc parseQueryValue*(stub: string): tuple[dataType: uint32; data: string; ok: bool; errorCode: uint32; needed: uint32] =
  if stub.len < 4: return
  var off = 0
  let typeRef = readU32Le(stub, off); off += 4
  if typeRef == 0: return
  if off + 4 > stub.len: return
  result.dataType = readU32Le(stub, off); off += 4
  if off + 4 > stub.len: return
  let dataRef = readU32Le(stub, off); off += 4
  if dataRef == 0:
    result.ok = true
    return
  if off + 12 > stub.len: return
  let maxCount = int(readU32Le(stub, off)); off += 4
  let dataOff  = int(readU32Le(stub, off)); off += 4
  let actCount = int(readU32Le(stub, off)); off += 4
  if maxCount < actCount or off + dataOff + actCount > stub.len: return
  result.data = stub[off + dataOff ..< off + dataOff + actCount]
  off += actCount
  while off mod 4 != 0: inc off
  if off + 4 > stub.len: return
  let cbDataRef = readU32Le(stub, off); off += 4
  if cbDataRef != 0 and off + 4 <= stub.len:
    result.needed = readU32Le(stub, off); off += 4
  if off + 4 > stub.len: return
  let cbLenRef = readU32Le(stub, off); off += 4
  if cbLenRef != 0 and off + 4 <= stub.len:
    discard readU32Le(stub, off); off += 4
  if off + 4 > stub.len: return
  result.errorCode = readU32Le(stub, off)
  if result.errorCode == 0xEA'u32:
    result.ok = false
    return
  if result.errorCode != 0: return
  result.ok = true

proc buildEnumKey*(hKey: string; index: uint32): string =
  result.add hKey[0 ..< 20]
  result.addU32Le index
  result.add ndrEmptyUnicodeStr(512, 0x00020014'u32)
  result.addU32Le 0'u32
  result.addU32Le 0'u32

proc parseEnumKey*(stub: string): tuple[name: string; ok: bool] =
  if stub.len < 4: return
  let retCode = readU32Le(stub, stub.len - 4)
  if retCode == 0x00000103'u32: return
  if retCode != 0: return
  if stub.len < 12: return
  let length  = int(readU16Le(stub, 0))
  let refId   = readU32Le(stub, 4)
  if refId == 0 or length == 0:
    result.ok = true
    return
  var off = 8
  if off + 12 > stub.len: return
  let actCount = int(readU32Le(stub, off + 8))
  off += 12
  if off + actCount * 2 > stub.len: return
  let rawUtf = stub[off ..< off + actCount * 2]
  var i = 0
  while i + 1 < rawUtf.len:
    let cp = uint32(ord(rawUtf[i])) or (uint32(ord(rawUtf[i+1])) shl 8)
    i += 2
    if cp == 0: break
    if cp < 0x80: result.name.add char(cp)
    elif cp < 0x800:
      result.name.add char(0xC0 or (cp shr 6))
      result.name.add char(0x80 or (cp and 0x3F))
    else:
      result.name.add char(0xE0 or (cp shr 12))
      result.name.add char(0x80 or ((cp shr 6) and 0x3F))
      result.name.add char(0x80 or (cp and 0x3F))
  result.ok = true

proc buildEnumValue*(hKey: string; index: uint32; dataLen = 65536'u32): string =
  result.add hKey[0 ..< 20]
  result.addU32Le index
  result.add ndrEmptyUnicodeStr(512, 0x00020014'u32)
  result.addU32Le 0x00020018'u32
  result.addU32Le 0x0002001c'u32
  result.addU32Le 0x00020020'u32
  result.addU32Le 0x00020024'u32
  result.addU32Le 0'u32
  result.addU32Le dataLen
  result.addU32Le 0'u32
  result.addU32Le dataLen
  result.add repeat('\x00', int(dataLen))
  result.addU32Le dataLen
  result.addU32Le dataLen

proc parseEnumValue*(stub: string): tuple[name: string; dataType: uint32; data: string; ok: bool] =
  if stub.len < 4: return
  let retCode = readU32Le(stub, stub.len - 4)
  if retCode == 0x00000103'u32: return
  if retCode != 0 and retCode != 0xEA'u32: return
  if stub.len < 8: return
  let length  = int(readU16Le(stub, 0))
  let nameRef = readU32Le(stub, 4)
  var off = 8
  if nameRef != 0 and length > 0 and off + 12 <= stub.len:
    let actCount = int(readU32Le(stub, off + 8))
    off += 12
    if off + actCount * 2 <= stub.len:
      let rawUtf = stub[off ..< off + actCount * 2]
      var i = 0
      while i + 1 < rawUtf.len:
        let cp = uint32(ord(rawUtf[i])) or (uint32(ord(rawUtf[i+1])) shl 8)
        i += 2
        if cp == 0: break
        if cp < 0x80: result.name.add char(cp)
        elif cp < 0x800:
          result.name.add char(0xC0 or (cp shr 6))
          result.name.add char(0x80 or (cp and 0x3F))
        else:
          result.name.add char(0xE0 or (cp shr 12))
          result.name.add char(0x80 or ((cp shr 6) and 0x3F))
          result.name.add char(0x80 or (cp and 0x3F))
      off += actCount * 2
      while off mod 4 != 0: inc off
  if off + 4 > stub.len: return
  let typeRef = readU32Le(stub, off); off += 4
  if off + 4 > stub.len: return
  let errCode2 = readU32Le(stub, off); off += 4
  if off + 4 > stub.len: return
  result.dataType = readU32Le(stub, off); off += 4
  if off + 12 > stub.len:
    result.ok = true
    return
  let dataRef = readU32Le(stub, off); off += 4
  if dataRef != 0 and off + 12 <= stub.len:
    let actCount2 = int(readU32Le(stub, off + 8))
    off += 12
    if off + actCount2 <= stub.len:
      result.data = stub[off ..< off + actCount2]
  result.ok = true

proc ndrWstr(s: string): string =
  let utf = smb.toUtf16Le(s) & "\x00\x00"
  let count = uint32(utf.len div 2)
  result.addU32Le count
  result.addU32Le 0'u32
  result.addU32Le count
  result.add utf

proc tryStartRemoteRegistry(ctx: smb.SmbRpcCtx): Future[bool] {.async.} =
  let pipe = await smb.openSmbPipe(ctx, "svcctl")
  if not pipe.attempted or pipe.status != 0: return false
  var cid = 200'u32
  let bindBytes = smb.buildDceRpcBind(ScmrUuidBytes, 2'u16, 0'u16, cid)
  let bindAck = await smb.rpcBindPipe(ctx, pipe, bindBytes)
  if not bindAck.attempted: return false
  inc cid

  var scmStub = ""
  scmStub.addU32Le 0'u32
  scmStub.addU32Le 0'u32
  scmStub.addU32Le 0xF003F'u32
  let scmResp = await smb.rpcCall(ctx, pipe, 15'u16, scmStub, cid); inc cid
  if scmResp.len < 24: return false
  let scmStatus = readU32Le(scmResp, 20)
  if scmStatus != 0: return false
  let scmHandle = scmResp[0 ..< 20]

  var svcStub = ""
  svcStub.add scmHandle
  svcStub.addU32Le 0x00020001'u32
  svcStub.add ndrWstr("RemoteRegistry")
  while svcStub.len mod 4 != 0: svcStub.add char(0)
  svcStub.addU32Le 0x0014'u32
  let svcResp = await smb.rpcCall(ctx, pipe, 16'u16, svcStub, cid); inc cid
  if svcResp.len < 24: return false
  let svcStatus = readU32Le(svcResp, 20)
  if svcStatus != 0: return false
  let svcHandle = svcResp[0 ..< 20]

  var qStub = ""
  qStub.add svcHandle
  let qResp = await smb.rpcCall(ctx, pipe, 6'u16, qStub, cid); inc cid
  if qResp.len >= 32:
    let state = readU32Le(qResp, 4)
    if state != ServiceStopped:
      return true

  var startStub = ""
  startStub.add svcHandle
  startStub.addU32Le 0'u32
  startStub.addU32Le 0'u32
  discard await smb.rpcCall(ctx, pipe, 19'u16, startStub, cid); inc cid

  await sleepAsync(1500)
  result = true

type RrpSession* = ref object
  ctx*: smb.SmbRpcCtx
  pipe*: smb.SmbPipeInfo
  callId*: uint32
  hklm*: string
  ok*: bool
  error*: string
  lastStatus*: uint32

proc newRrpSession*(ctx: smb.SmbRpcCtx): RrpSession =
  RrpSession(ctx: ctx, callId: 100)

proc call*(s: RrpSession; opnum: uint16; stub: string): Future[string] {.async.} =
  let cid = s.callId
  inc s.callId
  result = await smb.rpcCall(s.ctx, s.pipe, opnum, stub, cid)

proc connect*(s: RrpSession): Future[bool] {.async.} =
  s.pipe = await smb.openSmbPipe(s.ctx, "winreg")
  if not s.pipe.attempted or s.pipe.status != 0:
    let started = await tryStartRemoteRegistry(s.ctx)
    s.pipe = await smb.openSmbPipe(s.ctx, "winreg")
  if not s.pipe.attempted or s.pipe.status != 0:
    s.error = "cannot open \\pipe\\winreg (status 0x" & s.pipe.status.toHex(8) & ")"
    return false
  let bindAck = await smb.rpcBindPipe(s.ctx, s.pipe, buildDceRpcBindRrp(1'u32))
  if not bindAck.attempted:
    s.error = "winreg bind failed"
    return false
  let resp = await s.call(2'u16, buildOpenHklm())
  s.hklm = parseHKey(resp)
  if s.hklm.len == 0:
    s.error = "OpenLocalMachine failed"
    return false
  s.ok = true
  result = true

proc openKey*(s: RrpSession; path: string): Future[string] {.async.} =
  let stub = buildOpenKey(s.hklm, path)
  let resp = await s.call(15'u16, stub)
  result = parseHKeyResponse(resp)

proc openSubKey*(s: RrpSession; hKey: string; subPath: string): Future[string] {.async.} =
  let stub = buildOpenKey(hKey, subPath)
  let resp = await s.call(15'u16, stub)
  result = parseHKeyResponse(resp)

proc closeKey*(s: RrpSession; hKey: string): Future[void] {.async.} =
  discard await s.call(5'u16, buildCloseKey(hKey))

proc queryClass*(s: RrpSession; hKey: string): Future[string] {.async.} =
  let resp = await s.call(16'u16, buildQueryInfoKey(hKey))
  result = parseQueryInfoKeyClass(resp)

proc queryValue*(s: RrpSession; hKey: string; name: string): Future[tuple[dataType: uint32; data: string; ok: bool; errorCode: uint32]] {.async.} =
  var dataLen = 512'u32
  s.lastStatus = 0
  for _ in 0 ..< 7:
    let resp = await s.call(17'u16, buildQueryValue(hKey, name, dataLen))
    let parsed = parseQueryValue(resp)
    s.lastStatus = parsed.errorCode
    result.errorCode = parsed.errorCode
    if parsed.ok:
      result.dataType = parsed.dataType
      result.data = parsed.data
      result.ok = true
      return
    if parsed.errorCode != 0xEA'u32:
      return
    let nextLen =
      if parsed.needed > dataLen: parsed.needed
      else: dataLen * 2
    if nextLen <= dataLen or nextLen > 32768'u32:
      return
    dataLen = nextLen

proc enumKeys*(s: RrpSession; hKey: string): Future[seq[string]] {.async.} =
  var idx = 0'u32
  while true:
    let resp = await s.call(9'u16, buildEnumKey(hKey, idx))
    let parsed = parseEnumKey(resp)
    if not parsed.ok: break
    if parsed.name.len > 0:
      result.add parsed.name
    inc idx

proc enumValues*(s: RrpSession; hKey: string): Future[seq[string]] {.async.} =
  var idx = 0'u32
  while true:
    let resp = await s.call(10'u16, buildEnumValue(hKey, idx))
    let parsed = parseEnumValue(resp)
    if not parsed.ok: break
    if parsed.name.len > 0:
      result.add parsed.name
    inc idx

proc queryValueData*(s: RrpSession; hKey: string; name: string): Future[string] {.async.} =
  let r = await s.queryValue(hKey, name)
  if r.ok: result = r.data

proc readKeyData*(s: RrpSession; path: string; valueName: string): Future[string] {.async.} =
  let hk = await s.openKey(path)
  if hk.len == 0: return ""
  result = await s.queryValueData(hk, valueName)
  await s.closeKey(hk)

proc saveKey*(s: RrpSession; path, fileName: string): Future[uint32] {.async.} =
  let stub = buildOpenKey(s.hklm, path)
  let openResp = await s.call(15'u16, stub)
  let openStatus = parseHKeyStatus(openResp)
  if openStatus != 0:
    return openStatus
  let hk = parseHKey(openResp)
  if hk.len == 0:
    return 0xffffffff'u32
  let resp = await s.call(20'u16, buildSaveKey(hk, fileName))
  result = parseStatus(resp)
  await s.closeKey(hk)
