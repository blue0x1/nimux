import std/[asyncdispatch, asyncnet, net, strutils, md5]

import ../../core/scanner as scannercore
import ../../core/proxy as netproxy
import ../smb/client as smbntlm
import ../kerberos/gssapi as krb

const
  PduBind*       = 11'u8
  PduBindAck*    = 12'u8
  PduBindNak*    = 13'u8
  PduAlter*      = 14'u8
  PduAlterResp*  = 15'u8
  PduAuth3*      = 16'u8
  PduRequest*    = 0'u8
  PduResponse*   = 2'u8
  PduFault*      = 3'u8

  PfcFirstFrag* = 0x01'u8
  PfcLastFrag*  = 0x02'u8
  PfcSupportHeaderSign* = 0x04'u8

  AuthTypeNtlm*  = 10'u8
  AuthLevelPktConnect* = 2'u8
  AuthLevelPktIntegrity* = 5'u8
  AuthLevelPktPrivacy* = 6'u8

  NdrUuidBytes* = [
    byte 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
  ]
  EpmUuidBytes* = [
    byte 0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
    0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa
  ]
  EpmVersionMajor* = 3'u16
  EpmVersionMinor* = 0'u16

const NtlmSspNegotiateFlags*: uint32 =
  0x00000001'u32 or 0x00000004'u32 or 0x00000010'u32 or 0x00000020'u32 or
  0x00000200'u32 or 0x00008000'u32 or 0x00080000'u32 or 0x00800000'u32 or
  0x02000000'u32 or 0x20000000'u32 or 0x40000000'u32 or 0x80000000'u32

type Rc4State* = object
  s: array[256, uint8]
  i, j: uint8

proc rc4Init*(key: string): Rc4State =
  for k in 0 ..< 256:
    result.s[k] = uint8(k)
  var j: uint8 = 0
  for k in 0 ..< 256:
    j = j + result.s[k] + uint8(ord(key[k mod key.len]))
    swap(result.s[k], result.s[int(j)])

proc rc4Stream*(state: var Rc4State; data: string): string =
  result = newString(data.len)
  for k in 0 ..< data.len:
    state.i = state.i + 1
    state.j = state.j + state.s[int(state.i)]
    swap(state.s[int(state.i)], state.s[int(state.j)])
    let keyByte = state.s[(int(state.s[int(state.i)]) +
                            int(state.s[int(state.j)])) and 0xff]
    result[k] = chr(ord(data[k]) xor int(keyByte))

proc md5Bytes(data: string): string =
  let digest = toMd5(data)
  result = newString(16)
  for i in 0 ..< 16: result[i] = chr(digest[i])

proc hmacMd5*(key, data: string): string =
  var k = key
  if k.len > 64: k = md5Bytes(k)
  while k.len < 64: k.add char(0)
  var ipad = newString(64)
  var opad = newString(64)
  for i in 0 ..< 64:
    ipad[i] = chr(ord(k[i]) xor 0x36)
    opad[i] = chr(ord(k[i]) xor 0x5c)
  result = md5Bytes(opad & md5Bytes(ipad & data))

proc signKey*(exportedSessionKey: string; isClient: bool): string =
  let constant =
    if isClient: "session key to client-to-server signing key magic constant\x00"
    else: "session key to server-to-client signing key magic constant\x00"
  md5Bytes(exportedSessionKey & constant)

proc sealKey*(exportedSessionKey: string; isClient: bool;
              negotiatedFlags: uint32): string =
  let constant =
    if isClient: "session key to client-to-server sealing key magic constant\x00"
    else: "session key to server-to-client sealing key magic constant\x00"
  md5Bytes(exportedSessionKey & constant)

proc le32(value: uint32): string =
  result = newString(4)
  result[0] = chr(int(value and 0xff))
  result[1] = chr(int((value shr 8) and 0xff))
  result[2] = chr(int((value shr 16) and 0xff))
  result[3] = chr(int((value shr 24) and 0xff))

type NtlmSecCtx* = object
  sessionKey*: string
  signKeyOut*: string
  signKeyIn*: string
  sealStateOut*: Rc4State
  sealStateIn*: Rc4State
  seqNumOut*: uint32
  seqNumIn*: uint32

proc patchType3WithKeyExch*(type3Token, sessionBaseKey,
                            exportedSessionKey: string): string =
  if type3Token.len < 64:
    raise newException(ValueError, "Type-3 token too short to patch")
  if sessionBaseKey.len != 16 or exportedSessionKey.len != 16:
    raise newException(ValueError, "session keys must each be 16 bytes")
  var rc4 = rc4Init(sessionBaseKey)
  let encryptedSessionKey = rc4Stream(rc4, exportedSessionKey)
  result = type3Token
  let payloadOffset = uint32(type3Token.len)
  let len16 = uint16(encryptedSessionKey.len)
  proc setU16(s: var string; o: int; v: uint16) =
    s[o]   = chr(int(v) and 0xff)
    s[o+1] = chr((int(v) shr 8) and 0xff)
  proc setU32(s: var string; o: int; v: uint32) =
    s[o]   = chr(int(v) and 0xff)
    s[o+1] = chr((int(v) shr 8) and 0xff)
    s[o+2] = chr((int(v) shr 16) and 0xff)
    s[o+3] = chr((int(v) shr 24) and 0xff)
  setU16(result, 52, len16)
  setU16(result, 54, len16)
  setU32(result, 56, payloadOffset)
  let clientFlags: uint32 =
    0x00000001'u32 or 0x00000004'u32 or 0x00000010'u32 or 0x00000020'u32 or
    0x00000200'u32 or 0x00008000'u32 or 0x00080000'u32 or 0x00800000'u32 or
    0x02000000'u32 or 0x20000000'u32 or 0x40000000'u32 or 0x80000000'u32
  setU32(result, 60, clientFlags)
  result.add encryptedSessionKey

proc newNtlmSecCtx*(exportedSessionKey: string;
                    negotiatedFlags: uint32 = NtlmSspNegotiateFlags): NtlmSecCtx =
  result.sessionKey = exportedSessionKey
  result.signKeyOut = signKey(exportedSessionKey, isClient = true)
  result.signKeyIn  = signKey(exportedSessionKey, isClient = false)
  let outSeal = sealKey(exportedSessionKey, isClient = true, negotiatedFlags)
  let inSeal  = sealKey(exportedSessionKey, isClient = false, negotiatedFlags)
  result.sealStateOut = rc4Init(outSeal)
  result.sealStateIn  = rc4Init(inSeal)
  result.seqNumOut = 0
  result.seqNumIn = 0

proc signMessage*(ctx: var NtlmSecCtx; message: string;
                  forVerify = false; seqOverride = uint32.high): string =
  let seq = if seqOverride != uint32.high: seqOverride else: ctx.seqNumOut
  let key = if forVerify: ctx.signKeyIn else: ctx.signKeyOut
  let mac = hmacMd5(key, le32(seq) & message)
  let mac8 = mac[0 ..< 8]
  let sealed8 =
    if forVerify: rc4Stream(ctx.sealStateIn, mac8)
    else: rc4Stream(ctx.sealStateOut, mac8)
  result = "\x01\x00\x00\x00" & sealed8 & le32(seq)

proc sealAndSign*(ctx: var NtlmSecCtx; encryptRange: string;
                  macInput: string): tuple[sealed, signature: string] =
  result.sealed = rc4Stream(ctx.sealStateOut, encryptRange)
  let mac = hmacMd5(ctx.signKeyOut, le32(ctx.seqNumOut) & macInput)
  let mac8 = mac[0 ..< 8]
  let sealed8 = rc4Stream(ctx.sealStateOut, mac8)
  result.signature = "\x01\x00\x00\x00" & sealed8 & le32(ctx.seqNumOut)
  inc ctx.seqNumOut

proc signOnly*(ctx: var NtlmSecCtx; macInput: string): string =
  let mac = hmacMd5(ctx.signKeyOut, le32(ctx.seqNumOut) & macInput)
  let mac8 = mac[0 ..< 8]
  let sealed8 = rc4Stream(ctx.sealStateOut, mac8)
  result = "\x01\x00\x00\x00" & sealed8 & le32(ctx.seqNumOut)
  inc ctx.seqNumOut

proc unsealAndVerify*(ctx: var NtlmSecCtx; sealedRange, signature: string;
                      macPrefix = ""; macSuffix = ""): tuple[ok: bool; plain: string] =
  result.plain = rc4Stream(ctx.sealStateIn, sealedRange)
  if signature.len != 16:
    inc ctx.seqNumIn
    return
  let mac = hmacMd5(ctx.signKeyIn, le32(ctx.seqNumIn) & macPrefix & result.plain & macSuffix)
  let mac8 = mac[0 ..< 8]
  let expectedSealed = rc4Stream(ctx.sealStateIn, mac8)
  let receivedSealed = signature[4 ..< 12]
  result.ok = expectedSealed == receivedSealed
  inc ctx.seqNumIn

type
  DceRpcClient* = ref object
    socket*: AsyncSocket
    host*: string
    timeoutMs*: int
    callId*: uint32
    sec*: NtlmSecCtx
    kc*: krb.KerberosContext
    useKerb*: bool
    sealed*: bool
    contextId*: uint16
    maxXmitFrag*: uint16
    maxRecvFrag*: uint16
    authContextId*: uint32
    authLevel*: uint8

proc addU16Le*(d: var string; v: uint16) =
  d.add char(int(v) and 0xff); d.add char((int(v) shr 8) and 0xff)
proc addU32Le*(d: var string; v: uint32) =
  d.add char(int(v) and 0xff)
  d.add char((int(v) shr 8) and 0xff)
  d.add char((int(v) shr 16) and 0xff)
  d.add char((int(v) shr 24) and 0xff)
proc readU16Le*(d: string; o: int): uint16 =
  uint16(ord(d[o])) or (uint16(ord(d[o+1])) shl 8)
proc readU32Le*(d: string; o: int): uint32 =
  uint32(ord(d[o])) or (uint32(ord(d[o+1])) shl 8) or
    (uint32(ord(d[o+2])) shl 16) or (uint32(ord(d[o+3])) shl 24)

proc uuidBytes*(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b: result[i] = chr(int(x))

proc pduHeader(pduType: uint8; pfcFlags: uint8; fragLen: uint16;
               authLen: uint16; callId: uint32): string =
  result.add char(5)
  result.add char(0)
  result.add char(int(pduType))
  result.add char(int(pfcFlags))
  result.add "\x10\x00\x00\x00"
  result.addU16Le fragLen
  result.addU16Le authLen
  result.addU32Le callId

proc authVerifier(authType, authLevel: uint8; padLen: uint8;
                  contextId: uint32; token: string): string =
  result.add char(int(authType))
  result.add char(int(authLevel))
  result.add char(int(padLen))
  result.add char(0)
  result.addU32Le contextId
  result.add token

proc buildBindPdu*(interfaceUuid: openArray[byte]; majorVer, minorVer: uint16;
                   callId: uint32; ntlmToken: string;
                   authContextId: uint32 = 1;
                   maxXmit = 5840'u16;
                   authLevel: uint8 = AuthLevelPktPrivacy;
                   authType: uint8 = AuthTypeNtlm): string =
  let ifaceUuid = uuidBytes(interfaceUuid)
  let ndrUuid = uuidBytes(NdrUuidBytes)
  var body = ""
  body.addU16Le maxXmit
  body.addU16Le maxXmit
  body.addU32Le 0
  body.add char(1)
  body.add "\x00\x00\x00"
  body.addU16Le 0
  body.add char(1)
  body.add char(0)
  body.add ifaceUuid
  body.addU16Le majorVer
  body.addU16Le minorVer
  body.add ndrUuid
  body.addU32Le 2
  let authVerLen = uint16(ntlmToken.len)
  let authVerifierBytes = authVerifier(authType, authLevel,
                                       0, authContextId, ntlmToken)
  let fragLen = uint16(16 + body.len + authVerifierBytes.len)
  result.add pduHeader(PduBind, PfcFirstFrag or PfcLastFrag,
                       fragLen, authVerLen, callId)
  result.add body
  result.add authVerifierBytes

proc buildAlterContextPdu*(interfaceUuid: seq[byte]; majorVer, minorVer: uint16;
                           callId: uint32; ntlmToken: string;
                           contextId: uint16; authContextId: uint32 = 1;
                           maxXmit = 5840'u16;
                           authLevel: uint8 = AuthLevelPktPrivacy;
                           authType: uint8 = AuthTypeNtlm): string =
  let ifaceUuid = uuidBytes(interfaceUuid)
  let ndrUuid = uuidBytes(NdrUuidBytes)
  var body = ""
  body.addU16Le maxXmit
  body.addU16Le maxXmit
  body.addU32Le 0
  body.add char(1)
  body.add "\x00\x00\x00"
  body.addU16Le contextId
  body.add char(1)
  body.add char(0)
  body.add ifaceUuid
  body.addU16Le majorVer
  body.addU16Le minorVer
  body.add ndrUuid
  body.addU32Le 2
  let authVerLen = uint16(ntlmToken.len)
  let authBytes = authVerifier(authType, authLevel, 0,
                               authContextId, ntlmToken)
  let fragLen = uint16(16 + body.len + authBytes.len)
  result.add pduHeader(PduAlter, PfcFirstFrag or PfcLastFrag,
                       fragLen, authVerLen, callId)
  result.add body
  result.add authBytes

proc buildAuth3Pdu*(callId: uint32; ntlmType3: string;
                    authContextId: uint32 = 1;
                    authLevel: uint8 = AuthLevelPktPrivacy): string =
  let pad = "\x00\x00\x00\x00"
  let authVerLen = uint16(ntlmType3.len)
  let authVerifierBytes = authVerifier(AuthTypeNtlm, authLevel,
                                       0, authContextId, ntlmType3)
  let fragLen = uint16(16 + pad.len + authVerifierBytes.len)
  result.add pduHeader(PduAuth3, PfcFirstFrag or PfcLastFrag,
                       fragLen, authVerLen, callId)
  result.add pad
  result.add authVerifierBytes

proc nextCallId*(c: DceRpcClient): uint32 =
  result = c.callId
  inc c.callId

proc sendRequestFragment*(c: DceRpcClient; opnum: uint16; stub: string;
                          objectUuid: string; firstFrag, lastFrag: bool;
                          callId: uint32): Future[void] {.async.} =
  var stubPadded = stub
  while stubPadded.len mod 4 != 0: stubPadded.add char(0)
  let padLen = uint8(stubPadded.len - stub.len)
  let hasObject = objectUuid.len == 16 and firstFrag
  var reqHdr = ""
  reqHdr.addU32Le uint32(stubPadded.len)
  reqHdr.addU16Le c.contextId
  reqHdr.addU16Le opnum
  if hasObject: reqHdr.add objectUuid
  var pfcFlags: uint8 = 0
  if firstFrag: pfcFlags = pfcFlags or PfcFirstFrag
  if lastFrag: pfcFlags = pfcFlags or PfcLastFrag
  if hasObject: pfcFlags = pfcFlags or 0x80'u8
  if c.authLevel == 0:
    let fragLen = uint16(16 + reqHdr.len + stubPadded.len)
    var pkt = pduHeader(PduRequest, pfcFlags, fragLen, 0, callId)
    pkt.add reqHdr
    pkt.add stubPadded
    await c.socket.send(pkt)
    return
  if c.useKerb:
    let wrapped = c.kc.wrapDce(stubPadded)
    let authLen = uint16(wrapped.header.len)
    let fragLen = uint16(16 + reqHdr.len + wrapped.encrypted.len + 8 + int(authLen))
    let pduCommonHdr = pduHeader(PduRequest, pfcFlags, fragLen, authLen, callId)
    var secPreamble = ""
    secPreamble.add char(0x09)
    secPreamble.add char(int(c.authLevel))
    secPreamble.add char(int(padLen))
    secPreamble.add char(0)
    secPreamble.addU32Le c.authContextId
    var pkt = pduCommonHdr
    pkt.add reqHdr
    pkt.add wrapped.encrypted
    pkt.add secPreamble
    pkt.add wrapped.header
    await c.socket.send(pkt)
    return
  let signatureLen = 16'u16
  let fragLen = uint16(16 + reqHdr.len + stubPadded.len + 8 + int(signatureLen))
  let pduCommonHdr = pduHeader(PduRequest, pfcFlags, fragLen, signatureLen, callId)
  var secPreamble = ""
  secPreamble.add char(int(AuthTypeNtlm))
  secPreamble.add char(int(c.authLevel))
  secPreamble.add char(int(padLen))
  secPreamble.add char(0)
  secPreamble.addU32Le c.authContextId
  let messageToSign = pduCommonHdr & reqHdr & stubPadded & secPreamble
  var pkt = pduCommonHdr
  pkt.add reqHdr
  var signature: string
  if c.authLevel == AuthLevelPktIntegrity:
    pkt.add stubPadded
    signature = signOnly(c.sec, messageToSign)
  else:
    let sealed = sealAndSign(c.sec, stubPadded, messageToSign)
    pkt.add sealed.sealed
    signature = sealed.signature
  pkt.add secPreamble
  pkt.add signature
  await c.socket.send(pkt)

proc sendRequest*(c: DceRpcClient; opnum: uint16; stub: string;
                  objectUuid = ""): Future[void] {.async.} =
  let maxStubPerFrag = int(c.maxXmitFrag) - 16 - 24 - 8 - 16
  let callId = c.nextCallId()
  if stub.len <= maxStubPerFrag:
    await c.sendRequestFragment(opnum, stub, objectUuid, true, true, callId)
    return
  var offset = 0
  while offset < stub.len:
    let take = min(maxStubPerFrag, stub.len - offset)
    let chunk = stub[offset ..< offset + take]
    let isFirst = (offset == 0)
    let isLast = (offset + take >= stub.len)
    await c.sendRequestFragment(opnum, chunk, objectUuid, isFirst, isLast, callId)
    offset += take

proc recvExact(socket: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  while result.len < n:
    let want = n - result.len
    let fut = socket.recv(want)
    if not await withTimeout(fut, timeoutMs):
      return result
    let chunk = await fut
    if chunk.len == 0: return result
    result.add chunk

proc recvPdu*(c: DceRpcClient): Future[tuple[pduType: uint8; pfcFlags: uint8;
                                callId: uint32; body: string;
                                authVerifier: string]] {.async.} =
  let hdr = await recvExact(c.socket, 16, c.timeoutMs)
  if hdr.len < 16: return
  result.pduType = uint8(ord(hdr[2]))
  result.pfcFlags = uint8(ord(hdr[3]))
  let fragLen = readU16Le(hdr, 8)
  let authLen = readU16Le(hdr, 10)
  result.callId = readU32Le(hdr, 12)
  let bodyLen = int(fragLen) - 16
  let rest = await recvExact(c.socket, bodyLen, c.timeoutMs)
  let authPreambleLen = if authLen > 0'u16: 8 else: 0
  let bodyEnd = bodyLen - int(authLen) - authPreambleLen
  if bodyEnd < 0: return
  result.body = rest[0 ..< bodyEnd]
  if authLen > 0'u16:
    result.authVerifier = rest[bodyEnd + authPreambleLen ..< rest.len]

proc recvResponse*(c: DceRpcClient): Future[tuple[ok: bool; stub: string;
                                       faultStatus: uint32]] {.async.} =
  while true:
    let pdu = await c.recvPdu()
    if pdu.pduType == PduFault:
      if pdu.body.len >= 12:
        result.faultStatus = readU32Le(pdu.body, 8)
      return (false, "", result.faultStatus)
    if pdu.pduType != PduResponse:
      return (false, "", 0xffffffff'u32)
    if pdu.body.len < 8: return
    let rawStub = pdu.body[8 ..< pdu.body.len]
    var plain: string
    if c.authLevel == 0:
      plain = rawStub
    elif c.useKerb:
      let expectedTokenLen = c.kc.getDce2TokenSize(rawStub.len)
      let token =
        if expectedTokenLen > 0 and expectedTokenLen < pdu.authVerifier.len:
          pdu.authVerifier[0 ..< expectedTokenLen]
        else:
          pdu.authVerifier
      plain = c.kc.unwrapDce(token, rawStub)
      if plain.len == 0: plain = rawStub
    elif c.authLevel == AuthLevelPktIntegrity:
      discard unsealAndVerify(c.sec, "", pdu.authVerifier)
      plain = rawStub
    else:
      let unsealed = unsealAndVerify(c.sec, rawStub, pdu.authVerifier)
      plain = unsealed.plain
    result.stub.add plain
    if (pdu.pfcFlags and PfcLastFrag) != 0: break
  result.ok = true

proc connectAndBind*(host: string; port, timeoutMs: int;
                    interfaceUuid: seq[byte]; majorVer, minorVer: uint16;
                    cred: smbntlm.SmbCredential;
                    authLevel: uint8 = AuthLevelPktPrivacy): Future[DceRpcClient] {.async.} =
  result = DceRpcClient(
    socket: scannercore.newTcpAsyncSocket(host),
    host: host,
    timeoutMs: timeoutMs,
    callId: 1, authContextId: 1, contextId: 0,
    maxXmitFrag: 5840, maxRecvFrag: 5840,
    sealed: false,
    authLevel: authLevel
  )
  let connected = await netproxy.connectTcpResolved(result.socket, host, port, timeoutMs)
  if not connected:
    raise newException(IOError, "dcerpc: connect timeout to " & host & ":" & $port)
  proc buildDceRpcNtlmType1(): string =
    const flags: uint32 =
      0x00000001'u32 or 0x00000004'u32 or 0x00000010'u32 or 0x00000020'u32 or
      0x00000200'u32 or 0x00008000'u32 or 0x00080000'u32 or 0x00800000'u32 or
      0x02000000'u32 or 0x20000000'u32 or 0x40000000'u32 or 0x80000000'u32
    result.add "NTLMSSP\x00"
    result.add char(1); result.add char(0); result.add char(0); result.add char(0)
    result.add char(int(flags and 0xff))
    result.add char(int((flags shr 8) and 0xff))
    result.add char(int((flags shr 16) and 0xff))
    result.add char(int((flags shr 24) and 0xff))
    for _ in 0 ..< 16: result.add char(0)
    result.add "\x0a\x00\xa7\x3a\x00\x00\x00\x0f"
  let type1 = buildDceRpcNtlmType1()
  let bindCallId = result.nextCallId()
  let bindPdu = buildBindPdu(interfaceUuid, majorVer, minorVer,
                             bindCallId, type1, 1, 5840'u16, authLevel)
  await result.socket.send(bindPdu)
  let bindAck = await result.recvPdu()
  if bindAck.pduType != PduBindAck:
    raise newException(IOError, "dcerpc: bind rejected (pdu_type=" &
      $bindAck.pduType & ")")
  result.maxXmitFrag = readU16Le(bindAck.body, 0)
  result.maxRecvFrag = readU16Le(bindAck.body, 2)
  block parseResults:
    if bindAck.body.len < 10: break parseResults
    let secAddrLen = int(readU16Le(bindAck.body, 8))
    var off = 10 + secAddrLen
    while off mod 4 != 0: inc off
    if off + 4 > bindAck.body.len: break parseResults
    let numResults = int(uint8(bindAck.body[off]))
    off += 4
    for i in 0 ..< numResults:
      if off + 24 > bindAck.body.len: break
      let res = readU16Le(bindAck.body, off)
      let reason = readU16Le(bindAck.body, off + 2)
      if res != 0:
        raise newException(IOError,
          "dcerpc: BIND context " & $i & " rejected (result=" & $res &
          " reason=0x" & toHex(reason, 4) & ") — interface UUID not registered")
      off += 24
  if bindAck.authVerifier.len < 8:
    raise newException(IOError, "dcerpc: bind_ack has no NTLM challenge")
  let challenge = smbntlm.parseNtlmChallenge(bindAck.authVerifier)
  if not challenge.offered:
    raise newException(IOError, "dcerpc: server did not send NTLMSSP challenge")
  var authCred = cred
  if authCred.domain.len == 0 and challenge.targetName.len > 0:
    authCred.domain = challenge.targetName
  let auth = smbntlm.buildNtlmType3WithSessionKey(authCred, challenge,
    smbntlm.randomBytes(8))
  let exportedSessionKey = smbntlm.randomBytes(16)
  let patchedToken = patchType3WithKeyExch(
    auth.token, auth.sessionBaseKey, exportedSessionKey)
  result.sec = newNtlmSecCtx(exportedSessionKey)
  result.sealed = true
  let auth3 = buildAuth3Pdu(bindCallId, patchedToken, 1, authLevel)
  await result.socket.send(auth3)

proc derTlvDce(tag: byte; value: string): string =
  result.add char(int(tag))
  let n = value.len
  if n < 128:
    result.add char(n)
  elif n < 256:
    result.add char(0x81); result.add char(n)
  else:
    result.add char(0x82); result.add char((n shr 8) and 0xff); result.add char(n and 0xff)
  result.add value

proc derOidDce(bytes: openArray[byte]): string =
  result.add char(0x06); result.add char(bytes.len)
  for b in bytes: result.add char(int(b))

proc derLenDce(data: string; offset: int): tuple[value: int; next: int] =
  if offset >= data.len: return (0, offset)
  let b = uint8(ord(data[offset]))
  if (b and 0x80) == 0:
    return (int(b), offset + 1)
  let nb = int(b and 0x7f)
  var v = 0
  for i in 0 ..< nb:
    if offset + 1 + i < data.len:
      v = (v shl 8) or int(uint8(ord(data[offset + 1 + i])))
  return (v, offset + 1 + nb)

proc spnegoExtractApReq(gssToken: string): string =
  var apReq = gssToken
  if apReq.len > 0 and apReq[0] == '\x60':
    let (_, afterOuterLen) = derLenDce(apReq, 1)
    var i = afterOuterLen
    if i < apReq.len and apReq[i] == '\x06':
      let oidLen = if i + 1 < apReq.len: int(uint8(ord(apReq[i + 1]))) else: 0
      i += 2 + oidLen
      if i + 1 < apReq.len and apReq[i] == '\x01' and apReq[i+1] == '\x00':
        i += 2
      apReq = apReq[i .. ^1]
  apReq

proc spnegoKerberosWrap(gssToken: string): string =
  let apReq = spnegoExtractApReq(gssToken)
  let spnegoOid = derOidDce([byte 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
  let msKrb5Oid = derOidDce([byte 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02])
  let krb5Oid  = derOidDce([byte 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02])
  let mechTypes  = derTlvDce(0xa0'u8, derTlvDce(0x30'u8, msKrb5Oid & krb5Oid))
  let mechToken  = derTlvDce(0xa2'u8, derTlvDce(0x04'u8, apReq))
  let negTokenInit = derTlvDce(0xa0'u8, derTlvDce(0x30'u8, mechTypes & mechToken))
  derTlvDce(0x60'u8, spnegoOid & negTokenInit)

proc spnegoExtractResponseToken(spnegoResp: string): string =
  var i = 0
  if i >= spnegoResp.len: return ""
  if spnegoResp[i] != '\xa1': return spnegoResp
  let (_, afterA1) = derLenDce(spnegoResp, i + 1)
  i = afterA1
  if i >= spnegoResp.len or spnegoResp[i] != '\x30': return ""
  let (_, afterSeq) = derLenDce(spnegoResp, i + 1)
  i = afterSeq
  while i < spnegoResp.len:
    let tag = uint8(ord(spnegoResp[i]))
    let (fieldLen, afterFieldLen) = derLenDce(spnegoResp, i + 1)
    let fieldStart = afterFieldLen
    let fieldEnd = fieldStart + fieldLen
    if tag == 0xa2'u8:
      if fieldStart < spnegoResp.len and spnegoResp[fieldStart] == '\x04':
        let (innerLen, afterInnerLen) = derLenDce(spnegoResp, fieldStart + 1)
        return spnegoResp[afterInnerLen ..< afterInnerLen + innerLen]
    i = fieldEnd
  ""

proc connectAndBindKerb*(host: string; port, timeoutMs: int;
                         interfaceUuid: seq[byte]; majorVer, minorVer: uint16;
                         domain: string;
                         authLevel: uint8 = AuthLevelPktPrivacy): Future[DceRpcClient] {.async.} =
  result = DceRpcClient(
    socket: scannercore.newTcpAsyncSocket(host),
    host: host,
    timeoutMs: timeoutMs,
    callId: 1, authContextId: 1, contextId: 0,
    maxXmitFrag: 5840, maxRecvFrag: 5840,
    sealed: true,
    authLevel: authLevel,
    useKerb: true
  )
  let connected = await netproxy.connectTcpResolved(result.socket, host, port, timeoutMs)
  if not connected:
    raise newException(IOError, "dcerpc: connect timeout to " & host & ":" & $port)
  let kc = krb.newKerberosContext("ldap", host, domain)
  result.kc = kc
  let tok = kc.stepWithFlags("", 0x3e'u32)
  if tok.token.len == 0:
    raise newException(IOError, "dcerpc: Kerberos produced no AP-REQ token")
  let spnegoTok = spnegoKerberosWrap(tok.token)
  let bindCallId = result.nextCallId()
  let bindPdu = buildBindPdu(interfaceUuid, majorVer, minorVer,
                             bindCallId, spnegoTok, 1, 5840'u16, authLevel,
                             authType = 0x09'u8)
  await result.socket.send(bindPdu)
  let bindAck = await result.recvPdu()
  if bindAck.pduType != PduBindAck:
    raise newException(IOError, "dcerpc: Kerberos bind rejected (pdu_type=" &
      $bindAck.pduType & ")")
  result.maxXmitFrag = readU16Le(bindAck.body, 0)
  result.maxRecvFrag = readU16Le(bindAck.body, 2)
  if bindAck.authVerifier.len > 0:
    let apRep = spnegoExtractResponseToken(bindAck.authVerifier)
    if apRep.len > 0:
      discard kc.stepWithFlags(apRep, 0x3e'u32)

proc call*(c: DceRpcClient; opnum: uint16; stub: string;
           objectUuid = ""): Future[tuple[ok: bool;
                                              stub: string; faultStatus: uint32]] {.async.} =
  await c.sendRequest(opnum, stub, objectUuid)
  return await c.recvResponse()

proc buildDceRpcNtlmType1Pub*(): string =
  const flags: uint32 =
    0x00000001'u32 or 0x00000004'u32 or 0x00000010'u32 or 0x00000020'u32 or
    0x00000200'u32 or 0x00008000'u32 or 0x00080000'u32 or 0x00800000'u32 or
    0x02000000'u32 or 0x20000000'u32 or 0x40000000'u32 or 0x80000000'u32
  result.add "NTLMSSP\x00"
  result.add char(1); result.add char(0); result.add char(0); result.add char(0)
  result.add char(int(flags and 0xff))
  result.add char(int((flags shr 8) and 0xff))
  result.add char(int((flags shr 16) and 0xff))
  result.add char((int(flags) shr 24) and 0xff)
  for _ in 0 ..< 16: result.add char(0)
  result.add "\x0a\x00\xa7\x3a\x00\x00\x00\x0f"

proc alterContext*(c: DceRpcClient; interfaceUuid: seq[byte];
                   majorVer, minorVer: uint16;
                   cred: smbntlm.SmbCredential;
                   newContextId: uint16;
                   authContextId: uint32 = 1): Future[void] {.async.} =
  if c.useKerb:
    let alterCallId = c.nextCallId()
    let alterPdu = buildAlterContextPdu(interfaceUuid, majorVer, minorVer,
      alterCallId, "", newContextId, authContextId, 5840'u16, c.authLevel,
      authType = 0x09'u8)
    await c.socket.send(alterPdu)
    let resp = await c.recvPdu()
    if resp.pduType != PduAlterResp:
      raise newException(IOError, "alter_context (Kerberos) rejected (pdu=" & $resp.pduType & ")")
    c.contextId = newContextId
    return
  let type1 = buildDceRpcNtlmType1Pub()
  let alterCallId = c.nextCallId()
  let alterPdu = buildAlterContextPdu(interfaceUuid, majorVer, minorVer,
    alterCallId, type1, newContextId, authContextId, 5840'u16, c.authLevel)
  await c.socket.send(alterPdu)
  let resp = await c.recvPdu()
  if resp.pduType != PduAlterResp:
    raise newException(IOError, "alter_context rejected (pdu=" & $resp.pduType & ")")
  if resp.authVerifier.len < 8:
    c.contextId = newContextId
    return
  let challenge = smbntlm.parseNtlmChallenge(resp.authVerifier)
  if not challenge.offered:
    c.contextId = newContextId
    return
  var authCred = cred
  if authCred.domain.len == 0 and challenge.targetName.len > 0:
    authCred.domain = challenge.targetName
  let auth = smbntlm.buildNtlmType3WithSessionKey(authCred, challenge,
    smbntlm.randomBytes(8))
  let exportedSessionKey = smbntlm.randomBytes(16)
  let patchedToken = patchType3WithKeyExch(
    auth.token, auth.sessionBaseKey, exportedSessionKey)
  c.sec = newNtlmSecCtx(exportedSessionKey)
  c.authContextId = authContextId
  c.contextId = newContextId
  let auth3 = buildAuth3Pdu(alterCallId, patchedToken, authContextId, c.authLevel)
  await c.socket.send(auth3)

proc close*(c: DceRpcClient) =
  try: c.socket.close() except CatchableError: discard

proc addU16Be(d: var string; v: uint16) =
  d.add char((int(v) shr 8) and 0xff); d.add char(int(v) and 0xff)

proc buildEpmTower(interfaceUuid: openArray[byte]; majorVer, minorVer: uint16): string =
  proc floor(lhs, rhs: string): string =
    result.addU16Le uint16(lhs.len)
    result.add lhs
    result.addU16Le uint16(rhs.len)
    result.add rhs
  let ndrUuid = uuidBytes(NdrUuidBytes)
  let ifaceUuid = uuidBytes(interfaceUuid)
  var f1Lhs = "\x0d"; f1Lhs.add ifaceUuid; f1Lhs.addU16Le majorVer
  var f1Rhs = ""; f1Rhs.addU16Le minorVer
  var f2Lhs = "\x0d"; f2Lhs.add ndrUuid; f2Lhs.addU16Le 2
  var f2Rhs = ""; f2Rhs.addU16Le 0
  let f3Lhs = "\x0b"; let f3Rhs = "\x00\x00"
  var f4Lhs = "\x07"; var f4Rhs = ""; f4Rhs.addU16Be 135
  let f5Lhs = "\x09"; let f5Rhs = "\x00\x00\x00\x00"
  var floors = ""; floors.addU16Le 5
  floors.add floor(f1Lhs, f1Rhs)
  floors.add floor(f2Lhs, f2Rhs)
  floors.add floor(f3Lhs, f3Rhs)
  floors.add floor(f4Lhs, f4Rhs)
  floors.add floor(f5Lhs, f5Rhs)
  return floors

proc buildEptMapStub(interfaceUuid: openArray[byte]; majorVer, minorVer: uint16): string =
  let tower = buildEpmTower(interfaceUuid, majorVer, minorVer)
  result.addU32Le 1'u32
  result.add "\x00".repeat(16)
  result.addU32Le 2'u32
  result.addU32Le uint32(tower.len)
  result.addU32Le uint32(tower.len)
  result.add tower
  while result.len mod 4 != 0: result.add char(0)
  result.add "\x00".repeat(20)
  result.addU32Le 4'u32

proc parseEptMapResponse(stub: string): seq[int] =
  var i = 0
  if stub.len < 36: return
  i += 20
  let numTowers = int(readU32Le(stub, i)); i += 4
  if numTowers == 0: return
  i += 12 + numTowers * 4
  for t in 0 ..< numTowers:
    if i + 8 > stub.len: return
    discard readU32Le(stub, i); i += 4
    let towerLen = int(readU32Le(stub, i)); i += 4
    if i + towerLen > stub.len: return
    let twr = stub[i ..< i + towerLen]
    i += towerLen
    while i mod 4 != 0: inc i
    var j = 0
    if twr.len < 2: continue
    let floors = int(readU16Le(twr, 0)); j += 2
    for _ in 0 ..< floors:
      if j + 2 > twr.len: break
      let lhsLen = int(readU16Le(twr, j)); j += 2
      if j + lhsLen > twr.len: break
      let lhsFirst = ord(twr[j])
      j += lhsLen
      if j + 2 > twr.len: break
      let rhsLen = int(readU16Le(twr, j)); j += 2
      if j + rhsLen > twr.len: break
      if lhsFirst == 0x07 and rhsLen == 2:
        let port = (ord(twr[j]) shl 8) or ord(twr[j+1])
        result.add port
      j += rhsLen

proc connectAndBindNoAuth*(host: string; port, timeoutMs: int;
                           interfaceUuid: seq[byte]; majorVer, minorVer: uint16): Future[DceRpcClient] {.async.} =
  result = DceRpcClient(
    socket: scannercore.newTcpAsyncSocket(host),
    host: host,
    timeoutMs: timeoutMs,
    callId: 1, authContextId: 0, contextId: 0,
    maxXmitFrag: 5840, maxRecvFrag: 5840,
    sealed: false,
    authLevel: 0
  )
  let connected = await netproxy.connectTcpResolved(result.socket, host, port, timeoutMs)
  if not connected:
    raise newException(IOError, "dcerpc: connect timeout to " & host & ":" & $port)
  let ifaceUuid = uuidBytes(interfaceUuid)
  let ndrUuid = uuidBytes(NdrUuidBytes)
  var body = ""
  body.addU16Le 5840'u16
  body.addU16Le 5840'u16
  body.addU32Le 0
  body.add char(1)
  body.add "\x00\x00\x00"
  body.addU16Le 0
  body.add char(1)
  body.add char(0)
  body.add ifaceUuid
  body.addU16Le majorVer
  body.addU16Le minorVer
  body.add ndrUuid
  body.addU32Le 2
  let fragLen = uint16(16 + body.len)
  var bindPdu = pduHeader(PduBind, PfcFirstFrag or PfcLastFrag, fragLen, 0, result.nextCallId())
  bindPdu.add body
  await result.socket.send(bindPdu)
  let bindAck = await result.recvPdu()
  if bindAck.pduType != PduBindAck:
    raise newException(IOError, "dcerpc: EPM bind rejected (pdu_type=" & $bindAck.pduType & ")")
  result.maxXmitFrag = readU16Le(bindAck.body, 0)
  result.maxRecvFrag = readU16Le(bindAck.body, 2)

proc resolveDynamicPort*(host: string; epmPort, timeoutMs: int;
                        interfaceUuid: seq[byte]; majorVer, minorVer: uint16;
                        cred: smbntlm.SmbCredential): Future[int] {.async.} =
  let c = await connectAndBind(host, epmPort, timeoutMs,
    @EpmUuidBytes, EpmVersionMajor, EpmVersionMinor, cred)
  let stub = buildEptMapStub(interfaceUuid, majorVer, minorVer)
  let r = await c.call(3'u16, stub)
  c.close()
  if not r.ok:
    raise newException(IOError,
      "epm ept_map failed (fault 0x" & r.faultStatus.toHex(8) & ")")
  let ports = parseEptMapResponse(r.stub)
  if ports.len == 0:
    raise newException(IOError, "epm returned no TCP endpoints")
  return ports[0]

proc resolveDynamicPortKerb*(host: string; epmPort, timeoutMs: int;
                            interfaceUuid: seq[byte]; majorVer, minorVer: uint16;
                            domain: string): Future[int] {.async.} =
  let c = await connectAndBindNoAuth(host, epmPort, timeoutMs,
    @EpmUuidBytes, EpmVersionMajor, EpmVersionMinor)
  let stub = buildEptMapStub(interfaceUuid, majorVer, minorVer)
  let r = await c.call(3'u16, stub)
  c.close()
  if not r.ok:
    raise newException(IOError,
      "epm ept_map failed (fault 0x" & r.faultStatus.toHex(8) & ")")
  let ports = parseEptMapResponse(r.stub)
  if ports.len == 0:
    raise newException(IOError, "epm returned no TCP endpoints")
  return ports[0]
