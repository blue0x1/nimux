import std/[asyncdispatch, asyncnet, md5, net, os, random, strutils, times]
import wrappers/openssl
import ../kerberos/gssapi as krb
import ../../core/scanner as scannercore
import ../../core/proxy as netproxy

let smbDebug = getEnv("NIMUX_DEBUG").len > 0

proc dbgDump(label: string; data: string) =
  if not smbDebug or data.len == 0:
    return
  const Hex = "0123456789abcdef"
  var line = label & " (" & $data.len & " bytes):"
  for index, item in data:
    if index mod 16 == 0:
      line.add "\n  "
    line.add Hex[(ord(item) shr 4) and 0xf]
    line.add Hex[ord(item) and 0xf]
    line.add ' '
  stderr.writeLine line

{.passL: "-lcrypto".}

type
  NtlmChallengeInfo* = object
    offered*: bool
    flags*: uint32
    targetName*: string
    targetInfo*: string
    serverChallenge*: string
    serverChallengeHex*: string
    netbiosComputer*: string
    netbiosDomain*: string
    dnsComputer*: string
    dnsDomain*: string
    dnsForest*: string

  SmbCredential* = object
    username*: string
    password*: string
    ntlmHash*: string
    domain*: string
    workstation*: string
    ccache*: string
    krb5Config*: string

  SmbAuthMethod* = enum
    samNtlm, samKerberos

  SmbNegotiateRequest* = object
    dialects*: seq[uint16]
    securityMode*: uint16
    capabilities*: uint32
    messageId*: uint64
    clientGuid*: array[16, byte]

  SmbNegotiateInfo* = object
    dialect*: string
    securityMode*: uint16
    signingEnabled*: bool
    signingRequired*: bool
    capabilities*: uint32
    dfs*: bool
    leasing*: bool
    largeMtu*: bool
    multiChannel*: bool
    persistentHandles*: bool
    directoryLeasing*: bool
    encryption*: bool
    maxTransactSize*: uint32
    maxReadSize*: uint32
    maxWriteSize*: uint32
    serverGuid*: string

  SmbTreeConnectInfo* = object
    attempted*: bool
    connected*: bool
    status*: uint32
    treeId*: uint32
    shareType*: uint8
    shareFlags*: uint32
    capabilities*: uint32
    maximalAccess*: uint32

  SmbPipeInfo* = object
    attempted*: bool
    opened*: bool
    status*: uint32
    fileId*: string

  DceRpcInfo* = object
    attempted*: bool
    bound*: bool
    packetType*: uint8
    callId*: uint32
    ackResult*: uint16
    message*: string

  SmbShareInfo* = object
    name*: string
    typ*: uint32
    comment*: string
    accessProbed*: bool
    accessStatus*: uint32
    maximalAccess*: uint32
    canRead*: bool
    canWrite*: bool

  SmbSessionInfo* = object
    clientName*: string
    userName*: string
    openFiles*: uint32
    activeSeconds*: uint32
    idleSeconds*: uint32

  SmbLoggedOnUser* = object
    userName*: string
    logonDomain*: string
    otherDomains*: string
    logonServer*: string

  SmbDiskInfo* = object
    drive*: string

  SmbDomainInfo* = object
    name*: string
    sid*: string

  SmbDomainUser* = object
    rid*: uint32
    name*: string

  SmbDomainGroup* = object
    rid*: uint32
    name*: string
    kind*: string

  SmbPasswordPolicy* = object
    minPasswordLength*: uint16
    passwordHistory*: uint16
    passwordProperties*: uint32
    maxPasswordAgeDays*: int64
    minPasswordAgeDays*: int64
    lockoutThreshold*: uint16
    lockoutDurationMinutes*: int64
    lockoutWindowMinutes*: int64

  SmbEnumResult*[T] = object
    attempted*: bool
    succeeded*: bool
    status*: uint32
    rpcStatus*: uint32
    message*: string
    entries*: seq[T]

  SmbRidLookup* = object
    rid*: uint32
    name*: string
    domain*: string
    sidType*: uint32

  SmbLocalGroupMember* = object
    sid*: string
    name*: string
    domain*: string
    sidType*: uint32

  SmbEnumRequests* = object
    shares*: bool
    sessions*: bool
    disks*: bool
    loggedOnUsers*: bool
    users*: bool
    groups*: bool
    passwordPolicy*: bool
    ridBrute*: bool
    ridBruteStart*: uint32
    ridBruteEnd*: uint32
    localAdmins*: bool

  SmbProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksSmb*: bool
    status*: uint32
    sessionId*: uint64
    authAttempted*: bool
    authenticated*: bool
    signingEnabled*: bool
    signingApplied*: bool
    adminTree*: SmbTreeConnectInfo
    ipcTree*: SmbTreeConnectInfo
    srvsvcPipe*: SmbPipeInfo
    srvsvcRpc*: DceRpcInfo
    shares*: seq[SmbShareInfo]
    sessions*: SmbEnumResult[SmbSessionInfo]
    disks*: SmbEnumResult[SmbDiskInfo]
    loggedOnUsers*: SmbEnumResult[SmbLoggedOnUser]
    domains*: seq[SmbDomainInfo]
    domainUsers*: SmbEnumResult[SmbDomainUser]
    domainGroups*: SmbEnumResult[SmbDomainGroup]
    passwordPolicy*: SmbEnumResult[SmbPasswordPolicy]
    ridBrute*: SmbEnumResult[SmbRidLookup]
    localAdmins*: SmbEnumResult[SmbLocalGroupMember]
    rdpUsers*: SmbEnumResult[SmbLocalGroupMember]
    dcomUsers*: SmbEnumResult[SmbLocalGroupMember]
    psRemoteUsers*: SmbEnumResult[SmbLocalGroupMember]
    negotiate*: SmbNegotiateInfo
    ntlmChallenge*: NtlmChallengeInfo
    message*: string

const
  Smb2HeaderLen = 64
  Smb2NegotiateRequestLen = 36
  Smb2CommandNegotiate = 0'u16
  Smb2CommandSessionSetup = 1'u16
  Smb2CommandTreeConnect = 3'u16
  Smb2CommandCreate = 5'u16
  Smb2CommandClose = 6'u16
  Smb2CommandRead = 8'u16
  Smb2CommandWrite = 9'u16
  Smb2CommandQueryDirectory = 0x000e'u16
  Smb2SecurityModeSigningEnabled* = 0x0001'u16
  Smb2GlobalCapDfs* = 0x00000001'u32
  Smb2GlobalCapLeasing* = 0x00000002'u32
  Smb2GlobalCapLargeMtu* = 0x00000004'u32
  Smb2GlobalCapMultiChannel* = 0x00000008'u32
  Smb2GlobalCapPersistentHandles* = 0x00000010'u32
  Smb2GlobalCapDirectoryLeasing* = 0x00000020'u32
  Smb2GlobalCapEncryption* = 0x00000040'u32

proc defaultSmbNegotiateRequest*(): SmbNegotiateRequest =
  SmbNegotiateRequest(
    dialects: @[0x0202'u16, 0x0210'u16, 0x0300'u16, 0x0302'u16],
    securityMode: Smb2SecurityModeSigningEnabled,
    capabilities: Smb2GlobalCapEncryption,
    messageId: 0
  )

proc kerberosSmbNegotiateRequest*(): SmbNegotiateRequest =
  result = defaultSmbNegotiateRequest()
  result.dialects = @[0x0210'u16]

proc addU16Le(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc addU64Le(data: var string; value: uint64) =
  for shift in countup(0, 56, 8):
    data.add char((value shr shift) and 0xff)

proc addBytes(data: var string; values: openArray[byte]) =
  for value in values:
    data.add char(value)

proc setU16Le(data: var string; offset: int; value: uint16) =
  data[offset] = char(value and 0xff)
  data[offset + 1] = char((value shr 8) and 0xff)

proc setU32Le(data: var string; offset: int; value: uint32) =
  data[offset] = char(value and 0xff)
  data[offset + 1] = char((value shr 8) and 0xff)
  data[offset + 2] = char((value shr 16) and 0xff)
  data[offset + 3] = char((value shr 24) and 0xff)

proc patchNetbiosLength(data: var string) =
  let payloadLen = data.len - 4
  data[1] = char((payloadLen shr 16) and 0xff)
  data[2] = char((payloadLen shr 8) and 0xff)
  data[3] = char(payloadLen and 0xff)

proc buildSmbNegotiateRequest*(request: SmbNegotiateRequest): string =
  if request.dialects.len == 0:
    raise newException(ValueError, "SMB negotiate needs at least one dialect")
  if request.dialects.len > uint16.high.int:
    raise newException(ValueError, "too many SMB dialects")

  result = newStringOfCap(4 + Smb2HeaderLen + Smb2NegotiateRequestLen + request.dialects.len * 2)
  result.add "\x00\x00\x00\x00"

  result.add "\xfeSMB"
  result.addU16Le Smb2HeaderLen.uint16
  result.addU16Le 0
  result.addU32Le 0
  result.addU16Le Smb2CommandNegotiate
  result.addU16Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU64Le request.messageId
  result.addU32Le 0
  result.addU32Le 0
  result.addU64Le 0
  for _ in 0 ..< 16:
    result.add char(0)

  result.addU16Le Smb2NegotiateRequestLen.uint16
  result.addU16Le request.dialects.len.uint16
  result.addU16Le request.securityMode
  result.addU16Le 0
  result.addU32Le request.capabilities
  for value in request.clientGuid:
    result.add char(value)
  result.addU32Le 0
  result.addU16Le 0
  result.addU16Le 0
  for dialect in request.dialects:
    result.addU16Le dialect

  result.patchNetbiosLength()

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

proc derTlv(tag: byte; value: string): string =
  result.add char(tag)
  result.add derLen(value.len)
  result.add value

proc derOid(values: openArray[byte]): string =
  result.add char(0x06)
  result.add derLen(values.len)
  result.addBytes values

proc buildNtlmType1*(domain = ""; workstation = ""): string =
  const
    ntlmNegotiateUnicode = 0x00000001'u32
    ntlmRequestTarget = 0x00000004'u32
    ntlmNegotiateSign = 0x00000010'u32
    ntlmNegotiateSeal = 0x00000020'u32
    ntlmNegotiateNtlm = 0x00000200'u32
    ntlmNegotiateAlwaysSign = 0x00008000'u32
    ntlmNegotiateExtendedSessionSecurity = 0x00080000'u32
    ntlmNegotiateTargetInfo = 0x00800000'u32
    ntlmNegotiate128 = 0x20000000'u32
    ntlmNegotiateKeyExchange = 0x40000000'u32
    ntlmNegotiate56 = 0x80000000'u32
  let flags = ntlmNegotiateUnicode or ntlmRequestTarget or ntlmNegotiateNtlm or
    ntlmNegotiateSign or ntlmNegotiateSeal or ntlmNegotiateAlwaysSign or
    ntlmNegotiateExtendedSessionSecurity or ntlmNegotiateTargetInfo or
    ntlmNegotiate128 or ntlmNegotiateKeyExchange or ntlmNegotiate56
  let payloadOffset = 32'u32

  result.add "NTLMSSP\0"
  result.addU32Le 1
  result.addU32Le flags
  result.addU16Le domain.len.uint16
  result.addU16Le domain.len.uint16
  result.addU32Le(if domain.len > 0: payloadOffset else: 0'u32)
  result.addU16Le workstation.len.uint16
  result.addU16Le workstation.len.uint16
  result.addU32Le(if workstation.len > 0: payloadOffset + domain.len.uint32 else: 0'u32)
  result.add domain.toUpperAscii()
  result.add workstation.toUpperAscii()

proc spnegoNtlmInit*(ntlmToken: string): string =
  let spnegoOid = derOid([byte 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
  let ntlmOid = derOid([byte 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
  let mechTypes = derTlv(0xa0'u8, derTlv(0x30'u8, ntlmOid))
  let mechToken = derTlv(0xa2'u8, derTlv(0x04'u8, ntlmToken))
  let negTokenInit = derTlv(0xa0'u8, derTlv(0x30'u8, mechTypes & mechToken))
  derTlv(0x60'u8, spnegoOid & negTokenInit)

proc buildSmb2Header(command: uint16; messageId: uint64; sessionId = 0'u64; treeId = 0'u32; creditCharge = 0'u16): string =
  result.add "\xfeSMB"
  result.addU16Le Smb2HeaderLen.uint16
  result.addU16Le creditCharge
  result.addU32Le 0
  result.addU16Le command
  result.addU16Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU64Le messageId
  result.addU32Le 0
  result.addU32Le treeId
  result.addU64Le sessionId
  for _ in 0 ..< 16:
    result.add char(0)

proc buildSmbSessionSetupRequest*(securityBlob: string; messageId = 1'u64): string =
  let securityBufferOffset = Smb2HeaderLen + 24
  result = newStringOfCap(4 + Smb2HeaderLen + 24 + securityBlob.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandSessionSetup, messageId)
  result.addU16Le 25
  result.add char(0)
  result.add char(1)
  result.addU32Le 0
  result.addU32Le 0
  result.addU16Le securityBufferOffset.uint16
  result.addU16Le securityBlob.len.uint16
  result.addU64Le 0
  result.add securityBlob
  result.patchNetbiosLength()

proc buildSmbSessionSetupRequest*(securityBlob: string; messageId, sessionId: uint64): string =
  let securityBufferOffset = Smb2HeaderLen + 24
  result = newStringOfCap(4 + Smb2HeaderLen + 24 + securityBlob.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandSessionSetup, messageId, sessionId,
    creditCharge = 1'u16)
  result.addU16Le 25
  result.add char(0)
  result.add char(1)
  result.addU32Le 0
  result.addU32Le 0
  result.addU16Le securityBufferOffset.uint16
  result.addU16Le securityBlob.len.uint16
  result.addU64Le 0
  result.add securityBlob
  result.patchNetbiosLength()

proc toUtf16Le*(value: string): string

proc buildSmbTreeConnectRequest*(host, share: string; messageId, sessionId: uint64): string =
  let unc = "\\\\" & host & "\\" & share
  let path = toUtf16Le(unc)
  let pathOffset = Smb2HeaderLen + 8
  result = newStringOfCap(4 + Smb2HeaderLen + 8 + path.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandTreeConnect, messageId, sessionId)
  result.addU16Le 9
  result.addU16Le 0
  result.addU16Le pathOffset.uint16
  result.addU16Le path.len.uint16
  result.add path
  result.patchNetbiosLength()

proc buildSmbCreatePipeRequest*(pipeName: string; messageId, sessionId: uint64; treeId: uint32): string =
  let name = toUtf16Le(pipeName)
  let nameOffset = Smb2HeaderLen + 56
  result = newStringOfCap(4 + Smb2HeaderLen + 56 + name.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandCreate, messageId, sessionId, treeId)
  result.addU16Le 57
  result.add char(0)
  result.add char(0)
  result.addU32Le 2
  result.addU64Le 0
  result.addU64Le 0
  result.addU32Le 0x0012019f'u32
  result.addU32Le 0
  result.addU32Le 7
  result.addU32Le 1
  result.addU32Le 0x00000040'u32
  result.addU16Le nameOffset.uint16
  result.addU16Le name.len.uint16
  result.addU32Le 0
  result.addU32Le 0
  result.add name
  result.patchNetbiosLength()

proc buildSmbFileCreateRequest*(path: string; desiredAccess, createDisposition,
                                createOptions: uint32; messageId, sessionId: uint64;
                                treeId: uint32): string =
  let name = toUtf16Le(path)
  let nameOffset = Smb2HeaderLen + 56
  let actualNameLen = max(1, name.len)
  result = newStringOfCap(4 + Smb2HeaderLen + 56 + actualNameLen)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandCreate, messageId, sessionId, treeId)
  result.addU16Le 57
  result.add char(0)
  result.add char(0)
  result.addU32Le 2
  result.addU64Le 0
  result.addU64Le 0
  result.addU32Le desiredAccess
  result.addU32Le 0
  result.addU32Le 7
  result.addU32Le createDisposition
  result.addU32Le createOptions
  result.addU16Le nameOffset.uint16
  result.addU16Le name.len.uint16
  result.addU32Le 0
  result.addU32Le 0
  if name.len > 0:
    result.add name
  else:
    result.add char(0)
  result.patchNetbiosLength()

proc buildSmbCloseRequest*(fileId: string; messageId, sessionId: uint64;
                           treeId: uint32): string =
  if fileId.len != 16:
    raise newException(ValueError, "SMB file id must be 16 bytes")
  result = newStringOfCap(4 + Smb2HeaderLen + 24)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandClose, messageId, sessionId, treeId)
  result.addU16Le 24
  result.addU16Le 0
  result.addU32Le 0
  result.add fileId
  result.patchNetbiosLength()

proc patchCreditCharge(pkt: var string; payloadBytes: int) =
  let charge = max(1, (payloadBytes + 65535) div 65536)
  pkt[10] = char(charge and 0xff)
  pkt[11] = char((charge shr 8) and 0xff)

proc buildSmbWriteRequest*(fileId, payload: string; messageId, sessionId: uint64; treeId: uint32; offset: uint64 = 0): string =
  if fileId.len != 16:
    raise newException(ValueError, "SMB file id must be 16 bytes")
  let dataOffset = Smb2HeaderLen + 48
  let charge = uint16(max(1, (payload.len + 65535) div 65536))
  result = newStringOfCap(4 + Smb2HeaderLen + 48 + payload.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandWrite, messageId, sessionId, treeId, charge)
  result.addU16Le 49
  result.addU16Le dataOffset.uint16
  result.addU32Le payload.len.uint32
  result.addU64Le offset
  result.add fileId
  result.addU32Le 0
  result.addU32Le 0
  result.addU16Le 0
  result.addU16Le 0
  result.addU32Le 0
  result.add payload
  result.patchNetbiosLength()

proc buildSmbReadRequest*(fileId: string; readLength: uint32; messageId, sessionId: uint64; treeId: uint32; offset: uint64 = 0): string =
  if fileId.len != 16:
    raise newException(ValueError, "SMB file id must be 16 bytes")
  result = newStringOfCap(4 + Smb2HeaderLen + 48)
  result.add "\x00\x00\x00\x00"
  let readCharge = uint16(max(1, (int(readLength) + 65535) div 65536))
  result.add buildSmb2Header(Smb2CommandRead, messageId, sessionId, treeId, readCharge)
  result.addU16Le 49
  result.add char(0)
  result.add char(0)
  result.addU32Le readLength
  result.addU64Le offset
  result.add fileId
  result.addU32Le 1
  result.addU32Le 0
  result.addU32Le 0
  result.addU16Le 0
  result.addU16Le 0
  result.add char(0)
  result.patchNetbiosLength()

proc buildSmbSetInfoDispositionDelete*(fileId: string; messageId, sessionId: uint64; treeId: uint32): string =
  if fileId.len != 16:
    raise newException(ValueError, "SMB file id must be 16 bytes")
  let buffer = "\x01"
  let bufferOffset = Smb2HeaderLen + 32
  result = newStringOfCap(4 + Smb2HeaderLen + 32 + buffer.len)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(0x0011'u16, messageId, sessionId, treeId)
  result.addU16Le 33
  result.add char(1)
  result.add char(13)
  result.addU32Le buffer.len.uint32
  result.addU16Le bufferOffset.uint16
  result.addU16Le 0
  result.addU32Le 0
  result.add fileId
  result.add buffer
  result.patchNetbiosLength()

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc readU16Le(data: string; offset: int): uint16 =
  if offset + 1 >= data.len:
    return 0
  uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

proc readU32Le(data: string; offset: int): uint32 =
  if offset + 3 >= data.len:
    return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc fileIdFromCreateResponse*(response: string): string =
  if response.len < 4 + Smb2HeaderLen + 88: return ""
  let status = readU32Le(response, 12)
  if status != 0: return ""
  return response[4 + Smb2HeaderLen + 64 ..< 4 + Smb2HeaderLen + 80]

proc readU64Le(data: string; offset: int): uint64 =
  if offset + 7 >= data.len:
    return 0
  for shift in countup(0, 56, 8):
    result = result or (uint64(ord(data[offset + (shift div 8)])) shl shift)

proc hmacSha256*(key, data: string): string

proc SHA256(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}
proc SHA512(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}

proc sha256Digest*(data: string): string =
  result = newString(32)
  let dataPtr = if data.len == 0: nil else: unsafeAddr data[0]
  discard SHA256(dataPtr, data.len.csize_t, addr result[0])

proc sha512Digest(data: string): string =
  result = newString(64)
  let dataPtr = if data.len == 0: nil else: unsafeAddr data[0]
  discard SHA512(dataPtr, data.len.csize_t, addr result[0])

proc zeroPreauthHash(): string =
  newString(64)

proc smb2Bytes(packet: string): string =
  if packet.len > 4: packet[4 .. ^1] else: ""

proc updatePreauthHash(hash: var string; packet: string) =
  if hash.len != 64:
    hash = zeroPreauthHash()
  hash = sha512Digest(hash & smb2Bytes(packet))

type
  CmacCtxPtr = pointer
  EvpCipherPtr = pointer

proc CMAC_CTX_new(): CmacCtxPtr {.cdecl, importc.}
proc CMAC_CTX_free(ctx: CmacCtxPtr) {.cdecl, importc.}
proc CMAC_Init(ctx: CmacCtxPtr; key: pointer; keylen: csize_t;
               cipher: EvpCipherPtr; impl: pointer): cint {.cdecl, importc.}
proc CMAC_Update(ctx: CmacCtxPtr; data: pointer; dlen: csize_t): cint {.cdecl, importc.}
proc CMAC_Final(ctx: CmacCtxPtr; mac: pointer; maclen: ptr csize_t): cint {.cdecl, importc.}
proc EVP_aes_128_cbc(): EvpCipherPtr {.cdecl, importc.}

proc aesCmac128*(key, data: string): string =
  if key.len == 0:
    return ""
  let ctx = CMAC_CTX_new()
  if ctx.isNil:
    return ""
  result = newString(16)
  var outLen: csize_t = 16
  let cipher = EVP_aes_128_cbc()
  if CMAC_Init(ctx, unsafeAddr key[0], csize_t(key.len), cipher, nil) != 1:
    CMAC_CTX_free(ctx)
    return ""
  if data.len > 0:
    discard CMAC_Update(ctx, unsafeAddr data[0], csize_t(data.len))
  discard CMAC_Final(ctx, addr result[0], addr outLen)
  CMAC_CTX_free(ctx)
  result.setLen int(outLen)

proc addU32Be(data: var string; value: uint32) =
  data.add char((value shr 24) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc smb3KdfCounter*(ki, label, context: string; lBits: uint32): string =
  var input = ""
  input.addU32Be 1'u32
  input.add label
  input.add char(0)
  input.add context
  input.addU32Be lBits
  let mac = hmacSha256(ki, input)
  result = mac[0 ..< min(16, mac.len)]

proc deriveSmb3SigningKey*(sessionKey, dialect: string;
                           preauthHash: string = ""): string =
  case dialect
  of "SMB 3.0", "SMB 3.0.2":
    smb3KdfCounter(sessionKey, "SMB2AESCMAC\0", "SmbSign\0", 128'u32)
  of "SMB 3.1.1":
    if preauthHash.len == 0: "" else: smb3KdfCounter(sessionKey, "SMBSigningKey\0", preauthHash, 128'u32)
  else:
    ""

proc canUseSmb2Signing(info: SmbNegotiateInfo): bool =
  info.dialect in ["SMB 2.0.2", "SMB 2.1"]

proc canUseSmb3Signing(info: SmbNegotiateInfo): bool =
  info.dialect in ["SMB 3.0", "SMB 3.0.2", "SMB 3.1.1"]

proc signSmb2Packet*(packet, sessionKey: string): string =
  if packet.len < 4 + Smb2HeaderLen:
    return packet
  result = packet
  let flagsOffset = 4 + 16
  let signatureOffset = 4 + 48
  let flags = readU32Le(result, flagsOffset) or 0x00000008'u32
  result.setU32Le(flagsOffset, flags)
  for index in signatureOffset ..< signatureOffset + 16:
    result[index] = char(0)
  let signature = hmacSha256(sessionKey, result[4 .. ^1])
  for index in 0 ..< min(16, signature.len):
    result[signatureOffset + index] = signature[index]

proc signSmb3Packet*(packet, signingKey: string): string =
  if packet.len < 4 + Smb2HeaderLen:
    return packet
  result = packet
  let flagsOffset = 4 + 16
  let signatureOffset = 4 + 48
  let flags = readU32Le(result, flagsOffset) or 0x00000008'u32
  result.setU32Le(flagsOffset, flags)
  for index in signatureOffset ..< signatureOffset + 16:
    result[index] = char(0)
  let signature = aesCmac128(signingKey, result[4 .. ^1])
  for index in 0 ..< min(16, signature.len):
    result[signatureOffset + index] = signature[index]

proc maybeSign(packet, sessionKey: string; info: SmbNegotiateInfo; signingEnabled: bool;
               preauthHash = ""): tuple[data: string, signed: bool] =
  if not signingEnabled or sessionKey.len == 0:
    return (packet, false)
  if info.canUseSmb2Signing():
    return (signSmb2Packet(packet, sessionKey), true)
  if info.canUseSmb3Signing():
    let signingKey = deriveSmb3SigningKey(sessionKey, info.dialect, preauthHash)
    if signingKey.len == 16:
      return (signSmb3Packet(packet, signingKey), true)
  (packet, false)

proc toHexByte(value: char): string =
  const Hex = "0123456789abcdef"
  let item = ord(value)
  result.add Hex[(item shr 4) and 0xf]
  result.add Hex[item and 0xf]

proc formatGuid(data: string; offset: int): string =
  if offset + 15 >= data.len:
    return ""
  for index in 0 ..< 16:
    if index in [4, 6, 8, 10]:
      result.add "-"
    result.add toHexByte(data[offset + index])

proc hexBytes(data: string; offset, count: int): string =
  if offset < 0 or count < 0 or offset + count > data.len:
    return ""
  for index in offset ..< offset + count:
    result.add toHexByte(data[index])

proc readUtf16LeAscii(data: string; offset, count: int): string =
  if offset < 0 or count < 0 or offset + count > data.len:
    return ""
  var index = offset
  while index + 1 < offset + count:
    let lo = ord(data[index])
    let hi = ord(data[index + 1])
    if hi == 0 and lo >= 32 and lo <= 126:
      result.add char(lo)
    index += 2

proc toUtf16Le*(value: string): string =
  for item in value:
    result.add item
    result.add char(0)

proc parseHexBytes*(value: string): string =
  var clean = value.strip()
  if ":" in clean:
    clean = clean.split(':')[^1]
  clean = clean.replace(" ", "")
  if clean.len mod 2 != 0:
    raise newException(ValueError, "hex string length must be even")
  var index = 0
  while index < clean.len:
    result.add char(parseHexInt(clean[index .. index + 1]))
    index += 2

proc md4Digest*(data: string): string =
  proc f(x, y, z: uint32): uint32 = (x and y) or ((not x) and z)
  proc g(x, y, z: uint32): uint32 = (x and y) or (x and z) or (y and z)
  proc h(x, y, z: uint32): uint32 = x xor y xor z
  proc rol(x: uint32; n: int): uint32 = (x shl n) or (x shr (32 - n))

  var msg = data
  let bitLen = uint64(msg.len) * 8
  msg.add char(0x80)
  while (msg.len mod 64) != 56:
    msg.add char(0)
  for shift in countup(0, 56, 8):
    msg.add char((bitLen shr shift) and 0xff)

  var a = 0x67452301'u32
  var b = 0xefcdab89'u32
  var c = 0x98badcfe'u32
  var d = 0x10325476'u32

  var offset = 0
  while offset < msg.len:
    var x: array[16, uint32]
    for index in 0 ..< 16:
      x[index] = readU32Le(msg, offset + index * 4)
    let aa = a
    let bb = b
    let cc = c
    let dd = d

    template round1(a0, b0, c0, d0: untyped; k, s: int) =
      a0 = rol(a0 + f(b0, c0, d0) + x[k], s)
    template round2(a0, b0, c0, d0: untyped; k, s: int) =
      a0 = rol(a0 + g(b0, c0, d0) + x[k] + 0x5a827999'u32, s)
    template round3(a0, b0, c0, d0: untyped; k, s: int) =
      a0 = rol(a0 + h(b0, c0, d0) + x[k] + 0x6ed9eba1'u32, s)

    round1(a, b, c, d, 0, 3); round1(d, a, b, c, 1, 7); round1(c, d, a, b, 2, 11); round1(b, c, d, a, 3, 19)
    round1(a, b, c, d, 4, 3); round1(d, a, b, c, 5, 7); round1(c, d, a, b, 6, 11); round1(b, c, d, a, 7, 19)
    round1(a, b, c, d, 8, 3); round1(d, a, b, c, 9, 7); round1(c, d, a, b, 10, 11); round1(b, c, d, a, 11, 19)
    round1(a, b, c, d, 12, 3); round1(d, a, b, c, 13, 7); round1(c, d, a, b, 14, 11); round1(b, c, d, a, 15, 19)

    let r2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    for index, k in r2:
      case index mod 4
      of 0: round2(a, b, c, d, k, 3)
      of 1: round2(d, a, b, c, k, 5)
      of 2: round2(c, d, a, b, k, 9)
      else: round2(b, c, d, a, k, 13)

    let r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    for index, k in r3:
      case index mod 4
      of 0: round3(a, b, c, d, k, 3)
      of 1: round3(d, a, b, c, k, 9)
      of 2: round3(c, d, a, b, k, 11)
      else: round3(b, c, d, a, k, 15)

    a += aa; b += bb; c += cc; d += dd
    offset += 64

  result.addU32Le a
  result.addU32Le b
  result.addU32Le c
  result.addU32Le d

proc md5Digest*(data: string): string =
  let digest = toMD5(data)
  for item in digest:
    result.add char(item)

proc hmacMd5*(key, data: string): string =
  var actualKey = key
  if actualKey.len > 64:
    actualKey = md5Digest(actualKey)
  while actualKey.len < 64:
    actualKey.add char(0)
  var ipad = ""
  var opad = ""
  for item in actualKey:
    ipad.add char(ord(item) xor 0x36)
    opad.add char(ord(item) xor 0x5c)
  md5Digest(opad & md5Digest(ipad & data))

type Rc4State* = object
  s: array[256, uint8]
  i, j: int

proc rc4Init*(key: string): Rc4State =
  for idx in 0..255: result.s[idx] = uint8(idx)
  var j = 0
  for idx in 0..255:
    j = (j + int(result.s[idx]) + int(ord(key[idx mod key.len]))) mod 256
    swap(result.s[idx], result.s[j])

proc rc4Process*(state: var Rc4State; data: string): string =
  result = newString(data.len)
  for k in 0 ..< data.len:
    state.i = (state.i + 1) mod 256
    state.j = (state.j + int(state.s[state.i])) mod 256
    swap(state.s[state.i], state.s[state.j])
    result[k] = char(int(ord(data[k])) xor int(state.s[(int(state.s[state.i]) + int(state.s[state.j])) mod 256]))

const
  RpcClientSignMagic = "session key to client-to-server signing key magic constant\0"
  RpcClientSealMagic = "session key to client-to-server sealing key magic constant\0"
  RpcServerSealMagic = "session key to server-to-client sealing key magic constant\0"

proc rpcDeriveKeys(esk: string): tuple[cSign, cSeal, sSeal: string] =
  result.cSign = md5Digest(esk & RpcClientSignMagic)
  result.cSeal = md5Digest(esk & RpcClientSealMagic)
  result.sSeal = md5Digest(esk & RpcServerSealMagic)
  dbgDump("TSCH RPC ESK", esk)
  dbgDump("TSCH RPC cSign", result.cSign)
  dbgDump("TSCH RPC cSeal", result.cSeal)

proc hmacSha256*(key, data: string): string =
  var output = newString(32)
  var outputLen: cuint = 0
  let keyPtr = if key.len == 0: nil else: unsafeAddr key[0]
  let dataPtr = if data.len == 0: nil else: cast[cstring](unsafeAddr data[0])
  discard HMAC(
    EVP_sha256(),
    keyPtr,
    key.len.cint,
    dataPtr,
    data.len.csize_t,
    cast[cstring](addr output[0]),
    addr outputLen
  )
  output.setLen int(outputLen)
  result = output

proc ntHashFromPassword*(password: string): string =
  md4Digest(toUtf16Le(password))

proc ntHashFromCredential*(credential: SmbCredential): string =
  if credential.ntlmHash.len > 0:
    return parseHexBytes(credential.ntlmHash)
  ntHashFromPassword(credential.password)

proc ntowfV2*(username, domain, ntHash: string): string =
  hmacMd5(ntHash, toUtf16Le(username.toUpperAscii() & domain))

proc windowsFileTimeNow(): uint64 =
  uint64(toUnix(getTime()) + 11644473600'i64) * 10000000'u64

proc buildNtlmV2Blob*(targetInfo, clientChallenge: string; timestamp = 0'u64): string =
  let ts = if timestamp == 0'u64: windowsFileTimeNow() else: timestamp
  result.add char(0x01)
  result.add char(0x01)
  result.add char(0)
  result.add char(0)
  result.addU32Le 0
  result.addU64Le ts
  result.add clientChallenge
  result.addU32Le 0
  result.add targetInfo
  result.addU32Le 0

proc extractMsvAvString(targetInfo: string; wantedAvId: uint16): string =
  var index = 0
  while index + 4 <= targetInfo.len:
    let avId  = readU16Le(targetInfo, index)
    let avLen = int(readU16Le(targetInfo, index + 2))
    index += 4
    if avId == 0'u16: break
    if index + avLen > targetInfo.len: break
    if avId == wantedAvId and avLen > 0:
      var i = index
      while i + 1 < index + avLen:
        let cp = uint32(ord(targetInfo[i])) or (uint32(ord(targetInfo[i+1])) shl 8)
        i += 2
        if cp == 0: break
        if cp < 0x80: result.add char(cp)
        elif cp < 0x800:
          result.add char(0xC0 or (cp shr 6))
          result.add char(0x80 or (cp and 0x3F))
      return
    index += avLen

proc extractMsvAvTimestamp(targetInfo: string): uint64 =
  var index = 0
  while index + 4 <= targetInfo.len:
    let avId = readU16Le(targetInfo, index)
    let avLen = int(readU16Le(targetInfo, index + 2))
    index += 4
    if avId == 0'u16:
      return 0
    if index + avLen > targetInfo.len:
      return 0
    if avId == 7'u16 and avLen == 8:
      return readU64Le(targetInfo, index)
    index += avLen
  0

proc buildNtlmV2Responses*(username, domain, ntHash, serverChallenge, targetInfo, clientChallenge: string; timestamp = 0'u64): tuple[lm, nt, sessionBaseKey: string] =
  let key = ntowfV2(username, domain, ntHash)
  let serverTimestamp = extractMsvAvTimestamp(targetInfo)
  let effectiveTs =
    if timestamp != 0'u64: timestamp
    elif serverTimestamp != 0'u64: serverTimestamp
    else: 0'u64
  let blob = buildNtlmV2Blob(targetInfo, clientChallenge, effectiveTs)
  let ntProof = hmacMd5(key, serverChallenge & blob)
  result.nt = ntProof & blob
  if serverTimestamp != 0'u64:
    result.lm = newString(24)
  else:
    result.lm = hmacMd5(key, serverChallenge & clientChallenge) & clientChallenge
  result.sessionBaseKey = hmacMd5(key, ntProof)

proc buildNtlmV2ResponsesSmb(username, domain, ntHash, serverChallenge, targetInfo, clientChallenge: string; timestamp = 0'u64): tuple[lm, nt, sessionBaseKey: string] =
  let key = ntowfV2(username, domain, ntHash)
  let serverTimestamp = extractMsvAvTimestamp(targetInfo)
  let effectiveTs =
    if timestamp != 0'u64: timestamp
    elif serverTimestamp != 0'u64: serverTimestamp
    else: 0'u64
  let blob = buildNtlmV2Blob(targetInfo, clientChallenge, effectiveTs)
  let ntProof = hmacMd5(key, serverChallenge & blob)
  result.nt = ntProof & blob
  result.lm = hmacMd5(key, serverChallenge & clientChallenge) & clientChallenge
  result.sessionBaseKey = hmacMd5(key, ntProof)

proc secBuf(data: var string; offset: int; length: int; payloadOffset: int) =
  data.setU16Le(offset, length.uint16)
  data.setU16Le(offset + 2, length.uint16)
  data.setU32Le(offset + 4, payloadOffset.uint32)

proc buildNtlmType3*(credential: SmbCredential; challenge: NtlmChallengeInfo; clientChallenge: string; timestamp = 0'u64): string =
  if not challenge.offered:
    raise newException(ValueError, "NTLM challenge is required")
  let ntHash = ntHashFromCredential(credential)
  let responses = buildNtlmV2ResponsesSmb(
    credential.username,
    credential.domain,
    ntHash,
    challenge.serverChallenge,
    challenge.targetInfo,
    clientChallenge,
    timestamp
  )
  let authDomain =
    if credential.domain.len > 0: credential.domain
    else: extractMsvAvString(challenge.targetInfo, 1)
  let domain = toUtf16Le(authDomain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  let flags = challenge.flags

  result.add "NTLMSSP\0"
  result.addU32Le 3
  while result.len < 64:
    result.add char(0)
  var payloadOffset = 64
  secBuf(result, 12, responses.lm.len, payloadOffset); payloadOffset += responses.lm.len
  secBuf(result, 20, responses.nt.len, payloadOffset); payloadOffset += responses.nt.len
  secBuf(result, 28, domain.len, payloadOffset); payloadOffset += domain.len
  secBuf(result, 36, user.len, payloadOffset); payloadOffset += user.len
  secBuf(result, 44, workstation.len, payloadOffset); payloadOffset += workstation.len
  secBuf(result, 52, 0, payloadOffset)
  result.setU32Le(60, flags)
  result.add responses.lm
  result.add responses.nt
  result.add domain
  result.add user
  result.add workstation

proc buildNtlmType3CredSsp*(credential: SmbCredential; challenge: NtlmChallengeInfo; clientChallenge: string): string =
  if not challenge.offered:
    raise newException(ValueError, "NTLM challenge is required")
  let ntHash = ntHashFromCredential(credential)
  var avPairs = challenge.targetInfo
  if avPairs.len >= 4 and readU16Le(avPairs, avPairs.len - 4) == 0'u16:
    avPairs.setLen(avPairs.len - 4)
  avPairs.addU16Le 6'u16; avPairs.addU16Le 4'u16; avPairs.addU32Le 0x00000002'u32
  avPairs.addU16Le 0'u16; avPairs.addU16Le 0'u16
  let responses = buildNtlmV2Responses(
    credential.username, credential.domain, ntHash,
    challenge.serverChallenge, avPairs, clientChallenge)
  let domain = toUtf16Le(credential.domain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  let flags = challenge.flags
  result.add "NTLMSSP\0"
  result.addU32Le 3
  while result.len < 64:
    result.add char(0)
  var payloadOffset = 64
  secBuf(result, 12, responses.lm.len, payloadOffset); payloadOffset += responses.lm.len
  secBuf(result, 20, responses.nt.len, payloadOffset); payloadOffset += responses.nt.len
  secBuf(result, 28, domain.len, payloadOffset); payloadOffset += domain.len
  secBuf(result, 36, user.len, payloadOffset); payloadOffset += user.len
  secBuf(result, 44, workstation.len, payloadOffset); payloadOffset += workstation.len
  secBuf(result, 52, 0, payloadOffset)
  result.setU32Le(60, flags)
  result.add responses.lm
  result.add responses.nt
  result.add domain
  result.add user
  result.add workstation

proc buildNtlmType3WithSessionKey*(credential: SmbCredential; challenge: NtlmChallengeInfo; clientChallenge: string; timestamp = 0'u64): tuple[token, sessionBaseKey: string] =
  if not challenge.offered:
    raise newException(ValueError, "NTLM challenge is required")
  let ntHash = ntHashFromCredential(credential)
  let responses = buildNtlmV2Responses(
    credential.username,
    credential.domain,
    ntHash,
    challenge.serverChallenge,
    challenge.targetInfo,
    clientChallenge,
    timestamp
  )
  result.sessionBaseKey = responses.sessionBaseKey
  let authDomain =
    if credential.domain.len > 0: credential.domain
    else: extractMsvAvString(challenge.targetInfo, 1)
  let domain = toUtf16Le(authDomain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  let flags = challenge.flags

  result.token.add "NTLMSSP\0"
  result.token.addU32Le 3
  while result.token.len < 64:
    result.token.add char(0)
  var payloadOffset = 64
  secBuf(result.token, 12, responses.lm.len, payloadOffset); payloadOffset += responses.lm.len
  secBuf(result.token, 20, responses.nt.len, payloadOffset); payloadOffset += responses.nt.len
  secBuf(result.token, 28, domain.len, payloadOffset); payloadOffset += domain.len
  secBuf(result.token, 36, user.len, payloadOffset); payloadOffset += user.len
  secBuf(result.token, 44, workstation.len, payloadOffset); payloadOffset += workstation.len
  secBuf(result.token, 52, 0, payloadOffset)
  result.token.setU32Le(60, flags)
  result.token.add responses.lm
  result.token.add responses.nt
  result.token.add domain
  result.token.add user
  result.token.add workstation


proc spnegoNtlmAuth*(ntlmToken: string): string =
  let responseToken = derTlv(0xa2'u8, derTlv(0x04'u8, ntlmToken))
  derTlv(0xa1'u8, derTlv(0x30'u8, responseToken))

proc stripGssApiWrapper(token: string): string =
  if token.len < 13 or token[0] != '\x60':
    return token
  var i = 1
  if i >= token.len: return token
  if (token[i].uint8 and 0x80) != 0:
    let lenBytes = int(token[i].uint8 and 0x7f)
    i += 1 + lenBytes
  else:
    i += 1
  if i >= token.len or token[i] != '\x06': return token
  if i + 1 >= token.len: return token
  let oidLen = int(token[i + 1].uint8)
  i += 2 + oidLen
  if i + 1 >= token.len: return token
  i += 2
  token[i .. ^1]

proc spnegoKerberosInit*(gssToken: string): string =
  let spnegoOid = derOid([byte 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
  let msKrb5Oid = derOid([byte 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02])
  let krb5Oid = derOid([byte 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02])
  let apReq = stripGssApiWrapper(gssToken)
  let mechTypes = derTlv(0xa0'u8, derTlv(0x30'u8, msKrb5Oid & krb5Oid))
  let mechToken = derTlv(0xa2'u8, derTlv(0x04'u8, apReq))
  let negTokenInit = derTlv(0xa0'u8, derTlv(0x30'u8, mechTypes & mechToken))
  derTlv(0x60'u8, spnegoOid & negTokenInit)

proc spnegoKerberosNext*(gssToken: string): string =
  let apReq = stripGssApiWrapper(gssToken)
  let mechToken = derTlv(0xa2'u8, derTlv(0x04'u8, apReq))
  let negTokenResp = derTlv(0xa1'u8, derTlv(0x30'u8, mechToken))
  negTokenResp

proc readDerItem(data: string; offset: var int): tuple[tag: int; body: string] =
  if offset + 2 > data.len:
    return (-1, "")
  result.tag = ord(data[offset])
  inc offset
  var length = ord(data[offset])
  inc offset
  if (length and 0x80) != 0:
    let count = length and 0x7f
    length = 0
    if offset + count > data.len:
      return (-1, "")
    for i in 0 ..< count:
      length = (length shl 8) or ord(data[offset + i])
    offset += count
  if offset + length > data.len:
    return (-1, "")
  result.body = data[offset ..< offset + length]
  offset += length

proc firstSpnegoResponseToken*(blob: string): string =
  proc walk(data: string): string =
    var pos = 0
    while pos < data.len:
      let item = readDerItem(data, pos)
      if item.tag < 0:
        break
      if item.tag == 0xa2:
        var p = 0
        let inner = readDerItem(item.body, p)
        if inner.tag == 0x04:
          return inner.body
      let nested = walk(item.body)
      if nested.len > 0:
        return nested
    ""
  walk(blob)


proc hasCredential*(credential: SmbCredential): bool =
  credential.username.len > 0 and (credential.password.len > 0 or credential.ntlmHash.len > 0)

proc randomBytes*(count: int): string =
  randomize()
  for _ in 0 ..< count:
    result.add char(rand(255))

proc randomAsciiBytes(count: int): string =
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  randomize()
  for _ in 0 ..< count:
    result.add alphabet[rand(alphabet.high)]

proc buildNtlmType3Tds*(credential: SmbCredential; challenge: NtlmChallengeInfo;
                        clientChallenge, type1Msg, type2Msg: string): tuple[token, exportedKey: string] =
  let ntHash = ntHashFromCredential(credential)
  var avPairs = challenge.targetInfo
  if avPairs.len >= 4 and readU16Le(avPairs, avPairs.len - 4) == 0'u16:
    avPairs.setLen(avPairs.len - 4)
  avPairs.addU16Le 6'u16; avPairs.addU16Le 4'u16; avPairs.addU32Le 0x00000002'u32
  avPairs.addU16Le 0'u16; avPairs.addU16Le 0'u16
  let responses = buildNtlmV2Responses(
    credential.username, credential.domain, ntHash,
    challenge.serverChallenge, avPairs, clientChallenge)
  result.exportedKey = randomBytes(16)
  var ekState = rc4Init(responses.sessionBaseKey)
  let encRsk = rc4Process(ekState, result.exportedKey)
  let flags = challenge.flags or 0x40000000'u32
  let domain = toUtf16Le(credential.domain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  result.token.add "NTLMSSP\0"
  result.token.addU32Le 3'u32
  while result.token.len < 64:
    result.token.add char(0)
  result.token.setU32Le(60, flags)
  result.token.addBytes [byte 10, 0, 0, 0, 0, 0, 0, 15]
  for _ in 0..15: result.token.add char(0)
  let payloadOffset = 88
  var po = payloadOffset
  secBuf(result.token, 12, responses.lm.len, po); po += responses.lm.len
  secBuf(result.token, 20, responses.nt.len, po); po += responses.nt.len
  secBuf(result.token, 28, domain.len, po); po += domain.len
  secBuf(result.token, 36, user.len, po); po += user.len
  secBuf(result.token, 44, workstation.len, po); po += workstation.len
  secBuf(result.token, 52, encRsk.len, po)
  result.token.add responses.lm
  result.token.add responses.nt
  result.token.add domain
  result.token.add user
  result.token.add workstation
  result.token.add encRsk
  let mic = hmacMd5(result.exportedKey, type1Msg & type2Msg & result.token)
  for i in 0..15:
    result.token[72 + i] = mic[i]

proc buildNtlmType1Rpc*(): string =
  let flags: uint32 = 0x00000001'u32 or 0x00000010'u32 or 0x00000020'u32 or
    0x00000200'u32 or 0x00008000'u32 or 0x00080000'u32 or 0x00800000'u32 or
    0x02000000'u32 or 0x20000000'u32 or 0x40000000'u32 or 0x80000000'u32
  result.add "NTLMSSP\0"
  result.addU32Le 1'u32
  result.addU32Le flags
  result.addU16Le 0'u16; result.addU16Le 0'u16; result.addU32Le 40'u32
  result.addU16Le 0'u16; result.addU16Le 0'u16; result.addU32Le 40'u32
  result.addBytes [byte 10, 0, 0, 0, 0, 0, 0, 15]

proc buildNtlmType3Rpc*(credential: SmbCredential; challenge: NtlmChallengeInfo;
                        clientChallenge, type1Msg, type2Msg: string): tuple[token, exportedKey: string] =
  let ntHash = ntHashFromCredential(credential)
  var avPairs = challenge.targetInfo
  if avPairs.len >= 4 and readU16Le(avPairs, avPairs.len - 4) == 0'u16:
    avPairs.setLen(avPairs.len - 4)
  avPairs.addU16Le 6'u16; avPairs.addU16Le 4'u16; avPairs.addU32Le 0x00000002'u32
  avPairs.addU16Le 0'u16; avPairs.addU16Le 0'u16
  let responses = buildNtlmV2Responses(
    credential.username, credential.domain, ntHash,
    challenge.serverChallenge, avPairs, clientChallenge)
  result.exportedKey = randomBytes(16)
  var ekState = rc4Init(responses.sessionBaseKey)
  let encRsk = rc4Process(ekState, result.exportedKey)
  let flags = challenge.flags or 0x40000000'u32 or 0x00000010'u32 or 0x00000020'u32
  let domain = toUtf16Le(credential.domain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  result.token.add "NTLMSSP\0"
  result.token.addU32Le 3'u32
  while result.token.len < 64:
    result.token.add char(0)
  result.token.setU32Le(60, flags)
  result.token.addBytes [byte 10, 0, 0, 0, 0, 0, 0, 15]
  for _ in 0..15: result.token.add char(0)
  let payloadOffset = 88
  var po = payloadOffset
  secBuf(result.token, 12, responses.lm.len, po); po += responses.lm.len
  secBuf(result.token, 20, responses.nt.len, po); po += responses.nt.len
  secBuf(result.token, 28, domain.len, po); po += domain.len
  secBuf(result.token, 36, user.len, po); po += user.len
  secBuf(result.token, 44, workstation.len, po); po += workstation.len
  secBuf(result.token, 52, encRsk.len, po)
  result.token.add responses.lm
  result.token.add responses.nt
  result.token.add domain
  result.token.add user
  result.token.add workstation
  result.token.add encRsk
  let mic = hmacMd5(result.exportedKey, type1Msg & type2Msg & result.token)
  for i in 0..15:
    result.token[72 + i] = mic[i]

proc buildNtlmType3SmbSession*(credential: SmbCredential; challenge: NtlmChallengeInfo;
                               clientChallenge, type1Msg: string;
                               service = "cifs"): tuple[token, exportedKey: string] =
  if not challenge.offered:
    raise newException(ValueError, "NTLM challenge is required")
  let ntHash = ntHashFromCredential(credential)
  var targetInfo = challenge.targetInfo
  if targetInfo.len >= 4 and readU16Le(targetInfo, targetInfo.len - 4) == 0'u16:
    targetInfo.setLen(targetInfo.len - 4)
  if challenge.dnsComputer.len > 0 and service.len > 0:
    targetInfo.addU16Le 9'u16
    targetInfo.addU16Le uint16(toUtf16Le(service & "/" & challenge.dnsComputer).len)
    targetInfo.add toUtf16Le(service & "/" & challenge.dnsComputer)
  targetInfo.addU16Le 0'u16
  targetInfo.addU16Le 0'u16
  let responses = buildNtlmV2ResponsesSmb(
    credential.username, credential.domain, ntHash,
    challenge.serverChallenge, targetInfo, clientChallenge)
  result.exportedKey = randomBytes(16)
  var ekState = rc4Init(responses.sessionBaseKey)
  let encRsk = rc4Process(ekState, result.exportedKey)
  var flags =
    if type1Msg.len >= 16: readU32Le(type1Msg, 12)
    else: challenge.flags
  const
    ntlmNegotiateSign = 0x00000010'u32
    ntlmNegotiateSeal = 0x00000020'u32
    ntlmNegotiateAlwaysSign = 0x00008000'u32
    ntlmNegotiateExtendedSessionSecurity = 0x00080000'u32
    ntlmNegotiate128 = 0x20000000'u32
    ntlmNegotiateKeyExchange = 0x40000000'u32
  for bit in [ntlmNegotiateExtendedSessionSecurity, ntlmNegotiate128,
              ntlmNegotiateKeyExchange, ntlmNegotiateSeal, ntlmNegotiateSign,
              ntlmNegotiateAlwaysSign]:
    if (challenge.flags and bit) == 0:
      flags = flags and not bit
  let authDomain =
    if credential.domain.len > 0: credential.domain
    else: extractMsvAvString(challenge.targetInfo, 1)
  let domain = toUtf16Le(authDomain)
  let user = toUtf16Le(credential.username)
  let workstation = toUtf16Le(credential.workstation)
  result.token.add "NTLMSSP\0"
  result.token.addU32Le 3'u32
  while result.token.len < 64:
    result.token.add char(0)
  result.token.setU32Le(60, flags)
  if (flags and 0x02000000'u32) != 0:
    result.token.addBytes [byte 10, 0, 0, 0, 0, 0, 0, 15]
    for _ in 0 ..< 16:
      result.token.add char(0)
  var payloadOffset = result.token.len
  secBuf(result.token, 28, domain.len, payloadOffset); payloadOffset += domain.len
  secBuf(result.token, 36, user.len, payloadOffset); payloadOffset += user.len
  secBuf(result.token, 44, workstation.len, payloadOffset); payloadOffset += workstation.len
  secBuf(result.token, 12, responses.lm.len, payloadOffset); payloadOffset += responses.lm.len
  secBuf(result.token, 20, responses.nt.len, payloadOffset); payloadOffset += responses.nt.len
  secBuf(result.token, 52, encRsk.len, payloadOffset)
  result.token.add domain
  result.token.add user
  result.token.add workstation
  result.token.add responses.lm
  result.token.add responses.nt
  result.token.add encRsk

proc parseNtlmChallenge*(blob: string): NtlmChallengeInfo =
  let start = blob.find("NTLMSSP\0")
  if start < 0 or start + 48 > blob.len:
    return
  if readU32Le(blob, start + 8) != 2:
    return

  let targetLen = int(readU16Le(blob, start + 12))
  let targetOffset = int(readU32Le(blob, start + 16))
  result = NtlmChallengeInfo(
    offered: true,
    flags: readU32Le(blob, start + 20),
    serverChallenge: blob[start + 24 ..< start + 32],
    serverChallengeHex: hexBytes(blob, start + 24, 8)
  )
  if targetLen > 0 and start + targetOffset + targetLen <= blob.len:
    result.targetName = readUtf16LeAscii(blob, start + targetOffset, targetLen)
  let targetInfoLen = int(readU16Le(blob, start + 40))
  let targetInfoOffset = int(readU32Le(blob, start + 44))
  if targetInfoLen > 0 and start + targetInfoOffset + targetInfoLen <= blob.len:
    result.targetInfo = blob[start + targetInfoOffset ..< start + targetInfoOffset + targetInfoLen]
    var cursor = 0
    while cursor + 4 <= result.targetInfo.len:
      let avId = readU16Le(result.targetInfo, cursor)
      let avLen = int(readU16Le(result.targetInfo, cursor + 2))
      cursor += 4
      if avId == 0'u16 or cursor + avLen > result.targetInfo.len:
        break
      let value = readUtf16LeAscii(result.targetInfo, cursor, avLen)
      case avId
      of 1: result.netbiosComputer = value
      of 2: result.netbiosDomain = value
      of 3: result.dnsComputer = value
      of 4: result.dnsDomain = value
      of 5: result.dnsForest = value
      else: discard
      cursor += avLen

proc parseSessionSetupChallenge*(response: string): NtlmChallengeInfo =
  let body = 4 + Smb2HeaderLen
  if response.len < body + 8:
    return
  let securityBufferOffset = int(readU16Le(response, body + 4))
  let securityBufferLength = int(readU16Le(response, body + 6))
  let absolute = 4 + securityBufferOffset
  if absolute < response.len and absolute + securityBufferLength <= response.len:
    result = parseNtlmChallenge(response[absolute ..< absolute + securityBufferLength])

proc parseSessionSetupSecurityBlob*(response: string): string =
  let body = 4 + Smb2HeaderLen
  if response.len < body + 8:
    return ""
  let securityBufferOffset = int(readU16Le(response, body + 4))
  let securityBufferLength = int(readU16Le(response, body + 6))
  let absolute = 4 + securityBufferOffset
  if securityBufferLength > 0 and absolute < response.len and
      absolute + securityBufferLength <= response.len:
    result = response[absolute ..< absolute + securityBufferLength]

proc extractNtlmMessage(blob: string): string =
  let start = blob.find("NTLMSSP\0")
  if start < 0:
    return ""
  blob[start ..< blob.len]

proc parseSmbTreeConnectResponse*(response: string): SmbTreeConnectInfo =
  result.attempted = true
  if response.len < 4 + Smb2HeaderLen:
    result.status = uint32.high
    return
  result.status = readU32Le(response, 12)
  result.treeId = readU32Le(response, 40)
  result.connected = result.status == 0
  if response.len >= 4 + Smb2HeaderLen + 16:
    let body = 4 + Smb2HeaderLen
    result.shareType = uint8(ord(response[body + 2]))
    result.shareFlags = readU32Le(response, body + 4)
    result.capabilities = readU32Le(response, body + 8)
    result.maximalAccess = readU32Le(response, body + 12)

proc parseSmbCreatePipeResponse*(response: string): SmbPipeInfo =
  result.attempted = true
  if response.len < 4 + Smb2HeaderLen:
    result.status = uint32.high
    return
  result.status = readU32Le(response, 12)
  result.opened = result.status == 0
  let body = 4 + Smb2HeaderLen
  if response.len >= body + 80:
    result.fileId = response[body + 64 ..< body + 80]

proc parseSmbReadData*(response: string): string =
  if response.len < 4 + Smb2HeaderLen + 16:
    return ""
  let status = readU32Le(response, 12)
  if status != 0 and status != 0x80000005'u32:
    return ""
  let body = 4 + Smb2HeaderLen
  let dataOffset = int(ord(response[body + 2]))
  let dataLength = int(readU32Le(response, body + 4))
  let absolute = 4 + dataOffset
  if dataLength > 0 and absolute >= 0 and absolute + dataLength <= response.len:
    result = response[absolute ..< absolute + dataLength]

proc dceUuid(value: openArray[byte]): string =
  for item in value:
    result.add char(item)

const
  SrvSvcUuidBytes* = [
    byte 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
    0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88
  ]
  RprnUuidBytes* = [
    byte 0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
    0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab
  ]
  WksSvcUuidBytes* = [
    byte 0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36,
    0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a
  ]
  SamrUuidBytes* = [
    byte 0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
    0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac
  ]
  LsarpcUuidBytes* = [
    byte 0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
    0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab
  ]
  NdrUuidBytes = [
    byte 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
  ]

proc buildDceRpcBind*(interfaceUuid: openArray[byte];
                     versionMajor, versionMinor: uint16;
                     callId = 1'u32): string =
  let ifaceUuid = dceUuid(interfaceUuid)
  let ndrUuid = dceUuid(NdrUuidBytes)
  var body = ""
  body.addU16Le 4280
  body.addU16Le 4280
  body.addU32Le 0
  body.add char(1)
  body.add char(0)
  body.addU16Le 0
  body.addU16Le 0
  body.add char(1)
  body.add char(0)
  body.add ifaceUuid
  body.addU16Le versionMajor
  body.addU16Le versionMinor
  body.add ndrUuid
  body.addU32Le 2

  result.add char(5)
  result.add char(0)
  result.add char(11)
  result.add char(3)
  result.addBytes [byte 0x10, 0, 0, 0]
  result.addU16Le (16 + body.len).uint16
  result.addU16Le 0
  result.addU32Le callId
  result.add body

proc buildDceRpcBindAuth*(interfaceUuid: openArray[byte]; versionMajor, versionMinor: uint16;
                          authBytes: string; callId = 1'u32): string =
  let ifaceUuid = dceUuid(interfaceUuid)
  let ndrUuid = dceUuid(NdrUuidBytes)
  var body = ""
  body.addU16Le 4280; body.addU16Le 4280; body.addU32Le 0
  body.add char(1); body.add char(0); body.addU16Le 0
  body.addU16Le 0; body.add char(1); body.add char(0)
  body.add ifaceUuid; body.addU16Le versionMajor; body.addU16Le versionMinor
  body.add ndrUuid; body.addU32Le 2
  result.add char(5); result.add char(0); result.add char(11); result.add char(3)
  result.addBytes [byte 0x10, 0, 0, 0]
  result.addU16Le uint16(16 + body.len + 8 + authBytes.len)
  result.addU16Le uint16(authBytes.len)
  result.addU32Le callId
  result.add body
  result.add char(0x0a); result.add char(0x06); result.add char(0); result.add char(0)
  result.addU32Le 79231'u32
  result.add authBytes

proc buildDceRpcAuth3*(authBytes: string; callId = 1'u32): string =
  result.add char(5); result.add char(0); result.add char(16); result.add char(3)
  result.addBytes [byte 0x10, 0, 0, 0]
  result.addU16Le uint16(16 + 4 + 8 + authBytes.len)
  result.addU16Le uint16(authBytes.len)
  result.addU32Le callId
  result.add "    "
  result.add char(0x0a); result.add char(0x06); result.add char(0); result.add char(0)
  result.addU32Le 79231'u32
  result.add authBytes

proc buildDceRpcBindSrvSvc*(callId = 1'u32): string =
  buildDceRpcBind(SrvSvcUuidBytes, 3'u16, 0'u16, callId)

proc buildDceRpcBindRprn*(callId = 1'u32): string =
  buildDceRpcBind(RprnUuidBytes, 1'u16, 0'u16, callId)

proc buildDceRpcBindWksSvc*(callId = 1'u32): string =
  buildDceRpcBind(WksSvcUuidBytes, 1'u16, 0'u16, callId)

proc buildDceRpcBindSamr*(callId = 1'u32): string =
  buildDceRpcBind(SamrUuidBytes, 1'u16, 0'u16, callId)

proc buildDceRpcBindLsarpc*(callId = 1'u32): string =
  buildDceRpcBind(LsarpcUuidBytes, 0'u16, 0'u16, callId)

proc parseDceRpcBindAck*(payload: string): DceRpcInfo =
  result.attempted = true
  if payload.len < 24:
    result.message = "short DCE/RPC response"
    return
  result.packetType = uint8(ord(payload[2]))
  result.callId = readU32Le(payload, 12)
  if result.packetType != 12:
    result.message = "unexpected DCE/RPC packet type"
    return
  var offset = 16
  offset += 2
  offset += 2
  offset += 4
  if offset >= payload.len:
    result.message = "missing secondary address"
    return
  let addrLen = int(readU16Le(payload, offset))
  offset += 2 + addrLen
  if offset mod 4 != 0:
    offset += 4 - (offset mod 4)
  if offset + 6 <= payload.len:
    let resultCount = ord(payload[offset])
    if resultCount > 0:
      result.ackResult = readU16Le(payload, offset + 4)
      result.bound = result.ackResult == 0
      result.message = if result.bound: "DCE/RPC SRVSVC bind ack" else: "DCE/RPC bind rejected"

proc parseBindAckAuthValue*(payload: string): string =
  if payload.len < 16: return ""
  let authLen = int(readU16Le(payload, 10))
  if authLen == 0 or payload.len < authLen + 8: return ""
  result = payload[payload.len - authLen ..< payload.len]

proc buildSrvSvcNetShareEnumAllStub*(serverName: string; level = 1'u32; preferredMaxLen = 0xffffffff'u32): string =
  let server = "\\\\" & serverName & "\0"
  let serverUtf16 = toUtf16Le(server)
  let charCount = uint32(server.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add serverUtf16
  while result.len mod 4 != 0:
    result.add char(0)
  result.addU32Le level
  result.addU32Le level
  result.addU32Le 0x00020004'u32
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le preferredMaxLen
  result.addU32Le 0x00020008'u32
  result.addU32Le 0

proc buildDceRpcRequest*(opnum: uint16; stub: string; callId: uint32): string =
  result.add char(5)
  result.add char(0)
  result.add char(0)
  result.add char(3)
  result.addBytes [byte 0x10, 0, 0, 0]
  result.addU16Le (24 + stub.len).uint16
  result.addU16Le 0
  result.addU32Le callId
  result.addU32Le stub.len.uint32
  result.addU16Le 0
  result.addU16Le opnum
  result.add stub

proc parseDceRpcResponseStub*(payload: string): string =
  if payload.len < 24 or ord(payload[0]) != 5:
    return ""
  let packetType = ord(payload[2])
  if packetType != 2:
    return ""
  let fragLen = int(readU16Le(payload, 8))
  let authLen = int(readU16Le(payload, 10))
  let pduEnd = if fragLen > 0 and fragLen <= payload.len: fragLen else: payload.len
  var stubEnd = pduEnd
  if authLen > 0:
    stubEnd -= authLen + 8
  if stubEnd <= 24 or stubEnd > payload.len:
    return ""
  result = payload[24 ..< stubEnd]

proc readNdrUtf16String(data: string; offset: var int): string =
  if offset + 12 > data.len:
    return ""
  let maxCount = int(readU32Le(data, offset)); offset += 4
  discard readU32Le(data, offset); offset += 4
  let actualCount = int(readU32Le(data, offset)); offset += 4
  let bytesLen = actualCount * 2
  if maxCount < actualCount or actualCount < 0 or offset + bytesLen > data.len:
    return ""
  result = readUtf16LeAscii(data, offset, max(0, bytesLen - 2))
  offset += bytesLen
  while offset mod 4 != 0:
    inc offset

proc parseSrvSvcNetShareEnumAll*(stub: string): seq[SmbShareInfo] =
  if stub.len < 24:
    return @[]
  var levelOffset = -1
  var entryCount = 0
  var arrayOffset = -1

  var offset = 0
  while offset + 24 <= stub.len:
    if readU32Le(stub, offset) == 1:
      let count = int(readU32Le(stub, offset + 8))
      let bufferPtr = readU32Le(stub, offset + 12)
      let maxCount = int(readU32Le(stub, offset + 16))
      if count > 0 and count < 4096 and bufferPtr != 0 and maxCount == count and offset + 20 + count * 12 <= stub.len:
        levelOffset = offset
        entryCount = count
        arrayOffset = offset + 20
        break
    offset += 4

  if levelOffset < 0:
    return @[]

  var entries: seq[SmbShareInfo]
  var stringRefs: seq[tuple[index: int, field: int]]
  offset = arrayOffset
  for index in 0 ..< entryCount:
    if offset + 12 > stub.len:
      return @[]
    let namePtr = readU32Le(stub, offset)
    let typ = readU32Le(stub, offset + 4)
    let commentPtr = readU32Le(stub, offset + 8)
    entries.add SmbShareInfo(typ: typ)
    if namePtr != 0:
      stringRefs.add (index, 0)
    if commentPtr != 0:
      stringRefs.add (index, 1)
    offset += 12

  while offset mod 4 != 0:
    inc offset
  for refItem in stringRefs:
    let value = readNdrUtf16String(stub, offset)
    if refItem.field == 0:
      entries[refItem.index].name = value
    else:
      entries[refItem.index].comment = value

  for entry in entries:
    if entry.name.len > 0:
      result.add entry

proc dialectName(value: uint16): string =
  case value
  of 0x0202'u16: "SMB 2.0.2"
  of 0x0210'u16: "SMB 2.1"
  of 0x0300'u16: "SMB 3.0"
  of 0x0302'u16: "SMB 3.0.2"
  of 0x0311'u16: "SMB 3.1.1"
  else: "0x" & value.toHex(4)

proc parseSmbNegotiateResponse*(response: string): SmbNegotiateInfo =
  let body = 4 + 64
  if response.len < body + 60:
    return
  let securityMode = readU16Le(response, body + 2)
  let dialect = readU16Le(response, body + 4)
  let capabilities = readU32Le(response, body + 24)

  result = SmbNegotiateInfo(
    dialect: dialectName(dialect),
    securityMode: securityMode,
    signingEnabled: (securityMode and 0x0001'u16) != 0,
    signingRequired: (securityMode and 0x0002'u16) != 0,
    capabilities: capabilities,
    dfs: (capabilities and 0x00000001'u32) != 0,
    leasing: (capabilities and 0x00000002'u32) != 0,
    largeMtu: (capabilities and 0x00000004'u32) != 0,
    multiChannel: (capabilities and 0x00000008'u32) != 0,
    persistentHandles: (capabilities and 0x00000010'u32) != 0,
    directoryLeasing: (capabilities and 0x00000020'u32) != 0,
    encryption: (capabilities and 0x00000040'u32) != 0,
    maxTransactSize: readU32Le(response, body + 28),
    maxReadSize: readU32Le(response, body + 32),
    maxWriteSize: readU32Le(response, body + 36),
    serverGuid: formatGuid(response, body + 8)
  )

proc recvWithTimeout*(socket: AsyncSocket; size, timeoutMs: int): Future[string] {.async.}

type
  SmbRpcCtx* = ref object
    socket*: AsyncSocket
    host*: string
    sessionId*: uint64
    treeId*: uint32
    sessionKey*: string
    negotiate*: SmbNegotiateInfo
    signingEnabled*: bool
    signingApplied*: bool
    preauthHash*: string
    timeoutMs*: int
    mid*: uint64

proc nextMid*(ctx: SmbRpcCtx): uint64 =
  result = ctx.mid
  inc ctx.mid

proc signed*(ctx: SmbRpcCtx; packet: string): string =
  let r = maybeSign(packet, ctx.sessionKey, ctx.negotiate, ctx.signingEnabled,
    ctx.preauthHash)
  if r.signed:
    ctx.signingApplied = true
  r.data

proc addNdrPad4*(data: var string) =
  while data.len mod 4 != 0:
    data.add char(0)

proc addNdrPad2*(data: var string) =
  while data.len mod 2 != 0:
    data.add char(0)

proc addNdrUtf16NullTerminatedPtr*(data: var string; value: string; referent: uint32) =
  data.addU32Le referent
  let text = value & "\0"
  let count = uint32(text.len)
  data.addU32Le count
  data.addU32Le 0
  data.addU32Le count
  data.add toUtf16Le(text)
  data.addNdrPad4()

proc addNdrUnicodeStringHeader*(data: var string; value: string; referent: uint32) =
  let bytes = uint16(toUtf16Le(value).len)
  data.addU16Le bytes
  data.addU16Le bytes
  data.addU32Le referent

proc addNdrUnicodeStringBuffer*(data: var string; value: string) =
  let utf = toUtf16Le(value)
  let chars = uint32(value.len)
  data.addU32Le chars
  data.addU32Le 0
  data.addU32Le chars
  data.add utf
  data.addNdrPad4()

proc parseSidBytes*(data: string; offset: int): tuple[sid: string, length: int] =
  if offset + 8 > data.len:
    return ("", 0)
  let revision = ord(data[offset])
  let subAuth = ord(data[offset + 1])
  let total = 8 + subAuth * 4
  if offset + total > data.len:
    return ("", 0)
  var s = "S-" & $revision & "-"
  var authority: uint64 = 0
  for index in 0 ..< 6:
    authority = (authority shl 8) or uint64(ord(data[offset + 2 + index]))
  s.add $authority
  for index in 0 ..< subAuth:
    let value = readU32Le(data, offset + 8 + index * 4)
    s.add "-"
    s.add $value
  result = (s, total)

proc sidToBytes*(sid: string): string =
  var parts = sid.split('-')
  if parts.len < 3 or parts[0] != "S":
    return ""
  let revision = uint8(parseInt(parts[1]))
  let authority = uint64(parseBiggestUInt(parts[2]))
  let subAuths = parts[3 .. ^1]
  result.add char(revision)
  result.add char(subAuths.len)
  for shift in countdown(40, 0, 8):
    result.add char((authority shr shift) and 0xff)
  for value in subAuths:
    result.addU32Le uint32(parseBiggestUInt(value))

proc domainSidFromAccount*(accountSid: string): string =
  let parts = accountSid.split('-')
  if parts.len < 5:
    return accountSid
  result = parts[0 .. ^2].join("-")

proc readNdrUtf16Counted*(data: string; offset: var int): string =
  if offset + 12 > data.len:
    return ""
  let maxCount = int(readU32Le(data, offset)); offset += 4
  discard readU32Le(data, offset); offset += 4
  let actualCount = int(readU32Le(data, offset)); offset += 4
  let bytesLen = actualCount * 2
  if maxCount < actualCount or actualCount < 0 or offset + bytesLen > data.len:
    return ""
  var stripped = bytesLen
  if stripped >= 2 and data[offset + stripped - 2] == '\0' and data[offset + stripped - 1] == '\0':
    stripped -= 2
  result = readUtf16LeAscii(data, offset, stripped)
  offset += bytesLen
  while offset mod 4 != 0:
    inc offset

proc openSmbPipe*(ctx: SmbRpcCtx; pipeName: string): Future[SmbPipeInfo] {.async.} =
  let pkt = ctx.signed(buildSmbCreatePipeRequest(pipeName, ctx.nextMid(),
    ctx.sessionId, ctx.treeId))
  dbgDump("SEND create " & pipeName, pkt)
  await ctx.socket.send(pkt)
  let resp = await recvWithTimeout(ctx.socket, 4096, ctx.timeoutMs)
  dbgDump("RECV create " & pipeName, resp)
  result.attempted = true
  if resp.len >= 4 + Smb2HeaderLen and resp[4 .. 7] == "\xfeSMB":
    result = parseSmbCreatePipeResponse(resp)
  else:
    result.status = uint32.high

proc rpcBindPipe*(ctx: SmbRpcCtx; pipe: SmbPipeInfo; bindBytes: string): Future[DceRpcInfo] {.async.} =
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, bindBytes,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  discard await recvWithTimeout(ctx.socket, 1024, ctx.timeoutMs)
  let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(readPkt)
  let resp = await recvWithTimeout(ctx.socket, 8192, ctx.timeoutMs)
  let bindPayload = parseSmbReadData(resp)
  dbgDump("DCE/RPC BIND response", bindPayload)
  result = parseDceRpcBindAck(bindPayload)

type
  DceRpcCallResult* = object
    stub*: string
    packetType*: uint8
    faultStatus*: uint32

  NtlmSealContext* = ref object
    signKey*: string
    sealHandle*: Rc4State
    serverSealHandle*: Rc4State
    seqNum*: uint32
    sessionKey*: string

proc rpcCallEx*(ctx: SmbRpcCtx; pipe: SmbPipeInfo; opnum: uint16;
                stub: string; callId: uint32): Future[DceRpcCallResult] {.async.} =
  let req = buildDceRpcRequest(opnum, stub, callId)
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, req,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  var writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while writeAck.len >= 16 and readU32Le(writeAck, 12) == 0x00000103'u32:
    writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while true:
    let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
      ctx.nextMid(), ctx.sessionId, ctx.treeId))
    await ctx.socket.send(readPkt)
    var resp = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    while resp.len >= 16 and readU32Le(resp, 12) == 0x00000103'u32:
      resp = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    let payload = parseSmbReadData(resp)
    if payload.len < 24 or ord(payload[0]) != 5:
      break
    let pType = uint8(ord(payload[2]))
    let pfcFlags = ord(payload[3])
    result.packetType = pType
    if pType == 3'u8 and payload.len >= 28:
      result.faultStatus = readU32Le(payload, 24)
      break
    if pType != 2'u8:
      break
    let frag = parseDceRpcResponseStub(payload)
    result.stub.add frag
    if (pfcFlags and 0x02) != 0:
      break

proc rpcCall*(ctx: SmbRpcCtx; pipe: SmbPipeInfo; opnum: uint16;
              stub: string; callId: uint32): Future[string] {.async.} =
  let r = await rpcCallEx(ctx, pipe, opnum, stub, callId)
  result = r.stub

proc buildSealedDceRpcRequest(sealCtx: NtlmSealContext; opnum: uint16;
                               stub: string; callId: uint32): string =
  dbgDump("TSCH sealed STUB plaintext", stub)
  let padLen = (4 - ((24 + stub.len) mod 4)) mod 4
  var paddedStub = stub
  for _ in 0 ..< padLen: paddedStub.add char(0xBB)
  var hdr = ""
  hdr.add char(5); hdr.add char(0); hdr.add char(0); hdr.add char(3)
  hdr.addBytes [byte 0x10, 0, 0, 0]
  hdr.addU16Le uint16(24 + paddedStub.len + 8 + 16)
  hdr.addU16Le 16'u16
  hdr.addU32Le callId
  hdr.addU32Le uint32(stub.len)
  hdr.addU16Le 0'u16
  hdr.addU16Le opnum
  var secTrailer = ""
  secTrailer.add char(0x0a); secTrailer.add char(0x06)
  secTrailer.add char(padLen.uint8); secTrailer.add char(0)
  secTrailer.addU32Le 79231'u32
  let messageToSign = hdr & paddedStub & secTrailer
  var seqBuf = newString(4)
  seqBuf.setU32Le(0, sealCtx.seqNum)
  sealCtx.seqNum += 1
  let encStub = rc4Process(sealCtx.sealHandle, paddedStub)
  let hmac = hmacMd5(sealCtx.signKey, seqBuf & messageToSign)
  let encHmac = rc4Process(sealCtx.sealHandle, hmac[0..7])
  let signature = "\x01\x00\x00\x00" & encHmac & seqBuf
  result = hdr & encStub & secTrailer & signature

proc unsealDceRpcResponseStub(sealCtx: NtlmSealContext; payload: string): string =
  let authLen = int(readU16Le(payload, 10))
  if authLen == 0: return parseDceRpcResponseStub(payload)
  let authVerifOffset = payload.len - authLen - 8
  if authVerifOffset < 24: return ""
  let padLen = int(ord(payload[authVerifOffset + 2]))
  let encStub = payload[24 ..< authVerifOffset]
  let decStub = rc4Process(sealCtx.serverSealHandle, encStub)
  if payload.len - authLen + 12 <= payload.len:
    discard rc4Process(sealCtx.serverSealHandle, payload[payload.len - authLen + 4 ..< payload.len - authLen + 12])
  result = decStub[0 ..< max(0, decStub.len - padLen)]

proc rpcBindPipeNtlm*(ctx: SmbRpcCtx; pipe: SmbPipeInfo;
                      interfaceUuid: seq[byte]; versionMajor, versionMinor: uint16;
                      credential: SmbCredential; callId = 1'u32): Future[tuple[info: DceRpcInfo; sealCtx: NtlmSealContext]] {.async.} =
  let type1 = buildNtlmType1Rpc()
  let bindPdu = buildDceRpcBindAuth(interfaceUuid, versionMajor, versionMinor, type1, callId)
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, bindPdu,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  discard await recvWithTimeout(ctx.socket, 4096, ctx.timeoutMs)
  let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(readPkt)
  let resp = await recvWithTimeout(ctx.socket, 8192, ctx.timeoutMs)
  let bindAckPayload = parseSmbReadData(resp)
  result.info = parseDceRpcBindAck(bindAckPayload)
  dbgDump("TSCH BIND_ACK raw", bindAckPayload)
  if not result.info.bound:
    result.info.message = "TSCH NTLM bind rejected (ackResult=" & $result.info.ackResult & ")"
    return
  let authValue = parseBindAckAuthValue(bindAckPayload)
  let challenge = parseNtlmChallenge(authValue)
  if not challenge.offered:
    result.info.bound = false
    result.info.message = "TSCH BIND_ACK has no NTLM challenge"
    return
  let clientChallenge = randomBytes(8)
  let (type3Token, exportedKey) = buildNtlmType3Rpc(credential, challenge, clientChallenge, type1, authValue)
  let auth3Pdu = buildDceRpcAuth3(type3Token, callId)
  let write3Pkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, auth3Pdu,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(write3Pkt)
  let auth3Ack = await recvWithTimeout(ctx.socket, 4096, ctx.timeoutMs)
  dbgDump("TSCH AUTH3 WRITE_ACK", auth3Ack)
  let keys = rpcDeriveKeys(exportedKey)
  result.sealCtx = NtlmSealContext(
    signKey: keys.cSign,
    sealHandle: rc4Init(keys.cSeal),
    serverSealHandle: rc4Init(keys.sSeal),
    sessionKey: exportedKey)

proc rpcCallExSealed*(ctx: SmbRpcCtx; pipe: SmbPipeInfo;
                      sealCtx: NtlmSealContext;
                      opnum: uint16; stub: string; callId: uint32): Future[DceRpcCallResult] {.async.} =
  let req = buildSealedDceRpcRequest(sealCtx, opnum, stub, callId)
  dbgDump("TSCH sealed REQUEST", req)
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, req,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  var writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while writeAck.len >= 16 and readU32Le(writeAck, 12) == 0x00000103'u32:
    writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while true:
    let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
      ctx.nextMid(), ctx.sessionId, ctx.treeId))
    await ctx.socket.send(readPkt)
    var resp2 = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    while resp2.len >= 16 and readU32Le(resp2, 12) == 0x00000103'u32:
      resp2 = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    let payload = parseSmbReadData(resp2)
    if payload.len < 24 or ord(payload[0]) != 5: break
    let pType = uint8(ord(payload[2]))
    let pfcFlags = ord(payload[3])
    result.packetType = pType
    if pType == 3'u8:
      dbgDump("TSCH sealed FAULT raw", payload)
      let decFault = unsealDceRpcResponseStub(sealCtx, payload)
      dbgDump("TSCH sealed FAULT decrypted", decFault)
      result.faultStatus = if decFault.len >= 4: readU32Le(decFault, 0) else: readU32Le(payload, 24)
      break
    if pType != 2'u8: break
    result.stub.add unsealDceRpcResponseStub(sealCtx, payload)
    if (pfcFlags and 0x02) != 0: break

type KerbSealContext* = ref object
  kc*: krb.KerberosContext

proc buildKerbSealedDceRpcRequest(sealCtx: KerbSealContext; opnum: uint16;
                                   stub: string; callId: uint32): string =
  let padLen = (4 - ((24 + stub.len) mod 4)) mod 4
  var paddedStub = stub
  for _ in 0 ..< padLen: paddedStub.add char(0)
  let wrapped = sealCtx.kc.wrapDce(paddedStub)
  if smbDebug:
    stderr.writeLine("[kerbSeal] opnum=" & $opnum & " stub.len=" & $stub.len &
      " padded.len=" & $paddedStub.len & " token.len=" & $wrapped.header.len)
  let authLen = uint16(wrapped.header.len)
  var pduHdr = ""
  pduHdr.add char(5); pduHdr.add char(0); pduHdr.add char(0); pduHdr.add char(3)
  pduHdr.addBytes [byte 0x10, 0, 0, 0]
  pduHdr.addU16Le uint16(24 + paddedStub.len + 8 + int(authLen))
  pduHdr.addU16Le authLen
  pduHdr.addU32Le callId
  pduHdr.addU32Le uint32(stub.len)
  pduHdr.addU16Le 0'u16
  pduHdr.addU16Le opnum
  var secTrailer = ""
  secTrailer.add char(0x09); secTrailer.add char(0x06)
  secTrailer.add char(padLen.uint8); secTrailer.add char(0)
  secTrailer.addU32Le 79231'u32
  result = pduHdr & wrapped.encrypted & secTrailer & wrapped.header

proc unsealKerbDceRpcResponseStub(sealCtx: KerbSealContext; payload: string): string =
  let authLen = int(readU16Le(payload, 10))
  if authLen == 0: return parseDceRpcResponseStub(payload)
  let authVerifOffset = payload.len - authLen - 8
  if authVerifOffset < 24: return ""
  let padLen = int(ord(payload[authVerifOffset + 2]))
  let pduHdr = payload[0 ..< 24]
  let encStub = payload[24 ..< authVerifOffset]
  let secTrailer = payload[authVerifOffset ..< authVerifOffset + 8]
  let fullToken = payload[payload.len - authLen ..< payload.len]
  let expectedTokenLen = sealCtx.kc.getDce2TokenSize(encStub.len)
  let token =
    if expectedTokenLen > 0 and expectedTokenLen < fullToken.len:
      fullToken[0 ..< expectedTokenLen]
    else:
      fullToken
  if smbDebug:
    stderr.writeLine("[kerbUnseal] ptype=" & $ord(payload[2]) & " authLen=" & $authLen &
      " encStub.len=" & $encStub.len & " padLen=" & $padLen &
      " expectedToken.len=" & $expectedTokenLen & " token.len=" & $token.len)
    dbgDump("TSCH kerb RESPONSE raw", payload)
  var decStub = sealCtx.kc.unwrapDce(token, encStub)
  if decStub.len == 0:
    decStub = sealCtx.kc.unwrapDce4(pduHdr, encStub, secTrailer, token)
  result = decStub[0 ..< max(0, decStub.len - padLen)]

proc rpcBindPipeKerb*(ctx: SmbRpcCtx; pipe: SmbPipeInfo;
                      interfaceUuid: seq[byte]; versionMajor, versionMinor: uint16;
                      host, domain: string; callId = 1'u32;
                      ccache = ""; krb5Config = ""): Future[tuple[info: DceRpcInfo; sealCtx: KerbSealContext]] {.async.} =
  let oldCc = if existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME") else: ""
  let hadCc = existsEnv("KRB5CCNAME")
  let oldCfg = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadCfg = existsEnv("KRB5_CONFIG")
  if ccache.len > 0:
    if ccache.startsWith("FILE:") or ccache.startsWith("MEMORY:") or ccache.startsWith("API:"):
      putEnv("KRB5CCNAME", ccache)
    else:
      putEnv("KRB5CCNAME", "FILE:" & expandFilename(ccache))
  if krb5Config.len > 0:
    putEnv("KRB5_CONFIG", expandFilename(krb5Config))
  defer:
    if ccache.len > 0:
      if hadCc: putEnv("KRB5CCNAME", oldCc)
      else: delEnv("KRB5CCNAME")
    if krb5Config.len > 0:
      if hadCfg: putEnv("KRB5_CONFIG", oldCfg)
      else: delEnv("KRB5_CONFIG")
  let kc = krb.newKerberosContext("cifs", host, domain)
  let tok = kc.stepWithFlags("", 0x3e'u32)
  if tok.token.len == 0:
    result.info.message = "Kerberos produced no AP-REQ token for DCE/RPC bind"
    kc.close()
    return
  let ifaceUuid = dceUuid(interfaceUuid)
  let ndrUuid = dceUuid(NdrUuidBytes)
  var body = ""
  body.addU16Le 4280; body.addU16Le 4280; body.addU32Le 0
  body.add char(1); body.add char(0); body.addU16Le 0
  body.addU16Le 0; body.add char(1); body.add char(0)
  body.add ifaceUuid; body.addU16Le versionMajor; body.addU16Le versionMinor
  body.add ndrUuid; body.addU32Le 2
  var bindPdu = ""
  bindPdu.add char(5); bindPdu.add char(0); bindPdu.add char(11); bindPdu.add char(3)
  bindPdu.addBytes [byte 0x10, 0, 0, 0]
  bindPdu.addU16Le uint16(16 + body.len + 8 + tok.token.len)
  bindPdu.addU16Le uint16(tok.token.len)
  bindPdu.addU32Le callId
  bindPdu.add body
  bindPdu.add char(0x09); bindPdu.add char(0x06); bindPdu.add char(0); bindPdu.add char(0)
  bindPdu.addU32Le 79231'u32
  bindPdu.add tok.token
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, bindPdu,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  discard await recvWithTimeout(ctx.socket, 4096, ctx.timeoutMs)
  let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(readPkt)
  let resp = await recvWithTimeout(ctx.socket, 8192, ctx.timeoutMs)
  let bindAckPayload = parseSmbReadData(resp)
  result.info = parseDceRpcBindAck(bindAckPayload)
  if not result.info.bound:
    result.info.message = "Kerberos DCE/RPC bind rejected (ackResult=" & $result.info.ackResult & ")"
    kc.close()
    return
  let authValue = parseBindAckAuthValue(bindAckPayload)
  if authValue.len > 0:
    try:
      discard kc.stepWithFlags(authValue, 0x3e'u32)
    except CatchableError:
      discard
  result.sealCtx = KerbSealContext(kc: kc)

proc rpcCallExKerbSealed*(ctx: SmbRpcCtx; pipe: SmbPipeInfo;
                           sealCtx: KerbSealContext;
                           opnum: uint16; stub: string; callId: uint32): Future[DceRpcCallResult] {.async.} =
  let req = buildKerbSealedDceRpcRequest(sealCtx, opnum, stub, callId)
  let writePkt = ctx.signed(buildSmbWriteRequest(pipe.fileId, req,
    ctx.nextMid(), ctx.sessionId, ctx.treeId))
  await ctx.socket.send(writePkt)
  var writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while writeAck.len >= 16 and readU32Le(writeAck, 12) == 0x00000103'u32:
    writeAck = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
  while true:
    let readPkt = ctx.signed(buildSmbReadRequest(pipe.fileId, 4280,
      ctx.nextMid(), ctx.sessionId, ctx.treeId))
    await ctx.socket.send(readPkt)
    var resp2 = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    while resp2.len >= 16 and readU32Le(resp2, 12) == 0x00000103'u32:
      resp2 = await recvWithTimeout(ctx.socket, 65535, ctx.timeoutMs)
    let payload = parseSmbReadData(resp2)
    if payload.len < 24 or ord(payload[0]) != 5: break
    let pType = uint8(ord(payload[2]))
    let pfcFlags = ord(payload[3])
    result.packetType = pType
    if pType == 3'u8:
      let decFault = unsealKerbDceRpcResponseStub(sealCtx, payload)
      result.faultStatus = if decFault.len >= 4: readU32Le(decFault, 0) else: readU32Le(payload, 24)
      break
    if pType != 2'u8: break
    result.stub.add unsealKerbDceRpcResponseStub(sealCtx, payload)
    if (pfcFlags and 0x02) != 0: break

proc recvOneSmb*(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  result = await recvWithTimeout(socket, 65535, timeoutMs)

proc recvWithTimeout*(socket: AsyncSocket; size, timeoutMs: int): Future[string] {.async.} =
  let deadline = epochTime() + timeoutMs.float / 1000.0
  var buffer = ""
  while buffer.len < 4:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0:
      return ""
    let recvFuture = socket.recv(4 - buffer.len)
    if not await withTimeout(recvFuture, remaining):
      return ""
    let chunk = await recvFuture
    if chunk.len == 0:
      return ""
    buffer.add chunk
  let payloadLen =
    (int(ord(buffer[1])) shl 16) or
    (int(ord(buffer[2])) shl 8) or
    int(ord(buffer[3]))
  let want = min(payloadLen, max(0, size - 4))
  while buffer.len < 4 + want:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0:
      return buffer
    let recvFuture = socket.recv(4 + want - buffer.len)
    if not await withTimeout(recvFuture, remaining):
      return buffer
    let chunk = await recvFuture
    if chunk.len == 0:
      return buffer
    buffer.add chunk
  result = buffer


proc buildSrvSvcNetSessEnumStub*(serverName: string; level = 10'u32;
                                 preferredMaxLen = 0xffffffff'u32): string =
  let server = "\\\\" & serverName & "\0"
  let charCount = uint32(server.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add toUtf16Le(server)
  result.addNdrPad4()
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le level
  result.addU32Le level
  result.addU32Le 0x00020004'u32
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le preferredMaxLen
  result.addU32Le 0x00020008'u32
  result.addU32Le 0

proc parseSrvSvcNetSessEnum*(stub: string): SmbEnumResult[SmbSessionInfo] =
  result.attempted = true
  if stub.len < 16:
    result.message = "short response"
    return
  var offset = 0
  let level = readU32Le(stub, offset); offset += 4
  discard readU32Le(stub, offset); offset += 4
  let containerPtr = readU32Le(stub, offset); offset += 4
  if containerPtr == 0:
    result.succeeded = true
    return
  let entriesRead = int(readU32Le(stub, offset)); offset += 4
  let bufferPtr = readU32Le(stub, offset); offset += 4
  if bufferPtr == 0 or entriesRead == 0:
    result.succeeded = true
    return
  let maxCount = int(readU32Le(stub, offset)); offset += 4
  if maxCount != entriesRead:
    result.message = "session array bounds mismatch"
    return
  var perEntry: int
  case level
  of 0: perEntry = 4
  of 1: perEntry = 24
  of 2: perEntry = 28
  of 10: perEntry = 16
  of 502: perEntry = 32
  else: perEntry = 16
  var entries = newSeq[SmbSessionInfo](entriesRead)
  var strRefs: seq[tuple[idx, field: int]]
  for index in 0 ..< entriesRead:
    if offset + perEntry > stub.len: return
    let clientPtr = readU32Le(stub, offset)
    let userPtr = readU32Le(stub, offset + 4)
    case level
    of 10:
      entries[index].activeSeconds = readU32Le(stub, offset + 8)
      entries[index].idleSeconds = readU32Le(stub, offset + 12)
    of 1, 2, 502:
      entries[index].openFiles = readU32Le(stub, offset + 8)
      entries[index].activeSeconds = readU32Le(stub, offset + 12)
      entries[index].idleSeconds = readU32Le(stub, offset + 16)
    else: discard
    if clientPtr != 0: strRefs.add (index, 0)
    if userPtr != 0: strRefs.add (index, 1)
    offset += perEntry
  for refItem in strRefs:
    let value = readNdrUtf16Counted(stub, offset)
    case refItem.field
    of 0: entries[refItem.idx].clientName = value
    else: entries[refItem.idx].userName = value
  result.entries = entries
  result.succeeded = true
  if offset + 4 <= stub.len:
    result.rpcStatus = readU32Le(stub, stub.len - 4)


proc buildSrvSvcNetServerDiskEnumStub*(serverName: string;
                                       preferredMaxLen = 0xffffffff'u32): string =
  let server = "\\\\" & serverName & "\0"
  let charCount = uint32(server.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add toUtf16Le(server)
  result.addNdrPad4()
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le preferredMaxLen
  result.addU32Le 0x00020004'u32
  result.addU32Le 0

proc parseSrvSvcNetServerDiskEnum*(stub: string): SmbEnumResult[SmbDiskInfo] =
  result.attempted = true
  result.succeeded = true
  if stub.len < 6:
    return
  var offset = 0
  while offset + 6 <= stub.len:
    let c0 = ord(stub[offset])
    let c1 = ord(stub[offset + 1])
    let c2 = ord(stub[offset + 2])
    let c3 = ord(stub[offset + 3])
    let c4 = ord(stub[offset + 4])
    let c5 = ord(stub[offset + 5])
    if c1 == 0 and c3 == 0 and c5 == 0 and c2 == ord(':') and c4 == 0 and
        ((c0 >= ord('A') and c0 <= ord('Z')) or (c0 >= ord('a') and c0 <= ord('z'))):
      result.entries.add SmbDiskInfo(drive: $char(c0) & ":")
      offset += 6
    else:
      offset += 2


proc buildWksSvcNetWkstaUserEnumStub*(serverName: string; level = 1'u32;
                                      preferredMaxLen = 0xffffffff'u32): string =
  let server = "\\\\" & serverName & "\0"
  let charCount = uint32(server.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add toUtf16Le(server)
  result.addNdrPad4()
  result.addU32Le level
  result.addU32Le level
  result.addU32Le 0x00020004'u32
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le preferredMaxLen
  result.addU32Le 0x00020008'u32
  result.addU32Le 0

proc parseWksSvcNetWkstaUserEnum*(stub: string): SmbEnumResult[SmbLoggedOnUser] =
  result.attempted = true
  if stub.len < 16:
    result.message = "short response"
    return
  var offset = 0
  let level = readU32Le(stub, offset); offset += 4
  discard readU32Le(stub, offset); offset += 4
  let containerPtr = readU32Le(stub, offset); offset += 4
  if containerPtr == 0:
    result.succeeded = true
    return
  let entriesRead = int(readU32Le(stub, offset)); offset += 4
  let bufferPtr = readU32Le(stub, offset); offset += 4
  if bufferPtr == 0 or entriesRead == 0:
    result.succeeded = true
    return
  let maxCount = int(readU32Le(stub, offset)); offset += 4
  if maxCount != entriesRead:
    result.message = "user array bounds mismatch"
    return
  let fieldsPerEntry = if level == 1: 4 else: 1
  var entries = newSeq[SmbLoggedOnUser](entriesRead)
  var strRefs: seq[tuple[idx, field: int]]
  for index in 0 ..< entriesRead:
    if offset + fieldsPerEntry * 4 > stub.len: return
    for field in 0 ..< fieldsPerEntry:
      let ptrValue = readU32Le(stub, offset + field * 4)
      if ptrValue != 0: strRefs.add (index, field)
    offset += fieldsPerEntry * 4
  for refItem in strRefs:
    let value = readNdrUtf16Counted(stub, offset)
    case refItem.field
    of 0: entries[refItem.idx].userName = value
    of 1: entries[refItem.idx].logonDomain = value
    of 2: entries[refItem.idx].otherDomains = value
    of 3: entries[refItem.idx].logonServer = value
    else: discard
  result.entries = entries
  result.succeeded = true


const
  SamrAccessMaxAllowed* = 0x02000000'u32
  SamrDomainListAccounts* = 0x00000200'u32

proc buildSamrConnect5Stub*(serverName: string;
                            desiredAccess = SamrAccessMaxAllowed): string =
  let server = "\\\\" & serverName & "\0"
  let charCount = uint32(server.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add toUtf16Le(server)
  result.addNdrPad4()
  result.addU32Le desiredAccess
  result.addU32Le 1
  result.addU32Le 1
  result.addU32Le 3
  result.addU32Le 0

proc parseSamrConnect5*(stub: string): tuple[handle: string, status: uint32] =
  if stub.len < 4 + 4 + 8 + 20 + 4:
    return ("", uint32.high)
  var offset = 0
  offset += 4
  offset += 4
  offset += 8
  if offset + 20 > stub.len: return ("", uint32.high)
  result.handle = stub[offset ..< offset + 20]
  offset += 20
  if offset + 4 <= stub.len:
    result.status = readU32Le(stub, offset)
  else:
    result.status = 0

proc buildSamrEnumDomainsStub*(serverHandle: string;
                               enumContext = 0'u32;
                               preferredMaxLen = 0xffffffff'u32): string =
  if serverHandle.len != 20:
    raise newException(ValueError, "SAMR server handle must be 20 bytes")
  result.add serverHandle
  result.addU32Le enumContext
  result.addU32Le preferredMaxLen

proc parseSamrEnumeration(stub: string;
                          extractRid: bool): tuple[entries: seq[SmbDomainGroup],
                                                   status: uint32] =
  if stub.len < 16:
    result.status = uint32.high
    return
  var offset = 4
  let bufferPtr = readU32Le(stub, offset); offset += 4
  if bufferPtr == 0:
    if stub.len >= 8:
      result.status = readU32Le(stub, stub.len - 4)
    return
  let entriesRead = int(readU32Le(stub, offset)); offset += 4
  let arrayPtr = readU32Le(stub, offset); offset += 4
  if arrayPtr == 0 or entriesRead == 0:
    if stub.len >= 4:
      result.status = readU32Le(stub, stub.len - 4)
    return
  if offset + 4 > stub.len: return
  let maxCount = int(readU32Le(stub, offset)); offset += 4
  if maxCount != entriesRead: return
  var entries = newSeq[SmbDomainGroup](entriesRead)
  var strRefs: seq[int]
  for index in 0 ..< entriesRead:
    if offset + 12 > stub.len: return
    let rid = readU32Le(stub, offset)
    let namePtr = readU32Le(stub, offset + 8)
    if extractRid:
      entries[index].rid = rid
    if namePtr != 0:
      strRefs.add index
    offset += 12
  for index in strRefs:
    entries[index].name = readNdrUtf16Counted(stub, offset)
  result.entries = entries
  if stub.len >= 4:
    result.status = readU32Le(stub, stub.len - 4)

proc parseSamrEnumDomains*(stub: string): tuple[domains: seq[SmbDomainInfo], status: uint32] =
  let raw = parseSamrEnumeration(stub, extractRid = false)
  result.status = raw.status
  for item in raw.entries:
    result.domains.add SmbDomainInfo(name: item.name)

proc buildSamrLookupDomainStub*(serverHandle: string; name: string): string =
  if serverHandle.len != 20:
    raise newException(ValueError, "SAMR server handle must be 20 bytes")
  result.add serverHandle
  result.addNdrUnicodeStringHeader(name, 0x00020000'u32)
  result.addNdrUnicodeStringBuffer(name)

proc parseSamrLookupDomain*(stub: string): tuple[sid: string, status: uint32] =
  if stub.len < 12:
    result.status = uint32.high
    return
  var offset = 0
  let sidPtr = readU32Le(stub, offset); offset += 4
  if sidPtr == 0:
    if stub.len >= 4:
      result.status = readU32Le(stub, stub.len - 4)
    return
  let maxCount = int(readU32Le(stub, offset)); offset += 4
  if offset + 8 > stub.len: return
  let parsed = parseSidBytes(stub, offset)
  if parsed.length == 0: return
  result.sid = parsed.sid
  offset += parsed.length
  while offset mod 4 != 0: inc offset
  if offset + 4 <= stub.len:
    result.status = readU32Le(stub, offset)

proc buildSamrOpenDomainStub*(serverHandle: string;
                              domainSid: string;
                              desiredAccess = SamrAccessMaxAllowed): string =
  if serverHandle.len != 20:
    raise newException(ValueError, "SAMR server handle must be 20 bytes")
  let sidBytes = sidToBytes(domainSid)
  if sidBytes.len < 8:
    raise newException(ValueError, "invalid domain SID for SamrOpenDomain")
  let subAuthCount = uint32(ord(sidBytes[1]))
  result.add serverHandle
  result.addU32Le desiredAccess
  result.addU32Le subAuthCount
  result.add sidBytes
  result.addNdrPad4()

proc parseSamrOpenDomain*(stub: string): tuple[handle: string, status: uint32] =
  if stub.len < 24:
    result.status = uint32.high
    return
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc buildSamrEnumDomainUsersStub*(domainHandle: string;
                                   enumContext = 0'u32;
                                   userAccountControl = 0'u32;
                                   preferredMaxLen = 0xffffffff'u32): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU32Le enumContext
  result.addU32Le userAccountControl
  result.addU32Le preferredMaxLen

proc buildSamrEnumDomainGroupsStub*(domainHandle: string;
                                    enumContext = 0'u32;
                                    preferredMaxLen = 0xffffffff'u32): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU32Le enumContext
  result.addU32Le preferredMaxLen

proc buildSamrEnumDomainAliasesStub*(domainHandle: string;
                                     enumContext = 0'u32;
                                     preferredMaxLen = 0xffffffff'u32): string =
  buildSamrEnumDomainGroupsStub(domainHandle, enumContext, preferredMaxLen)

proc parseSamrEnumUsers*(stub: string): tuple[users: seq[SmbDomainUser], status: uint32] =
  let raw = parseSamrEnumeration(stub, extractRid = true)
  result.status = raw.status
  for item in raw.entries:
    result.users.add SmbDomainUser(rid: item.rid, name: item.name)

proc parseSamrEnumGroups*(stub: string; kind: string): tuple[groups: seq[SmbDomainGroup], status: uint32] =
  let raw = parseSamrEnumeration(stub, extractRid = true)
  result.status = raw.status
  for item in raw.entries:
    var g = item
    g.kind = kind
    result.groups.add g

proc buildSamrQueryInformationDomainStub*(domainHandle: string;
                                          level: uint16): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU16Le level
  result.addNdrPad4()

proc readI64Le(data: string; offset: int): int64 =
  if offset + 7 >= data.len: return 0
  var raw: uint64 = 0
  for shift in countup(0, 56, 8):
    raw = raw or (uint64(ord(data[offset + (shift div 8)])) shl shift)
  cast[int64](raw)

proc filetimeToMinutes(value: int64): int64 =
  if value == 0 or value == int64.low: return 0
  let absVal = -value
  absVal div 600000000

proc filetimeToDays(value: int64): int64 =
  let mins = filetimeToMinutes(value)
  if mins == 0: 0'i64 else: mins div 1440

proc parseSamrPasswordPolicy*(stub: string): SmbEnumResult[SmbPasswordPolicy] =
  result.attempted = true
  if stub.len < 8:
    result.message = "short response"
    return
  var offset = 0
  let bufferPtr = readU32Le(stub, offset); offset += 4
  if bufferPtr == 0:
    result.message = "no policy buffer"
    if stub.len >= 4:
      result.rpcStatus = readU32Le(stub, stub.len - 4)
    return
  offset += 2
  while offset mod 4 != 0: inc offset
  if offset + 24 > stub.len:
    result.message = "truncated password policy"
    return
  var pol: SmbPasswordPolicy
  pol.minPasswordLength = readU16Le(stub, offset); offset += 2
  pol.passwordHistory = readU16Le(stub, offset); offset += 2
  pol.passwordProperties = readU32Le(stub, offset); offset += 4
  pol.maxPasswordAgeDays = filetimeToDays(readI64Le(stub, offset)); offset += 8
  pol.minPasswordAgeDays = filetimeToDays(readI64Le(stub, offset)); offset += 8
  result.entries.add pol
  result.succeeded = true
  if stub.len >= 4:
    result.rpcStatus = readU32Le(stub, stub.len - 4)

proc mergeLockoutInfo*(policy: var SmbEnumResult[SmbPasswordPolicy]; stub: string) =
  if policy.entries.len == 0 or stub.len < 8: return
  var offset = 0
  let bufferPtr = readU32Le(stub, offset); offset += 4
  if bufferPtr == 0: return
  offset += 2
  while offset mod 4 != 0: inc offset
  if offset + 20 > stub.len: return
  let lockoutDuration = readI64Le(stub, offset); offset += 8
  let lockoutWindow = readI64Le(stub, offset); offset += 8
  let lockoutThreshold = readU16Le(stub, offset); offset += 2
  policy.entries[0].lockoutDurationMinutes = filetimeToMinutes(lockoutDuration)
  policy.entries[0].lockoutWindowMinutes = filetimeToMinutes(lockoutWindow)
  policy.entries[0].lockoutThreshold = lockoutThreshold


proc buildLsarOpenPolicy2Stub*(systemName: string;
                               desiredAccess = 0x02000000'u32): string =
  if systemName.len > 0:
    let host = "\\\\" & systemName & "\0"
    let charCount = uint32(host.len)
    result.addU32Le 0x00020000'u32
    result.addU32Le charCount
    result.addU32Le 0
    result.addU32Le charCount
    result.add toUtf16Le(host)
    result.addNdrPad4()
  else:
    result.addU32Le 0
  result.addU32Le 24
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le desiredAccess

proc parseLsarOpenPolicy2*(stub: string): tuple[handle: string, status: uint32] =
  if stub.len < 24:
    result.status = uint32.high
    return
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc buildLsarLookupSidsStub*(policyHandle: string;
                              sids: openArray[string];
                              lookupLevel: uint16 = 1): string =
  if policyHandle.len != 20:
    raise newException(ValueError, "LSARPC policy handle must be 20 bytes")
  result.add policyHandle
  result.addU32Le uint32(sids.len)
  result.addU32Le 0x00020000'u32
  result.addU32Le uint32(sids.len)
  var referent = 0x00020004'u32
  for _ in sids:
    result.addU32Le referent
    referent += 4
  for sid in sids:
    let bytes = sidToBytes(sid)
    let subAuth = uint32(ord(bytes[1]))
    result.addU32Le subAuth
    result.add bytes
    result.addNdrPad4()
  result.addU32Le 0
  result.addU32Le 0
  result.addU16Le lookupLevel
  result.addNdrPad4()
  result.addU32Le 0

proc parseLsarLookupSids*(stub: string; sids: openArray[string]): seq[SmbRidLookup] =
  if stub.len < 20: return
  var offset = 0
  let domPtr = readU32Le(stub, offset); offset += 4
  var domainNames: seq[string]
  if domPtr != 0:
    if offset + 12 > stub.len: return
    let entries = int(readU32Le(stub, offset)); offset += 4
    let domArrPtr = readU32Le(stub, offset); offset += 4
    let maxEntries = int(readU32Le(stub, offset)); offset += 4
    if domArrPtr != 0 and entries > 0:
      if offset + 4 > stub.len: return
      let arrayCount = int(readU32Le(stub, offset)); offset += 4
      var domNameRefs: seq[bool]
      for _ in 0 ..< arrayCount:
        if offset + 12 > stub.len: return
        discard readU16Le(stub, offset)
        discard readU16Le(stub, offset + 2)
        let namePtr = readU32Le(stub, offset + 4)
        discard readU32Le(stub, offset + 8)
        domNameRefs.add (namePtr != 0)
        offset += 12
      for hasName in domNameRefs:
        if hasName:
          domainNames.add readNdrUtf16Counted(stub, offset)
        else:
          domainNames.add ""
      for hasName in domNameRefs:
        if offset + 8 > stub.len: return
        let subAuth = int(readU32Le(stub, offset)); offset += 4
        let sidLen = 8 + 4 * subAuth
        if offset + sidLen > stub.len: return
        offset += sidLen
        while offset mod 4 != 0: inc offset
  if offset + 8 > stub.len: return
  let nameCount = int(readU32Le(stub, offset)); offset += 4
  let namesPtr = readU32Le(stub, offset); offset += 4
  if namesPtr == 0 or nameCount == 0:
    return
  if offset + 4 > stub.len: return
  let arrLen = int(readU32Le(stub, offset)); offset += 4
  var nameInfos = newSeq[tuple[sidType: uint32, hasName: bool, domainIndex: int32]](arrLen)
  for index in 0 ..< arrLen:
    if offset + 16 > stub.len: return
    let sidType = readU32Le(stub, offset); offset += 4
    discard readU16Le(stub, offset); offset += 2
    discard readU16Le(stub, offset); offset += 2
    let namePtr = readU32Le(stub, offset); offset += 4
    let domainIndex = cast[int32](readU32Le(stub, offset)); offset += 4
    nameInfos[index] = (sidType, namePtr != 0, domainIndex)
  var output: seq[SmbRidLookup]
  for index in 0 ..< arrLen:
    var entry = SmbRidLookup(sidType: nameInfos[index].sidType)
    if index < sids.len:
      let parts = sids[index].split('-')
      if parts.len > 0:
        try: entry.rid = uint32(parseBiggestUInt(parts[^1])) except: discard
    if nameInfos[index].hasName:
      entry.name = readNdrUtf16Counted(stub, offset)
    let di = nameInfos[index].domainIndex
    if di >= 0 and di.int < domainNames.len:
      entry.domain = domainNames[di.int]
    output.add entry
  result = output


type
  SmbExtrasResult* = object
    sessions*: SmbEnumResult[SmbSessionInfo]
    disks*: SmbEnumResult[SmbDiskInfo]
    loggedOnUsers*: SmbEnumResult[SmbLoggedOnUser]
    domains*: seq[SmbDomainInfo]
    domainUsers*: SmbEnumResult[SmbDomainUser]
    domainGroups*: SmbEnumResult[SmbDomainGroup]
    passwordPolicy*: SmbEnumResult[SmbPasswordPolicy]
    ridBrute*: SmbEnumResult[SmbRidLookup]
    localAdmins*: SmbEnumResult[SmbLocalGroupMember]
    rdpUsers*: SmbEnumResult[SmbLocalGroupMember]
    dcomUsers*: SmbEnumResult[SmbLocalGroupMember]
    psRemoteUsers*: SmbEnumResult[SmbLocalGroupMember]

  SamrAddComputerResult* = object
    host*: string
    port*: int
    authenticated*: bool
    success*: bool
    computerName*: string
    samAccountName*: string
    domainName*: string
    domainSid*: string
    rid*: uint32
    createStatus*: uint32
    passwordStatus*: uint32
    controlStatus*: uint32
    message*: string
    error*: string

  SamrChangePasswdResult* = object
    host*: string
    port*: int
    authenticated*: bool
    success*: bool
    rid*: uint32
    status*: uint32
    message*: string
    error*: string

const
  SamrServerEnumDomains = 0x00000010'u32
  SamrServerLookupDomain = 0x00000020'u32
  SamrDomainCreateUser = 0x00000010'u32
  SamrDomainLookup = 0x00000200'u32
  SamrUserWorkstationTrust = 0x00000080'u32
  SamrUserForcePasswordChange = 0x00000100'u32
  SamrUserControlInformation = 16'u16
  SamrUserInternal5InformationNew = 26'u16

proc normalizeComputerSam(name: string): string =
  var clean = name.strip()
  while clean.endsWith("$"):
    clean.setLen(clean.len - 1)
  clean & "$"

proc buildSamrCreateUser2InDomainStub*(domainHandle: string; name: string;
                                       accountType = SamrUserWorkstationTrust;
                                       desiredAccess = SamrUserForcePasswordChange): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addNdrUnicodeStringHeader(name, 0x00020000'u32)
  result.addNdrUnicodeStringBuffer(name)
  result.addU32Le accountType
  result.addU32Le desiredAccess

proc parseSamrCreateUser2InDomain*(stub: string): tuple[handle: string, grantedAccess, rid, status: uint32] =
  if stub.len < 32:
    result.status = uint32.high
    return
  result.handle = stub[0 ..< 20]
  result.grantedAccess = readU32Le(stub, 20)
  result.rid = readU32Le(stub, 24)
  result.status = readU32Le(stub, 28)

proc buildSamrOpenUserStub*(domainHandle: string; rid: uint32;
                            desiredAccess = SamrAccessMaxAllowed): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU32Le desiredAccess
  result.addU32Le rid

proc parseSamrOpenUser*(stub: string): tuple[handle: string, status: uint32] =
  if stub.len < 24:
    result.status = uint32.high
    return
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc buildSamrOpenAliasStub*(domainHandle: string; rid: uint32;
                              desiredAccess = SamrAccessMaxAllowed): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU32Le desiredAccess
  result.addU32Le rid

proc parseSamrOpenAlias*(stub: string): tuple[handle: string, status: uint32] =
  if stub.len < 24:
    result.status = uint32.high
    return
  result.handle = stub[0 ..< 20]
  result.status = readU32Le(stub, 20)

proc buildSamrGetMembersInAliasStub*(aliasHandle: string): string =
  if aliasHandle.len != 20:
    raise newException(ValueError, "SAMR alias handle must be 20 bytes")
  result.add aliasHandle

proc parseSamrGetMembersInAlias*(stub: string): seq[string] =
  if stub.len < 8: return
  var offset = 0
  let count = int(readU32Le(stub, offset)); offset += 4
  if count == 0 or count > 10000: return
  let sidsPtr = readU32Le(stub, offset); offset += 4
  if sidsPtr == 0: return
  let maxCount = int(readU32Le(stub, offset)); offset += 4
  var sidPtrs: seq[uint32]
  for i in 0 ..< maxCount:
    if offset + 4 > stub.len: break
    sidPtrs.add readU32Le(stub, offset); offset += 4
  for sidPtr in sidPtrs:
    if sidPtr == 0: continue
    if offset + 4 > stub.len: break
    let subAuthCount = int(readU32Le(stub, offset)); offset += 4
    let sidBodyLen = 8 + subAuthCount * 4
    if offset + sidBodyLen > stub.len: break
    result.add stub[offset ..< offset + sidBodyLen]
    offset += sidBodyLen
    while offset mod 4 != 0: inc offset

proc buildSamrCloseHandleStub*(handle: string): string =
  if handle.len != 20:
    raise newException(ValueError, "SAMR handle must be 20 bytes")
  result.add handle

proc buildLsarClosePolicyStub*(handle: string): string =
  buildSamrCloseHandleStub(handle)

proc buildSamrLookupNamesInDomainStub*(domainHandle: string; name: string): string =
  if domainHandle.len != 20:
    raise newException(ValueError, "SAMR domain handle must be 20 bytes")
  result.add domainHandle
  result.addU32Le 1
  result.addU32Le 1000
  result.addU32Le 0
  result.addU32Le 1
  result.addNdrUnicodeStringHeader(name, 0x00020070'u32)
  result.addNdrUnicodeStringBuffer(name)

proc parseSamrLookupNamesInDomain*(stub: string): tuple[rid, use, status: uint32] =
  if stub.len < 24:
    result.status = uint32.high
    return
  var offset = 0
  let ridCount = readU32Le(stub, offset); offset += 4
  let ridPtr = readU32Le(stub, offset); offset += 4
  if ridCount > 0 and ridPtr != 0 and offset + 8 <= stub.len:
    let maxCount = readU32Le(stub, offset); offset += 4
    if maxCount > 0 and offset + 4 <= stub.len:
      result.rid = readU32Le(stub, offset)
      offset += int(maxCount) * 4
  let useCount = if offset + 4 <= stub.len: readU32Le(stub, offset) else: 0'u32
  offset += 4
  let usePtr = if offset + 4 <= stub.len: readU32Le(stub, offset) else: 0'u32
  offset += 4
  if useCount > 0 and usePtr != 0 and offset + 8 <= stub.len:
    let maxCount = readU32Le(stub, offset); offset += 4
    if maxCount > 0 and offset + 4 <= stub.len:
      result.use = readU32Le(stub, offset)
      offset += int(maxCount) * 4
  if offset + 4 <= stub.len:
    result.status = readU32Le(stub, offset)

type DesKeyScheduleSamr {.importc: "DES_key_schedule", header: "<openssl/des.h>".} = object

proc DES_set_key_unchecked_samr(key: pointer; schedule: ptr DesKeyScheduleSamr)
  {.cdecl, importc: "DES_set_key_unchecked", header: "<openssl/des.h>".}

proc DES_ecb_encrypt_samr(inp, outp: pointer; schedule: ptr DesKeyScheduleSamr; enc: cint)
  {.cdecl, importc: "DES_ecb_encrypt", header: "<openssl/des.h>".}

const DES_ENCRYPT_FLAG = 1.cint

proc desTransformKeySamr(s: string): string =
  result = newString(8)
  result[0] = chr(((ord(s[0]) shr 1) shl 1) and 0xfe)
  result[1] = chr(((((ord(s[0]) and 0x01) shl 6) or (ord(s[1]) shr 2)) shl 1) and 0xfe)
  result[2] = chr(((((ord(s[1]) and 0x03) shl 5) or (ord(s[2]) shr 3)) shl 1) and 0xfe)
  result[3] = chr(((((ord(s[2]) and 0x07) shl 4) or (ord(s[3]) shr 4)) shl 1) and 0xfe)
  result[4] = chr(((((ord(s[3]) and 0x0f) shl 3) or (ord(s[4]) shr 5)) shl 1) and 0xfe)
  result[5] = chr(((((ord(s[4]) and 0x1f) shl 2) or (ord(s[5]) shr 6)) shl 1) and 0xfe)
  result[6] = chr(((((ord(s[5]) and 0x3f) shl 1) or (ord(s[6]) shr 7)) shl 1) and 0xfe)
  result[7] = chr(((ord(s[6]) and 0x7f) shl 1) and 0xfe)

proc desEcbEncryptSamr(key8, data8: string): string =
  result = newString(8)
  var ks: DesKeyScheduleSamr
  var k = key8
  DES_set_key_unchecked_samr(addr k[0], addr ks)
  DES_ecb_encrypt_samr(unsafeAddr data8[0], addr result[0], addr ks, DES_ENCRYPT_FLAG)

proc samEncryptNTLMHash*(hashToEncrypt, key: string): string =
  let k1 = desTransformKeySamr(key[0 ..< 7])
  let k2 = desTransformKeySamr(key[7 ..< 14])
  desEcbEncryptSamr(k1, hashToEncrypt[0 ..< 8]) & desEcbEncryptSamr(k2, hashToEncrypt[8 ..< 16])

proc buildSamrChangePasswordUserStub*(userHandle, oldNtHash, newNtHash: string): string =
  if userHandle.len != 20:
    raise newException(ValueError, "SAMR user handle must be 20 bytes")
  if oldNtHash.len != 16 or newNtHash.len != 16:
    raise newException(ValueError, "NT hash must be 16 bytes")
  let emptyLm = "\xaa\xd3\xb4\x35\xb5\x14\x04\xee\xaa\xd3\xb4\x35\xb5\x14\x04\xee"
  let oldNtEncWithNewNt = samEncryptNTLMHash(oldNtHash, newNtHash)
  let newNtEncWithOldNt = samEncryptNTLMHash(newNtHash, oldNtHash)
  let newLmEncWithNewNt = samEncryptNTLMHash(emptyLm, newNtHash)
  result.add userHandle
  result.add char(0)
  result.add "\x00\x00\x00"
  result.addU32Le 0
  result.addU32Le 0
  result.add char(1)
  result.add "\x00\x00\x00"
  result.addU32Le 0x00005c6c'u32
  result.add oldNtEncWithNewNt
  result.addU32Le 0x000013d7'u32
  result.add newNtEncWithOldNt
  result.add char(0)
  result.add "\x00\x00\x00"
  result.addU32Le 0
  result.add char(1)
  result.add "\x00\x00\x00"
  result.addU32Le 0x000076d1'u32
  result.add newLmEncWithNewNt

proc samrEncryptedPasswordNew(password, sessionKey: string): string =
  var plain = toUtf16Le(password)
  let byteLen = plain.len
  if plain.len > 512:
    plain.setLen(512)
  while plain.len < 512:
    plain = char(0) & plain
  plain.addU32Le uint32(byteLen)
  let salt = randomBytes(16)
  let key = md5Digest(salt & sessionKey)
  var state = rc4Init(key)
  rc4Process(state, plain) & salt

proc buildSamrSetPasswordInternal5NewStub*(userHandle: string; password, sessionKey: string): string =
  if userHandle.len != 20:
    raise newException(ValueError, "SAMR user handle must be 20 bytes")
  result.add userHandle
  result.addU16Le SamrUserInternal5InformationNew
  result.addU16Le SamrUserInternal5InformationNew
  result.add samrEncryptedPasswordNew(password, sessionKey)
  result.add char(1)

proc buildSamrSetUserControlStub*(userHandle: string; userAccountControl = SamrUserWorkstationTrust): string =
  if userHandle.len != 20:
    raise newException(ValueError, "SAMR user handle must be 20 bytes")
  result.add userHandle
  result.addU16Le SamrUserControlInformation
  result.addU16Le SamrUserControlInformation
  result.addU32Le userAccountControl

proc parseSamrStatus*(stub: string): uint32 =
  if stub.len >= 4: readU32Le(stub, 0) else: uint32.high

proc enumerateSmbExtras*(ctx: SmbRpcCtx; srvsvcPipe: SmbPipeInfo;
                         srvsvcBound: bool;
                         requests: SmbEnumRequests): Future[SmbExtrasResult] {.async.} =
  var probe = SmbExtrasResult()
  template note(target: untyped; msg: string) =
    target.message = msg

  var activeSrvsvc = srvsvcPipe
  var activeSrvsvcBound = srvsvcBound
  if (requests.sessions or requests.disks) and not activeSrvsvcBound:
    try:
      activeSrvsvc = await openSmbPipe(ctx, "srvsvc")
      if activeSrvsvc.opened:
        let bindAck = await rpcBindPipe(ctx, activeSrvsvc, buildDceRpcBindSrvSvc(40'u32))
        activeSrvsvcBound = bindAck.bound
    except CatchableError: discard
  if activeSrvsvcBound and activeSrvsvc.opened and
      (requests.sessions or requests.disks):
    if requests.sessions:
      probe.sessions.attempted = true
      try:
        let r = await rpcCallEx(ctx, activeSrvsvc, 12'u16,
          buildSrvSvcNetSessEnumStub(ctx.host), 11'u32)
        if r.stub.len > 0:
          probe.sessions = parseSrvSvcNetSessEnum(r.stub)
        elif r.faultStatus != 0:
          probe.sessions.message = "NetSessEnum RPC fault 0x" & r.faultStatus.toHex(8)
        else:
          probe.sessions.message = "empty NetSessEnum response (pkt=" & $r.packetType & ")"
      except CatchableError as error:
        probe.sessions.message = cleanError(error)
    if requests.disks:
      probe.disks.attempted = true
      try:
        let r = await rpcCallEx(ctx, activeSrvsvc, 23'u16,
          buildSrvSvcNetServerDiskEnumStub(ctx.host), 12'u32)
        if r.stub.len > 0:
          probe.disks = parseSrvSvcNetServerDiskEnum(r.stub)
        elif r.faultStatus != 0:
          probe.disks.message = "NetServerDiskEnum RPC fault 0x" & r.faultStatus.toHex(8)
        else:
          probe.disks.message = "empty NetServerDiskEnum response (pkt=" & $r.packetType & ")"
      except CatchableError as error:
        probe.disks.message = cleanError(error)

  if requests.loggedOnUsers:
    probe.loggedOnUsers.attempted = true
    try:
      let pipe = await openSmbPipe(ctx, "wkssvc")
      if pipe.opened:
        let bindAck = await rpcBindPipe(ctx, pipe, buildDceRpcBindWksSvc(20'u32))
        if bindAck.bound:
          let stub = await rpcCall(ctx, pipe, 2'u16,
            buildWksSvcNetWkstaUserEnumStub(ctx.host), 21'u32)
          if stub.len > 0:
            probe.loggedOnUsers = parseWksSvcNetWkstaUserEnum(stub)
          else:
            probe.loggedOnUsers.message = "empty NetWkstaUserEnum response"
        else:
          probe.loggedOnUsers.message = "WKSSVC bind failed (ack=0x" & bindAck.ackResult.toHex(4) & ")"
      else:
        probe.loggedOnUsers.message = "wkssvc pipe open failed 0x" & pipe.status.toHex(8)
    except CatchableError as error:
      probe.loggedOnUsers.message = cleanError(error)

  let needSamr = requests.users or requests.groups or requests.passwordPolicy or requests.localAdmins
  var domainSid = ""
  var domainHandle = ""
  var serverHandle = ""
  var samrPipe: SmbPipeInfo
  if needSamr:
    if requests.users: probe.domainUsers.attempted = true
    if requests.groups: probe.domainGroups.attempted = true
    if requests.passwordPolicy: probe.passwordPolicy.attempted = true
    try:
      samrPipe = await openSmbPipe(ctx, "samr")
      if not samrPipe.opened:
        let msg = "samr pipe open failed 0x" & samrPipe.status.toHex(8)
        if requests.users: probe.domainUsers.message = msg
        if requests.groups: probe.domainGroups.message = msg
        if requests.passwordPolicy: probe.passwordPolicy.message = msg
      else:
        let bindAck = await rpcBindPipe(ctx, samrPipe, buildDceRpcBindSamr(30'u32))
        if not bindAck.bound:
          if requests.users: probe.domainUsers.message = "SAMR bind failed"
          if requests.groups: probe.domainGroups.message = "SAMR bind failed"
          if requests.passwordPolicy: probe.passwordPolicy.message = "SAMR bind failed"
        else:
          let connectStub = await rpcCall(ctx, samrPipe, 64'u16,
            buildSamrConnect5Stub(ctx.host), 31'u32)
          let connectInfo = parseSamrConnect5(connectStub)
          if connectInfo.handle.len != 20:
            if requests.users: probe.domainUsers.message = "SamrConnect5 failed"
            if requests.groups: probe.domainGroups.message = "SamrConnect5 failed"
            if requests.passwordPolicy: probe.passwordPolicy.message = "SamrConnect5 failed"
          else:
            serverHandle = connectInfo.handle
            let enumStub = await rpcCall(ctx, samrPipe, 6'u16,
              buildSamrEnumDomainsStub(serverHandle), 32'u32)
            let enumInfo = parseSamrEnumDomains(enumStub)
            probe.domains = enumInfo.domains
            var openedDomain = false
            for domainInfo in probe.domains:
              if domainInfo.name.toLowerAscii() == "builtin": continue
              let lookupStub = await rpcCall(ctx, samrPipe, 5'u16,
                buildSamrLookupDomainStub(serverHandle, domainInfo.name), 33'u32)
              let lookup = parseSamrLookupDomain(lookupStub)
              if lookup.sid.len == 0: continue
              domainSid = lookup.sid
              let openStub = await rpcCall(ctx, samrPipe, 7'u16,
                buildSamrOpenDomainStub(serverHandle, domainSid), 34'u32)
              let openInfo = parseSamrOpenDomain(openStub)
              if openInfo.handle.len != 20: continue
              domainHandle = openInfo.handle
              openedDomain = true
              if requests.users:
                let usersStub = await rpcCall(ctx, samrPipe, 13'u16,
                  buildSamrEnumDomainUsersStub(domainHandle), 35'u32)
                let parsed = parseSamrEnumUsers(usersStub)
                probe.domainUsers.entries.add parsed.users
                probe.domainUsers.succeeded = true
                probe.domainUsers.rpcStatus = parsed.status
              if requests.groups:
                let groupsStub = await rpcCall(ctx, samrPipe, 11'u16,
                  buildSamrEnumDomainGroupsStub(domainHandle), 36'u32)
                let parsedGroups = parseSamrEnumGroups(groupsStub, "group")
                probe.domainGroups.entries.add parsedGroups.groups
                let aliasStub = await rpcCall(ctx, samrPipe, 15'u16,
                  buildSamrEnumDomainAliasesStub(domainHandle), 37'u32)
                let parsedAlias = parseSamrEnumGroups(aliasStub, "alias")
                probe.domainGroups.entries.add parsedAlias.groups
                probe.domainGroups.succeeded = true
              if requests.passwordPolicy and probe.passwordPolicy.entries.len == 0:
                let polStub = await rpcCall(ctx, samrPipe, 8'u16,
                  buildSamrQueryInformationDomainStub(domainHandle, 1'u16), 38'u32)
                probe.passwordPolicy = parseSamrPasswordPolicy(polStub)
                if probe.passwordPolicy.succeeded:
                  let lockStub = await rpcCall(ctx, samrPipe, 8'u16,
                    buildSamrQueryInformationDomainStub(domainHandle, 12'u16), 39'u32)
                  mergeLockoutInfo(probe.passwordPolicy, lockStub)
              break
            if not openedDomain:
              if requests.users and probe.domainUsers.message.len == 0:
                probe.domainUsers.message = "no account domain returned"
              if requests.groups and probe.domainGroups.message.len == 0:
                probe.domainGroups.message = "no account domain returned"
              if requests.passwordPolicy and probe.passwordPolicy.message.len == 0:
                probe.passwordPolicy.message = "no account domain returned"
    except CatchableError as error:
      let msg = cleanError(error)
      if requests.users and probe.domainUsers.message.len == 0:
        probe.domainUsers.message = msg
      if requests.groups and probe.domainGroups.message.len == 0:
        probe.domainGroups.message = msg
      if requests.passwordPolicy and probe.passwordPolicy.message.len == 0:
        probe.passwordPolicy.message = msg

  if requests.localAdmins:
    const builtinSid = "S-1-5-32"
    const localGroupRids = [(544'u32, "Administrators"), (555'u32, "Remote Desktop Users"),
                            (562'u32, "Distributed COM Users"), (580'u32, "Remote Management Users")]
    probe.localAdmins.attempted = true
    probe.rdpUsers.attempted = true
    probe.dcomUsers.attempted = true
    probe.psRemoteUsers.attempted = true
    try:
      if not samrPipe.opened:
        samrPipe = await openSmbPipe(ctx, "samr")
        if samrPipe.opened:
          let bindAck = await rpcBindPipe(ctx, samrPipe, buildDceRpcBindSamr(69'u32))
          if bindAck.bound and serverHandle.len == 0:
            let connectStub = await rpcCall(ctx, samrPipe, 64'u16,
              buildSamrConnect5Stub(ctx.host), 70'u32)
            let connectInfo = parseSamrConnect5(connectStub)
            if connectInfo.handle.len == 20:
              serverHandle = connectInfo.handle
      if not samrPipe.opened or serverHandle.len == 0:
        probe.localAdmins.message = "SAMR pipe unavailable"
      else:
        let builtinOpenStub = await rpcCall(ctx, samrPipe, 7'u16,
          buildSamrOpenDomainStub(serverHandle, builtinSid), 71'u32)
        let builtinDomHandle = parseSamrOpenDomain(builtinOpenStub)

        if builtinDomHandle.handle.len == 20:
          let lsarPipe = await openSmbPipe(ctx, "lsarpc")
          var polHandle = ""
          if lsarPipe.opened:
            let lsarBind = await rpcBindPipe(ctx, lsarPipe, buildDceRpcBindLsarpc(71'u32))
            if lsarBind.bound:
              let polStub = await rpcCall(ctx, lsarPipe, 44'u16,
                buildLsarOpenPolicy2Stub(ctx.host), 72'u32)
              let pol = parseLsarOpenPolicy2(polStub)
              polHandle = pol.handle
          for (rid, groupName) in localGroupRids:
            let aliasStub = await rpcCall(ctx, samrPipe, 27'u16,
              buildSamrOpenAliasStub(builtinDomHandle.handle, rid), 73'u32)
            let aliasInfo = parseSamrOpenAlias(aliasStub)

            if aliasInfo.handle.len != 20: continue
            let membersStub = await rpcCall(ctx, samrPipe, 33'u16,
              buildSamrGetMembersInAliasStub(aliasInfo.handle), 74'u32)
            let memberSids = parseSamrGetMembersInAlias(membersStub)
            var members: seq[SmbLocalGroupMember]
            var sidStrings: seq[string]
            for rawSid in memberSids:
              let (s, _) = parseSidBytes(rawSid, 0)
              sidStrings.add s
            if polHandle.len == 20 and sidStrings.len > 0:
              let lookupStub = await rpcCall(ctx, lsarPipe, 15'u16,
                buildLsarLookupSidsStub(polHandle, sidStrings), 75'u32)
              let lookups = parseLsarLookupSids(lookupStub, memberSids)
              for i, lookup in lookups:
                let sid = if i < sidStrings.len: sidStrings[i] else: ""
                members.add SmbLocalGroupMember(sid: sid, name: lookup.name,
                  domain: lookup.domain, sidType: lookup.sidType)
            else:
              for sid in sidStrings:
                members.add SmbLocalGroupMember(sid: sid)
            var res = SmbEnumResult[SmbLocalGroupMember](attempted: true, succeeded: true,
              entries: members, message: groupName & " members")
            case rid
            of 544: probe.localAdmins = res
            of 555: probe.rdpUsers = res
            of 562: probe.dcomUsers = res
            of 580: probe.psRemoteUsers = res
            else: discard
    except CatchableError as error:
      let msg = cleanError(error)
      if probe.localAdmins.message.len == 0: probe.localAdmins.message = msg

  if requests.ridBrute:
    probe.ridBrute.attempted = true
    try:
      if domainSid.len == 0:
        probe.ridBrute.message = "rid-brute requires a domain SID (enable --users)"
      else:
        let pipe = await openSmbPipe(ctx, "lsarpc")
        if not pipe.opened:
          probe.ridBrute.message = "lsarpc pipe failed"
        else:
          let bindAck = await rpcBindPipe(ctx, pipe, buildDceRpcBindLsarpc(40'u32))
          if not bindAck.bound:
            probe.ridBrute.message = "LSARPC bind failed"
          else:
            let openStub = await rpcCall(ctx, pipe, 44'u16,
              buildLsarOpenPolicy2Stub(ctx.host), 41'u32)
            let pol = parseLsarOpenPolicy2(openStub)
            if pol.handle.len != 20:
              probe.ridBrute.message = "LsarOpenPolicy2 failed"
            else:
              const Batch = 100
              var rid = requests.ridBruteStart
              var callId = 42'u32
              while rid <= requests.ridBruteEnd:
                var batch: seq[string]
                var r = rid
                while r <= requests.ridBruteEnd and batch.len < Batch:
                  batch.add domainSid & "-" & $r
                  inc r
                let lookupStub = await rpcCall(ctx, pipe, 15'u16,
                  buildLsarLookupSidsStub(pol.handle, batch), callId)
                inc callId
                let lookups = parseLsarLookupSids(lookupStub, batch)
                for item in lookups:
                  if item.name.len > 0 and item.sidType != 0 and item.sidType != 8:
                    probe.ridBrute.entries.add item
                rid = r
              probe.ridBrute.succeeded = true
    except CatchableError as error:
      probe.ridBrute.message = cleanError(error)

  result = probe

proc probeSmb*(host: string; port, timeoutMs: int; request: SmbNegotiateRequest; credential = SmbCredential(); requestNtlmChallenge = true; requests = SmbEnumRequests()): Future[SmbProbe] {.async.} =
  var socket = scannercore.newTcpAsyncSocket(host)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      return SmbProbe(host: host, port: port, reachable: false, speaksSmb: false, message: "timeout")

    let negotiatePacket = buildSmbNegotiateRequest(request)
    dbgDump("SEND negotiate", negotiatePacket)
    await socket.send(negotiatePacket)
    let response = await recvWithTimeout(socket, 4096, timeoutMs)
    dbgDump("RECV negotiate", response)
    if response.len == 0:
      return SmbProbe(host: host, port: port, reachable: true, speaksSmb: false, message: "connected, receive timeout")

    if response.len >= 8 and response[4 .. 7] == "\xfeSMB":
      let status = readU32Le(response, 12)
      if status == 0:
        var probe = SmbProbe(
          host: host,
          port: port,
          reachable: true,
          speaksSmb: true,
          status: status,
          negotiate: parseSmbNegotiateResponse(response),
          message: "SMB2 negotiate response"
        )
        if requestNtlmChallenge:
          let type1 = buildNtlmType1()
          let blob = spnegoNtlmInit(type1)
          await socket.send(buildSmbSessionSetupRequest(blob))
          let sessionResponse = await recvWithTimeout(socket, 4096, timeoutMs)
          if sessionResponse.len > 0 and sessionResponse.len >= 8 and sessionResponse[4 .. 7] == "\xfeSMB":
            probe.status = readU32Le(sessionResponse, 12)
            probe.sessionId = readU64Le(sessionResponse, 44)
            probe.ntlmChallenge = parseSessionSetupChallenge(sessionResponse)
            if probe.ntlmChallenge.offered:
              probe.message = "SMB2 negotiate and NTLM challenge"
              if credential.hasCredential():
                probe.authAttempted = true
                var authCredential = credential
                let ntlmAuth = buildNtlmType3SmbSession(
                  authCredential, probe.ntlmChallenge, randomAsciiBytes(8), type1)
                dbgDump("NTLM Type3", ntlmAuth.token)
                let authPacket = buildSmbSessionSetupRequest(spnegoNtlmAuth(ntlmAuth.token), 2'u64, probe.sessionId)
                dbgDump("SEND session-setup-auth", authPacket)
                await socket.send(authPacket)
                let authResponse = await recvWithTimeout(socket, 4096, timeoutMs)
                dbgDump("RECV session-setup-auth", authResponse)
                if authResponse.len >= 16 and authResponse[4 .. 7] == "\xfeSMB":
                  probe.status = readU32Le(authResponse, 12)
                  probe.sessionId = readU64Le(authResponse, 44)
                  probe.authenticated = probe.status == 0
                  probe.signingEnabled = probe.negotiate.signingRequired or probe.negotiate.signingEnabled
                  probe.message = if probe.authenticated: "SMB authentication succeeded" else: "SMB authentication failed 0x" & probe.status.toHex(8)
                  if probe.authenticated:
                    let adminPacket = maybeSign(buildSmbTreeConnectRequest(host, "ADMIN$", 3'u64, probe.sessionId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                    probe.signingApplied = probe.signingApplied or adminPacket.signed
                    await socket.send(adminPacket.data)
                    let adminResponse = await recvWithTimeout(socket, 1024, timeoutMs)
                    if adminResponse.len > 0 and adminResponse.len >= 8 and adminResponse[4 .. 7] == "\xfeSMB":
                      probe.adminTree = parseSmbTreeConnectResponse(adminResponse)
                    let ipcPacket = maybeSign(buildSmbTreeConnectRequest(host, "IPC$", 4'u64, probe.sessionId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                    probe.signingApplied = probe.signingApplied or ipcPacket.signed
                    await socket.send(ipcPacket.data)
                    let treeResponse = await recvWithTimeout(socket, 1024, timeoutMs)
                    if treeResponse.len > 0 and treeResponse.len >= 8 and treeResponse[4 .. 7] == "\xfeSMB":
                      probe.ipcTree = parseSmbTreeConnectResponse(treeResponse)
                      if probe.ipcTree.connected:
                        probe.message = "SMB authentication succeeded and IPC$ connected"
                        if requests.shares or requests.sessions or
                            requests.disks or requests.loggedOnUsers or
                            requests.users or requests.groups or
                            requests.passwordPolicy or requests.ridBrute:
                          let createPacket = maybeSign(buildSmbCreatePipeRequest("srvsvc", 5'u64, probe.sessionId, probe.ipcTree.treeId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                          probe.signingApplied = probe.signingApplied or createPacket.signed
                          await socket.send(createPacket.data)
                          let createResponse = await recvWithTimeout(socket, 2048, timeoutMs)
                          if createResponse.len > 0 and createResponse.len >= 8 and createResponse[4 .. 7] == "\xfeSMB":
                            probe.srvsvcPipe = parseSmbCreatePipeResponse(createResponse)
                          if probe.srvsvcPipe.opened:
                            let bindWrite = maybeSign(buildSmbWriteRequest(probe.srvsvcPipe.fileId, buildDceRpcBindSrvSvc(), 6'u64, probe.sessionId, probe.ipcTree.treeId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                            probe.signingApplied = probe.signingApplied or bindWrite.signed
                            await socket.send(bindWrite.data)
                            discard await recvWithTimeout(socket, 1024, timeoutMs)
                            let bindReadPacket = maybeSign(buildSmbReadRequest(probe.srvsvcPipe.fileId, 4280, 7'u64, probe.sessionId, probe.ipcTree.treeId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                            probe.signingApplied = probe.signingApplied or bindReadPacket.signed
                            await socket.send(bindReadPacket.data)
                            let bindRead = await recvWithTimeout(socket, 8192, timeoutMs)
                            dbgDump("RECV srvsvc bind-ack", bindRead)
                            let bindPayload = parseSmbReadData(bindRead)
                            dbgDump("DCE/RPC bind payload", bindPayload)
                            probe.srvsvcRpc = parseDceRpcBindAck(bindPayload)
                            if probe.srvsvcRpc.bound:
                              var nextMid = 8'u64
                              if requests.shares:
                                let shareStub = buildSrvSvcNetShareEnumAllStub(host)
                                let shareRequest = buildDceRpcRequest(15'u16, shareStub, 2'u32)
                                let shareWrite = maybeSign(buildSmbWriteRequest(probe.srvsvcPipe.fileId, shareRequest, nextMid, probe.sessionId, probe.ipcTree.treeId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                                probe.signingApplied = probe.signingApplied or shareWrite.signed
                                inc nextMid
                                await socket.send(shareWrite.data)
                                discard await recvWithTimeout(socket, 1024, timeoutMs)
                                let shareReadPacket = maybeSign(buildSmbReadRequest(probe.srvsvcPipe.fileId, 4280, nextMid, probe.sessionId, probe.ipcTree.treeId), ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                                probe.signingApplied = probe.signingApplied or shareReadPacket.signed
                                inc nextMid
                                await socket.send(shareReadPacket.data)
                                let shareRead = await recvWithTimeout(socket, 65535, timeoutMs)
                                dbgDump("RECV share-read", shareRead)
                                let sharePayload = parseSmbReadData(shareRead)
                                dbgDump("DCE/RPC share payload", sharePayload)
                                let shareStubResp = parseDceRpcResponseStub(sharePayload)
                                dbgDump("DCE/RPC share stub", shareStubResp)
                                probe.shares = parseSrvSvcNetShareEnumAll(shareStubResp)
                                probe.message = "SMB authenticated, IPC$ connected, SRVSVC shares parsed: " & $probe.shares.len
                              if requests.shares:
                                for index in 0 ..< probe.shares.len:
                                  let probePacket = maybeSign(
                                    buildSmbTreeConnectRequest(host, probe.shares[index].name, nextMid, probe.sessionId),
                                    ntlmAuth.exportedKey, probe.negotiate, probe.signingEnabled)
                                  probe.signingApplied = probe.signingApplied or probePacket.signed
                                  inc nextMid
                                  await socket.send(probePacket.data)
                                  let probeResponse = await recvWithTimeout(socket, 1024, timeoutMs)
                                  probe.shares[index].accessProbed = true
                                  if probeResponse.len >= 4 + Smb2HeaderLen:
                                    let info = parseSmbTreeConnectResponse(probeResponse)
                                    probe.shares[index].accessStatus = info.status
                                    if info.connected:
                                      probe.shares[index].maximalAccess = info.maximalAccess
                                      let shareType = probe.shares[index].typ and 0x0f'u32
                                      probe.shares[index].canRead = true
                                      probe.shares[index].canWrite = false
                                      if shareType != 3'u32:
                                        let probeName = "nimux_w_" & $epochTime().int64 &
                                          "_" & $rand(1_000_000)
                                        let createPkt = maybeSign(
                                          buildSmbFileCreateRequest(
                                            probeName,
                                            desiredAccess = 0x00010002'u32,
                                            createDisposition = 2'u32,
                                            createOptions = 0x00001040'u32,
                                            nextMid, probe.sessionId, info.treeId),
                                          ntlmAuth.exportedKey, probe.negotiate,
                                          probe.signingEnabled)
                                        probe.signingApplied = probe.signingApplied or createPkt.signed
                                        inc nextMid
                                        await socket.send(createPkt.data)
                                        let createResp = await recvWithTimeout(socket, 2048, timeoutMs)
                                        if createResp.len >= 4 + Smb2HeaderLen and
                                            readU32Le(createResp, 12) == 0:
                                          probe.shares[index].canWrite = true
                                          let createInfo = parseSmbCreatePipeResponse(createResp)
                                          if createInfo.fileId.len == 16:
                                            let closePkt = maybeSign(
                                              buildSmbCloseRequest(createInfo.fileId,
                                                nextMid, probe.sessionId, info.treeId),
                                              ntlmAuth.exportedKey, probe.negotiate,
                                              probe.signingEnabled)
                                            probe.signingApplied = probe.signingApplied or closePkt.signed
                                            inc nextMid
                                            await socket.send(closePkt.data)
                                            discard await recvWithTimeout(socket, 1024, timeoutMs)
                              if requests.sessions or requests.disks or
                                  requests.loggedOnUsers or requests.users or
                                  requests.groups or requests.passwordPolicy or
                                  requests.ridBrute:
                                let ctx = SmbRpcCtx(
                                  socket: socket,
                                  host: host,
                                  sessionId: probe.sessionId,
                                  treeId: probe.ipcTree.treeId,
                                  sessionKey: ntlmAuth.exportedKey,
                                  negotiate: probe.negotiate,
                                  signingEnabled: probe.signingEnabled,
                                  timeoutMs: timeoutMs,
                                  mid: nextMid
                                )
                                let extras = await enumerateSmbExtras(ctx,
                                  probe.srvsvcPipe, probe.srvsvcRpc.bound, requests)
                                probe.sessions = extras.sessions
                                probe.disks = extras.disks
                                probe.loggedOnUsers = extras.loggedOnUsers
                                probe.domains = extras.domains
                                probe.domainUsers = extras.domainUsers
                                probe.domainGroups = extras.domainGroups
                                probe.passwordPolicy = extras.passwordPolicy
                                probe.ridBrute = extras.ridBrute
                                probe.signingApplied = probe.signingApplied or ctx.signingApplied
                            else:
                              probe.message = "SMB authenticated, IPC$ connected, SRVSVC bind failed"
                          else:
                            probe.message = "SMB authenticated, IPC$ connected, srvsvc pipe failed 0x" & probe.srvsvcPipe.status.toHex(8)
                      else:
                        probe.message = "SMB authentication succeeded; IPC$ failed 0x" & probe.ipcTree.status.toHex(8)
        return probe
      return SmbProbe(
        host: host,
        port: port,
        reachable: true,
        speaksSmb: true,
        status: status,
        message: "SMB2 error status 0x" & status.toHex(8)
      )
    if response.len > 0:
      return SmbProbe(host: host, port: port, reachable: true, speaksSmb: false, message: "non-SMB response: " & response.len.intToStr & " bytes")
    result = SmbProbe(host: host, port: port, reachable: true, speaksSmb: false, message: "connected, no response")
  except CatchableError as error:
    result = SmbProbe(host: host, port: port, reachable: false, speaksSmb: false, message: cleanError(error))
  finally:
    try: socket.close()
    except CatchableError: discard


type
  SmbSession* = ref object
    ctx*: SmbRpcCtx
    ipcTreeId*: uint32
    adminTreeId*: uint32
    sessionBaseKey*: string
    authenticated*: bool
    message*: string
    negotiate*: SmbNegotiateInfo

proc establishSmbSession*(host: string; port, timeoutMs: int;
                          credential: SmbCredential;
                          authMethod: SmbAuthMethod = samNtlm): Future[SmbSession] {.async.} =
  result = SmbSession()
  var socket = scannercore.newTcpAsyncSocket(host)
  let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
  if not connected:
    socket.close()
    result.message = "connect timeout"
    return
  try:
    var preauthHash = zeroPreauthHash()
    let request =
      if authMethod == samKerberos: kerberosSmbNegotiateRequest()
      else: defaultSmbNegotiateRequest()
    let negotiateReq = buildSmbNegotiateRequest(request)
    updatePreauthHash(preauthHash, negotiateReq)
    await socket.send(negotiateReq)
    let negResp = await recvWithTimeout(socket, 4096, timeoutMs)
    if negResp.len < 8 or negResp[4 .. 7] != "\xfeSMB":
      result.message = "SMB negotiate failed"
      socket.close()
      return
    updatePreauthHash(preauthHash, negResp)
    result.negotiate = parseSmbNegotiateResponse(negResp)
    if authMethod == samKerberos:
      let oldCc = if existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME") else: ""
      let hadCc = existsEnv("KRB5CCNAME")
      let oldCfg = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
      let hadCfg = existsEnv("KRB5_CONFIG")
      if credential.ccache.len > 0:
        let ccname = credential.ccache
        if ccname.startsWith("FILE:") or ccname.startsWith("MEMORY:") or
            ccname.startsWith("API:"):
          putEnv("KRB5CCNAME", ccname)
        else:
          putEnv("KRB5CCNAME", "FILE:" & expandFilename(ccname))
      elif existsEnv("KRB5CCNAME"):
        let ccname = getEnv("KRB5CCNAME")
        if not ccname.startsWith("FILE:") and not ccname.startsWith("MEMORY:") and
            not ccname.startsWith("API:") and not ccname.isAbsolute():
          putEnv("KRB5CCNAME", "FILE:" & expandFilename(ccname))
      if credential.krb5Config.len > 0:
        putEnv("KRB5_CONFIG", expandFilename(credential.krb5Config))
      let kc = krb.newKerberosContext("cifs", host, credential.domain)
      defer:
        kc.close()
        if credential.ccache.len > 0:
          if hadCc: putEnv("KRB5CCNAME", oldCc)
          else: delEnv("KRB5CCNAME")
        if credential.krb5Config.len > 0:
          if hadCfg: putEnv("KRB5_CONFIG", oldCfg)
          else: delEnv("KRB5_CONFIG")
      let tok = kc.step()
      if tok.token.len == 0:
        result.message = "Kerberos produced no AP-REQ token; check KRB5CCNAME/kinit"
        socket.close()
        return
      let authReq = buildSmbSessionSetupRequest(spnegoKerberosInit(tok.token))
      updatePreauthHash(preauthHash, authReq)
      await socket.send(authReq)
      let authResp = await recvWithTimeout(socket, 4096, timeoutMs)
      if authResp.len < 16 or authResp[4 .. 7] != "\xfeSMB":
        result.message = "SMB Kerberos session-setup malformed"
        socket.close()
        return
      updatePreauthHash(preauthHash, authResp)
      var authStatus = readU32Le(authResp, 12)
      var finalSessionId = readU64Le(authResp, 44)
      var finalResp = authResp
      if authStatus == 0xC0000016'u32:
        let serverBlob = parseSessionSetupSecurityBlob(authResp)
        let mechToken = firstSpnegoResponseToken(serverBlob)
        var nextTok: krb.KerberosToken
        var continuationBlob = ""
        try:
          nextTok = kc.step(if mechToken.len > 0: mechToken else: serverBlob)
          if nextTok.token.len > 0:
            continuationBlob = spnegoKerberosNext(nextTok.token)
        except CatchableError as error:
          if error.msg.contains("Context is already fully established"):
            continuationBlob = derTlv(0xa1'u8, derTlv(0x30'u8, ""))
          else:
            result.message = "SMB Kerberos continuation failed: " & error.msg
            socket.close()
            return
        let nextReq = buildSmbSessionSetupRequest(continuationBlob, 2'u64, finalSessionId)
        updatePreauthHash(preauthHash, nextReq)
        await socket.send(nextReq)
        finalResp = await recvWithTimeout(socket, 4096, timeoutMs)
        if finalResp.len < 16 or finalResp[4 .. 7] != "\xfeSMB":
          result.message = "SMB Kerberos final session-setup malformed"
          socket.close()
          return
        updatePreauthHash(preauthHash, finalResp)
        authStatus = readU32Le(finalResp, 12)
        finalSessionId = readU64Le(finalResp, 44)
      if authStatus != 0:
        result.message = "SMB Kerberos authentication failed 0x" & authStatus.toHex(8)
        socket.close()
        return
      let serverBlob = parseSessionSetupSecurityBlob(finalResp)
      if serverBlob.len > 0 and not tok.complete:
        let mechToken = firstSpnegoResponseToken(serverBlob)
        discard kc.step(if mechToken.len > 0: mechToken else: serverBlob)
      var kerbSessionKey = kc.sessionKey()
      if kerbSessionKey.len == 0:
        result.message = "SMB Kerberos authenticated, but GSSAPI did not export a session key for signing"
        socket.close()
        return
      if result.negotiate.dialect in ["SMB 2.0.2", "SMB 2.1"] and kerbSessionKey.len > 16:
        kerbSessionKey = kerbSessionKey[0 ..< 16]
      result.sessionBaseKey = kerbSessionKey
      let signingEnabled =
        result.negotiate.signingRequired or result.negotiate.signingEnabled
      result.authenticated = true
      let ipcPkt = maybeSign(
        buildSmbTreeConnectRequest(host, "IPC$", 2'u64, finalSessionId),
        result.sessionBaseKey, result.negotiate, signingEnabled, preauthHash)
      await socket.send(ipcPkt.data)
      let ipcResp = await recvWithTimeout(socket, 2048, timeoutMs)
      let ipcInfo = parseSmbTreeConnectResponse(ipcResp)
      if not ipcInfo.connected:
        result.message = "IPC$ tree connect failed 0x" & ipcInfo.status.toHex(8)
        socket.close()
        return
      result.ipcTreeId = ipcInfo.treeId
      let adminPkt = maybeSign(
        buildSmbTreeConnectRequest(host, "ADMIN$", 3'u64, finalSessionId),
        result.sessionBaseKey, result.negotiate, signingEnabled, preauthHash)
      await socket.send(adminPkt.data)
      let adminResp = await recvWithTimeout(socket, 2048, timeoutMs)
      let adminInfo = parseSmbTreeConnectResponse(adminResp)
      if adminInfo.connected:
        result.adminTreeId = adminInfo.treeId
      else:
        result.message = "ADMIN$ tree connect failed 0x" & adminInfo.status.toHex(8)
      result.ctx = SmbRpcCtx(
        socket: socket,
        host: host,
        sessionId: finalSessionId,
        treeId: ipcInfo.treeId,
        sessionKey: result.sessionBaseKey,
        negotiate: result.negotiate,
        signingEnabled: signingEnabled,
        preauthHash: preauthHash,
        timeoutMs: timeoutMs,
        mid: 4'u64
      )
      if result.message.len == 0:
        result.message = "Kerberos session established"
      return
    let type1 = buildNtlmType1()
    let initBlob = spnegoNtlmInit(type1)
    let type1Req = buildSmbSessionSetupRequest(initBlob)
    updatePreauthHash(preauthHash, type1Req)
    await socket.send(type1Req)
    let chalResp = await recvWithTimeout(socket, 4096, timeoutMs)
    if chalResp.len < 16 or chalResp[4 .. 7] != "\xfeSMB":
      result.message = "SMB session-setup (Type1) failed"
      socket.close()
      return
    updatePreauthHash(preauthHash, chalResp)
    let sessionId = readU64Le(chalResp, 44)
    let challengeBlob = parseSessionSetupSecurityBlob(chalResp)
    let challenge = parseNtlmChallenge(challengeBlob)
    if not challenge.offered:
      result.message = "no NTLM challenge from server"
      socket.close()
      return
    var authCred = credential
    let (type3Token, exportedKey) = buildNtlmType3SmbSession(authCred,
      challenge, randomAsciiBytes(8), type1)
    let authPacket = buildSmbSessionSetupRequest(spnegoNtlmAuth(type3Token),
      2'u64, sessionId)
    updatePreauthHash(preauthHash, authPacket)
    await socket.send(authPacket)
    let authResp = await recvWithTimeout(socket, 4096, timeoutMs)
    if authResp.len < 16 or authResp[4 .. 7] != "\xfeSMB":
      result.message = "SMB session-setup (Type3) malformed"
      socket.close()
      return
    updatePreauthHash(preauthHash, authResp)
    let authStatus = readU32Le(authResp, 12)
    let finalSessionId = readU64Le(authResp, 44)
    if authStatus != 0:
      result.message = "SMB authentication failed 0x" & authStatus.toHex(8)
      socket.close()
      return
    result.authenticated = true
    result.sessionBaseKey = exportedKey
    let signingEnabled =
      result.negotiate.signingRequired or result.negotiate.signingEnabled
    let ipcPkt = maybeSign(
      buildSmbTreeConnectRequest(host, "IPC$", 3'u64, finalSessionId),
      exportedKey, result.negotiate, signingEnabled, preauthHash)
    await socket.send(ipcPkt.data)
    let ipcResp = await recvWithTimeout(socket, 2048, timeoutMs)
    let ipcInfo = parseSmbTreeConnectResponse(ipcResp)
    if not ipcInfo.connected:
      result.message = "IPC$ tree connect failed 0x" & ipcInfo.status.toHex(8)
      socket.close()
      return
    result.ipcTreeId = ipcInfo.treeId
    let adminPkt = maybeSign(
      buildSmbTreeConnectRequest(host, "ADMIN$", 4'u64, finalSessionId),
      exportedKey, result.negotiate, signingEnabled, preauthHash)
    await socket.send(adminPkt.data)
    let adminResp = await recvWithTimeout(socket, 2048, timeoutMs)
    let adminInfo = parseSmbTreeConnectResponse(adminResp)
    if adminInfo.connected:
      result.adminTreeId = adminInfo.treeId
    else:
      result.message = "ADMIN$ tree connect failed 0x" & adminInfo.status.toHex(8)
    result.ctx = SmbRpcCtx(
      socket: socket,
      host: host,
      sessionId: finalSessionId,
      treeId: ipcInfo.treeId,
      sessionKey: exportedKey,
      negotiate: result.negotiate,
      signingEnabled: signingEnabled,
      preauthHash: preauthHash,
      timeoutMs: timeoutMs,
      mid: 5'u64
    )
    if result.message.len == 0:
      result.message = "session established"
  except CatchableError as error:
    result.message = cleanError(error)
    try: socket.close()
    except CatchableError: discard

proc samrChangePasswordHashes*(host: string; port, timeoutMs: int;
                               credential: SmbCredential;
                               username, oldNtHash, newNtHash: string;
                               authMethod: SmbAuthMethod = samNtlm): Future[SamrChangePasswdResult] {.async.} =
  result = SamrChangePasswdResult(host: host, port: port)
  var session: SmbSession
  try:
    session = await establishSmbSession(host, port, timeoutMs, credential, authMethod)
    if session == nil or not session.authenticated:
      result.message = if session == nil: "SMB session failed" else: session.message
      return
    result.authenticated = true
    let pipe = await openSmbPipe(session.ctx, "samr")
    if not pipe.opened:
      result.message = "samr pipe open failed 0x" & pipe.status.toHex(8)
      return
    let bindAck = await rpcBindPipe(session.ctx, pipe, buildDceRpcBindSamr(80'u32))
    if not bindAck.bound:
      result.message = "SAMR bind failed"
      return
    let connectStub = await rpcCall(session.ctx, pipe, 64'u16,
      buildSamrConnect5Stub(session.ctx.host, SamrServerEnumDomains or SamrServerLookupDomain), 81'u32)
    let connectInfo = parseSamrConnect5(connectStub)
    if connectInfo.handle.len != 20:
      result.message = "SamrConnect5 failed"
      result.status = connectInfo.status
      return
    let enumStub = await rpcCall(session.ctx, pipe, 6'u16,
      buildSamrEnumDomainsStub(connectInfo.handle), 82'u32)
    let enumInfo = parseSamrEnumDomains(enumStub)
    var selectedDomain = ""
    let wanted = credential.domain.split('.')[0].toLowerAscii()
    for d in enumInfo.domains:
      if d.name.toLowerAscii() == "builtin": continue
      if selectedDomain.len == 0:
        selectedDomain = d.name
      if wanted.len > 0 and d.name.toLowerAscii() == wanted:
        selectedDomain = d.name
        break
    if selectedDomain.len == 0:
      result.message = "no account domain found"
      return
    let lookupStub = await rpcCall(session.ctx, pipe, 5'u16,
      buildSamrLookupDomainStub(connectInfo.handle, selectedDomain), 83'u32)
    let lookup = parseSamrLookupDomain(lookupStub)
    if lookup.sid.len == 0:
      result.message = "SamrLookupDomain failed"
      result.status = lookup.status
      return
    let openStub = await rpcCall(session.ctx, pipe, 7'u16,
      buildSamrOpenDomainStub(connectInfo.handle, lookup.sid, SamrDomainLookup), 84'u32)
    let openInfo = parseSamrOpenDomain(openStub)
    if openInfo.handle.len != 20 or openInfo.status != 0:
      result.message = "SamrOpenDomain failed: 0x" & openInfo.status.toHex(8)
      result.status = openInfo.status
      return
    let lookupNameStub = await rpcCall(session.ctx, pipe, 17'u16,
      buildSamrLookupNamesInDomainStub(openInfo.handle, username), 85'u32)
    let lookedUp = parseSamrLookupNamesInDomain(lookupNameStub)
    if lookedUp.rid == 0:
      result.message = "SamrLookupNamesInDomain failed: user not found"
      result.status = lookedUp.status
      return
    result.rid = lookedUp.rid
    let openUserStub = await rpcCall(session.ctx, pipe, 34'u16,
      buildSamrOpenUserStub(openInfo.handle, lookedUp.rid, 0x00000040'u32), 86'u32)
    let userHandle = parseSamrOpenUser(openUserStub)
    if userHandle.handle.len != 20 or userHandle.status != 0:
      result.message = "SamrOpenUser failed: 0x" & userHandle.status.toHex(8)
      result.status = userHandle.status
      return
    let changeStub = await rpcCall(session.ctx, pipe, 38'u16,
      buildSamrChangePasswordUserStub(userHandle.handle, oldNtHash, newNtHash), 87'u32)
    result.status = parseSamrStatus(changeStub)
    if result.status != 0:
      result.message = "SamrChangePasswordUser failed: 0x" & result.status.toHex(8)
      return
    result.success = true
    result.message = "password hashes updated"
  except CatchableError as error:
    result.error = cleanError(error)
    if result.message.len == 0:
      result.message = result.error
  finally:
    if session != nil and session.ctx != nil and session.ctx.socket != nil:
      session.ctx.socket.close()

proc addComputerSamr*(host: string; port, timeoutMs: int;
                      credential: SmbCredential;
                      computerName, computerPassword: string;
                      authMethod: SmbAuthMethod = samNtlm): Future[SamrAddComputerResult] {.async.} =
  result = SamrAddComputerResult(host: host, port: port)
  let samName = normalizeComputerSam(computerName)
  result.samAccountName = samName
  result.computerName = samName.strip(chars = {'$'}, leading = false)
  var session: SmbSession
  try:
    session = await establishSmbSession(host, port, timeoutMs, credential, authMethod)
    if session == nil or not session.authenticated:
      result.message = if session == nil: "SMB session failed" else: session.message
      return
    result.authenticated = true
    let pipe = await openSmbPipe(session.ctx, "samr")
    if not pipe.opened:
      result.message = "samr pipe open failed 0x" & pipe.status.toHex(8)
      return
    let bindAck = await rpcBindPipe(session.ctx, pipe, buildDceRpcBindSamr(60'u32))
    if not bindAck.bound:
      result.message = "SAMR bind failed"
      return
    let connectStub = await rpcCall(session.ctx, pipe, 64'u16,
      buildSamrConnect5Stub(session.ctx.host, SamrServerEnumDomains or SamrServerLookupDomain), 61'u32)
    let connectInfo = parseSamrConnect5(connectStub)
    if connectInfo.handle.len != 20:
      result.message = "SamrConnect5 failed"
      result.createStatus = connectInfo.status
      return
    let enumStub = await rpcCall(session.ctx, pipe, 6'u16,
      buildSamrEnumDomainsStub(connectInfo.handle), 62'u32)
    let enumInfo = parseSamrEnumDomains(enumStub)
    var selectedDomain = ""
    let wanted = credential.domain.split('.')[0].toLowerAscii()
    for d in enumInfo.domains:
      if d.name.toLowerAscii() == "builtin": continue
      if selectedDomain.len == 0:
        selectedDomain = d.name
      if wanted.len > 0 and d.name.toLowerAscii() == wanted:
        selectedDomain = d.name
        break
    if selectedDomain.len == 0:
      result.message = "no account domain returned"
      return
    result.domainName = selectedDomain
    let lookupStub = await rpcCall(session.ctx, pipe, 5'u16,
      buildSamrLookupDomainStub(connectInfo.handle, selectedDomain), 63'u32)
    let lookup = parseSamrLookupDomain(lookupStub)
    if lookup.sid.len == 0:
      result.message = "SamrLookupDomain failed"
      result.createStatus = lookup.status
      return
    result.domainSid = lookup.sid
    let openStub = await rpcCall(session.ctx, pipe, 7'u16,
      buildSamrOpenDomainStub(connectInfo.handle, lookup.sid,
        SamrDomainLookup or SamrDomainCreateUser), 64'u32)
    let openInfo = parseSamrOpenDomain(openStub)
    if openInfo.handle.len != 20 or openInfo.status != 0:
      result.message = "SamrOpenDomain failed"
      result.createStatus = openInfo.status
      return
    let createStub = await rpcCall(session.ctx, pipe, 50'u16,
      buildSamrCreateUser2InDomainStub(openInfo.handle, samName,
        SamrUserWorkstationTrust, SamrAccessMaxAllowed), 65'u32)
    let created = parseSamrCreateUser2InDomain(createStub)
    result.createStatus = created.status
    result.rid = created.rid
    var existingAccount = false
    if created.handle.len != 20 or created.status != 0:
      let lookupNameStub = await rpcCall(session.ctx, pipe, 17'u16,
        buildSamrLookupNamesInDomainStub(openInfo.handle, samName), 66'u32)
      let lookedUp = parseSamrLookupNamesInDomain(lookupNameStub)
      if lookedUp.status == 0:
        result.rid = lookedUp.rid
        existingAccount = true
      if result.rid == 0:
        result.message = "SamrCreateUser2InDomain failed"
        return
    let samrKey =
      case session.ctx.negotiate.dialect
      of "SMB 3.0", "SMB 3.0.2":
        smb3KdfCounter(session.sessionBaseKey, "SMB2APP\0", "SmbRpc\0", 128'u32)
      of "SMB 3.1.1":
        smb3KdfCounter(session.sessionBaseKey, "SMBAppKey\0", session.ctx.preauthHash, 128'u32)
      else:
        session.sessionBaseKey
    if not existingAccount:
      let passwordHandle =
        if created.handle.len == 20: created.handle
        else:
          let openPasswordStub = await rpcCall(session.ctx, pipe, 34'u16,
            buildSamrOpenUserStub(openInfo.handle, result.rid), 67'u32)
          let opened = parseSamrOpenUser(openPasswordStub)
          if opened.handle.len != 20 or opened.status != 0:
            result.message = "SamrOpenUser for password failed"
            result.passwordStatus = opened.status
            return
          opened.handle
      let passStub = await rpcCall(session.ctx, pipe, 58'u16,
        buildSamrSetPasswordInternal5NewStub(passwordHandle, computerPassword,
          samrKey), 68'u32)
      result.passwordStatus = parseSamrStatus(passStub)
      if result.passwordStatus != 0:
        result.message = "SamrSetInformationUser2 password failed"
        return
    let openControlStub = await rpcCall(session.ctx, pipe, 34'u16,
      buildSamrOpenUserStub(openInfo.handle, result.rid), 69'u32)
    let controlHandle = parseSamrOpenUser(openControlStub)
    if controlHandle.handle.len != 20 or controlHandle.status != 0:
      result.message = "SamrOpenUser for control failed"
      result.controlStatus = controlHandle.status
      return
    let controlStub = await rpcCall(session.ctx, pipe, 58'u16,
      buildSamrSetUserControlStub(controlHandle.handle), 70'u32)
    result.controlStatus = parseSamrStatus(controlStub)
    if result.controlStatus != 0:
      result.message = "SamrSetInformationUser2 control failed"
      return
    result.success = true
    result.message =
      if existingAccount: "computer account already existed; control updated"
      else: "computer account added"
  except CatchableError as error:
    result.error = cleanError(error)
    if result.message.len == 0:
      result.message = result.error
  finally:
    if session != nil and session.ctx != nil and session.ctx.socket != nil:
      session.ctx.socket.close()

proc connectShareTree*(session: SmbSession; share: string): Future[uint32] {.async.} =
  let ctx = session.ctx
  let pkt = ctx.signed(buildSmbTreeConnectRequest(ctx.host, share,
    ctx.nextMid(), ctx.sessionId))
  await ctx.socket.send(pkt)
  let resp = await recvOneSmb(ctx.socket, ctx.timeoutMs)
  let info = parseSmbTreeConnectResponse(resp)
  if info.connected: return info.treeId
  return 0


type
  SmbDirEntry* = object
    name*: string
    size*: int64
    isDirectory*: bool
    attributes*: uint32
    lastWriteTime*: uint64

const
  FileDirectoryInformation = 0x01'u8
  Smb2QueryDirectoryFlagsRestart = 0x01'u8

proc buildSmbOpenDirRequest*(path: string; messageId, sessionId: uint64;
                             treeId: uint32): string =
  const DesiredAccess: uint32 = 0x00100081
  const OpenExisting: uint32 = 0x00000001
  const DirectoryFile: uint32 = 0x00000001
  let name = toUtf16Le(path)
  let nameOffset = Smb2HeaderLen + 56
  let actualNameLen = max(1, name.len)
  result = newStringOfCap(4 + Smb2HeaderLen + 56 + actualNameLen)
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandCreate, messageId, sessionId, treeId)
  result.addU16Le 57
  result.add char(0); result.add char(0)
  result.addU32Le 2
  result.addU64Le 0; result.addU64Le 0
  result.addU32Le DesiredAccess
  result.addU32Le 0
  result.addU32Le 7
  result.addU32Le OpenExisting
  result.addU32Le DirectoryFile
  result.addU16Le nameOffset.uint16
  result.addU16Le name.len.uint16
  result.addU32Le 0; result.addU32Le 0
  if name.len > 0: result.add name
  else: result.add char(0)
  result.patchNetbiosLength()

proc buildSmbQueryDirectoryRequest*(fileId: string; pattern: string;
                                    messageId, sessionId: uint64; treeId: uint32;
                                    restartScan = false; bufferLen: uint32 = 65535): string =
  if fileId.len != 16:
    raise newException(ValueError, "QUERY_DIRECTORY fileId must be 16 bytes")
  let pattUtf = toUtf16Le(pattern)
  let pattOffset = Smb2HeaderLen + 32
  result = newStringOfCap(4 + Smb2HeaderLen + 32 + max(1, pattUtf.len))
  result.add "\x00\x00\x00\x00"
  result.add buildSmb2Header(Smb2CommandQueryDirectory, messageId, sessionId, treeId)
  result.addU16Le 33
  result.add char(FileDirectoryInformation)
  let flags = if restartScan: Smb2QueryDirectoryFlagsRestart else: 0'u8
  result.add char(flags)
  result.addU32Le 0
  result.add fileId
  result.addU16Le pattOffset.uint16
  result.addU16Le pattUtf.len.uint16
  result.addU32Le bufferLen
  if pattUtf.len > 0: result.add pattUtf
  else: result.add char(0)
  result.patchNetbiosLength()

proc parseSmbDirEntries*(response: string): tuple[entries: seq[SmbDirEntry]; status: uint32] =
  if response.len < 4 + Smb2HeaderLen + 8:
    return (entries: @[], status: 0xffffffff'u32)
  result.status = readU32Le(response, 12)
  if result.status != 0: return
  let body = 4 + Smb2HeaderLen
  let outOff = int(readU16Le(response, body + 2))
  let outLen = int(readU32Le(response, body + 4))
  let absolute = 4 + outOff
  if outLen <= 0 or absolute + outLen > response.len: return
  let buf = response[absolute ..< absolute + outLen]
  var cursor = 0
  while cursor + 64 <= buf.len:
    let nextOffset = int(readU32Le(buf, cursor))
    let lastWrite = readU64Le(buf, cursor + 24)
    let eof = cast[int64](readU64Le(buf, cursor + 40))
    let attrs = readU32Le(buf, cursor + 56)
    let nameLen = int(readU32Le(buf, cursor + 60))
    let nameStart = cursor + 64
    if nameStart + nameLen > buf.len: break
    let name = readUtf16LeAscii(buf, nameStart, nameLen)
    if name notin [".", ".."]:
      result.entries.add SmbDirEntry(
        name: name, size: eof,
        isDirectory: (attrs and 0x10) != 0,
        attributes: attrs,
        lastWriteTime: lastWrite)
    if nextOffset == 0: break
    cursor += nextOffset

proc listShareDirectory*(session: SmbSession; share, path: string): Future[tuple[entries: seq[SmbDirEntry]; status: uint32; message: string]] {.async.} =
  let treeId = await session.connectShareTree(share)
  if treeId == 0:
    return (entries: @[], status: 0xffffffff'u32,
            message: "could not mount share " & share)
  let ctx = session.ctx
  let openPkt = ctx.signed(buildSmbOpenDirRequest(path, ctx.nextMid(),
    ctx.sessionId, treeId))
  await ctx.socket.send(openPkt)
  let openResp = await recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = fileIdFromCreateResponse(openResp)
  if fid.len != 16:
    let s = if openResp.len >= 16: readU32Le(openResp, 12) else: 0xffffffff'u32
    return (entries: @[], status: s,
            message: "open dir failed 0x" & s.toHex(8))
  var first = true
  while true:
    let qryPkt = ctx.signed(buildSmbQueryDirectoryRequest(fid, "*",
      ctx.nextMid(), ctx.sessionId, treeId, restartScan = first))
    first = false
    await ctx.socket.send(qryPkt)
    let qryResp = await recvOneSmb(ctx.socket, ctx.timeoutMs)
    let parsed = parseSmbDirEntries(qryResp)
    result.status = parsed.status
    if parsed.status == 0:
      result.entries.add parsed.entries
      continue
    if parsed.status == 0x80000006'u32:
      result.status = 0
    else:
      result.message = "QUERY_DIRECTORY failed 0x" & parsed.status.toHex(8)
    break
  let closePkt = ctx.signed(buildSmbCloseRequest(fid, ctx.nextMid(),
    ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await recvOneSmb(ctx.socket, ctx.timeoutMs)
