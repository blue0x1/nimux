import std/[asyncdispatch, strutils]

when defined(windows):
  import std/widestrs

  type
    SECURITY_STATUS = int32
    NCRYPT_DESCRIPTOR_HANDLE = pointer

  proc NCryptUnprotectSecret(phDescriptor: ptr NCRYPT_DESCRIPTOR_HANDLE;
                             dwFlags: uint32;
                             pbProtectedBlob: pointer;
                             cbProtectedBlob: uint32;
                             pMemPara: pointer;
                             hWnd: pointer;
                             ppbData: ptr pointer;
                             pcbData: ptr uint32): SECURITY_STATUS
    {.stdcall, importc, dynlib: "ncrypt.dll".}

  proc LocalFree(hMem: pointer): pointer {.stdcall, importc, dynlib: "kernel32.dll".}

  proc decryptDpapiNgBlob*(blob: string; host = ""; username = ""; password = "";
                           ntlmHash = ""; domain = ""; kerberos = false): Future[tuple[ok: bool; plaintext, message: string]] {.async.} =
    var desc: NCRYPT_DESCRIPTOR_HANDLE = nil
    var outPtr: pointer = nil
    var outLen: uint32 = 0
    let status = NCryptUnprotectSecret(addr desc, 0'u32,
      if blob.len > 0: cast[pointer](unsafeAddr blob[0]) else: nil,
      uint32(blob.len), nil, nil, addr outPtr, addr outLen)
    if status != 0:
      return (false, "", "NCryptUnprotectSecret failed: 0x" & status.toHex(8))
    var plaintext = ""
    if outPtr != nil and outLen > 0:
      let p = cast[ptr UncheckedArray[byte]](outPtr)
      for i in 0 ..< int(outLen):
        plaintext.add char(p[i])
      discard LocalFree(outPtr)
    return (true, plaintext, "DPAPI-NG secret decrypted")
else:
  import ../smb/client as smbclient
  import ../dcerpc/client as rpcclient
  {.passL: "-lcrypto".}

  const
    GkdiUuid = [
      byte 0x60, 0x59, 0x78, 0xb9, 0x4f, 0x52, 0xdf, 0x11,
      0x8b, 0x6d, 0x83, 0xdc, 0xde, 0xd7, 0x20, 0x85
    ]
    KdsServiceLabel = "K\0D\0S\0 \0s\0e\0r\0v\0i\0c\0e\0\0\0"
    KekPublicKeyLabel = "K\0D\0S\0 \0p\0u\0b\0l\0i\0c\0 \0k\0e\0y\0\0\0"
    GkdiOpnumGetKey = 0'u16
    GkdiVersionMajor = 1'u16
    GkdiVersionMinor = 0'u16

  type
    EvpCipherCtxPtr = pointer
    EvpCipherPtr = pointer
    EvpMdPtr = pointer
    BignumPtr = pointer
    BnCtxPtr = pointer

    DerReader = object
      data: string
      pos: int

    KeyIdentifier = object
      flags: uint32
      l0Index: int32
      l1Index: int32
      l2Index: int32
      rootKeyId: string
      extra: string
      domain: string
      forest: string

    GroupKeyEnvelope = object
      l0Index: int32
      l1Index: int32
      l2Index: int32
      rootKeyId: string
      kdfAlgo: string
      hashName: string
      secAlgo: string
      secAlgoRaw: string
      secPara: string
      privKeyLength: uint32
      l1Key: string
      l2Key: string

    EnvelopedInfo = object
      consumed: int
      keyIdentifier: string
      sid: string
      encryptedKey: string
      iv: string
      tagLen: int

  proc HMAC(evpMd: EvpMdPtr; key: pointer; keyLen: cint; data: pointer; dataLen: csize_t;
            md: pointer; mdLen: ptr cuint): pointer {.cdecl, importc.}
  proc EVP_sha512(): EvpMdPtr {.cdecl, importc.}
  proc SHA256(data: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc.}
  proc EVP_CIPHER_CTX_new(): EvpCipherCtxPtr {.cdecl, importc.}
  proc EVP_CIPHER_CTX_free(ctx: EvpCipherCtxPtr) {.cdecl, importc.}
  proc EVP_CIPHER_CTX_set_padding(ctx: EvpCipherCtxPtr; pad: cint): cint {.cdecl, importc.}
  proc EVP_DecryptInit_ex(ctx: EvpCipherCtxPtr; cipher: EvpCipherPtr; impl: pointer;
                          key, iv: pointer): cint {.cdecl, importc.}
  proc EVP_DecryptUpdate(ctx: EvpCipherCtxPtr; outBuf: pointer; outLen: ptr cint;
                         inBuf: pointer; inLen: cint): cint {.cdecl, importc.}
  proc EVP_DecryptFinal_ex(ctx: EvpCipherCtxPtr; outm: pointer; outLen: ptr cint): cint {.cdecl, importc.}
  proc EVP_CIPHER_CTX_ctrl(ctx: EvpCipherCtxPtr; typ, arg: cint; ptrArg: pointer): cint {.cdecl, importc.}
  proc EVP_aes_256_ecb(): EvpCipherPtr {.cdecl, importc.}
  proc EVP_aes_256_gcm(): EvpCipherPtr {.cdecl, importc.}
  proc BN_new(): BignumPtr {.cdecl, importc.}
  proc BN_free(a: BignumPtr) {.cdecl, importc.}
  proc BN_CTX_new(): BnCtxPtr {.cdecl, importc.}
  proc BN_CTX_free(ctx: BnCtxPtr) {.cdecl, importc.}
  proc BN_bin2bn(s: pointer; len: cint; ret: BignumPtr): BignumPtr {.cdecl, importc.}
  proc BN_num_bits(a: BignumPtr): cint {.cdecl, importc.}
  proc BN_bn2bin(a: BignumPtr; to: pointer): cint {.cdecl, importc.}
  proc BN_mod_exp(r, a, p, m: BignumPtr; ctx: BnCtxPtr): cint {.cdecl, importc.}

  const
    EvpCtrlAeadSetIvLen = 0x9
    EvpCtrlAeadSetTag = 0x11

  proc readU32Le(data: string; offset: int): uint32 =
    if offset + 3 >= data.len: return 0
    uint32(ord(data[offset])) or
      (uint32(ord(data[offset + 1])) shl 8) or
      (uint32(ord(data[offset + 2])) shl 16) or
      (uint32(ord(data[offset + 3])) shl 24)

  proc readI32Le(data: string; offset: int): int32 =
    cast[int32](readU32Le(data, offset))

  proc addU16Le(data: var string; value: uint16) =
    data.add char(value and 0xff)
    data.add char((value shr 8) and 0xff)

  proc addU32Le(data: var string; value: uint32) =
    for shift in countup(0, 24, 8):
      data.add char((value shr shift) and 0xff)

  proc addU32Be(data: var string; value: uint32) =
    data.add char((value shr 24) and 0xff)
    data.add char((value shr 16) and 0xff)
    data.add char((value shr 8) and 0xff)
    data.add char(value and 0xff)

  proc addI32Le(data: var string; value: int32) =
    data.addU32Le(cast[uint32](value))

  proc atEnd(r: DerReader): bool = r.pos >= r.data.len

  proc readByte(r: var DerReader): int =
    if r.pos >= r.data.len: return -1
    result = ord(r.data[r.pos])
    inc r.pos

  proc readLen(r: var DerReader): int =
    let first = r.readByte()
    if first < 0: return -1
    if (first and 0x80) == 0: return first
    let n = first and 0x7f
    if n == 0 or n > 4: return -1
    result = 0
    for _ in 0 ..< n:
      let b = r.readByte()
      if b < 0: return -1
      result = (result shl 8) or b

  proc readTlv(r: var DerReader): tuple[tag: int, body: string, start, finish: int] =
    let start = r.pos
    let tag = r.readByte()
    if tag < 0: return (-1, "", start, start)
    let length = r.readLen()
    if length < 0 or r.pos + length > r.data.len: return (-1, "", start, start)
    result = (tag, r.data[r.pos ..< r.pos + length], start, r.pos + length)
    r.pos += length

  proc sha256Digest(data: string): string =
    result = newString(32)
    let p = if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil
    discard SHA256(p, data.len.csize_t, addr result[0])

  proc hmacSha512(key, data: string): string =
    var outLen: cuint = 64
    result = newString(64)
    let keyPtr = if key.len > 0: cast[pointer](unsafeAddr key[0]) else: nil
    let dataPtr = if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil
    discard HMAC(EVP_sha512(), keyPtr, cint(key.len), dataPtr, data.len.csize_t,
      addr result[0], addr outLen)
    result.setLen int(outLen)

  proc hmacForHash(hashName, key, data: string): string =
    if hashName.toUpperAscii().contains("SHA256"):
      smbclient.hmacSha256(key, data)
    else:
      hmacSha512(key, data)

  proc sp800108Counter(secret, label, context, hashName: string; keyLen: int): string =
    var input = ""
    input.addU32Be 1'u32
    input.add label
    input.add char(0)
    input.add context
    input.addU32Be uint32(keyLen * 8)
    let mac = hmacForHash(hashName, secret, input)
    mac[0 ..< min(keyLen, mac.len)]

  proc computeKdfHash(length: int; keyMaterial, otherInfo: string): string =
    var counter = 1'u32
    while result.len < length:
      var data = ""
      data.addU32Be counter
      data.add keyMaterial
      data.add otherInfo
      result.add sha256Digest(data)
      inc counter
    result.setLen length

  proc computeKdfContext(rootKeyId: string; l0, l1, l2: int32): string =
    result = rootKeyId
    result.addI32Le l0
    result.addI32Le l1
    result.addI32Le l2

  proc utf16LeNull(s: string): string =
    for ch in s:
      result.add ch
      result.add char(0)
    result.add char(0)
    result.add char(0)

  proc padTo4(data: var string) =
    while data.len mod 4 != 0:
      data.add char(0)

  proc utf16LeToString(data: string): string =
    var i = 0
    while i + 1 < data.len:
      let code = ord(data[i]) or (ord(data[i + 1]) shl 8)
      if code == 0: break
      result.add char(code and 0xff)
      inc i, 2

  proc sidToBytes(sid: string): string =
    let parts = sid.split('-')
    if parts.len < 3 or parts[0] != "S":
      return ""
    result.add char(parseInt(parts[1]))
    result.add char(parts.len - 3)
    let authority = uint64(parseBiggestUInt(parts[2]))
    for shift in countdown(40, 0, 8):
      result.add char((authority shr shift) and 0xff)
    for part in parts[3 .. ^1]:
      let value = uint32(parseBiggestUInt(part))
      for shift in countup(0, 24, 8):
        result.add char((value shr shift) and 0xff)

  proc createAce(sid: string; mask: uint32): string =
    let sidBytes = sidToBytes(sid)
    result.add char(0)
    result.add char(0)
    result.addU16Le uint16(8 + sidBytes.len)
    result.addU32Le mask
    result.add sidBytes

  proc createSecurityDescriptor(sid: string): string =
    let owner = sidToBytes("S-1-5-18")
    let group = sidToBytes("S-1-5-18")
    let ace1 = createAce(sid, 3'u32)
    let ace2 = createAce("S-1-1-0", 2'u32)
    let daclSize = uint16(8 + ace1.len + ace2.len)
    let daclOffset = 20'u32
    let ownerOffset = uint32(20 + daclSize)
    let groupOffset = ownerOffset + uint32(owner.len)
    result.add char(1)
    result.add char(0)
    result.add char(0x04)
    result.add char(0x80)
    result.addU32Le ownerOffset
    result.addU32Le groupOffset
    result.addU32Le 0
    result.addU32Le daclOffset
    result.add char(2)
    result.add char(0)
    result.addU16Le daclSize
    result.addU16Le 2
    result.addU16Le 0
    result.add ace1
    result.add ace2
    result.add owner
    result.add group

  proc resolveGkdiPort(host: string; timeoutMs: int; username, password, ntlmHash, domain: string;
                       kerberos: bool): Future[int] {.async.} =
    if kerberos:
      return await rpcclient.resolveDynamicPortKerb(host, 135, timeoutMs,
        @GkdiUuid, GkdiVersionMajor, GkdiVersionMinor, domain)
    let cred = smbclient.SmbCredential(
      username: username, password: password, ntlmHash: ntlmHash, domain: domain)
    return await rpcclient.resolveDynamicPort(host, 135, timeoutMs,
      @GkdiUuid, GkdiVersionMajor, GkdiVersionMinor, cred)

  proc buildGkdiGetKeyStub(targetSd, rootKeyId: string; l0, l1, l2: int32): string =
    result.addU32Le uint32(targetSd.len)
    result.addU32Le uint32(targetSd.len)
    result.add targetSd
    result.padTo4()
    result.addU32Le 1'u32
    result.add rootKeyId
    result.addI32Le l0
    result.addI32Le l1
    result.addI32Le l2

  proc parseGkdiGetKeyResponse(stub: string): string =
    if stub.len < 12:
      return ""
    let outLen = int(readU32Le(stub, 0))
    if outLen <= 0:
      return ""
    let referentId = readU32Le(stub, 4)
    if referentId == 0'u32:
      return ""
    let count = int(readU32Le(stub, 8))
    let bodyLen = min(outLen, count)
    if bodyLen <= 0:
      return ""
    if 12 + bodyLen > stub.len:
      return ""
    result = stub[12 ..< 12 + bodyLen]

  proc parseKeyIdentifier(data: string): KeyIdentifier =
    if data.len < 40:
      return
    result.flags = readU32Le(data, 8)
    result.l0Index = readI32Le(data, 12)
    result.l1Index = readI32Le(data, 16)
    result.l2Index = readI32Le(data, 20)
    result.rootKeyId = data[24 ..< 40]
    let extraLen = int(readU32Le(data, 40))
    let domainLen = int(readU32Le(data, 44))
    let forestLen = int(readU32Le(data, 48))
    var pos = 52
    if pos + extraLen > data.len: return
    result.extra = data[pos ..< pos + extraLen]
    pos += extraLen
    if pos + domainLen > data.len: return
    result.domain = data[pos ..< pos + domainLen]
    pos += domainLen
    if pos + forestLen > data.len: return
    result.forest = data[pos ..< pos + forestLen]

  proc parseGroupKeyEnvelope(data: string): GroupKeyEnvelope =
    if data.len < 64:
      return
    result.l0Index = readI32Le(data, 12)
    result.l1Index = readI32Le(data, 16)
    result.l2Index = readI32Le(data, 20)
    result.rootKeyId = data[24 ..< 40]
    let kdfAlgoLen = int(readU32Le(data, 40))
    let kdfParaLen = int(readU32Le(data, 44))
    let secAlgoLen = int(readU32Le(data, 48))
    let secParaLen = int(readU32Le(data, 52))
    result.privKeyLength = readU32Le(data, 56)
    discard readU32Le(data, 60)
    let l1KeyLen = int(readU32Le(data, 64))
    let l2KeyLen = int(readU32Le(data, 68))
    let domainLen = int(readU32Le(data, 72))
    let forestLen = int(readU32Le(data, 76))
    var pos = 80
    if pos + kdfAlgoLen > data.len: return
    result.kdfAlgo = utf16LeToString(data[pos ..< pos + kdfAlgoLen])
    pos += kdfAlgoLen
    if pos + kdfParaLen > data.len: return
    let kdfPara = data[pos ..< pos + kdfParaLen]
    pos += kdfParaLen
    if kdfPara.len >= 16:
      let hashLen = int(readU32Le(kdfPara, 8))
      if 16 + hashLen <= kdfPara.len:
        result.hashName = utf16LeToString(kdfPara[16 ..< 16 + hashLen])
    if pos + secAlgoLen > data.len: return
    result.secAlgoRaw = data[pos ..< pos + secAlgoLen]
    result.secAlgo = utf16LeToString(result.secAlgoRaw)
    pos += secAlgoLen
    if pos + secParaLen > data.len: return
    result.secPara = data[pos ..< pos + secParaLen]
    pos += secParaLen
    pos += domainLen + forestLen
    if pos + l1KeyLen > data.len: return
    result.l1Key = data[pos ..< pos + l1KeyLen]
    pos += l1KeyLen
    if pos + l2KeyLen > data.len: return
    result.l2Key = data[pos ..< pos + l2KeyLen]

  proc parseSidFromKeyAttr(data: string): string =
    let sidLabel = data.find("SID")
    if sidLabel >= 0:
      var i = sidLabel + 3
      while i + 2 < data.len:
        if data[i] == '\x0c':
          let slen = ord(data[i + 1])
          if slen > 0 and i + 2 + slen <= data.len:
            let candidate = data[i + 2 ..< i + 2 + slen]
            if candidate.startsWith("S-1-"):
              return candidate
        inc i
    let marker = "S-1-"
    let start = data.find(marker)
    if start < 0: return ""
    var i = start
    while i < data.len and (data[i] in {'S', '-', '0'..'9'}):
      result.add data[i]
      inc i

  proc parseEnvelopedInfo(data: string): EnvelopedInfo =
    var outer = DerReader(data: data)
    let outerTlv = readTlv(outer)
    if outerTlv.tag != 0x30:
      return
    result.consumed = outerTlv.finish
    var outerBody = DerReader(data: outerTlv.body)
    discard readTlv(outerBody)
    let wrapped = readTlv(outerBody)
    if wrapped.tag != 0xa0:
      return
    var innerSeq = DerReader(data: wrapped.body)
    let env = readTlv(innerSeq)
    if env.tag != 0x30:
      return
    var envBody = DerReader(data: env.body)
    discard readTlv(envBody)
    let recipients = readTlv(envBody)
    if recipients.tag != 0x31:
      return
    var recSet = DerReader(data: recipients.body)
    let kekCtx = readTlv(recSet)
    if kekCtx.tag != 0xa2:
      return
    var kekBody = DerReader(data: kekCtx.body)
    discard readTlv(kekBody)
    let kekId = readTlv(kekBody)
    if kekId.tag != 0x30:
      return
    var kekIdBody = DerReader(data: kekId.body)
    let keyIdentifier = readTlv(kekIdBody)
    if keyIdentifier.tag != 0x04:
      return
    result.keyIdentifier = keyIdentifier.body
    while not kekIdBody.atEnd():
      let extra = readTlv(kekIdBody)
      if extra.tag == 0x30:
        result.sid = parseSidFromKeyAttr(extra.body)
    discard readTlv(kekBody)
    let encryptedKey = readTlv(kekBody)
    if encryptedKey.tag == 0x04:
      result.encryptedKey = encryptedKey.body
    let encInfo = readTlv(envBody)
    if encInfo.tag != 0x30:
      return
    var encBody = DerReader(data: encInfo.body)
    discard readTlv(encBody)
    let alg = readTlv(encBody)
    if alg.tag != 0x30:
      return
    var algBody = DerReader(data: alg.body)
    discard readTlv(algBody)
    let params = readTlv(algBody)
    if params.tag == 0x30:
      var paramsBody = DerReader(data: params.body)
      let iv = readTlv(paramsBody)
      if iv.tag == 0x04:
        result.iv = iv.body
      let tagLen = readTlv(paramsBody)
      if tagLen.tag == 0x02:
        var value = 0
        for c in tagLen.body:
          value = (value shl 8) or ord(c)
        result.tagLen = value

  proc kdf(hashName, secret, label, context: string; length: int): string =
    sp800108Counter(secret, label, context, hashName, length)

  proc computeL2Key(keyId: KeyIdentifier; gke: GroupKeyEnvelope): string =
    var l1 = gke.l1Index
    var l1Key = gke.l1Key
    var l2 = gke.l2Index
    var l2Key = gke.l2Key
    var reseedL2 = l2 == 31 or l1 != keyId.l1Index
    let hashName = gke.hashName
    if l2 != 31 and l1 != keyId.l1Index:
      dec l1
    while l1 != keyId.l1Index:
      reseedL2 = true
      dec l1
      l1Key = kdf(hashName, l1Key, KdsServiceLabel,
        computeKdfContext(gke.rootKeyId, gke.l0Index, l1, -1), 64)
    if reseedL2:
      l2 = 31
      l2Key = kdf(hashName, l1Key, KdsServiceLabel,
        computeKdfContext(gke.rootKeyId, gke.l0Index, l1, l2), 64)
    while l2 != keyId.l2Index:
      dec l2
      l2Key = kdf(hashName, l2Key, KdsServiceLabel,
        computeKdfContext(gke.rootKeyId, gke.l0Index, l1, l2), 64)
    l2Key

  proc aes256EcbDecrypt(key, cipherBlock: string): string =
    if key.len != 32 or cipherBlock.len != 16:
      return ""
    let ctx = EVP_CIPHER_CTX_new()
    if ctx.isNil:
      return ""
    defer: EVP_CIPHER_CTX_free(ctx)
    if EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nil,
        cast[pointer](unsafeAddr key[0]), nil) != 1:
      return ""
    discard EVP_CIPHER_CTX_set_padding(ctx, 0)
    result = newString(32)
    var outLen = 0.cint
    var finalLen = 0.cint
    if EVP_DecryptUpdate(ctx, addr result[0], addr outLen,
        cast[pointer](unsafeAddr cipherBlock[0]), cint(cipherBlock.len)) != 1:
      return ""
    if EVP_DecryptFinal_ex(ctx, addr result[outLen], addr finalLen) != 1:
      return ""
    result.setLen int(outLen + finalLen)

  proc aesUnwrap(kek, wrapped: string): string =
    if wrapped.len < 16 or wrapped.len mod 8 != 0:
      return ""
    var blocks: seq[string]
    var i = 0
    while i < wrapped.len:
      blocks.add wrapped[i ..< i + 8]
      inc i, 8
    var a = blocks[0]
    blocks.delete(0)
    for j in countdown(5, 0):
      for idx in countdown(blocks.high, 0):
        var t = uint64(blocks.len * j + idx + 1)
        var aXor = newString(8)
        let aVal =
          (uint64(ord(a[0])) shl 56) or (uint64(ord(a[1])) shl 48) or
          (uint64(ord(a[2])) shl 40) or (uint64(ord(a[3])) shl 32) or
          (uint64(ord(a[4])) shl 24) or (uint64(ord(a[5])) shl 16) or
          (uint64(ord(a[6])) shl 8) or uint64(ord(a[7]))
        let mixed = aVal xor t
        for shift in countdown(56, 0, 8):
          aXor[7 - (shift div 8)] = char((mixed shr shift) and 0xff)
        let plain = aes256EcbDecrypt(kek, aXor & blocks[idx])
        if plain.len != 16:
          return ""
        a = plain[0 ..< 8]
        blocks[idx] = plain[8 ..< 16]
    if a != "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6":
      return ""
    for chunk in blocks:
      result.add chunk

  proc decryptAes256Gcm(key, iv, ciphertext, tag: string): string =
    if key.len != 32 or iv.len == 0 or tag.len == 0:
      return ""
    let ctx = EVP_CIPHER_CTX_new()
    if ctx.isNil:
      return ""
    defer: EVP_CIPHER_CTX_free(ctx)
    if EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nil, nil, nil) != 1:
      return ""
    if EVP_CIPHER_CTX_ctrl(ctx, EvpCtrlAeadSetIvLen, cint(iv.len), nil) != 1:
      return ""
    if EVP_DecryptInit_ex(ctx, nil, nil, cast[pointer](unsafeAddr key[0]),
        cast[pointer](unsafeAddr iv[0])) != 1:
      return ""
    result = newString(ciphertext.len + 16)
    var outLen = 0.cint
    if ciphertext.len > 0 and EVP_DecryptUpdate(ctx, addr result[0], addr outLen,
        cast[pointer](unsafeAddr ciphertext[0]), cint(ciphertext.len)) != 1:
      return ""
    var mutableTag = tag
    if EVP_CIPHER_CTX_ctrl(ctx, EvpCtrlAeadSetTag, cint(tag.len),
        cast[pointer](unsafeAddr mutableTag[0])) != 1:
      return ""
    var finalLen = 0.cint
    if EVP_DecryptFinal_ex(ctx, addr result[outLen], addr finalLen) != 1:
      return ""
    result.setLen int(outLen + finalLen)

  proc generateKekSecretFromPublicKey(gke: GroupKeyEnvelope; keyId: KeyIdentifier;
                                      l2Key: string): tuple[secret, context: string] =
    let privateKey = kdf(gke.hashName, l2Key, KdsServiceLabel, gke.secAlgoRaw,
      int((gke.privKeyLength + 7) div 8))
    if gke.secAlgo != "DH":
      return ("", "")
    if keyId.extra.len < 12:
      return ("", "")
    let keyLength = int(readU32Le(keyId.extra, 4))
    if keyId.extra.len < 8 + keyLength * 3:
      return ("", "")
    let fieldOrder = keyId.extra[8 ..< 8 + keyLength]
    let pubKey = keyId.extra[8 + keyLength * 2 ..< 8 + keyLength * 3]
    let bnPub = BN_bin2bn(cast[pointer](unsafeAddr pubKey[0]), cint(pubKey.len), nil)
    let bnPriv = BN_bin2bn(cast[pointer](unsafeAddr privateKey[0]), cint(privateKey.len), nil)
    let bnMod = BN_bin2bn(cast[pointer](unsafeAddr fieldOrder[0]), cint(fieldOrder.len), nil)
    let bnRes = BN_new()
    let bnCtx = BN_CTX_new()
    if bnPub.isNil or bnPriv.isNil or bnMod.isNil or bnRes.isNil or bnCtx.isNil:
      if not bnPub.isNil: BN_free(bnPub)
      if not bnPriv.isNil: BN_free(bnPriv)
      if not bnMod.isNil: BN_free(bnMod)
      if not bnRes.isNil: BN_free(bnRes)
      if not bnCtx.isNil: BN_CTX_free(bnCtx)
      return ("", "")
    defer:
      BN_free(bnPub)
      BN_free(bnPriv)
      BN_free(bnMod)
      BN_free(bnRes)
      BN_CTX_free(bnCtx)
    if BN_mod_exp(bnRes, bnPub, bnPriv, bnMod, bnCtx) != 1:
      return ("", "")
    let sharedLen = (int(BN_num_bits(bnRes)) + 7) div 8
    if sharedLen <= 0:
      return ("", "")
    var shared = newString(sharedLen)
    discard BN_bn2bin(bnRes, addr shared[0])
    let otherInfo = utf16LeNull("SHA512") & KekPublicKeyLabel & KdsServiceLabel
    (computeKdfHash(32, shared, otherInfo), KekPublicKeyLabel)

  proc computeKek(gke: GroupKeyEnvelope; keyId: KeyIdentifier): string =
    let l2Key = computeL2Key(keyId, gke)
    var secret = ""
    var context = ""
    if (keyId.flags and 1'u32) != 0:
      (secret, context) = generateKekSecretFromPublicKey(gke, keyId, l2Key)
    else:
      secret = l2Key
      context = keyId.extra
    if secret.len == 0:
      return ""
    kdf(gke.hashName, secret, KdsServiceLabel, context, 32)

  proc decodeLapsPlaintext(plain: string): string =
    utf16LeToString(plain)

  proc decryptDpapiNgBlob*(blob: string; host = ""; username = ""; password = "";
                           ntlmHash = ""; domain = ""; kerberos = false): Future[tuple[ok: bool; plaintext, message: string]] {.async.} =
    try:
      if blob.len < 16:
        return (false, "", "blob too short")
      let blobLen = int(readU32Le(blob, 8))
      if blobLen <= 0 or 16 + blobLen > blob.len:
        return (false, "", "invalid encrypted blob length")
      let payload = blob[16 ..< 16 + blobLen]
      let env = parseEnvelopedInfo(payload)
      if env.keyIdentifier.len == 0 or env.sid.len == 0 or env.encryptedKey.len == 0:
        return (false, "", "failed to parse DPAPI-NG CMS envelope")
      let keyId = parseKeyIdentifier(env.keyIdentifier)
      let gkdiPort = await resolveGkdiPort(host, 8000, username, password, ntlmHash, domain, kerberos)
      let gkdi = 
        if kerberos:
          await rpcclient.connectAndBindKerb(host, gkdiPort, 8000,
            @GkdiUuid, GkdiVersionMajor, GkdiVersionMinor, domain,
            authLevel = rpcclient.AuthLevelPktPrivacy)
        else:
          let cred = smbclient.SmbCredential(
            username: username, password: password, ntlmHash: ntlmHash, domain: domain)
          await rpcclient.connectAndBind(host, gkdiPort, 8000,
            @GkdiUuid, GkdiVersionMajor, GkdiVersionMinor, cred,
            authLevel = rpcclient.AuthLevelPktPrivacy)
      defer: gkdi.close()
      let sd = createSecurityDescriptor(env.sid)
      let req = buildGkdiGetKeyStub(sd, keyId.rootKeyId, keyId.l0Index, keyId.l1Index, keyId.l2Index)
      let rpcResp = await gkdi.call(GkdiOpnumGetKey, req)
      if not rpcResp.ok:
        return (false, "", "GKDI GetKey fault 0x" & rpcResp.faultStatus.toHex(8))
      let gkeRaw = parseGkdiGetKeyResponse(rpcResp.stub)
      if gkeRaw.len == 0:
        return (false, "", "GKDI returned no group key envelope")
      let gke = parseGroupKeyEnvelope(gkeRaw)
      let kek = computeKek(gke, keyId)
      if kek.len == 0:
        return (false, "", "failed to derive KEK")
      let cek = aesUnwrap(kek, env.encryptedKey)
      if cek.len == 0:
        return (false, "", "failed to unwrap CEK")
      let tail = payload[env.consumed .. ^1]
      if env.tagLen <= 0 or tail.len <= env.tagLen:
        return (false, "", "invalid encrypted payload tail")
      let ciphertext = tail[0 ..< tail.len - env.tagLen]
      let tag = tail[tail.len - env.tagLen .. ^1]
      let plain = decryptAes256Gcm(cek, env.iv, ciphertext, tag)
      if plain.len == 0:
        return (false, "", "AES-GCM decrypt failed")
      let decoded = decodeLapsPlaintext(plain)
      if decoded.len > 0:
        return (true, decoded, "DPAPI-NG secret decrypted")
      return (true, plain, "DPAPI-NG secret decrypted")
    except CatchableError as error:
      return (false, "", error.msg)
