import std/[asyncdispatch, asyncnet, net, strutils, tables, times]
import ../smb/client as smbclient
import ../dcerpc/client as dcerpc
import ../kerberos/gssapi as krb
import ../../core/proxy as netproxy

type
  LdapEntry* = object
    dn*: string
    attrs*: Table[string, seq[string]]

  LdapProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksLdap*: bool
    anonymous*: bool
    authAttempted*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    rootDomainNamingContext*: string
    configurationNamingContext*: string
    schemaNamingContext*: string
    domainSid*: string
    domainFunctionality*: string
    forestFunctionality*: string
    dnsHostName*: string
    serverName*: string
    ldapServiceName*: string
    supportedSaslMechanisms*: seq[string]
    users*: seq[LdapEntry]
    groups*: seq[LdapEntry]
    computers*: seq[LdapEntry]
    asreproastable*: seq[LdapEntry]
    kerberoastable*: seq[LdapEntry]
    trusts*: seq[LdapEntry]
    gpos*: seq[LdapEntry]
    schema*: seq[LdapEntry]
    config*: seq[LdapEntry]
    fgpp*: seq[LdapEntry]
    deleted*: seq[LdapEntry]
    locked*: seq[LdapEntry]
    expiredPasswords*: seq[LdapEntry]
    staleUsers*: seq[LdapEntry]
    neverLoggedOn*: seq[LdapEntry]
    unconstrained*: seq[LdapEntry]
    constrained*: seq[LdapEntry]
    rbcdTargets*: seq[LdapEntry]
    passwdNotReqd*: seq[LdapEntry]
    dontExpire*: seq[LdapEntry]
    adminCount*: seq[LdapEntry]
    sites*: seq[LdapEntry]
    subnets*: seq[LdapEntry]
    dcs*: seq[LdapEntry]
    admins*: seq[LdapEntry]
    dnsZones*: seq[LdapEntry]
    certificateInventory*: seq[LdapEntry]
    custom*: seq[LdapEntry]
    queryRequested*: bool
    message*: string

  LdapAddComputerResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    success*: bool
    bindResultCode*: int
    resultCode*: int
    diagnostic*: string
    defaultNamingContext*: string
    distinguishedName*: string
    computerName*: string
    samAccountName*: string
    message*: string

  LdapRbcdResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    success*: bool
    bindResultCode*: int
    resultCode*: int
    diagnostic*: string
    defaultNamingContext*: string
    delegateFrom*: string
    delegateFromDn*: string
    delegateFromSid*: string
    delegateTo*: string
    delegateToDn*: string
    message*: string

  LdapModOp* = enum
    lmoAdd, lmoDelete, lmoReplace

  LdapModification* = object
    op*: LdapModOp
    attr*: string
    values*: seq[string]

  LdapWriteKind* = enum
    lwAdd, lwModify, lwDelete

  LdapWriteAction* = object
    kind*: LdapWriteKind
    dn*: string
    attrs*: seq[tuple[name: string, values: seq[string]]]
    mods*: seq[LdapModification]

  LdapWriteItem* = object
    kind*: string
    dn*: string
    success*: bool
    resultCode*: int
    diagnostic*: string
    message*: string

  LdapWriteResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    success*: bool
    items*: seq[LdapWriteItem]
    message*: string

  LdapGpoInfoResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    gpo*: string
    dn*: string
    cn*: string
    displayName*: string
    gpcFileSysPath*: string
    versionNumber*: int
    success*: bool
    message*: string

  LdapNestedGroupsResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    target*: string
    targetDn*: string
    groups*: seq[LdapEntry]
    success*: bool
    message*: string

  LdapAce* = object
    aceType*: int
    aceFlags*: int
    mask*: uint32
    trusteeSid*: string
    rights*: seq[string]
    objectType*: string
    inheritedObjectType*: string
    raw*: string

  LdapAclResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    target*: string
    targetDn*: string
    ownerSid*: string
    groupSid*: string
    aces*: seq[LdapAce]
    success*: bool
    message*: string

  LdapAclModifyResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    target*: string
    targetDn*: string
    principal*: string
    principalSid*: string
    owner*: string
    ownerSid*: string
    rights*: seq[string]
    mask*: uint32
    aceType*: int
    aceFlags*: int
    objectType*: string
    inheritedObjectType*: string
    operation*: string
    resultCode*: int
    diagnostic*: string
    success*: bool
    message*: string

  LdapLapsResult* = object
    host*: string
    port*: int
    reachable*: bool
    authenticated*: bool
    bindResultCode*: int
    bindDiagnostic*: string
    defaultNamingContext*: string
    computer*: string
    computerDn*: string
    samAccountName*: string
    dnsHostName*: string
    legacyPassword*: string
    legacyExpiration*: string
    windowsPassword*: string
    windowsEncryptedPassword*: string
    windowsEncryptedDsrmPassword*: string
    windowsExpiration*: string
    success*: bool
    message*: string

  LdapQueryOptions* = object
    rootDse*: bool
    users*: bool
    groups*: bool
    computers*: bool
    asreproast*: bool
    kerberoast*: bool
    trusts*: bool
    gpos*: bool
    schema*: bool
    config*: bool
    fgpp*: bool
    deleted*: bool
    locked*: bool
    expiredPasswords*: bool
    staleUsers*: bool
    neverLoggedOn*: bool
    unconstrained*: bool
    constrained*: bool
    rbcdTargets*: bool
    passwdNotReqd*: bool
    dontExpire*: bool
    adminCount*: bool
    sites*: bool
    subnets*: bool
    dcs*: bool
    admins*: bool
    dns*: bool
    certificateInventory*: bool
    customBase*: string
    customFilter*: string
    customAttrs*: seq[string]
    limit*: int

  LdapWriteSession = ref object
    messageId: int
    sealed: bool
    secCtx: dcerpc.NtlmSecCtx
    gssCtx: krb.KerberosContext
    gssPrivacy: bool

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc addU16Le(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32Le(data: var string; value: uint32) =
  for shift in countup(0, 24, 8):
    data.add char((value shr shift) and 0xff)

proc readU16Le(data: string; offset: int): uint16 =
  if offset + 1 >= data.len: return 0
  uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

proc readU32Le(data: string; offset: int): uint32 =
  if offset + 3 >= data.len: return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc addLen(data: var string; length: int) =
  if length < 128:
    data.add char(length)
  elif length <= 255:
    data.add char(0x81)
    data.add char(length)
  elif length <= 65535:
    data.add char(0x82)
    data.add char((length shr 8) and 0xff)
    data.add char(length and 0xff)
  else:
    data.add char(0x84)
    data.add char((length shr 24) and 0xff)
    data.add char((length shr 16) and 0xff)
    data.add char((length shr 8) and 0xff)
    data.add char(length and 0xff)

proc tlv(tag: int; content: string): string =
  result.add char(tag)
  result.addLen content.len
  result.add content

proc encInt(value: int64): string =
  if value == 0:
    return "\x00"
  var v = value
  var bytes: seq[byte]
  let negative = v < 0
  if negative:
    while v != -1 or (bytes.len > 0 and (bytes[0] and 0x80'u8) == 0):
      bytes.insert(byte(v and 0xff), 0)
      v = v shr 8
  else:
    while v > 0 or (bytes.len > 0 and (bytes[0] and 0x80'u8) != 0):
      bytes.insert(byte(v and 0xff), 0)
      v = v shr 8
  for b in bytes: result.add char(b)

proc ldapInteger(value: int): string =
  tlv(0x02, encInt(value.int64))

proc ldapEnum(value: int): string =
  tlv(0x0a, encInt(value.int64))

proc ldapString(value: string): string =
  tlv(0x04, value)

proc ldapBool(value: bool): string =
  tlv(0x01, if value: "\xff" else: "\x00")

proc buildAnonymousBindRequest*(messageId = 1): string =
  let bindBody = ldapInteger(3) & ldapString("") & tlv(0x80, "")
  tlv(0x30, ldapInteger(messageId) & tlv(0x60, bindBody))

proc buildSimpleBindRequest*(name, password: string; messageId = 1): string =
  let bindBody = ldapInteger(3) & ldapString(name) & tlv(0x80, password)
  tlv(0x30, ldapInteger(messageId) & tlv(0x60, bindBody))

proc buildSaslBindRequest*(mechanism, credentials: string; messageId = 1): string =
  let saslCredentials = ldapString(mechanism) & ldapString(credentials)
  let bindBody = ldapInteger(3) & ldapString("") & tlv(0xa3, saslCredentials)
  tlv(0x30, ldapInteger(messageId) & tlv(0x60, bindBody))

proc buildSicilyNegotiateRequest*(name, token: string; messageId = 1): string =
  let bindBody = ldapInteger(3) & ldapString(name) & tlv(0x8a, token)
  tlv(0x30, ldapInteger(messageId) & tlv(0x60, bindBody))

proc buildSicilyResponseRequest*(name, token: string; messageId = 1): string =
  let bindBody = ldapInteger(3) & ldapString(name) & tlv(0x8b, token)
  tlv(0x30, ldapInteger(messageId) & tlv(0x60, bindBody))

proc buildLdapNtlmType1(domain = ""; workstation = ""): string =
  const
    ntlmNegotiateUnicode = 0x00000001'u32
    ntlmRequestTarget = 0x00000004'u32
    ntlmNegotiateNtlm = 0x00000200'u32
    ntlmNegotiateAlwaysSign = 0x00008000'u32
    ntlmNegotiateExtendedSessionSecurity = 0x00080000'u32
    ntlmNegotiateTargetInfo = 0x00800000'u32
    ntlmNegotiate128 = 0x20000000'u32
    ntlmNegotiate56 = 0x80000000'u32
  let flags = ntlmNegotiateUnicode or ntlmRequestTarget or ntlmNegotiateNtlm or
    ntlmNegotiateAlwaysSign or ntlmNegotiateExtendedSessionSecurity or
    ntlmNegotiateTargetInfo or ntlmNegotiate128 or ntlmNegotiate56
  let payloadOffset = 32'u32

  result.add "NTLMSSP\0"
  result.addU32Le 1'u32
  result.addU32Le flags
  result.addU16Le domain.len.uint16
  result.addU16Le domain.len.uint16
  result.addU32Le(if domain.len > 0: payloadOffset else: 0'u32)
  result.addU16Le workstation.len.uint16
  result.addU16Le workstation.len.uint16
  result.addU32Le(if workstation.len > 0: payloadOffset + domain.len.uint32 else: 0'u32)
  result.add domain.toUpperAscii()
  result.add workstation.toUpperAscii()

type
  AsnReader = object
    data: string
    pos: int

proc atEnd(r: AsnReader): bool = r.pos >= r.data.len

proc readByte(r: var AsnReader): int =
  if r.pos >= r.data.len: return -1
  result = ord(r.data[r.pos])
  inc r.pos

proc readLen(r: var AsnReader): int =
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

proc readTLV(r: var AsnReader): tuple[tag: int, body: string] =
  let tag = r.readByte()
  if tag < 0: return (-1, "")
  let length = r.readLen()
  if length < 0 or r.pos + length > r.data.len: return (-1, "")
  result = (tag, r.data[r.pos ..< r.pos + length])
  r.pos += length

proc decodeAsnInt(body: string): int64 =
  if body.len == 0: return 0
  result = if (ord(body[0]) and 0x80) != 0: -1 else: 0
  for c in body:
    result = (result shl 8) or int64(ord(c) and 0xff)

proc parseLdapMessage*(response: string): tuple[messageId: int, op: int, body: string] =
  var r = AsnReader(data: response)
  let outer = r.readTLV()
  if outer.tag != 0x30: return (-1, -1, "")
  var inner = AsnReader(data: outer.body)
  let idTlv = inner.readTLV()
  if idTlv.tag != 0x02: return (-1, -1, "")
  let messageId = int(decodeAsnInt(idTlv.body))
  let opTlv = inner.readTLV()
  result = (messageId, opTlv.tag, opTlv.body)

proc parseBindResponse*(body: string): tuple[code: int, matchedDn, diagnostic: string] =
  var r = AsnReader(data: body)
  let codeTlv = r.readTLV()
  if codeTlv.tag != 0x0a: return (-1, "", "")
  result.code = int(decodeAsnInt(codeTlv.body))
  let dnTlv = r.readTLV()
  if dnTlv.tag == 0x04: result.matchedDn = dnTlv.body
  let diagTlv = r.readTLV()
  if diagTlv.tag == 0x04: result.diagnostic = diagTlv.body

proc parseBindResponseWithCreds*(body: string): tuple[code: int, matchedDn, diagnostic, saslCreds: string] =
  var r = AsnReader(data: body)
  let codeTlv = r.readTLV()
  if codeTlv.tag != 0x0a: return (-1, "", "", "")
  result.code = int(decodeAsnInt(codeTlv.body))
  let dnTlv = r.readTLV()
  if dnTlv.tag == 0x04: result.matchedDn = dnTlv.body
  let diagTlv = r.readTLV()
  if diagTlv.tag == 0x04: result.diagnostic = diagTlv.body
  while not r.atEnd():
    let extra = r.readTLV()
    if extra.tag == 0x87:
      result.saslCreds = extra.body

proc parseLdapResult*(body: string): tuple[code: int, matchedDn, diagnostic: string] =
  parseBindResponse(body)

proc parseLdapResultCode*(response: string): int =
  let parsed = parseLdapMessage(response)
  if parsed.op != 0x61: return -1
  let b = parseBindResponse(parsed.body)
  b.code

proc filterPresent(attr: string): string =
  tlv(0x87, attr)

proc filterEquality(attr, value: string): string =
  tlv(0xa3, ldapString(attr) & ldapString(value))

proc filterAnd(filters: openArray[string]): string =
  var inner = ""
  for f in filters: inner.add f
  tlv(0xa0, inner)

proc filterOr(filters: openArray[string]): string =
  var inner = ""
  for f in filters: inner.add f
  tlv(0xa1, inner)

proc filterNot(f: string): string =
  tlv(0xa2, f)

proc filterExtensible(attr, value: string; rule = ""): string =
  var inner = ""
  if rule.len > 0:
    inner.add tlv(0x81, rule)
  inner.add tlv(0x82, attr)
  inner.add tlv(0x83, value)
  tlv(0xa9, inner)

proc parseLdapFilter*(text: string): string =
  var pos = 0
  proc parseFilter(): string
  proc parseSimple(content: string): string =
    let eq = content.find('=')
    if eq < 0:
      raise newException(ValueError, "missing '=' in filter: " & content)
    var attr = content[0 ..< eq]
    var value = content[eq + 1 .. ^1]
    var op = '='
    if attr.endsWith(">"):
      op = '>'; attr = attr[0 ..< attr.len - 1]
    elif attr.endsWith("<"):
      op = '<'; attr = attr[0 ..< attr.len - 1]
    elif attr.endsWith("~"):
      op = '~'; attr = attr[0 ..< attr.len - 1]
    elif attr.endsWith(":"):
      let colon = attr.find(':')
      let head = attr[0 ..< colon]
      let modifier = attr[colon + 1 ..< attr.len - 1]
      return filterExtensible(head, value, modifier)
    case op
    of '>': return tlv(0xa5, ldapString(attr) & ldapString(value))
    of '<': return tlv(0xa6, ldapString(attr) & ldapString(value))
    of '~': return tlv(0xa8, ldapString(attr) & ldapString(value))
    else:
      if value == "*":
        return filterPresent(attr)
      if '*' in value:
        var parts = value.split('*')
        var inner = ldapString(attr)
        var subStrs = ""
        for i, p in parts:
          if p.len == 0: continue
          let tag = if i == 0: 0x80
            elif i == parts.len - 1: 0x82
            else: 0x81
          subStrs.add tlv(tag, p)
        return tlv(0xa4, inner & tlv(0x30, subStrs))
      return filterEquality(attr, value)
  proc parseFilter(): string =
    if pos >= text.len or text[pos] != '(':
      raise newException(ValueError, "expected '(' at " & $pos)
    inc pos
    if pos >= text.len:
      raise newException(ValueError, "truncated filter")
    case text[pos]
    of '&':
      inc pos
      var children: seq[string]
      while pos < text.len and text[pos] == '(':
        children.add parseFilter()
      if pos >= text.len or text[pos] != ')':
        raise newException(ValueError, "expected ')' after '&'")
      inc pos
      return filterAnd(children)
    of '|':
      inc pos
      var children: seq[string]
      while pos < text.len and text[pos] == '(':
        children.add parseFilter()
      if pos >= text.len or text[pos] != ')':
        raise newException(ValueError, "expected ')' after '|'")
      inc pos
      return filterOr(children)
    of '!':
      inc pos
      let child = parseFilter()
      if pos >= text.len or text[pos] != ')':
        raise newException(ValueError, "expected ')' after '!'")
      inc pos
      return filterNot(child)
    else:
      let start = pos
      var depth = 1
      while pos < text.len and depth > 0:
        if text[pos] == '(': inc depth
        elif text[pos] == ')': dec depth
        if depth > 0: inc pos
      if pos >= text.len:
        raise newException(ValueError, "unterminated simple filter")
      let body = text[start ..< pos]
      inc pos
      return parseSimple(body)
  parseFilter()

proc buildSearchRequest*(baseDn: string; scope: int; filter: string;
                         attributes: openArray[string];
                         sizeLimit = 0; timeLimit = 0;
                         derefAliases = 0; typesOnly = false;
                         messageId: int): string =
  var attrSeq = ""
  for a in attributes: attrSeq.add ldapString(a)
  let body = ldapString(baseDn) &
    ldapEnum(scope) &
    ldapEnum(derefAliases) &
    ldapInteger(sizeLimit) &
    ldapInteger(timeLimit) &
    ldapBool(typesOnly) &
    filter &
    tlv(0x30, attrSeq)
  tlv(0x30, ldapInteger(messageId) & tlv(0x63, body))

proc buildSearchRequestWithControls*(baseDn: string; scope: int; filter: string;
                                     attributes: openArray[string];
                                     controls: string;
                                     sizeLimit = 0; timeLimit = 0;
                                     derefAliases = 0; typesOnly = false;
                                     messageId: int): string =
  var attrSeq = ""
  for a in attributes: attrSeq.add ldapString(a)
  let body = ldapString(baseDn) &
    ldapEnum(scope) &
    ldapEnum(derefAliases) &
    ldapInteger(sizeLimit) &
    ldapInteger(timeLimit) &
    ldapBool(typesOnly) &
    filter &
    tlv(0x30, attrSeq)
  tlv(0x30, ldapInteger(messageId) & tlv(0x63, body) & tlv(0xa0, controls))

proc buildSdFlagsControl(flags: int): string =
  let value = tlv(0x30, ldapInteger(flags))
  tlv(0x30, ldapString("1.2.840.113556.1.4.801") & ldapString(value))

proc buildShowDeletedControl(): string =
  tlv(0x30, ldapString("1.2.840.113556.1.4.417"))

proc buildAddRequest*(dn: string; attrs: openArray[tuple[name: string, values: seq[string]]];
                      messageId: int): string =
  var attrList = ""
  for attr in attrs:
    var valueSet = ""
    for value in attr.values:
      valueSet.add ldapString(value)
    attrList.add tlv(0x30, ldapString(attr.name) & tlv(0x31, valueSet))
  let body = ldapString(dn) & tlv(0x30, attrList)
  tlv(0x30, ldapInteger(messageId) & tlv(0x68, body))

proc buildStartTlsRequest*(messageId: int): string =
  let body = tlv(0x80, "1.3.6.1.4.1.1466.20037")
  tlv(0x30, ldapInteger(messageId) & tlv(0x77, body))

proc buildModifyReplaceRequest*(dn, attr: string; values: openArray[string];
                                messageId: int): string =
  var vals = ""
  for value in values:
    vals.add ldapString(value)
  let modification = tlv(0x30, ldapString(attr) & tlv(0x31, vals))
  let change = tlv(0x30, ldapEnum(2) & modification)
  let body = ldapString(dn) & tlv(0x30, change)
  tlv(0x30, ldapInteger(messageId) & tlv(0x66, body))

proc buildModifyRequest*(dn: string; mods: openArray[LdapModification];
                         messageId: int): string =
  var changes = ""
  for modn in mods:
    var vals = ""
    for value in modn.values:
      vals.add ldapString(value)
    let operation =
      case modn.op
      of lmoAdd: 0
      of lmoDelete: 1
      of lmoReplace: 2
    let modification = tlv(0x30, ldapString(modn.attr) & tlv(0x31, vals))
    changes.add tlv(0x30, ldapEnum(operation) & modification)
  let body = ldapString(dn) & tlv(0x30, changes)
  tlv(0x30, ldapInteger(messageId) & tlv(0x66, body))

proc buildModifyRequestWithControls*(dn: string; mods: openArray[LdapModification];
                                     controls: string; messageId: int): string =
  var changes = ""
  for modn in mods:
    var vals = ""
    for value in modn.values:
      vals.add ldapString(value)
    let operation =
      case modn.op
      of lmoAdd: 0
      of lmoDelete: 1
      of lmoReplace: 2
    let modification = tlv(0x30, ldapString(modn.attr) & tlv(0x31, vals))
    changes.add tlv(0x30, ldapEnum(operation) & modification)
  let body = ldapString(dn) & tlv(0x30, changes)
  tlv(0x30, ldapInteger(messageId) & tlv(0x66, body) & tlv(0xa0, controls))

proc buildDeleteRequest*(dn: string; messageId: int): string =
  tlv(0x30, ldapInteger(messageId) & tlv(0x4a, dn))

proc buildModifyDnRequestWithControls*(dn, newRdn: string; deleteOldRdn: bool;
                                       newSuperior, controls: string;
                                       messageId: int): string =
  var body = ldapString(dn) & ldapString(newRdn) & ldapBool(deleteOldRdn)
  if newSuperior.len > 0:
    body.add tlv(0x80, newSuperior)
  tlv(0x30, ldapInteger(messageId) & tlv(0x6c, body) & tlv(0xa0, controls))

proc parseSearchEntry*(body: string): LdapEntry =
  var r = AsnReader(data: body)
  let dnTlv = r.readTLV()
  if dnTlv.tag != 0x04: return
  result.dn = dnTlv.body
  result.attrs = initTable[string, seq[string]]()
  let attrsTlv = r.readTLV()
  if attrsTlv.tag != 0x30: return
  var ar = AsnReader(data: attrsTlv.body)
  while not ar.atEnd():
    let attrTlv = ar.readTLV()
    if attrTlv.tag != 0x30: break
    var inner = AsnReader(data: attrTlv.body)
    let nameTlv = inner.readTLV()
    if nameTlv.tag != 0x04: break
    let valuesTlv = inner.readTLV()
    if valuesTlv.tag != 0x31: break
    var vr = AsnReader(data: valuesTlv.body)
    var values: seq[string]
    while not vr.atEnd():
      let v = vr.readTLV()
      if v.tag != 0x04: break
      values.add v.body
    result.attrs[nameTlv.body] = values

proc formatSid(raw: string): string =
  if raw.len < 8: return ""
  let revision = ord(raw[0])
  let subAuthCount = ord(raw[1])
  var authority: int64 = 0
  for i in 0 ..< 6:
    authority = (authority shl 8) or int64(ord(raw[2 + i]))
  result = "S-" & $revision & "-" & $authority
  for i in 0 ..< subAuthCount:
    let offset = 8 + i * 4
    if offset + 4 > raw.len: break
    var v: uint32 = 0
    for j in 0 ..< 4:
      v = v or (uint32(ord(raw[offset + j])) shl (j * 8))
    result.add "-" & $v

proc functionalityName(level: string): string =
  case level.strip()
  of "0": "Windows 2000"
  of "1": "Windows 2003 (interim)"
  of "2": "Windows 2003"
  of "3": "Windows 2008"
  of "4": "Windows 2008 R2"
  of "5": "Windows 2012"
  of "6": "Windows 2012 R2"
  of "7": "Windows 2016"
  of "10": "Windows 2025"
  else:
    if level.len == 0: "unknown" else: "level " & level

proc sendLdap(socket: AsyncSocket; request: string; timeoutMs: int): Future[string] {.async.} =
  await socket.send(request)
  var buffer = ""
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while buffer.len < 2:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return ""
    let recvFuture = socket.recv(2 - buffer.len)
    if not await withTimeout(recvFuture, remaining): return ""
    let chunk = await recvFuture
    if chunk.len == 0: return ""
    buffer.add chunk
  var lengthBytesNeeded = 0
  var totalLen = 0
  let lengthByte = ord(buffer[1])
  if (lengthByte and 0x80) == 0:
    totalLen = 2 + lengthByte
  else:
    lengthBytesNeeded = lengthByte and 0x7f
    while buffer.len < 2 + lengthBytesNeeded:
      let remaining = int((deadline - epochTime()) * 1000)
      if remaining <= 0: return ""
      let recvFuture = socket.recv(2 + lengthBytesNeeded - buffer.len)
      if not await withTimeout(recvFuture, remaining): return ""
      let chunk = await recvFuture
      if chunk.len == 0: return ""
      buffer.add chunk
    var actualLen = 0
    for i in 0 ..< lengthBytesNeeded:
      actualLen = (actualLen shl 8) or ord(buffer[2 + i])
    totalLen = 2 + lengthBytesNeeded + actualLen
  while buffer.len < totalLen:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return buffer
    let recvFuture = socket.recv(totalLen - buffer.len)
    if not await withTimeout(recvFuture, remaining): return buffer
    let chunk = await recvFuture
    if chunk.len == 0: return buffer
    buffer.add chunk
  result = buffer

proc addU32Be(data: var string; value: uint32) =
  data.add char((value shr 24) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc readU32Be(data: string; offset: int): uint32 =
  if offset + 4 > data.len: return 0
  (uint32(ord(data[offset])) shl 24) or
    (uint32(ord(data[offset + 1])) shl 16) or
    (uint32(ord(data[offset + 2])) shl 8) or
    uint32(ord(data[offset + 3]))

proc recvGssLdapFrame(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  var buffer = ""
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while buffer.len < 4:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return ""
    let recvFuture = socket.recv(4 - buffer.len)
    if not await withTimeout(recvFuture, remaining): return ""
    let chunk = await recvFuture
    if chunk.len == 0: return ""
    buffer.add chunk
  let totalLen = int(readU32Be(buffer, 0))
  while buffer.len < 4 + totalLen:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return ""
    let recvFuture = socket.recv(4 + totalLen - buffer.len)
    if not await withTimeout(recvFuture, remaining): return ""
    let chunk = await recvFuture
    if chunk.len == 0: return ""
    buffer.add chunk
  result = buffer[4 ..< 4 + totalLen]

proc sendLdapSealed(socket: AsyncSocket; request: string; timeoutMs: int;
                    state: LdapWriteSession; confidential = false): Future[string] {.async.} =
  if state.gssCtx != nil:
    let wrapped = state.gssCtx.wrapToken(request, confidential = confidential or state.gssPrivacy)
    var msg = ""
    msg.addU32Be(wrapped.len.uint32)
    msg.add wrapped
    await socket.send(msg)
    let frame = await recvGssLdapFrame(socket, timeoutMs)
    if frame.len == 0: return ""
    return state.gssCtx.unwrapToken(frame)
  if not state.sealed:
    return await sendLdap(socket, request, timeoutMs)
  let sealed = dcerpc.sealAndSign(state.secCtx, request, request)
  let wrappedBody = sealed.signature & sealed.sealed
  var wrapped = ""
  wrapped.addU32Be(wrappedBody.len.uint32)
  wrapped.add wrappedBody
  await socket.send(wrapped)

  var buffer = ""
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while buffer.len < 4:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return ""
    let recvFuture = socket.recv(4 - buffer.len)
    if not await withTimeout(recvFuture, remaining): return ""
    let chunk = await recvFuture
    if chunk.len == 0: return ""
    buffer.add chunk
  let totalLen = int(readU32Be(buffer, 0))
  while buffer.len < 4 + totalLen:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return ""
    let recvFuture = socket.recv(4 + totalLen - buffer.len)
    if not await withTimeout(recvFuture, remaining): return ""
    let chunk = await recvFuture
    if chunk.len == 0: return ""
    buffer.add chunk
  if totalLen < 16: return ""
  let signature = buffer[4 ..< 20]
  let encrypted = buffer[20 ..< 4 + totalLen]
  let plain = dcerpc.unsealAndVerify(state.secCtx, encrypted, signature)
  if not plain.ok:
    return ""
  result = plain.plain

proc newLdapSocket(port: int): AsyncSocket =
  result = newAsyncSocket()

proc wrapLdapsAfterConnect(socket: AsyncSocket; host: string; port: int;
                           certFile = ""; keyFile = ""): tuple[ok: bool, message: string] =
  when defined(ssl):
    if port in [636, 3269]:
      try:
        let ctx = newContext(verifyMode = CVerifyNone,
          certFile = certFile, keyFile = keyFile)
        ctx.wrapConnectedSocket(socket, handshakeAsClient)
      except CatchableError as error:
        return (false, cleanError(error))
  else:
    if port in [636, 3269]:
      return (false, "LDAPS requires -d:ssl build")
  result = (true, "")

proc closeLdapSocket(socket: AsyncSocket) =
  try:
    close(socket)
  except CatchableError:
    discard

proc startTls(socket: AsyncSocket; host: string; messageId, timeoutMs: int): Future[tuple[ok: bool, code: int, diagnostic: string]] {.async.} =
  when defined(ssl):
    let response = await sendLdap(socket, buildStartTlsRequest(messageId), timeoutMs)
    if response.len == 0:
      return (false, -1, "StartTLS: no response")
    let parsed = parseLdapMessage(response)
    if parsed.op != 0x78:
      return (false, -1, "StartTLS: unexpected response")
    let r = parseLdapResult(parsed.body)
    if r.code != 0:
      return (false, r.code, r.diagnostic.strip())
    try:
      let ctx = newContext(verifyMode = CVerifyNone)
      ctx.wrapConnectedSocket(socket, handshakeAsClient)
      return (true, 0, "")
    except CatchableError as e:
      return (false, -1, "StartTLS handshake: " & e.msg)
  else:
    return (false, -1, "StartTLS requires -d:ssl build")

proc recvUntilDone(socket: AsyncSocket; timeoutMs: int): Future[seq[string]] {.async.} =
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while true:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return
    var buffer = ""
    while buffer.len < 2:
      let recvFuture = socket.recv(2 - buffer.len)
      if not await withTimeout(recvFuture, remaining): return
      let chunk = await recvFuture
      if chunk.len == 0: return
      buffer.add chunk
    var totalLen = 0
    let lengthByte = ord(buffer[1])
    if (lengthByte and 0x80) == 0:
      totalLen = 2 + lengthByte
    else:
      let need = lengthByte and 0x7f
      while buffer.len < 2 + need:
        let recvFuture = socket.recv(2 + need - buffer.len)
        if not await withTimeout(recvFuture, remaining): return
        let chunk = await recvFuture
        if chunk.len == 0: return
        buffer.add chunk
      var actualLen = 0
      for i in 0 ..< need:
        actualLen = (actualLen shl 8) or ord(buffer[2 + i])
      totalLen = 2 + need + actualLen
    while buffer.len < totalLen:
      let recvFuture = socket.recv(totalLen - buffer.len)
      if not await withTimeout(recvFuture, remaining): return
      let chunk = await recvFuture
      if chunk.len == 0: return
      buffer.add chunk
    result.add buffer
    let parsed = parseLdapMessage(buffer)
    if parsed.op == 0x65: return

proc sendLdapSearchProtected(socket: AsyncSocket; request: string; state: LdapWriteSession) {.async.} =
  if state.gssCtx != nil:
    let wrapped = state.gssCtx.wrapToken(request, confidential = state.gssPrivacy)
    var msg = ""
    msg.addU32Be(wrapped.len.uint32)
    msg.add wrapped
    await socket.send(msg)
  else:
    await socket.send(request)

proc recvLdapSearchProtected(socket: AsyncSocket; timeoutMs: int;
                             state: LdapWriteSession): Future[seq[string]] {.async.} =
  if state.gssCtx == nil:
    return await recvUntilDone(socket, timeoutMs)
  let deadline = epochTime() + timeoutMs.float / 1000.0
  while true:
    let remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0: return
    let frame = await recvGssLdapFrame(socket, remaining)
    if frame.len == 0: return
    let plain = state.gssCtx.unwrapToken(frame)
    if plain.len == 0: return
    result.add plain
    let parsed = parseLdapMessage(plain)
    if parsed.op == 0x65: return

proc decodeBindDn(name, password, domain: string): string =
  if name.len == 0: return ""
  if "@" in name or "=" in name or "\\" in name: return name
  if domain.len > 0: return name & "@" & domain
  name

proc ntlmSaslBind(socket: AsyncSocket; username, password, ntlmHash, domain: string;
                  messageId, timeoutMs: int): Future[tuple[code: int, diagnostic: string, nextMessageId: int]] {.async.} =
  var nextId = messageId
  let type1 = buildLdapNtlmType1(domain, "")
  let initResp = await sendLdap(socket,
    buildSicilyNegotiateRequest(username, type1, nextId), timeoutMs)
  if initResp.len == 0:
    return (80, "bind: no response", nextId)
  let parsedInit = parseLdapMessage(initResp)
  if parsedInit.op != 0x61:
    return (80, "non-LDAP bind response", nextId)
  let initResult = parseBindResponse(parsedInit.body)
  if initResult.code != 0:
    return (initResult.code, initResult.diagnostic.strip(), nextId)
  let challenge = smbclient.parseNtlmChallenge(initResult.matchedDn)
  if not challenge.offered:
    return (80, "NTLM challenge missing from bind response", nextId)

  inc nextId
  let authDomain =
    if challenge.netbiosDomain.len > 0: challenge.netbiosDomain
    else: domain
  let credential = smbclient.SmbCredential(
    username: username,
    password: password,
    ntlmHash: ntlmHash,
    domain: authDomain,
    workstation: ""
  )
  let type3 = smbclient.buildNtlmType3SmbSession(
    credential, challenge, smbclient.randomBytes(8), type1, "ldap").token
  let authResp = await sendLdap(socket,
    buildSicilyResponseRequest(username, type3, nextId), timeoutMs)
  if authResp.len == 0:
    return (80, "bind: no response", nextId)
  let parsedAuth = parseLdapMessage(authResp)
  if parsedAuth.op != 0x61:
    return (80, "non-LDAP bind response", nextId)
  let authResult = parseBindResponseWithCreds(parsedAuth.body)
  result = (authResult.code, authResult.diagnostic.strip(), nextId)

proc extractNtlmToken(blob: string): string =
  let marker = blob.find("NTLMSSP\0")
  if marker < 0: return ""
  blob[marker .. ^1]

proc ntlmSpnegoSealedBind(socket: AsyncSocket; username, password, ntlmHash, domain: string;
                          messageId, timeoutMs: int): Future[tuple[code: int, diagnostic: string, nextMessageId: int, secCtx: dcerpc.NtlmSecCtx]] {.async.} =
  var nextId = messageId
  let type1 = smbclient.buildNtlmType1(domain, "")
  let initResp = await sendLdap(socket,
    buildSaslBindRequest("GSS-SPNEGO", smbclient.spnegoNtlmInit(type1), nextId),
    timeoutMs)
  if initResp.len == 0:
    return (80, "bind: no response", nextId, result.secCtx)
  let parsedInit = parseLdapMessage(initResp)
  if parsedInit.op != 0x61:
    return (80, "non-LDAP bind response", nextId, result.secCtx)
  let initResult = parseBindResponseWithCreds(parsedInit.body)
  if initResult.code != 14 and initResult.code != 0:
    return (initResult.code, initResult.diagnostic.strip(), nextId, result.secCtx)
  let type2 = extractNtlmToken(initResult.saslCreds)
  if type2.len == 0:
    return (80, "NTLM challenge missing from SPNEGO bind response", nextId, result.secCtx)
  let challenge = smbclient.parseNtlmChallenge(type2)
  if not challenge.offered:
    return (80, "NTLM challenge parse failed", nextId, result.secCtx)

  inc nextId
  let authDomain =
    if challenge.netbiosDomain.len > 0: challenge.netbiosDomain
    else: domain
  let credential = smbclient.SmbCredential(
    username: username,
    password: password,
    ntlmHash: ntlmHash,
    domain: authDomain,
    workstation: ""
  )
  let auth = smbclient.buildNtlmType3SmbSession(
    credential, challenge, smbclient.randomBytes(8), type1, "ldap")
  let authResp = await sendLdap(socket,
    buildSaslBindRequest("GSS-SPNEGO", smbclient.spnegoNtlmAuth(auth.token), nextId),
    timeoutMs)
  if authResp.len == 0:
    return (80, "bind: no response", nextId, result.secCtx)
  let parsedAuth = parseLdapMessage(authResp)
  if parsedAuth.op != 0x61:
    return (80, "non-LDAP bind response", nextId, result.secCtx)
  let authResult = parseBindResponseWithCreds(parsedAuth.body)
  if authResult.code == 0:
    result.secCtx = dcerpc.newNtlmSecCtx(auth.exportedKey)
  result = (authResult.code, authResult.diagnostic.strip(), nextId, result.secCtx)

proc kerberosSaslBind(socket: AsyncSocket; host, realm: string;
                      messageId, timeoutMs: int): Future[tuple[code: int, diagnostic: string, nextMessageId: int, gssCtx: krb.KerberosContext, privacy: bool]] {.async.} =
  var nextId = messageId
  var ctx = krb.newKerberosContext("ldap", host, realm)
  var inputToken = ""
  var gssComplete = false
  for _ in 0 .. 4:
    var outputToken = ""
    if not gssComplete:
      let step = ctx.stepWithFlags(inputToken, reqFlags = 0x7e'u32)
      outputToken = step.token
      gssComplete = step.complete
    let resp = await sendLdap(socket,
      buildSaslBindRequest("GSSAPI", outputToken, nextId), timeoutMs)
    if resp.len == 0:
      ctx.close()
      return (0, "bind: no response", nextId, nil, false)
    let parsed = parseLdapMessage(resp)
    if parsed.op != 0x61:
      ctx.close()
      return (0, "non-LDAP bind response", nextId, nil, false)
    let bindResult = parseBindResponseWithCreds(parsed.body)
    if bindResult.code == 0:
      ctx.close()
      return (0, bindResult.diagnostic.strip(), nextId, nil, false)
    if bindResult.code != 14:
      ctx.close()
      return (bindResult.code, bindResult.diagnostic.strip(), nextId, nil, false)
    if gssComplete:
      if bindResult.saslCreds.len == 0:
        inc nextId
        continue
      let serverLayers = ctx.unwrapToken(bindResult.saslCreds)
      let noSecLayer = serverLayers.len > 0 and (ord(serverLayers[0]) and 1) != 0
      let signingLayer = serverLayers.len > 0 and (ord(serverLayers[0]) and 2) != 0
      let privacyLayer = serverLayers.len > 0 and (ord(serverLayers[0]) and 4) != 0
      if not noSecLayer and not signingLayer and not privacyLayer:
        ctx.close()
        return (8, "LDAP GSSAPI server requires encryption", nextId, nil, false)
      let chosenLayer =
        if privacyLayer: "\x04\x00\x00\x00"
        elif signingLayer: "\x02\x00\x00\x00"
        else: "\x01\x00\x00\x00"
      inc nextId
      let finalToken = ctx.wrapToken(chosenLayer, confidential = false)
      let finalResp = await sendLdap(socket,
        buildSaslBindRequest("GSSAPI", finalToken, nextId), timeoutMs)
      if finalResp.len == 0:
        ctx.close()
        return (0, "bind: no response", nextId, nil, false)
      let finalParsed = parseLdapMessage(finalResp)
      if finalParsed.op != 0x61:
        ctx.close()
        return (0, "non-LDAP bind response", nextId, nil, false)
      let finalResult = parseBindResponseWithCreds(finalParsed.body)
      if finalResult.code == 0 and (signingLayer or privacyLayer):
        return (0, finalResult.diagnostic.strip(), nextId, ctx, privacyLayer)
      ctx.close()
      return (finalResult.code, finalResult.diagnostic.strip(), nextId, nil, false)
    inputToken = bindResult.saslCreds
    inc nextId
  ctx.close()
  return (0, "GSSAPI bind did not complete", nextId, nil, false)

proc dcDnToDomain(dn: string): string =
  var parts: seq[string]
  for piece in dn.split(','):
    let p = piece.strip()
    if p.toLowerAscii().startsWith("dc="):
      parts.add p[3 .. ^1]
  parts.join(".")

proc domainToDcDn(domain: string): string =
  var parts: seq[string]
  for part in domain.split('.'):
    let clean = part.strip()
    if clean.len > 0:
      parts.add "DC=" & clean
  parts.join(",")

proc ldapEscapeDnValue(value: string): string =
  for i, c in value:
    case c
    of ',', '+', '"', '\\', '<', '>', ';', '=':
      result.add "\\" & $c
    of '#':
      if i == 0: result.add "\\#"
      else: result.add c
    of ' ':
      if i == 0 or i == value.len - 1: result.add "\\ "
      else: result.add c
    else:
      result.add c

proc utf16LeQuoted(value: string): string =
  let quoted = "\"" & value & "\""
  for c in quoted:
    result.add c
    result.add '\0'

proc encodeAdPassword*(value: string): string =
  utf16LeQuoted(value)

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
    var value = uint32(parseBiggestUInt(part))
    for shift in countup(0, 24, 8):
      result.add char((value shr shift) and 0xff)

proc sidFromBytes(raw: string; offset: int): tuple[sid: string, length: int] =
  if offset + 8 > raw.len:
    return ("", 0)
  let revision = ord(raw[offset])
  let subCount = ord(raw[offset + 1])
  if offset + 8 + subCount * 4 > raw.len:
    return ("", 0)
  var authority: uint64 = 0
  for i in 0 ..< 6:
    authority = (authority shl 8) or uint64(ord(raw[offset + 2 + i]))
  result.sid = "S-" & $revision & "-" & $authority
  var pos = offset + 8
  for _ in 0 ..< subCount:
    result.sid.add "-" & $readU32Le(raw, pos)
    pos += 4
  result.length = pos - offset

proc guidFromBytes(raw: string; offset: int): string =
  if offset + 16 > raw.len: return ""
  proc hex2(value: int): string =
    const Hex = "0123456789abcdef"
    result.add Hex[(value shr 4) and 0xf]
    result.add Hex[value and 0xf]
  let order = [3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15]
  for i, idx in order:
    if i in [4,6,8,10]: result.add "-"
    result.add hex2(ord(raw[offset + idx]))

proc rightsFromMask(mask: uint32): seq[string] =
  if (mask and 0x10000000'u32) != 0: result.add "GenericAll"
  if (mask and 0x40000000'u32) != 0: result.add "GenericWrite"
  if (mask and 0x80000000'u32) != 0: result.add "GenericRead"
  if (mask and 0x00040000'u32) != 0: result.add "WriteDACL"
  if (mask and 0x00080000'u32) != 0: result.add "WriteOwner"
  if (mask and 0x00020000'u32) != 0: result.add "ReadControl"
  if (mask and 0x00010000'u32) != 0: result.add "Delete"
  if (mask and 0x00000001'u32) != 0: result.add "CreateChild"
  if (mask and 0x00000002'u32) != 0: result.add "DeleteChild"
  if (mask and 0x00000004'u32) != 0: result.add "ListContents"
  if (mask and 0x00000008'u32) != 0: result.add "Self"
  if (mask and 0x00000010'u32) != 0: result.add "ReadProperty"
  if (mask and 0x00000020'u32) != 0: result.add "WriteProperty"
  if (mask and 0x00000040'u32) != 0: result.add "DeleteTree"
  if (mask and 0x00000080'u32) != 0: result.add "ListObject"
  if (mask and 0x00000100'u32) != 0: result.add "ControlAccess"

proc parseSecurityDescriptor*(sd: string): tuple[owner, group: string, aces: seq[LdapAce]] =
  if sd.len < 20: return
  let ownerOff = int(readU32Le(sd, 4))
  let groupOff = int(readU32Le(sd, 8))
  let daclOff = int(readU32Le(sd, 16))
  if ownerOff > 0:
    result.owner = sidFromBytes(sd, ownerOff).sid
  if groupOff > 0:
    result.group = sidFromBytes(sd, groupOff).sid
  if daclOff <= 0 or daclOff + 8 > sd.len:
    return
  let aceCount = int(readU16Le(sd, daclOff + 4))
  var pos = daclOff + 8
  for _ in 0 ..< aceCount:
    if pos + 8 > sd.len: break
    let aceType = ord(sd[pos])
    let aceFlags = ord(sd[pos + 1])
    let aceSize = int(readU16Le(sd, pos + 2))
    if aceSize < 8 or pos + aceSize > sd.len: break
    let mask = readU32Le(sd, pos + 4)
    var sidOffset = pos + 8
    var objectType = ""
    var inheritedObjectType = ""
    if aceType in [0x05, 0x06]:
      if pos + 12 > sd.len: break
      let objFlags = readU32Le(sd, pos + 8)
      sidOffset = pos + 12
      if (objFlags and 0x1'u32) != 0:
        objectType = guidFromBytes(sd, sidOffset)
        sidOffset += 16
      if (objFlags and 0x2'u32) != 0:
        inheritedObjectType = guidFromBytes(sd, sidOffset)
        sidOffset += 16
    let sidInfo = sidFromBytes(sd, sidOffset)
    if sidInfo.sid.len > 0:
      result.aces.add LdapAce(
        aceType: aceType,
        aceFlags: aceFlags,
        mask: mask,
        trusteeSid: sidInfo.sid,
        rights: rightsFromMask(mask),
        objectType: objectType,
        inheritedObjectType: inheritedObjectType,
        raw: sd[pos ..< pos + aceSize]
      )
    pos += aceSize

proc accessMaskFromRights*(rights: openArray[string]): uint32 =
  for raw in rights:
    let right = raw.strip().toLowerAscii().replace("-", "").replace("_", "")
    case right
    of "genericall", "all", "fullcontrol":
      result = result or 0x10000000'u32
    of "genericwrite":
      result = result or 0x40000000'u32
    of "genericread":
      result = result or 0x80000000'u32
    of "writedacl":
      result = result or 0x00040000'u32
    of "writeowner":
      result = result or 0x00080000'u32
    of "readcontrol":
      result = result or 0x00020000'u32
    of "delete":
      result = result or 0x00010000'u32
    of "createchild":
      result = result or 0x00000001'u32
    of "deletechild":
      result = result or 0x00000002'u32
    of "listcontents":
      result = result or 0x00000004'u32
    of "self":
      result = result or 0x00000008'u32
    of "readproperty":
      result = result or 0x00000010'u32
    of "writeproperty":
      result = result or 0x00000020'u32
    of "deletetree":
      result = result or 0x00000040'u32
    of "listobject":
      result = result or 0x00000080'u32
    of "controlaccess", "extendedright":
      result = result or 0x00000100'u32
    else:
      if right.startsWith("0x"):
        result = result or uint32(parseHexInt(right[2 .. ^1]))
      elif right.len > 0:
        result = result or uint32(parseBiggestUInt(right))

proc guidToBytes(guid: string): string =
  let clean = guid.strip().replace("{", "").replace("}", "").replace("-", "")
  if clean.len != 32:
    raise newException(ValueError, "GUID must be 32 hex chars or canonical GUID")
  var bytes: array[16, char]
  for i in 0 ..< 16:
    bytes[i] = char(parseHexInt(clean[i * 2 .. i * 2 + 1]))
  let order = [3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15]
  for idx in order:
    result.add bytes[idx]

proc buildBasicAce(aceType: int; aceFlags: int; mask: uint32; trusteeSid: string): string =
  let sid = sidToBytes(trusteeSid)
  let aceSize = uint16(4 + 4 + sid.len)
  result.add char(aceType)
  result.add char(aceFlags)
  result.addU16Le aceSize
  result.addU32Le mask
  result.add sid

proc buildObjectAce(aceType: int; aceFlags: int; mask: uint32; trusteeSid,
                    objectType, inheritedObjectType: string): string =
  let sid = sidToBytes(trusteeSid)
  var objFlags = 0'u32
  var guidBytes = ""
  if objectType.len > 0:
    objFlags = objFlags or 0x1'u32
    guidBytes.add guidToBytes(objectType)
  if inheritedObjectType.len > 0:
    objFlags = objFlags or 0x2'u32
    guidBytes.add guidToBytes(inheritedObjectType)
  let aceSize = uint16(4 + 4 + 4 + guidBytes.len + sid.len)
  result.add char(aceType)
  result.add char(aceFlags)
  result.addU16Le aceSize
  result.addU32Le mask
  result.addU32Le objFlags
  result.add guidBytes
  result.add sid

proc buildAce(ace: LdapAce): string =
  if ace.objectType.len > 0 or ace.inheritedObjectType.len > 0:
    let typ =
      if ace.aceType == 1 or ace.aceType == 6: 6
      else: 5
    buildObjectAce(typ, ace.aceFlags, ace.mask, ace.trusteeSid,
      ace.objectType, ace.inheritedObjectType)
  else:
    let typ = if ace.aceType == 1 or ace.aceType == 6: 1 else: 0
    buildBasicAce(typ, ace.aceFlags, ace.mask, ace.trusteeSid)

proc buildAcl(aces: seq[LdapAce]): string =
  var aceBytes = ""
  var aceCount = 0
  for ace in aces:
    if ace.raw.len > 0:
      aceBytes.add ace.raw
      inc aceCount
    elif ace.aceType in [0, 1, 5, 6] and ace.trusteeSid.len > 0:
      aceBytes.add buildAce(ace)
      inc aceCount
  let aclSize = uint16(8 + aceBytes.len)
  result.add char(4)
  result.add char(0)
  result.addU16Le aclSize
  result.addU16Le uint16(aceCount)
  result.addU16Le 0
  result.add aceBytes

proc buildSelfRelativeSd(ownerSid, groupSid: string; aces: seq[LdapAce]): string =
  let owner = if ownerSid.len > 0: sidToBytes(ownerSid) else: ""
  let group = if groupSid.len > 0: sidToBytes(groupSid) else: ""
  let dacl = buildAcl(aces)
  var offset = 20'u32
  let ownerOffset =
    if owner.len > 0:
      let current = offset
      offset += uint32(owner.len)
      current
    else: 0'u32
  let groupOffset =
    if group.len > 0:
      let current = offset
      offset += uint32(group.len)
      current
    else: 0'u32
  let daclOffset = offset
  result.add char(1)
  result.add char(0)
  result.add char(0x04)
  result.add char(0x80)
  result.addU32Le ownerOffset
  result.addU32Le groupOffset
  result.addU32Le 0
  result.addU32Le daclOffset
  result.add owner
  result.add group
  result.add dacl

proc buildDmsaGroupMsaMembership(userSidStr: string): string =
  let adminSid = sidToBytes("S-1-5-32-544")
  let trusteeSid = sidToBytes(userSidStr)
  let aceSize = uint16(4 + 4 + trusteeSid.len)
  let aclSize = uint16(8 + int(aceSize))
  let ownerOffset = 20'u32
  let groupOffset = ownerOffset + uint32(adminSid.len)
  let daclOffset = groupOffset + uint32(adminSid.len)
  result.add char(1)
  result.add char(0)
  result.add char(0x04)
  result.add char(0x80)
  result.addU32Le ownerOffset
  result.addU32Le groupOffset
  result.addU32Le 0
  result.addU32Le daclOffset
  result.add adminSid
  result.add adminSid
  result.add char(2)
  result.add char(0)
  result.addU16Le aclSize
  result.addU16Le 1
  result.addU16Le 0
  result.add char(0)
  result.add char(0)
  result.addU16Le aceSize
  result.addU32Le 0x000F01FF'u32
  result.add trusteeSid

proc rbcdSecurityDescriptor(sid: string): string =
  let ownerSid = sidToBytes("S-1-5-32-544")
  let trusteeSid = sidToBytes(sid)
  let aceSize = uint16(4 + 4 + trusteeSid.len)
  let aclSize = uint16(8 + int(aceSize))
  let ownerOffset = 20'u32
  let daclOffset = uint32(20 + ownerSid.len)
  result.add char(1)
  result.add char(0)
  result.add char(0x04)
  result.add char(0x80)
  result.addU32Le ownerOffset
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le daclOffset
  result.add ownerSid
  result.add char(4)
  result.add char(0)
  result.addU16Le aclSize
  result.addU16Le 1
  result.addU16Le 0
  result.add char(0)
  result.add char(0)
  result.addU16Le aceSize
  result.addU32Le 983551'u32
  result.add trusteeSid

proc normalizedComputerParts(name: string): tuple[cn, sam: string] =
  var clean = name.strip()
  while clean.endsWith("$"):
    clean.setLen(clean.len - 1)
  result.cn = clean
  result.sam = clean & "$"

proc ldapBindForWrite(socket: AsyncSocket; host, username, password, ntlmHash,
                      domain: string; state: LdapWriteSession; timeoutMs: int;
                      kerberos = false; sealNtlm = false;
                      external = false): Future[tuple[code: int, diagnostic: string, effectiveDomain: string, baseDn: string]] {.async.} =
  var effectiveDomain = domain
  var baseDn = ""
  if effectiveDomain.contains("."):
    baseDn = domainToDcDn(effectiveDomain)
  if username.len > 0 and effectiveDomain.len == 0 and
      "@" notin username and "=" notin username and "\\" notin username:
    let anonResp = await sendLdap(socket, buildAnonymousBindRequest(state.messageId), timeoutMs)
    if anonResp.len > 0:
      let parsedAnon = parseLdapMessage(anonResp)
      if parsedAnon.op == 0x61 and parseBindResponse(parsedAnon.body).code == 0:
        inc state.messageId
        let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
          @["defaultNamingContext"], sizeLimit = 1, messageId = state.messageId)
        await socket.send(rootReq)
        for raw in await recvUntilDone(socket, timeoutMs):
          let m = parseLdapMessage(raw)
          if m.op != 0x64: continue
          let entry = parseSearchEntry(m.body)
          if "defaultNamingContext" in entry.attrs and
              entry.attrs["defaultNamingContext"].len > 0:
            baseDn = entry.attrs["defaultNamingContext"][0]
            effectiveDomain = dcDnToDomain(baseDn)
            break

  inc state.messageId
  if external:
    let bindResp = await sendLdap(socket,
      buildSaslBindRequest("EXTERNAL", "", state.messageId), timeoutMs)
    if bindResp.len == 0:
      return (0, "bind: no response", effectiveDomain, baseDn)
    let parsedBind = parseLdapMessage(bindResp)
    if parsedBind.op != 0x61:
      return (0, "non-LDAP bind response", effectiveDomain, baseDn)
    let bindResult = parseBindResponse(parsedBind.body)
    result = (bindResult.code, bindResult.diagnostic.strip(), effectiveDomain, baseDn)
  elif kerberos:
    let bindResult = await kerberosSaslBind(socket, host, effectiveDomain,
      state.messageId, timeoutMs)
    state.messageId = bindResult.nextMessageId
    if bindResult.code == 0 and bindResult.gssCtx != nil:
      state.gssCtx = bindResult.gssCtx
      state.gssPrivacy = bindResult.privacy
    result = (bindResult.code, bindResult.diagnostic, effectiveDomain, baseDn)
  elif sealNtlm and username.len > 0 and (password.len > 0 or ntlmHash.len > 0):
    let bindResult = await ntlmSpnegoSealedBind(socket, username, password, ntlmHash,
      effectiveDomain, state.messageId, timeoutMs)
    state.messageId = bindResult.nextMessageId
    if bindResult.code == 0:
      state.sealed = true
      state.secCtx = bindResult.secCtx
    result = (bindResult.code, bindResult.diagnostic, effectiveDomain, baseDn)
  elif ntlmHash.len > 0 and password.len == 0:
    let bindResult = await ntlmSaslBind(socket, username, password, ntlmHash,
      effectiveDomain, state.messageId, timeoutMs)
    state.messageId = bindResult.nextMessageId
    result = (bindResult.code, bindResult.diagnostic, effectiveDomain, baseDn)
  else:
    let bindResp = await sendLdap(socket,
      buildSimpleBindRequest(decodeBindDn(username, password, effectiveDomain),
        password, state.messageId), timeoutMs)
    if bindResp.len == 0:
      return (0, "bind: no response", effectiveDomain, baseDn)
    let parsedBind = parseLdapMessage(bindResp)
    if parsedBind.op != 0x61:
      return (0, "non-LDAP bind response", effectiveDomain, baseDn)
    let bindResult = parseBindResponse(parsedBind.body)
    result = (bindResult.code, bindResult.diagnostic.strip(), effectiveDomain, baseDn)

proc discoverBaseDn(socket: AsyncSocket; timeoutMs: int; state: LdapWriteSession;
                    currentBase, domain: string): Future[string] {.async.} =
  if currentBase.len > 0:
    return currentBase
  if domain.contains("."):
    return domainToDcDn(domain)
  inc state.messageId
  let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
    @["defaultNamingContext"], sizeLimit = 1, messageId = state.messageId)
  if state.sealed:
    let raw = await sendLdapSealed(socket, rootReq, timeoutMs, state)
    if raw.len > 0:
      let m = parseLdapMessage(raw)
      if m.op == 0x64:
        let entry = parseSearchEntry(m.body)
        if "defaultNamingContext" in entry.attrs and
            entry.attrs["defaultNamingContext"].len > 0:
          return entry.attrs["defaultNamingContext"][0]
  else:
    await socket.send(rootReq)
    for raw in await recvUntilDone(socket, timeoutMs):
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      let entry = parseSearchEntry(m.body)
      if "defaultNamingContext" in entry.attrs and
          entry.attrs["defaultNamingContext"].len > 0:
        return entry.attrs["defaultNamingContext"][0]

proc accountFilter(name: string): string =
  var clean = name.strip()
  var noDollar = clean
  while noDollar.endsWith("$"):
    noDollar.setLen(noDollar.len - 1)
  var withDollar = noDollar & "$"
  filterOr([
    filterEquality("sAMAccountName", clean),
    filterEquality("sAMAccountName", withDollar),
    filterEquality("cn", noDollar),
    filterEquality("dNSHostName", clean)
  ])

proc findLdapAccount(socket: AsyncSocket; timeoutMs: int; state: LdapWriteSession;
                     baseDn, name: string; attrs: seq[string]): Future[LdapEntry] {.async.} =
  inc state.messageId
  let base = if "=" in name and "," in name: name else: baseDn
  let scope = if base == name: 0 else: 2
  let filter = if scope == 0: filterPresent("objectClass") else: accountFilter(name)
  let req = buildSearchRequest(base, scope, filter, attrs,
    sizeLimit = 1, messageId = state.messageId)
  if state.gssCtx != nil:
    let wrapped = state.gssCtx.wrapToken(req, confidential = false)
    var msg = ""
    msg.addU32Be(wrapped.len.uint32)
    msg.add wrapped
    await socket.send(msg)
    let deadline = epochTime() + timeoutMs.float / 1000.0
    while true:
      let remaining = int((deadline - epochTime()) * 1000)
      if remaining <= 0: break
      let frame = await recvGssLdapFrame(socket, remaining)
      if frame.len == 0: break
      let plain = state.gssCtx.unwrapToken(frame)
      if plain.len == 0: break
      let m = parseLdapMessage(plain)
      if m.op == 0x64:
        return parseSearchEntry(m.body)
      if m.op == 0x65: break
    return
  await socket.send(req)
  for raw in await recvUntilDone(socket, timeoutMs):
    let m = parseLdapMessage(raw)
    if m.op != 0x64: continue
    return parseSearchEntry(m.body)

proc addComputerLdap*(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain: string;
                      computerName, computerPassword: string;
                      computerOu = ""; dnsHostName = ""): Future[LdapAddComputerResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapAddComputerResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true

    var messageId = 1
    var effectiveDomain = domain
    var baseDn = ""
    var tlsActive = false
    if port in [389, 3268]:
      let tls = await startTls(socket, host, messageId, timeoutMs)
      inc messageId
      if tls.ok:
        tlsActive = true
    if effectiveDomain.len == 0 and username.len > 0 and
        "@" notin username and "=" notin username and "\\" notin username:
      let anonReq = buildAnonymousBindRequest(messageId)
      let anonResp = await sendLdap(socket, anonReq, timeoutMs)
      if anonResp.len > 0:
        let parsedAnon = parseLdapMessage(anonResp)
        if parsedAnon.op == 0x61 and parseBindResponse(parsedAnon.body).code == 0:
          inc messageId
          let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
            @["defaultNamingContext"], sizeLimit = 1, messageId = messageId)
          await socket.send(rootReq)
          let rootMessages = await recvUntilDone(socket, timeoutMs)
          for raw in rootMessages:
            let m = parseLdapMessage(raw)
            if m.op != 0x64: continue
            let entry = parseSearchEntry(m.body)
            if "defaultNamingContext" in entry.attrs and
                entry.attrs["defaultNamingContext"].len > 0:
              baseDn = entry.attrs["defaultNamingContext"][0]
              effectiveDomain = dcDnToDomain(baseDn)

    if ntlmHash.len > 0 or password.len > 0:
      let bindResult = await ntlmSaslBind(socket, username, password, ntlmHash,
        effectiveDomain, messageId, timeoutMs)
      messageId = bindResult.nextMessageId
      result.bindResultCode = bindResult.code
      result.diagnostic = bindResult.diagnostic.strip()
      if bindResult.code != 0:
        result.message = "bind failed (" & $bindResult.code & ")"
        return
    else:
      let bindDn = decodeBindDn(username, password, effectiveDomain)
      inc messageId
      let bindResp = await sendLdap(socket,
        buildSimpleBindRequest(bindDn, password, messageId), timeoutMs)
      if bindResp.len == 0:
        result.message = "bind: no response"
        return
      let parsedBind = parseLdapMessage(bindResp)
      if parsedBind.op != 0x61:
        result.message = "non-LDAP bind response"
        return
      let bindResult = parseBindResponse(parsedBind.body)
      result.bindResultCode = bindResult.code
      result.diagnostic = bindResult.diagnostic.strip()
      if bindResult.code != 0:
        result.message = "bind failed (" & $bindResult.code & ")"
        return
    result.authenticated = true

    if baseDn.len == 0:
      inc messageId
      let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
        @["defaultNamingContext"], sizeLimit = 1, messageId = messageId)
      await socket.send(rootReq)
      let rootMessages = await recvUntilDone(socket, timeoutMs)
      for raw in rootMessages:
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        let entry = parseSearchEntry(m.body)
        if "defaultNamingContext" in entry.attrs and
            entry.attrs["defaultNamingContext"].len > 0:
          baseDn = entry.attrs["defaultNamingContext"][0]
          break
    result.defaultNamingContext = baseDn
    if baseDn.len == 0 and computerOu.len == 0:
      result.message = "could not discover defaultNamingContext; use --computer-ou"
      return

    let parts = normalizedComputerParts(computerName)
    if parts.cn.len == 0:
      result.message = "computer name must not be empty"
      return
    let parentDn =
      if computerOu.len > 0: computerOu
      else: "CN=Computers," & baseDn
    let dn = "CN=" & ldapEscapeDnValue(parts.cn) & "," & parentDn
    let dnsName =
      if dnsHostName.len > 0: dnsHostName
      elif effectiveDomain.len > 0: parts.cn & "." & effectiveDomain
      else: ""

    var attrs: seq[tuple[name: string, values: seq[string]]]
    attrs.add (name: "objectClass", values: @["top", "person", "organizationalPerson", "user", "computer"])
    attrs.add (name: "cn", values: @[parts.cn])
    attrs.add (name: "sAMAccountName", values: @[parts.sam])
    attrs.add (name: "userAccountControl", values: @["4096"])
    if computerPassword.len > 0:
      attrs.add (name: "unicodePwd", values: @[utf16LeQuoted(computerPassword)])
    if dnsName.len > 0:
      attrs.add (name: "dNSHostName", values: @[dnsName])
      attrs.add (name: "servicePrincipalName", values: @[
        "HOST/" & parts.cn,
        "HOST/" & dnsName,
        "RestrictedKrbHost/" & parts.cn,
        "RestrictedKrbHost/" & dnsName
      ])

    inc messageId
    let addResp = await sendLdap(socket, buildAddRequest(dn, attrs, messageId), timeoutMs)
    if addResp.len == 0:
      result.message = "add: no response"
      return
    let parsedAdd = parseLdapMessage(addResp)
    if parsedAdd.op != 0x69:
      result.message = "unexpected LDAP response to add"
      return
    let addResult = parseLdapResult(parsedAdd.body)
    result.resultCode = addResult.code
    result.diagnostic = addResult.diagnostic.strip()
    result.distinguishedName = dn
    result.computerName = parts.cn
    result.samAccountName = parts.sam
    result.success = addResult.code == 0
    result.message =
      if result.success: "computer account added"
      else: "add failed (" & $addResult.code & ")"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc applyLdapActions*(host: string; port, timeoutMs: int;
                       username, password, ntlmHash, domain: string;
                       actions: seq[LdapWriteAction]; kerberos = false): Future[LdapWriteResult] {.async.} =
  proc needsSecurePasswordWrite(): bool =
    for action in actions:
      for attr in action.attrs:
        if attr.name.cmpIgnoreCase("unicodePwd") == 0:
          return true
      for modn in action.mods:
        if modn.attr.cmpIgnoreCase("unicodePwd") == 0:
          return true
    false

  proc actionWritesUnicodePwd(action: LdapWriteAction): bool =
    for attr in action.attrs:
      if attr.name.cmpIgnoreCase("unicodePwd") == 0:
        return true
    for modn in action.mods:
      if modn.attr.cmpIgnoreCase("unicodePwd") == 0:
        return true
    false

  proc unicodePwdHint(code: int; diagnostic: string): string =
    let base =
      if diagnostic.len > 0: diagnostic
      else: "LDAP result " & $code
    base & " — unicodePwd writes require LDAPS/StartTLS or sealed LDAP, a quoted UTF-16LE value, and a password accepted by domain policy"

  var socket = newAsyncSocket()
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    when defined(ssl):
      if port in [636, 3269]:
        let ctx = newContext(verifyMode = CVerifyNone)
        ctx.wrapConnectedSocket(socket, handshakeAsClient)
    else:
      if port in [636, 3269]:
        result.message = "LDAPS requires -d:ssl build"
        return

    let state = LdapWriteSession(messageId: 1)
    let securePasswordWrite = needsSecurePasswordWrite()
    if port in [389, 3268] and securePasswordWrite and not kerberos and
        (username.len == 0 or (password.len == 0 and ntlmHash.len == 0)):
      let tls = await startTls(socket, host, state.messageId, timeoutMs)
      inc state.messageId
      if not tls.ok:
        result.bindResultCode = tls.code
        result.bindDiagnostic = tls.diagnostic
        result.message =
          if tls.diagnostic.len > 0: "StartTLS failed: " & tls.diagnostic
          else: "StartTLS failed"
        return
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos,
      sealNtlm=port in [389, 3268] and securePasswordWrite)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    result.defaultNamingContext = await discoverBaseDn(socket, timeoutMs,
      state, bindResult.baseDn, bindResult.effectiveDomain)

    var effectiveActions = actions
    block dmsaSidPatch:
      for i in 0 ..< effectiveActions.len:
        if effectiveActions[i].kind != lwAdd: continue
        var isDmsa = false
        for attr in effectiveActions[i].attrs:
          if attr.name.cmpIgnoreCase("objectClass") == 0:
            for v in attr.values:
              if v.cmpIgnoreCase("msDS-DelegatedManagedServiceAccount") == 0:
                isDmsa = true
        if not isDmsa: continue
        var lookupName = username
        if "@" in lookupName: lookupName = lookupName.split("@")[0]
        if "\\" in lookupName: lookupName = lookupName.split("\\")[^1]
        if lookupName.len == 0: break dmsaSidPatch
        let userEntry = await findLdapAccount(socket, timeoutMs, state,
          result.defaultNamingContext, lookupName, @["objectSid"])
        let rawSid =
          if "objectSid" in userEntry.attrs and userEntry.attrs["objectSid"].len > 0:
            userEntry.attrs["objectSid"][0]
          else: ""
        if rawSid.len == 0: break dmsaSidPatch
        let sidStr = formatSid(rawSid)
        if sidStr.len == 0: break dmsaSidPatch
        let sd = buildDmsaGroupMsaMembership(sidStr)
        for j in 0 ..< effectiveActions[i].attrs.len:
          if effectiveActions[i].attrs[j].name.cmpIgnoreCase("msDS-GroupMSAMembership") == 0:
            effectiveActions[i].attrs[j].values = @[sd]

    for action in effectiveActions:
      var item = LdapWriteItem(dn: action.dn)
      inc state.messageId
      var req = ""
      var expectedOp = 0
      case action.kind
      of lwAdd:
        item.kind = "add"
        req = buildAddRequest(action.dn, action.attrs, state.messageId)
        expectedOp = 0x69
      of lwModify:
        item.kind = "modify"
        req = buildModifyRequest(action.dn, action.mods, state.messageId)
        expectedOp = 0x67
      of lwDelete:
        item.kind = "delete"
        req = buildDeleteRequest(action.dn, state.messageId)
        expectedOp = 0x6b
      let resp = await sendLdapSealed(socket, req, timeoutMs, state,
        confidential = actionWritesUnicodePwd(action))
      if resp.len == 0:
        item.message = item.kind & ": no response"
        result.items.add item
        continue
      let parsed = parseLdapMessage(resp)
      if parsed.op != expectedOp:
        item.message = "unexpected LDAP response"
        result.items.add item
        continue
      let opResult = parseLdapResult(parsed.body)
      item.resultCode = opResult.code
      item.diagnostic = opResult.diagnostic.strip()
      item.success = opResult.code == 0
      item.message =
        if item.success: item.kind & " ok"
        else: item.kind & " failed (" & $opResult.code & ")"
      if not item.success and actionWritesUnicodePwd(action):
        item.message = item.kind & " failed (" & $opResult.code & "): " &
          unicodePwdHint(opResult.code, item.diagnostic)
      result.items.add item
    result.success = result.items.len > 0
    for item in result.items:
      if not item.success:
        result.success = false
        break
    result.message =
      if result.success: "LDAP write operations completed"
      else: "one or more LDAP write operations failed"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc deletedOriginalName(entry: LdapEntry): string =
  var cn = ""
  if "cn" in entry.attrs and entry.attrs["cn"].len > 0:
    cn = entry.attrs["cn"][0]
  elif entry.dn.startsWith("CN="):
    let comma = entry.dn.find(",", 3)
    cn =
      if comma >= 0: entry.dn[3 ..< comma]
      else: entry.dn[3 .. ^1]
  let marker = cn.find("\nDEL:")
  if marker >= 0:
    return cn[0 ..< marker]
  let escapedMarker = cn.find("\\0ADEL:")
  if escapedMarker >= 0:
    return cn[0 ..< escapedMarker]
  cn

proc findDeletedLdapObject(socket: AsyncSocket; timeoutMs: int; state: LdapWriteSession;
                           baseDn, name: string): Future[LdapEntry] {.async.} =
  inc state.messageId
  let deletedBase = "CN=Deleted Objects," & baseDn
  let req = buildSearchRequestWithControls(deletedBase, 1,
    filterEquality("isDeleted", "TRUE"),
    @["cn", "lastKnownParent", "objectClass", "sAMAccountName", "distinguishedName"],
    buildShowDeletedControl(), sizeLimit = 200, messageId = state.messageId)
  let needle = name.strip()
  let needleNoDollar =
    if needle.endsWith("$"): needle[0 ..< needle.len - 1] else: needle
  proc matchEntry(entry: LdapEntry): bool =
    let original = deletedOriginalName(entry)
    if original.cmpIgnoreCase(needle) == 0 or original.cmpIgnoreCase(needleNoDollar) == 0:
      return true
    if "sAMAccountName" in entry.attrs:
      for sam in entry.attrs["sAMAccountName"]:
        if sam.cmpIgnoreCase(needle) == 0:
          return true
  if state.gssCtx != nil:
    let wrapped = state.gssCtx.wrapToken(req, confidential = false)
    var msg = ""
    msg.addU32Be(wrapped.len.uint32)
    msg.add wrapped
    await socket.send(msg)
    let deadline = epochTime() + timeoutMs.float / 1000.0
    while true:
      let remaining = int((deadline - epochTime()) * 1000)
      if remaining <= 0: break
      let frame = await recvGssLdapFrame(socket, remaining)
      if frame.len == 0: break
      let plain = state.gssCtx.unwrapToken(frame)
      if plain.len == 0: break
      let m = parseLdapMessage(plain)
      if m.op == 0x65: break
      if m.op != 0x64: continue
      let entry = parseSearchEntry(m.body)
      if matchEntry(entry): return entry
    return
  await socket.send(req)
  for raw in await recvUntilDone(socket, timeoutMs):
    let m = parseLdapMessage(raw)
    if m.op != 0x64: continue
    let entry = parseSearchEntry(m.body)
    if matchEntry(entry): return entry

proc restoreDeletedObject*(host: string; port, timeoutMs: int;
                           username, password, ntlmHash, domain: string;
                           deletedDn, name, restoreTo, newName: string;
                           kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn

    var targetDn = deletedDn
    var parentDn = restoreTo
    var restoreRdn = newName
    if restoreRdn.len > 0 and not restoreRdn.contains("="):
      restoreRdn = "CN=" & ldapEscapeDnValue(restoreRdn)
    if targetDn.len == 0:
      if name.len == 0:
        result.message = "--restore-deleted requires --dn or --name"
        return
      let deleted = await findDeletedLdapObject(socket, timeoutMs, state, baseDn, name)
      if deleted.dn.len == 0:
        result.message = "deleted object not found"
        return
      targetDn = deleted.dn
      if parentDn.len == 0 and "lastKnownParent" in deleted.attrs and
          deleted.attrs["lastKnownParent"].len > 0:
        parentDn = deleted.attrs["lastKnownParent"][0]
      if restoreRdn.len == 0:
        restoreRdn = "CN=" & ldapEscapeDnValue(deletedOriginalName(deleted))
    if parentDn.len == 0:
      parentDn = "CN=Users," & baseDn
    if restoreRdn.len == 0:
      result.message = "--restore-deleted with --dn requires --new-name"
      return

    var item = LdapWriteItem(kind: "restore", dn: targetDn)
    inc state.messageId
    let controls = buildShowDeletedControl()
    let restoreResp = await sendLdapSealed(socket,
      buildModifyDnRequestWithControls(targetDn, restoreRdn, true, parentDn,
        controls, state.messageId), timeoutMs, state)
    if restoreResp.len == 0:
      item.message = "restore: no response"
    else:
      let parsed = parseLdapMessage(restoreResp)
      if parsed.op == 0x6d:
        let opResult = parseLdapResult(parsed.body)
        item.resultCode = opResult.code
        item.diagnostic = opResult.diagnostic.strip()
        item.success = opResult.code == 0
        item.message =
          if item.success: "restore ok"
          else: "restore failed (" & $opResult.code & ")"
      else:
        item.message = "unexpected LDAP response"
    if not item.success:
      let restoreDn = restoreRdn & "," & parentDn
      let firstCode = item.resultCode
      let firstDiag = item.diagnostic
      inc state.messageId
      let fallbackResp = await sendLdapSealed(socket,
        buildModifyRequestWithControls(targetDn, @[
          LdapModification(op: lmoDelete, attr: "isDeleted", values: @[]),
          LdapModification(op: lmoReplace, attr: "distinguishedName", values: @[restoreDn])
        ], controls, state.messageId), timeoutMs, state)
      if fallbackResp.len == 0:
        item.message = "restore fallback: no response"
      else:
        let fallbackParsed = parseLdapMessage(fallbackResp)
        if fallbackParsed.op == 0x67:
          let fallbackResult = parseLdapResult(fallbackParsed.body)
          item.resultCode = fallbackResult.code
          item.diagnostic = fallbackResult.diagnostic.strip()
          item.success = fallbackResult.code == 0
          item.message =
            if item.success: "restore ok"
            else:
              "restore failed (" & $fallbackResult.code & "); modifyDN was " &
                $firstCode & (if firstDiag.len > 0: " " & firstDiag else: "")
        else:
          item.message = "unexpected LDAP response"
    item.dn = restoreRdn & "," & parentDn
    result.items.add item
    result.success = item.success
    result.message =
      if result.success: "deleted object restored"
      else: "deleted object restore failed"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc moveObject*(host: string; port, timeoutMs: int;
                 username, password, ntlmHash, domain: string;
                 sourceDn, newParentDn: string;
                 kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let rdnEnd = sourceDn.find(',')
    let rdn = if rdnEnd > 0: sourceDn[0 ..< rdnEnd] else: sourceDn
    var item = LdapWriteItem(kind: "move", dn: sourceDn)
    inc state.messageId
    let resp = await sendLdap(socket,
      buildModifyDnRequestWithControls(sourceDn, rdn, true, newParentDn, "", state.messageId),
      timeoutMs)
    if resp.len == 0:
      item.message = "no response"
    else:
      let parsed = parseLdapMessage(resp)
      if parsed.op == 0x6d:
        let opResult = parseLdapResult(parsed.body)
        item.resultCode = opResult.code
        item.diagnostic = opResult.diagnostic.strip()
        item.success = opResult.code == 0
        item.message =
          if item.success: "move ok"
          else: "move failed (" & $opResult.code & "): " & item.diagnostic
      else:
        item.message = "unexpected LDAP response"
    item.dn = rdn & "," & newParentDn
    result.items.add item
    result.success = item.success
    result.message =
      if result.success: "object moved to " & newParentDn
      else: item.message
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc addDomainAdminsMember*(host: string; port, timeoutMs: int;
                            username, password, ntlmHash, domain,
                            account: string; kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let memberEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName"])
    if memberEntry.dn.len == 0:
      result.message = "account not found"
      return
    let groupDn = "CN=Domain Admins,CN=Users," & baseDn
    let action = LdapWriteAction(kind: lwModify, dn: groupDn,
      mods: @[LdapModification(op: lmoAdd, attr: "member", values: @[memberEntry.dn])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc modifyGroupMember*(host: string; port, timeoutMs: int;
                        username, password, ntlmHash, domain,
                        groupName, memberName: string; remove = false;
                        kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let groupEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, groupName, @["distinguishedName"])
    if groupEntry.dn.len == 0:
      result.message = "group not found"
      return
    let memberEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, memberName, @["distinguishedName"])
    if memberEntry.dn.len == 0:
      result.message = "member not found"
      return
    let action = LdapWriteAction(kind: lwModify, dn: groupEntry.dn,
      mods: @[LdapModification(op: if remove: lmoDelete else: lmoAdd,
        attr: "member", values: @[memberEntry.dn])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc setAccountSpn*(host: string; port, timeoutMs: int;
                    username, password, ntlmHash, domain,
                    account, spn: string; kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName"])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    let action = LdapWriteAction(kind: lwModify, dn: acct.dn,
      mods: @[LdapModification(op: lmoAdd, attr: "servicePrincipalName", values: @[spn])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc addAccountAttribute*(host: string; port, timeoutMs: int;
                          username, password, ntlmHash, domain,
                          account, attr, value: string; kerberos = false;
                          replace = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName", attr])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    let actualValue = value.replace("{DN}", acct.dn)
    let action = LdapWriteAction(kind: lwModify, dn: acct.dn,
      mods: @[LdapModification(op: if replace: lmoReplace else: lmoAdd,
        attr: attr, values: @[actualValue])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc replaceAccountAttributeValue*(host: string; port, timeoutMs: int;
                                   username, password, ntlmHash, domain,
                                   account, attr, value: string;
                                   kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName"])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    let vals = if value.len == 0: @[] else: @[value]
    let action = LdapWriteAction(kind: lwModify, dn: acct.dn,
      mods: @[LdapModification(op: lmoReplace, attr: attr, values: vals)])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc modifyAccountAttributeValue*(host: string; port, timeoutMs: int;
                                  username, password, ntlmHash, domain,
                                  account, attr, value: string; deleteValue = false;
                                  kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName", attr])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    let actualValue = value.replace("{DN}", acct.dn)
    let op = if deleteValue: lmoDelete else: lmoAdd
    let action = LdapWriteAction(kind: lwModify, dn: acct.dn,
      mods: @[LdapModification(op: op, attr: attr, values: @[actualValue])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc nestedGroupsForAccount*(host: string; port, timeoutMs: int;
                             username, password, ntlmHash, domain,
                             account: string; kerberos = false): Future[LdapNestedGroupsResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapNestedGroupsResult(host: host, port: port, target: account)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName"])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    result.targetDn = acct.dn
    inc state.messageId
    let recursiveFilter = filterAnd([
      filterEquality("objectClass", "group"),
      filterExtensible("member", acct.dn, "1.2.840.113556.1.4.1941")
    ])
    let req = buildSearchRequest(baseDn, 2, recursiveFilter,
      @["sAMAccountName", "cn", "description", "objectSid", "groupType"],
      sizeLimit = 1000, messageId = state.messageId)
    await socket.send(req)
    for raw in await recvUntilDone(socket, timeoutMs):
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      result.groups.add parseSearchEntry(m.body)
    result.success = true
    result.message = "recursive group membership query completed"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc aclForObject*(host: string; port, timeoutMs: int;
                   username, password, ntlmHash, domain,
                   target: string; kerberos = false): Future[LdapAclResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapAclResult(host: host, port: port, target: target)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let entry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, target, @["distinguishedName"])
    let targetDn =
      if entry.dn.len > 0: entry.dn
      elif "=" in target and "," in target: target
      else: ""
    if targetDn.len == 0:
      result.message = "object not found"
      return
    result.targetDn = targetDn
    inc state.messageId
    let req = buildSearchRequestWithControls(targetDn, 0, filterPresent("objectClass"),
      @["nTSecurityDescriptor"], buildSdFlagsControl(0x07),
      sizeLimit = 1, messageId = state.messageId)
    await sendLdapSearchProtected(socket, req, state)
    for raw in await recvLdapSearchProtected(socket, timeoutMs, state):
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      let sdEntry = parseSearchEntry(m.body)
      if "nTSecurityDescriptor" in sdEntry.attrs and
          sdEntry.attrs["nTSecurityDescriptor"].len > 0:
        let parsed = parseSecurityDescriptor(sdEntry.attrs["nTSecurityDescriptor"][0])
        result.ownerSid = parsed.owner
        result.groupSid = parsed.group
        result.aces = parsed.aces
        result.success = true
        result.message = "ACL parsed"
        return
    result.message = "nTSecurityDescriptor not returned"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc modifyAclForObject*(host: string; port, timeoutMs: int;
                         username, password, ntlmHash, domain,
                         target, principal: string; rights: seq[string];
                         addAce: bool; denyAce = false; aceFlags = 0;
                         objectType = ""; inheritedObjectType = "";
                         exact = false; kerberos = false): Future[LdapAclModifyResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapAclModifyResult(host: host, port: port, target: target,
    principal: principal, operation: if addAce: (if denyAce: "acl-deny" else: "acl-add") else: "acl-remove",
    rights: rights, aceType: if denyAce: (if objectType.len > 0 or inheritedObjectType.len > 0: 6 else: 1) else: (if objectType.len > 0 or inheritedObjectType.len > 0: 5 else: 0),
    aceFlags: aceFlags, objectType: objectType, inheritedObjectType: inheritedObjectType)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let targetEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, target, @["distinguishedName"])
    let targetDn =
      if targetEntry.dn.len > 0: targetEntry.dn
      elif "=" in target and "," in target: target
      else: ""
    if targetDn.len == 0:
      result.message = "target not found"
      return
    result.targetDn = targetDn
    let principalEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, principal, @["distinguishedName", "objectSid"])
    if principalEntry.dn.len == 0:
      result.message = "principal not found"
      return
    if principalEntry.attrs.hasKey("objectSid") and principalEntry.attrs["objectSid"].len > 0:
      result.principalSid = formatSid(principalEntry.attrs["objectSid"][0])
    if result.principalSid.len == 0:
      result.message = "principal SID not found"
      return
    let mask = accessMaskFromRights(rights)
    result.mask = mask
    if mask == 0:
      result.message = "no valid rights supplied"
      return

    inc state.messageId
    let readReq = buildSearchRequestWithControls(targetDn, 0, filterPresent("objectClass"),
      @["nTSecurityDescriptor"], buildSdFlagsControl(0x04),
      sizeLimit = 1, messageId = state.messageId)
    await sendLdapSearchProtected(socket, readReq, state)
    var sd = ""
    for raw in await recvLdapSearchProtected(socket, timeoutMs, state):
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      let sdEntry = parseSearchEntry(m.body)
      if sdEntry.attrs.hasKey("nTSecurityDescriptor") and
          sdEntry.attrs["nTSecurityDescriptor"].len > 0:
        sd = sdEntry.attrs["nTSecurityDescriptor"][0]
    if sd.len == 0 and not addAce:
      result.message = "nTSecurityDescriptor not returned"
      return
    let parsed =
      if sd.len > 0: parseSecurityDescriptor(sd)
      else: (owner: "", group: "", aces: newSeq[LdapAce]())
    var aces = parsed.aces
    if addAce:
      aces.add LdapAce(aceType: result.aceType, aceFlags: aceFlags, mask: mask,
        trusteeSid: result.principalSid, rights: rightsFromMask(mask),
        objectType: objectType, inheritedObjectType: inheritedObjectType)
    else:
      var kept: seq[LdapAce]
      for ace in aces:
        let genericAllMatch = (mask and 0x10000000'u32) != 0 and
          ((ace.mask and 0x000F01FF'u32) == 0x000F01FF'u32 or
           (ace.mask and 0x10000000'u32) != 0)
        let genericWriteMatch = (mask and 0x40000000'u32) != 0 and
          ((ace.mask and 0x00020028'u32) == 0x00020028'u32 or
           (ace.mask and 0x40000000'u32) != 0)
        let genericReadMatch = (mask and 0x80000000'u32) != 0 and
          ((ace.mask and 0x00020094'u32) == 0x00020094'u32 or
           (ace.mask and 0x80000000'u32) != 0)
        let typeMatch =
          if denyAce: ace.aceType in [1, 6]
          else: ace.aceType in [0, 5]
        let maskMatch =
          if exact: ace.mask == mask
          else: mask == 0 or (ace.mask and mask) == mask or
            genericAllMatch or genericWriteMatch or genericReadMatch
        let objectMatch =
          (objectType.len == 0 or ace.objectType.cmpIgnoreCase(objectType) == 0) and
          (inheritedObjectType.len == 0 or ace.inheritedObjectType.cmpIgnoreCase(inheritedObjectType) == 0)
        if ace.trusteeSid == result.principalSid and
            typeMatch and maskMatch and objectMatch:
          continue
        kept.add ace
      aces = kept
    let newSd = buildSelfRelativeSd(parsed.owner, parsed.group, aces)
    inc state.messageId
    let modReq = buildModifyRequestWithControls(targetDn,
      @[LdapModification(op: lmoReplace, attr: "nTSecurityDescriptor", values: @[newSd])],
      buildSdFlagsControl(0x04), state.messageId)
    let modResp = await sendLdapSealed(socket, modReq, timeoutMs, state)
    if modResp.len == 0:
      result.message = "modify: no response"
      return
    let parsedMod = parseLdapMessage(modResp)
    if parsedMod.op != 0x67:
      result.message = "unexpected LDAP response to modify"
      return
    let modResult = parseLdapResult(parsedMod.body)
    result.resultCode = modResult.code
    result.diagnostic = modResult.diagnostic.strip()
    result.success = modResult.code == 0
    result.message =
      if result.success: "ACL modified"
      else: "modify failed (" & $modResult.code & ")"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc setOwnerForObject*(host: string; port, timeoutMs: int;
                        username, password, ntlmHash, domain,
                        target, owner: string; kerberos = false): Future[LdapAclModifyResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapAclModifyResult(host: host, port: port, target: target,
    owner: owner, operation: "set-owner")
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let targetEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, target, @["distinguishedName"])
    let targetDn =
      if targetEntry.dn.len > 0: targetEntry.dn
      elif "=" in target and "," in target: target
      else: ""
    if targetDn.len == 0:
      result.message = "target not found"
      return
    result.targetDn = targetDn
    let ownerEntry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, owner, @["distinguishedName", "objectSid"])
    if ownerEntry.dn.len == 0:
      result.message = "owner not found"
      return
    if ownerEntry.attrs.hasKey("objectSid") and ownerEntry.attrs["objectSid"].len > 0:
      result.ownerSid = formatSid(ownerEntry.attrs["objectSid"][0])
    if result.ownerSid.len == 0:
      result.message = "owner SID not found"
      return

    inc state.messageId
    let readReq = buildSearchRequestWithControls(targetDn, 0, filterPresent("objectClass"),
      @["nTSecurityDescriptor"], buildSdFlagsControl(0x07),
      sizeLimit = 1, messageId = state.messageId)
    await socket.send(readReq)
    var sd = ""
    for raw in await recvUntilDone(socket, timeoutMs):
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      let sdEntry = parseSearchEntry(m.body)
      if sdEntry.attrs.hasKey("nTSecurityDescriptor") and
          sdEntry.attrs["nTSecurityDescriptor"].len > 0:
        sd = sdEntry.attrs["nTSecurityDescriptor"][0]
    if sd.len == 0:
      result.message = "nTSecurityDescriptor not returned"
      return
    let parsed = parseSecurityDescriptor(sd)
    let newSd = buildSelfRelativeSd(result.ownerSid, parsed.group, parsed.aces)
    inc state.messageId
    let modReq = buildModifyRequestWithControls(targetDn,
      @[LdapModification(op: lmoReplace, attr: "nTSecurityDescriptor", values: @[newSd])],
      buildSdFlagsControl(0x01), state.messageId)
    let modResp = await sendLdapSealed(socket, modReq, timeoutMs, state)
    if modResp.len == 0:
      result.message = "modify: no response"
      return
    let parsedMod = parseLdapMessage(modResp)
    if parsedMod.op != 0x67:
      result.message = "unexpected LDAP response to modify"
      return
    let modResult = parseLdapResult(parsedMod.body)
    result.resultCode = modResult.code
    result.diagnostic = modResult.diagnostic.strip()
    result.success = modResult.code == 0
    result.message =
      if result.success: "owner modified"
      else: "modify failed (" & $modResult.code & ")"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc findGpoObject(socket: AsyncSocket; timeoutMs: int; state: LdapWriteSession;
                   baseDn, gpo: string; attrs: seq[string]): Future[LdapEntry] {.async.} =
  inc state.messageId
  let directDn = "=" in gpo and "," in gpo
  let base = baseDn
  let scope = 2
  let filter =
    if directDn:
      filterAnd([
        filterEquality("objectClass", "groupPolicyContainer"),
        filterEquality("distinguishedName", gpo)
      ])
    else:
      filterAnd([
        filterEquality("objectClass", "groupPolicyContainer"),
        filterOr([
          filterEquality("displayName", gpo),
          filterEquality("cn", gpo)
        ])
      ])
  let req = buildSearchRequest(base, scope, filter, attrs,
    sizeLimit = 1, messageId = state.messageId)
  await socket.send(req)
  for raw in await recvUntilDone(socket, timeoutMs):
    let m = parseLdapMessage(raw)
    if m.op != 0x64: continue
    return parseSearchEntry(m.body)

proc gpoInfo*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain,
              gpo: string; kerberos = false): Future[LdapGpoInfoResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapGpoInfoResult(host: host, port: port, gpo: gpo)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let entry = await findGpoObject(socket, timeoutMs, state, baseDn, gpo,
      @["distinguishedName", "displayName", "cn", "gPCFileSysPath", "versionNumber"])
    if entry.dn.len == 0:
      result.message = "GPO not found"
      return
    result.dn = entry.dn
    if entry.attrs.hasKey("cn") and entry.attrs["cn"].len > 0:
      result.cn = entry.attrs["cn"][0]
    if entry.attrs.hasKey("displayName") and entry.attrs["displayName"].len > 0:
      result.displayName = entry.attrs["displayName"][0]
    if entry.attrs.hasKey("gPCFileSysPath") and entry.attrs["gPCFileSysPath"].len > 0:
      result.gpcFileSysPath = entry.attrs["gPCFileSysPath"][0]
    if entry.attrs.hasKey("versionNumber") and entry.attrs["versionNumber"].len > 0:
      try: result.versionNumber = parseInt(entry.attrs["versionNumber"][0])
      except CatchableError: discard
    if result.gpcFileSysPath.len == 0:
      result.message = "GPO has no gPCFileSysPath"
      return
    result.success = true
    result.message = "GPO resolved"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc setGpoLink*(host: string; port, timeoutMs: int;
                 username, password, ntlmHash, domain,
                 gpo, targetDn: string; unlink = false;
                 kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let gpoEntry = await findGpoObject(socket, timeoutMs, state, baseDn, gpo,
      @["distinguishedName", "displayName", "cn"])
    if gpoEntry.dn.len == 0:
      result.message = "GPO not found"
      return
    let targetEntry = await findLdapAccount(socket, timeoutMs, state, baseDn,
      targetDn, @["distinguishedName", "gPLink"])
    let actualTargetDn =
      if targetEntry.dn.len > 0: targetEntry.dn
      elif "=" in targetDn and "," in targetDn: targetDn
      else: ""
    if actualTargetDn.len == 0:
      result.message = "target container not found"
      return
    var current = ""
    if targetEntry.attrs.hasKey("gPLink") and targetEntry.attrs["gPLink"].len > 0:
      current = targetEntry.attrs["gPLink"][0]
    let link = "[LDAP://" & gpoEntry.dn & ";0]"
    var next = current
    if unlink:
      next = next.replace(link, "")
    elif link notin next:
      next.add link
    let action = LdapWriteAction(kind: lwModify, dn: actualTargetDn,
      mods: @[LdapModification(op: lmoReplace, attr: "gPLink", values: @[next])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc modifyGpoObject*(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain,
                      gpo: string; mods: seq[LdapModification];
                      kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let gpoEntry = await findGpoObject(socket, timeoutMs, state, baseDn, gpo,
      @["distinguishedName", "displayName", "cn"])
    if gpoEntry.dn.len == 0:
      result.message = "GPO not found"
      return
    let action = LdapWriteAction(kind: lwModify, dn: gpoEntry.dn, mods: mods)
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc lapsForComputer*(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain,
                      computer: string; kerberos = false): Future[LdapLapsResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapLapsResult(host: host, port: port, computer: computer)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    result.authenticated = true
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    result.defaultNamingContext = baseDn
    let entry = await findLdapAccount(socket, timeoutMs, state,
      baseDn, computer, @[
        "distinguishedName",
        "sAMAccountName",
        "dNSHostName",
        "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedDSRMPassword",
        "msLAPS-PasswordExpirationTime"
      ])
    if entry.dn.len == 0:
      result.message = "computer not found"
      return
    result.computerDn = entry.dn
    if entry.attrs.hasKey("sAMAccountName") and entry.attrs["sAMAccountName"].len > 0:
      result.samAccountName = entry.attrs["sAMAccountName"][0]
    if entry.attrs.hasKey("dNSHostName") and entry.attrs["dNSHostName"].len > 0:
      result.dnsHostName = entry.attrs["dNSHostName"][0]
    if entry.attrs.hasKey("ms-Mcs-AdmPwd") and entry.attrs["ms-Mcs-AdmPwd"].len > 0:
      result.legacyPassword = entry.attrs["ms-Mcs-AdmPwd"][0]
    if entry.attrs.hasKey("ms-Mcs-AdmPwdExpirationTime") and entry.attrs["ms-Mcs-AdmPwdExpirationTime"].len > 0:
      result.legacyExpiration = entry.attrs["ms-Mcs-AdmPwdExpirationTime"][0]
    if entry.attrs.hasKey("msLAPS-Password") and entry.attrs["msLAPS-Password"].len > 0:
      result.windowsPassword = entry.attrs["msLAPS-Password"][0]
    if entry.attrs.hasKey("msLAPS-EncryptedPassword") and entry.attrs["msLAPS-EncryptedPassword"].len > 0:
      result.windowsEncryptedPassword = entry.attrs["msLAPS-EncryptedPassword"][0]
    if entry.attrs.hasKey("msLAPS-EncryptedDSRMPassword") and entry.attrs["msLAPS-EncryptedDSRMPassword"].len > 0:
      result.windowsEncryptedDsrmPassword = entry.attrs["msLAPS-EncryptedDSRMPassword"][0]
    if entry.attrs.hasKey("msLAPS-PasswordExpirationTime") and entry.attrs["msLAPS-PasswordExpirationTime"].len > 0:
      result.windowsExpiration = entry.attrs["msLAPS-PasswordExpirationTime"][0]
    result.success = result.legacyPassword.len > 0 or result.windowsPassword.len > 0 or
      result.windowsEncryptedPassword.len > 0 or
      result.windowsEncryptedDsrmPassword.len > 0
    result.message =
      if result.success: "LAPS attributes returned"
      else: "computer found, but no readable LAPS password attributes returned"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc setUserEnabled*(host: string; port, timeoutMs: int;
                     username, password, ntlmHash, domain,
                     account: string; enabled: bool; kerberos = false): Future[LdapWriteResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapWriteResult(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true
    let state = LdapWriteSession(messageId: 1)
    let bindResult = await ldapBindForWrite(socket, host, username, password, ntlmHash,
      domain, state, timeoutMs, kerberos=kerberos)
    if bindResult.code != 0:
      result.bindResultCode = bindResult.code
      result.bindDiagnostic = bindResult.diagnostic
      result.message = "bind failed (" & $bindResult.code & ")"
      return
    let baseDn = await discoverBaseDn(socket, timeoutMs, state,
      bindResult.baseDn, bindResult.effectiveDomain)
    let acct = await findLdapAccount(socket, timeoutMs, state,
      baseDn, account, @["distinguishedName", "userAccountControl"])
    if acct.dn.len == 0:
      result.message = "account not found"
      return
    var uac = 512
    if "userAccountControl" in acct.attrs and acct.attrs["userAccountControl"].len > 0:
      uac = parseInt(acct.attrs["userAccountControl"][0])
    if enabled: uac = uac and not 2
    else: uac = uac or 2
    let action = LdapWriteAction(kind: lwModify, dn: acct.dn,
      mods: @[LdapModification(op: lmoReplace, attr: "userAccountControl", values: @[$uac])])
    result = await applyLdapActions(host, port, timeoutMs, username, password,
      ntlmHash, domain, @[action], kerberos=kerberos)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc setRbcd*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain: string;
              delegateFrom, delegateTo: string; kerberos = false): Future[LdapRbcdResult] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapRbcdResult(host: host, port: port,
    delegateFrom: delegateFrom, delegateTo: delegateTo)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    result.reachable = true

    var messageId = 1
    var effectiveDomain = domain
    var baseDn = ""
    if effectiveDomain.contains("."):
      baseDn = domainToDcDn(effectiveDomain)
    if username.len > 0 and effectiveDomain.len == 0 and
        "@" notin username and "=" notin username and "\\" notin username:
      let anonResp = await sendLdap(socket, buildAnonymousBindRequest(messageId), timeoutMs)
      if anonResp.len > 0:
        let parsedAnon = parseLdapMessage(anonResp)
        if parsedAnon.op == 0x61 and parseBindResponse(parsedAnon.body).code == 0:
          inc messageId
          let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
            @["defaultNamingContext"], sizeLimit = 1, messageId = messageId)
          await socket.send(rootReq)
          for raw in await recvUntilDone(socket, timeoutMs):
            let m = parseLdapMessage(raw)
            if m.op != 0x64: continue
            let entry = parseSearchEntry(m.body)
            if "defaultNamingContext" in entry.attrs and
                entry.attrs["defaultNamingContext"].len > 0:
              baseDn = entry.attrs["defaultNamingContext"][0]
              effectiveDomain = dcDnToDomain(baseDn)

    inc messageId
    if kerberos:
      let bindResult = await kerberosSaslBind(socket, host, effectiveDomain,
        messageId, timeoutMs)
      messageId = bindResult.nextMessageId
      result.bindResultCode = bindResult.code
      result.diagnostic = bindResult.diagnostic
    elif ntlmHash.len > 0 and password.len == 0:
      let bindResult = await ntlmSaslBind(socket, username, password, ntlmHash,
        effectiveDomain, messageId, timeoutMs)
      messageId = bindResult.nextMessageId
      result.bindResultCode = bindResult.code
      result.diagnostic = bindResult.diagnostic
    else:
      let bindResp = await sendLdap(socket,
        buildSimpleBindRequest(decodeBindDn(username, password, effectiveDomain),
          password, messageId), timeoutMs)
      if bindResp.len == 0:
        result.message = "bind: no response"
        return
      let parsedBind = parseLdapMessage(bindResp)
      if parsedBind.op != 0x61:
        result.message = "non-LDAP bind response"
        return
      let bindResult = parseBindResponse(parsedBind.body)
      result.bindResultCode = bindResult.code
      result.diagnostic = bindResult.diagnostic.strip()
    if result.bindResultCode != 0:
      result.message = "bind failed (" & $result.bindResultCode & ")"
      return
    result.authenticated = true

    if baseDn.len == 0:
      inc messageId
      let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
        @["defaultNamingContext"], sizeLimit = 1, messageId = messageId)
      await socket.send(rootReq)
      for raw in await recvUntilDone(socket, timeoutMs):
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        let entry = parseSearchEntry(m.body)
        if "defaultNamingContext" in entry.attrs and
            entry.attrs["defaultNamingContext"].len > 0:
          baseDn = entry.attrs["defaultNamingContext"][0]
          break
    result.defaultNamingContext = baseDn
    if baseDn.len == 0:
      result.message = "could not discover defaultNamingContext"
      return

    proc accountFilter(name: string): string =
      var clean = name.strip()
      var noDollar = clean
      while noDollar.endsWith("$"):
        noDollar.setLen(noDollar.len - 1)
      var withDollar = noDollar & "$"
      filterOr([
        filterEquality("sAMAccountName", clean),
        filterEquality("sAMAccountName", withDollar),
        filterEquality("cn", noDollar),
        filterEquality("dNSHostName", clean)
      ])

    proc findAccount(name: string; attrs: seq[string]): Future[LdapEntry] {.async.} =
      inc messageId
      let base = if "=" in name and "," in name: name else: baseDn
      let scope = if base == name: 0 else: 2
      let filter = if scope == 0: filterPresent("objectClass") else: accountFilter(name)
      let req = buildSearchRequest(base, scope, filter, attrs,
        sizeLimit = 1, messageId = messageId)
      await socket.send(req)
      for raw in await recvUntilDone(socket, timeoutMs):
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        return parseSearchEntry(m.body)

    var fromSid = ""
    if delegateFrom.startsWith("S-1-"):
      fromSid = delegateFrom
    else:
      let fromEntry = await findAccount(delegateFrom,
        @["objectSid", "distinguishedName", "sAMAccountName"])
      if fromEntry.dn.len == 0:
        result.message = "delegate-from not found"
        return
      result.delegateFromDn = fromEntry.dn
      if "objectSid" in fromEntry.attrs and fromEntry.attrs["objectSid"].len > 0:
        fromSid = formatSid(fromEntry.attrs["objectSid"][0])
    if fromSid.len == 0:
      result.message = "delegate-from SID not found"
      return
    result.delegateFromSid = fromSid

    let toEntry = await findAccount(delegateTo,
      @["distinguishedName", "sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
    if toEntry.dn.len == 0:
      result.message = "delegate-to not found"
      return
    result.delegateToDn = toEntry.dn

    let sd = rbcdSecurityDescriptor(fromSid)
    inc messageId
    let modResp = await sendLdap(socket,
      buildModifyReplaceRequest(toEntry.dn,
        "msDS-AllowedToActOnBehalfOfOtherIdentity", [sd], messageId), timeoutMs)
    if modResp.len == 0:
      result.message = "modify: no response"
      return
    let parsedMod = parseLdapMessage(modResp)
    if parsedMod.op != 0x67:
      result.message = "unexpected LDAP response to modify"
      return
    let modResult = parseLdapResult(parsedMod.body)
    result.resultCode = modResult.code
    result.diagnostic = modResult.diagnostic.strip()
    result.success = modResult.code == 0
    result.message =
      if result.success: "RBCD delegation rights modified"
      else: "modify failed (" & $modResult.code & ")"
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)

proc probeLdap*(host: string; port, timeoutMs: int;
                username = ""; password = ""; domain = ""; ntlmHash = "";
                queries = LdapQueryOptions(rootDse: true);
                attempts = 1; kerberos = false; external = false;
                certFile = ""; keyFile = ""): Future[LdapProbe] {.async.} =
  var socket = newLdapSocket(port)
  result = LdapProbe(host: host, port: port)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      result.message = "timeout"
      return
    let secure = wrapLdapsAfterConnect(socket, host, port, certFile, keyFile)
    if not secure.ok:
      result.message = secure.message
      return

    var messageId = 1
    var effectiveDomain = domain
    var discoveredBaseDn = ""
    var discoveredAttrs = initTable[string, seq[string]]()
    if username.len > 0 and effectiveDomain.len == 0 and
        "@" notin username and "=" notin username and "\\" notin username:
      let anonReq = buildAnonymousBindRequest(messageId)
      let anonResp = await sendLdap(socket, anonReq, timeoutMs)
      if anonResp.len > 0:
        let parsedAnon = parseLdapMessage(anonResp)
        if parsedAnon.op == 0x61 and parseBindResponse(parsedAnon.body).code == 0:
          inc messageId
          let rootAttrs = @["defaultNamingContext", "rootDomainNamingContext",
            "configurationNamingContext", "schemaNamingContext",
            "domainFunctionality", "forestFunctionality", "dnsHostName",
            "serverName", "ldapServiceName", "supportedSASLMechanisms"]
          let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
            rootAttrs, sizeLimit = 1, messageId = messageId)
          await socket.send(rootReq)
          let rootMessages = await recvUntilDone(socket, timeoutMs)
          for raw in rootMessages:
            let m = parseLdapMessage(raw)
            if m.op != 0x64: continue
            let entry = parseSearchEntry(m.body)
            discoveredAttrs = entry.attrs
            if "defaultNamingContext" in entry.attrs and
                entry.attrs["defaultNamingContext"].len > 0:
              discoveredBaseDn = entry.attrs["defaultNamingContext"][0]
              effectiveDomain = dcDnToDomain(discoveredBaseDn)
    inc messageId
    var bindResult: tuple[code: int, matchedDn, diagnostic: string]
    var probeGssCtx: krb.KerberosContext = nil
    let bindDn = decodeBindDn(username, password, effectiveDomain)
    if external:
      result.authAttempted = true
      let bindResp = await sendLdap(socket,
        buildSaslBindRequest("EXTERNAL", "", messageId), timeoutMs)
      if bindResp.len == 0:
        result.reachable = true
        result.message = "bind: no response"
        return
      let parsed = parseLdapMessage(bindResp)
      if parsed.op != 0x61:
        result.reachable = true
        result.message = "non-LDAP response"
        return
      bindResult = parseBindResponse(parsed.body)
    elif kerberos:
      result.authAttempted = true
      let krbBind = await kerberosSaslBind(socket, host, effectiveDomain,
        messageId, timeoutMs)
      messageId = krbBind.nextMessageId
      bindResult = (krbBind.code, "", krbBind.diagnostic)
      if krbBind.code == 0 and krbBind.gssCtx != nil:
        probeGssCtx = krbBind.gssCtx
    elif username.len > 0 and ntlmHash.len > 0 and password.len == 0:
      result.authAttempted = true
      let ntlmBind = await ntlmSaslBind(socket, username, password, ntlmHash,
        effectiveDomain, messageId, timeoutMs)
      messageId = ntlmBind.nextMessageId
      bindResult = (ntlmBind.code, "", ntlmBind.diagnostic)
    else:
      let bindRequest =
        if bindDn.len > 0:
          result.authAttempted = true
          buildSimpleBindRequest(bindDn, password, messageId)
        else:
          buildAnonymousBindRequest(messageId)
      let bindResp = await sendLdap(socket, bindRequest, timeoutMs)
      if bindResp.len == 0:
        result.reachable = true
        result.message = "bind: no response"
        return
      let parsed = parseLdapMessage(bindResp)
      if parsed.op != 0x61:
        result.reachable = true
        result.message = "non-LDAP response"
        return
      bindResult = parseBindResponse(parsed.body)
    result.reachable = true
    result.speaksLdap = true
    result.bindResultCode = bindResult.code
    result.bindDiagnostic = bindResult.diagnostic.strip()
    result.anonymous = bindDn.len == 0 and not external
    result.authenticated = bindResult.code == 0 and result.authAttempted
    if bindResult.code != 0:
      result.message = "bind failed (" & $bindResult.code & ")"
      if not result.authAttempted:
        result.message.add " — anonymous bind denied"
      return
    result.message = if result.authenticated: "bind ok" else: "anonymous bind ok"

    if not queries.rootDse and not queries.users and not queries.groups and
        not queries.computers and not queries.asreproast and not queries.kerberoast and
        not queries.trusts and not queries.gpos and not queries.schema and
        not queries.config and not queries.fgpp and not queries.deleted and
        not queries.locked and not queries.expiredPasswords and
        not queries.staleUsers and not queries.neverLoggedOn and
        not queries.sites and not queries.subnets and not queries.dcs and
        not queries.admins and not queries.dns and
        not queries.certificateInventory and queries.customFilter.len == 0:
      return

    result.queryRequested = true

    proc gssSend(req: string) {.async.} =
      if probeGssCtx != nil:
        let wrapped = probeGssCtx.wrapToken(req, confidential = false)
        var msg = ""
        msg.addU32Be(wrapped.len.uint32)
        msg.add wrapped
        await socket.send(msg)
      else:
        await socket.send(req)

    proc splitLdapPdus(data: string): seq[string] =
      var pos = 0
      while pos < data.len:
        if pos + 2 > data.len: break
        if ord(data[pos]) != 0x30: break
        let lenByte = ord(data[pos + 1])
        var pduLen = 0
        var hdrLen = 0
        if (lenByte and 0x80) == 0:
          pduLen = 2 + lenByte
          hdrLen = 2
        else:
          let need = lenByte and 0x7f
          if pos + 2 + need > data.len: break
          var actualLen = 0
          for i in 0 ..< need:
            actualLen = (actualLen shl 8) or ord(data[pos + 2 + i])
          pduLen = 2 + need + actualLen
          hdrLen = 2 + need
        discard hdrLen
        if pos + pduLen > data.len: break
        result.add data[pos ..< pos + pduLen]
        pos += pduLen

    proc gssRecvAll(): Future[seq[string]] {.async.} =
      if probeGssCtx != nil:
        let deadline = epochTime() + timeoutMs.float / 1000.0
        while true:
          let remaining = int((deadline - epochTime()) * 1000)
          if remaining <= 0: break
          let frame = await recvGssLdapFrame(socket, remaining)
          if frame.len == 0: break
          let plain = probeGssCtx.unwrapToken(frame)
          if plain.len == 0: break
          var done = false
          for pdu in splitLdapPdus(plain):
            result.add pdu
            if parseLdapMessage(pdu).op == 0x65:
              done = true
          if done: break
      else:
        result = await recvUntilDone(socket, timeoutMs)

    var rootAttrsTable = discoveredAttrs
    if rootAttrsTable.len == 0:
      inc messageId
      let rootAttrs = @["defaultNamingContext", "rootDomainNamingContext",
        "configurationNamingContext", "schemaNamingContext",
        "domainFunctionality", "forestFunctionality", "dnsHostName",
        "serverName", "ldapServiceName", "supportedSASLMechanisms"]
      let rootReq = buildSearchRequest("", 0, filterPresent("objectClass"),
        rootAttrs, sizeLimit = 1, messageId = messageId)
      await gssSend(rootReq)
      let rootMessages = await gssRecvAll()
      for raw in rootMessages:
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        rootAttrsTable = parseSearchEntry(m.body).attrs
    block applyRootDse:
      for k, vs in rootAttrsTable:
        let lk = k.toLowerAscii()
        case lk
        of "defaultnamingcontext":
          if vs.len > 0: result.defaultNamingContext = vs[0]
        of "rootdomainnamingcontext":
          if vs.len > 0: result.rootDomainNamingContext = vs[0]
        of "configurationnamingcontext":
          if vs.len > 0: result.configurationNamingContext = vs[0]
        of "schemanamingcontext":
          if vs.len > 0: result.schemaNamingContext = vs[0]
        of "domainfunctionality":
          if vs.len > 0: result.domainFunctionality = functionalityName(vs[0])
        of "forestfunctionality":
          if vs.len > 0: result.forestFunctionality = functionalityName(vs[0])
        of "dnshostname":
          if vs.len > 0: result.dnsHostName = vs[0]
        of "servername":
          if vs.len > 0: result.serverName = vs[0]
        of "ldapservicename":
          if vs.len > 0: result.ldapServiceName = vs[0]
        of "supportedsaslmechanisms":
          for v in vs: result.supportedSaslMechanisms.add v

    let baseDn = result.defaultNamingContext
    if baseDn.len == 0: return

    inc messageId
    let sidReq = buildSearchRequest(baseDn, 0, filterPresent("objectClass"),
      @["objectSid"], sizeLimit = 1, messageId = messageId)
    await gssSend(sidReq)
    let sidMessages = await gssRecvAll()
    for raw in sidMessages:
      let m = parseLdapMessage(raw)
      if m.op != 0x64: continue
      let entry = parseSearchEntry(m.body)
      if "objectSid" in entry.attrs and entry.attrs["objectSid"].len > 0:
        result.domainSid = formatSid(entry.attrs["objectSid"][0])

    proc runQuery(filter: string; attrs: seq[string];
                  limit: int): Future[seq[LdapEntry]] {.async.} =
      inc messageId
      let req = buildSearchRequest(baseDn, 2, filter, attrs,
        sizeLimit = limit, messageId = messageId)
      await gssSend(req)
      let messages = await gssRecvAll()
      for raw in messages:
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        result.add parseSearchEntry(m.body)

    let perQueryLimit = if queries.limit > 0: queries.limit else: 1000

    if queries.users:
      let userFilter = filterEquality("sAMAccountType", "805306368")
      let userAttrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["sAMAccountName", "userPrincipalName", "displayName",
          "userAccountControl", "memberOf", "description", "objectSid",
          "servicePrincipalName"]
      result.users = await runQuery(userFilter,
        userAttrs, perQueryLimit)

    if queries.groups:
      let groupFilter = filterOr([
        filterEquality("sAMAccountType", "268435456"),
        filterEquality("sAMAccountType", "536870912")
      ])
      let groupAttrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["sAMAccountName", "cn", "description", "objectSid", "groupType"]
      result.groups = await runQuery(groupFilter,
        groupAttrs, perQueryLimit)

    if queries.computers:
      let compFilter = filterEquality("sAMAccountType", "805306369")
      let compAttrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["dNSHostName", "sAMAccountName", "operatingSystem",
          "operatingSystemVersion", "objectSid"]
      result.computers = await runQuery(compFilter,
        compAttrs, perQueryLimit)

    if queries.asreproast:
      let uacBit = filterExtensible("userAccountControl", "4194304",
        "1.2.840.113556.1.4.803")
      let asrepFilter = filterAnd([
        filterEquality("sAMAccountType", "805306368"),
        uacBit
      ])
      result.asreproastable = await runQuery(asrepFilter,
        @["sAMAccountName", "userPrincipalName", "userAccountControl"],
        perQueryLimit)

    if queries.kerberoast:
      let kerbFilter = filterAnd([
        filterEquality("sAMAccountType", "805306368"),
        filterPresent("servicePrincipalName")
      ])
      result.kerberoastable = await runQuery(kerbFilter,
        @["sAMAccountName", "servicePrincipalName", "userAccountControl",
          "memberOf"],
        perQueryLimit)

    proc runQueryAt(searchBase, filter: string; attrs: seq[string];
                    scope = 2; limit = perQueryLimit): Future[seq[LdapEntry]] {.async.} =
      inc messageId
      let req = buildSearchRequest(searchBase, scope, filter, attrs,
        sizeLimit = limit, messageId = messageId)
      await gssSend(req)
      let messages = await gssRecvAll()
      for raw in messages:
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        result.add parseSearchEntry(m.body)

    if queries.trusts:
      let trustFilter = filterEquality("objectClass", "trustedDomain")
      result.trusts = await runQueryAt(baseDn, trustFilter,
        @["cn", "trustPartner", "trustDirection", "trustType",
          "trustAttributes", "flatName", "securityIdentifier"])

    if queries.gpos:
      let gpoFilter = filterEquality("objectClass", "groupPolicyContainer")
      result.gpos = await runQueryAt(baseDn, gpoFilter,
        @["cn", "displayName", "gPCFileSysPath", "versionNumber",
          "flags", "whenChanged"])

    if queries.certificateInventory:
      let certFilter = filterOr([
        filterPresent("userCertificate"),
        filterPresent("altSecurityIdentities"),
        filterPresent("msDS-KeyCredentialLink")
      ])
      result.certificateInventory = await runQueryAt(baseDn, certFilter,
        @["objectClass", "sAMAccountName", "userPrincipalName", "dNSHostName",
          "displayName", "objectSid", "userCertificate", "altSecurityIdentities",
          "msDS-KeyCredentialLink", "whenChanged"])

    if queries.schema and result.schemaNamingContext.len > 0:
      let schemaFilter =
        if queries.customFilter.len > 0:
          try: parseLdapFilter(queries.customFilter)
          except CatchableError: filterPresent("objectClass")
        else:
          filterOr([
            filterEquality("objectClass", "attributeSchema"),
            filterEquality("objectClass", "classSchema")
          ])
      let schemaAttrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["lDAPDisplayName", "cn", "objectClass", "attributeID",
          "attributeSyntax", "oMSyntax", "isSingleValued", "systemOnly",
          "searchFlags", "schemaIDGUID", "mayContain", "mustContain",
          "subClassOf"]
      result.schema = await runQueryAt(result.schemaNamingContext,
        schemaFilter, schemaAttrs)

    if queries.config and result.configurationNamingContext.len > 0:
      let configFilter =
        if queries.customFilter.len > 0:
          try: parseLdapFilter(queries.customFilter)
          except CatchableError: filterPresent("objectClass")
        else:
          filterPresent("objectClass")
      let configAttrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["cn", "name", "objectClass", "distinguishedName",
          "whenChanged", "whenCreated"]
      result.config = await runQueryAt(result.configurationNamingContext,
        configFilter, configAttrs)

    if queries.fgpp:
      result.fgpp = await runQueryAt("CN=Password Settings Container,CN=System," & baseDn,
        filterEquality("objectClass", "msDS-PasswordSettings"),
        @["cn", "msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled",
          "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
          "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge",
          "msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
          "msDS-LockoutObservationWindow", "msDS-LockoutDuration", "msDS-PSOAppliesTo"])

    if queries.deleted:
      inc messageId
      let deletedBase = "CN=Deleted Objects," & baseDn
      let deletedReq = buildSearchRequestWithControls(deletedBase, 2,
        filterEquality("isDeleted", "TRUE"),
        @["cn", "lastKnownParent", "objectClass", "whenChanged", "isDeleted", "distinguishedName"],
        buildShowDeletedControl(), sizeLimit = perQueryLimit, messageId = messageId)
      await gssSend(deletedReq)
      for raw in await gssRecvAll():
        let m = parseLdapMessage(raw)
        if m.op != 0x64: continue
        result.deleted.add parseSearchEntry(m.body)

    if queries.locked:
      result.locked = await runQueryAt(baseDn,
        parseLdapFilter("(&(sAMAccountType=805306368)(lockoutTime>=1))"),
        @["sAMAccountName", "displayName", "lockoutTime", "badPwdCount", "badPasswordTime"],
        limit = perQueryLimit)

    if queries.expiredPasswords:
      result.expiredPasswords = await runQueryAt(baseDn,
        parseLdapFilter("(&(sAMAccountType=805306368)(pwdLastSet=0))"),
        @["sAMAccountName", "displayName", "pwdLastSet", "userAccountControl"],
        limit = perQueryLimit)

    if queries.staleUsers:
      result.staleUsers = await runQueryAt(baseDn,
        parseLdapFilter("(&(sAMAccountType=805306368)(lastLogonTimestamp<=133801632000000000))"),
        @["sAMAccountName", "displayName", "lastLogonTimestamp", "pwdLastSet", "userAccountControl"],
        limit = perQueryLimit)

    if queries.neverLoggedOn:
      result.neverLoggedOn = await runQueryAt(baseDn,
        parseLdapFilter("(&(sAMAccountType=805306368)(!(lastLogonTimestamp=*)))"),
        @["sAMAccountName", "displayName", "lastLogon", "lastLogonTimestamp", "pwdLastSet"],
        limit = perQueryLimit)

    if queries.unconstrained:
      let unconstrainedFilter = filterAnd([
        filterOr([
          filterEquality("sAMAccountType", "805306368"),
          filterEquality("sAMAccountType", "805306369")
        ]),
        filterExtensible("userAccountControl", "524288", "1.2.840.113556.1.4.803"),
        filterNot(filterExtensible("userAccountControl", "8192", "1.2.840.113556.1.4.803"))
      ])
      result.unconstrained = await runQueryAt(baseDn, unconstrainedFilter,
        @["sAMAccountName", "displayName", "dNSHostName", "userAccountControl", "objectClass"],
        limit = perQueryLimit)

    if queries.constrained:
      let constrainedFilter = filterAnd([
        filterOr([
          filterEquality("sAMAccountType", "805306368"),
          filterEquality("sAMAccountType", "805306369")
        ]),
        parseLdapFilter("(msDS-AllowedToDelegateTo=*)")
      ])
      result.constrained = await runQueryAt(baseDn, constrainedFilter,
        @["sAMAccountName", "displayName", "dNSHostName", "msDS-AllowedToDelegateTo",
          "userAccountControl", "objectClass"],
        limit = perQueryLimit)

    if queries.rbcdTargets:
      result.rbcdTargets = await runQueryAt(baseDn,
        parseLdapFilter("(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"),
        @["sAMAccountName", "displayName", "dNSHostName",
          "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"],
        limit = perQueryLimit)

    if queries.passwdNotReqd:
      result.passwdNotReqd = await runQueryAt(baseDn,
        filterAnd([
          filterEquality("sAMAccountType", "805306368"),
          filterExtensible("userAccountControl", "32", "1.2.840.113556.1.4.803")
        ]),
        @["sAMAccountName", "displayName", "userAccountControl", "pwdLastSet"],
        limit = perQueryLimit)

    if queries.dontExpire:
      result.dontExpire = await runQueryAt(baseDn,
        filterAnd([
          filterEquality("sAMAccountType", "805306368"),
          filterExtensible("userAccountControl", "65536", "1.2.840.113556.1.4.803")
        ]),
        @["sAMAccountName", "displayName", "userAccountControl", "pwdLastSet"],
        limit = perQueryLimit)

    if queries.adminCount:
      result.adminCount = await runQueryAt(baseDn,
        filterAnd([
          filterEquality("sAMAccountType", "805306368"),
          filterEquality("adminCount", "1")
        ]),
        @["sAMAccountName", "displayName", "memberOf", "adminCount"],
        limit = perQueryLimit)

    if queries.sites and result.configurationNamingContext.len > 0:
      result.sites = await runQueryAt("CN=Sites," & result.configurationNamingContext,
        filterEquality("objectClass", "site"),
        @["cn", "name", "description", "whenChanged"])

    if queries.subnets and result.configurationNamingContext.len > 0:
      result.subnets = await runQueryAt("CN=Subnets,CN=Sites," & result.configurationNamingContext,
        filterEquality("objectClass", "subnet"),
        @["cn", "name", "siteObject", "location", "description", "whenChanged"])

    if queries.dcs:
      let dcFilter = filterAnd([
        filterEquality("sAMAccountType", "805306369"),
        filterExtensible("userAccountControl", "8192",
          "1.2.840.113556.1.4.803")
      ])
      result.dcs = await runQueryAt(baseDn, dcFilter,
        @["dNSHostName", "sAMAccountName", "operatingSystem",
          "operatingSystemVersion", "servicePrincipalName"])

    if queries.admins:
      let groupsSnap = result.groups
      var groupCns: seq[string]
      for entry in groupsSnap:
        if "cn" in entry.attrs and entry.attrs["cn"].len > 0:
          let cn = entry.attrs["cn"][0]
          if cn in ["Domain Admins", "Enterprise Admins",
                    "Schema Admins", "Administrators"]:
            groupCns.add cn
      if groupCns.len == 0:
        groupCns = @["Domain Admins", "Enterprise Admins",
                     "Schema Admins", "Administrators"]
      var seenDns: seq[string]
      for groupCn in groupCns:
        let groupSearch = filterAnd([
          filterEquality("objectClass", "group"),
          filterEquality("cn", groupCn)
        ])
        let groupEntries = await runQueryAt(baseDn, groupSearch,
          @["member", "cn", "objectSid"])
        for g in groupEntries:
          let memberDns =
            if g.attrs.hasKey("member"): g.attrs["member"]
            else: @[]
          for memberDn in memberDns:
            if memberDn in seenDns: continue
            seenDns.add memberDn
            let memberSearch = filterEquality("distinguishedName", memberDn)
            let memberEntries = await runQueryAt(baseDn, memberSearch,
              @["sAMAccountName", "displayName", "userPrincipalName",
                "objectClass", "memberOf"])
            for me in memberEntries:
              var copy = me
              copy.attrs["adminOf"] = @[groupCn]
              result.admins.add copy

    if queries.dns:
      let dnsSearchBase = "CN=MicrosoftDNS,DC=DomainDnsZones," & baseDn
      let dnsFilter = filterEquality("objectClass", "dnsZone")
      try:
        result.dnsZones = await runQueryAt(dnsSearchBase, dnsFilter,
          @["name", "dc"])
      except CatchableError: discard

    if queries.customFilter.len > 0:
      let attrs =
        if queries.customAttrs.len > 0: queries.customAttrs
        else: @["*"]
      try:
        let compiled = parseLdapFilter(queries.customFilter)
        let customBase = if queries.customBase.len > 0: queries.customBase else: baseDn
        result.custom = await runQueryAt(customBase, compiled, attrs)
      except CatchableError as error:
        if result.message.len > 0: result.message.add "; "
        result.message.add "custom query: " & cleanError(error)
  except CatchableError as error:
    if result.message.len == 0:
      result.message = cleanError(error)
  finally:
    closeLdapSocket(socket)
