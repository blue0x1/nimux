import std/[asyncdispatch, asyncnet, nativesockets, net, posix, strutils, tables, times]
import ./output
import ./proxy as netproxy

when defined(ssl):
  import wrappers/openssl

type
  ScanProgress* = proc() {.closure.}

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc isIpLiteral(host: string): bool =
  if ':' in host: return true
  let parts = host.split('.')
  if parts.len != 4: return false
  for part in parts:
    if part.len == 0 or part.len > 3: return false
    for c in part:
      if c notin {'0'..'9'}: return false
  return true

var dnsCache {.threadvar.}: TableRef[string, string]

proc resolveHost*(host: string): string =
  if isIpLiteral(host): return host
  if dnsCache == nil: dnsCache = newTable[string, string]()
  if dnsCache.hasKey(host): return dnsCache[host]
  var resolved = host
  try:
    for family in [Domain.AF_INET, Domain.AF_INET6]:
      let infos = getAddrInfo(host, Port(0), family)
      if infos != nil:
        resolved = getAddrString(infos.ai_addr)
        freeAddrInfo(infos)
        break
  except CatchableError:
    discard
  dnsCache[host] = resolved
  result = resolved

proc hostFamily*(host: string): Domain =
  if ':' in host: Domain.AF_INET6 else: Domain.AF_INET

proc newTcpAsyncSocket*(host: string): AsyncSocket =
  newAsyncSocket(hostFamily(host), SockType.SOCK_STREAM, Protocol.IPPROTO_TCP)

proc newUdpAsyncSocket*(host: string): AsyncSocket =
  let fam = hostFamily(host)
  let domain = if fam == Domain.AF_INET6: nativesockets.AF_INET6 else: nativesockets.AF_INET
  newAsyncSocket(domain, nativesockets.SOCK_DGRAM, nativesockets.IPPROTO_UDP)

when defined(ssl):
  proc newTcpSyncSocket*(host: string): Socket =
    newSocket(hostFamily(netproxy.proxySocketHost(host)), SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP, buffered = false)

proc addU16Be(data: var string; value: uint16) =
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc addU16Le(data: var string; value: uint16) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc printable*(value: string; limit = 120): string =
  for ch in value:
    let c = ord(ch)
    if ch in {'\r', '\n', '\t'}:
      if result.len == 0 or result[^1] != ' ':
        result.add ' '
    elif c >= 32 and c <= 126:
      result.add ch
    if result.len >= limit:
      break
  result = result.strip()

proc headerValue(response, name: string): string =
  let wanted = name.toLowerAscii() & ":"
  for line in response.splitLines():
    let clean = line.strip()
    if clean.toLowerAscii().startsWith(wanted):
      return clean[wanted.len .. ^1].strip()

proc parseHttpVersion(response: string): tuple[service, version: string] =
  if not response.startsWith("HTTP/"):
    return ("", "")
  let server = headerValue(response, "Server")
  let auth = headerValue(response, "WWW-Authenticate")
  if auth.toLowerAscii().contains("negotiate") and server.toLowerAscii().contains("microsoft"):
    return ("winrm", server)
  if server.len > 0:
    return ("http", server)
  ("http", response.splitLines()[0].strip())

proc parseMssqlVersion(response: string): string =
  if response.len < 8 or ord(response[0]) != 18:
    return ""
  var pos = 8
  while pos + 4 < response.len and ord(response[pos]) != 255:
    let token = ord(response[pos])
    let offset = (ord(response[pos + 1]) shl 8) or ord(response[pos + 2])
    let length = (ord(response[pos + 3]) shl 8) or ord(response[pos + 4])
    let absolute = 8 + offset
    if token == 0 and length >= 6 and absolute + length <= response.len:
      return $ord(response[absolute]) & "." & $ord(response[absolute + 1]) & "." &
        $ord(response[absolute + 2]) & "." & $ord(response[absolute + 3])
    pos += 5

proc dnsRcodeName(code: int): string =
  case code
  of 0: "NOERROR"
  of 1: "FORMERR"
  of 2: "SERVFAIL"
  of 3: "NXDOMAIN"
  of 4: "NOTIMP"
  of 5: "REFUSED"
  else: "RCODE " & $code

proc buildDnsVersionBind(): string =
  var dns = ""
  dns.addU16Be 0x4e58'u16
  dns.addU16Be 0x0100'u16
  dns.addU16Be 1'u16
  dns.addU16Be 0'u16
  dns.addU16Be 0'u16
  dns.addU16Be 0'u16
  dns.add char(7)
  dns.add "version"
  dns.add char(4)
  dns.add "bind"
  dns.add char(0)
  dns.addU16Be 16'u16
  dns.addU16Be 3'u16
  result.addU16Be dns.len.uint16
  result.add dns

proc skipDnsName(data: string; offset: var int) =
  var jumps = 0
  while offset < data.len and jumps < 32:
    let length = ord(data[offset])
    if (length and 0xc0) == 0xc0:
      offset += 2
      return
    inc offset
    if length == 0:
      return
    offset += length
    inc jumps

proc parseDnsVersionResponse(response: string): string =
  if response.len < 14:
    return ""
  var base = 0
  if response.len >= 2:
    let framedLen = (ord(response[0]) shl 8) or ord(response[1])
    if framedLen == response.len - 2:
      base = 2
  if base + 12 > response.len:
    return ""
  let flags = (ord(response[base + 2]) shl 8) or ord(response[base + 3])
  let rcode = flags and 0x0f
  let qdCount = (ord(response[base + 4]) shl 8) or ord(response[base + 5])
  let anCount = (ord(response[base + 6]) shl 8) or ord(response[base + 7])
  var offset = base + 12
  for _ in 0 ..< qdCount:
    skipDnsName(response, offset)
    offset += 4
    if offset > response.len:
      return "DNS response " & dnsRcodeName(rcode)
  for _ in 0 ..< anCount:
    skipDnsName(response, offset)
    if offset + 10 > response.len:
      break
    let rrType = (ord(response[offset]) shl 8) or ord(response[offset + 1])
    offset += 8
    let rdLen = (ord(response[offset]) shl 8) or ord(response[offset + 1])
    offset += 2
    if offset + rdLen > response.len:
      break
    if rrType == 16 and rdLen > 0:
      let txtLen = min(ord(response[offset]), rdLen - 1)
      if txtLen > 0 and offset + 1 + txtLen <= response.len:
        return "version.bind " & printable(response[offset + 1 ..< offset + 1 + txtLen])
    offset += rdLen
  "DNS response " & dnsRcodeName(rcode)

proc buildRdpProbe(): string
proc parseRdpSelectedProtocol(response: string): int

when defined(ssl):
  proc sslNameLine(name: PX509_NAME): string =
    if name == nil:
      return ""
    when defined(windows):
      ""
    else:
      var buffer = newString(1024)
      let line = X509_NAME_oneline(name, cstring(buffer), buffer.len.cint)
      if line == nil:
        return ""
      ($line).strip()

  proc sslCommonName(line: string): string =
    let marker = "/CN="
    let start = line.find(marker)
    if start < 0:
      return ""
    let valueStart = start + marker.len
    var valueEnd = line.find("/", valueStart)
    if valueEnd < 0:
      valueEnd = line.len
    line[valueStart ..< valueEnd]

  proc applyRecvTimeout(socket: Socket; timeoutMs: int) =
    var tv = Timeval(tv_sec: posix.Time(max(1, timeoutMs div 1000)),
                     tv_usec: Suseconds((timeoutMs mod 1000) * 1000))
    discard setsockopt(socket.getFd, SOL_SOCKET, SO_RCVTIMEO,
                       addr tv, sizeof(tv).SockLen)

  proc probeTlsCertificate(host: string; port, timeoutMs: int): tuple[version, banner: string] =
    var socket = newTcpSyncSocket(host)
    let ctx = newContext(verifyMode = CVerifyNone)
    try:
      ctx.wrapSocket(socket)
      netproxy.connectTcpSync(socket, resolveHost(host), port, timeoutMs)
      socket.applyRecvTimeout(timeoutMs)
      let cert = SSL_get_peer_certificate(socket.sslHandle)
      if cert == nil:
        result.version = "TLS handshake"
        return
      try:
        let subject = sslNameLine(X509_get_subject_name(cert))
        let issuer = sslNameLine(X509_get_issuer_name(cert))
        let cn = sslCommonName(subject)
        var parts: seq[string]
        if cn.len > 0:
          parts.add "CN=" & cn
        elif subject.len > 0:
          parts.add "subject=" & subject
        if issuer.len > 0:
          let issuerCn = sslCommonName(issuer)
          if issuerCn.len > 0:
            parts.add "issuer=" & issuerCn
          else:
            parts.add "issuer=" & issuer
        result.version =
          if parts.len > 0: "TLS cert " & parts.join(" ")
          else: "TLS certificate"
        result.banner = subject
      finally:
        X509_free(cert)
    finally:
      try:
        socket.close()
      except CatchableError:
        discard

  proc certSummary(socket: Socket): tuple[version, banner: string] =
    let cert = SSL_get_peer_certificate(socket.sslHandle)
    if cert == nil:
      result.version = "TLS handshake"
      return
    try:
      let subject = sslNameLine(X509_get_subject_name(cert))
      let issuer = sslNameLine(X509_get_issuer_name(cert))
      let cn = sslCommonName(subject)
      var parts: seq[string]
      if cn.len > 0:
        parts.add "CN=" & cn
      elif subject.len > 0:
        parts.add "subject=" & subject
      if issuer.len > 0:
        let issuerCn = sslCommonName(issuer)
        if issuerCn.len > 0:
          parts.add "issuer=" & issuerCn
        else:
          parts.add "issuer=" & issuer
      result.version =
        if parts.len > 0: "TLS cert " & parts.join(" ")
        else: "TLS certificate"
      result.banner = subject
    finally:
      X509_free(cert)

  proc derLen(n: int): string =
    if n < 128: result.add char(n)
    elif n < 256:
      result.add char(0x81)
      result.add char(n)
    else:
      result.add char(0x82)
      result.add char((n shr 8) and 0xff)
      result.add char(n and 0xff)

  proc derTlv(tag: int; body: string): string =
    result.add char(tag)
    result.add derLen(body.len)
    result.add body

  proc buildNtlmNegotiateRdp(): string =
    result.add "NTLMSSP\0"
    result.add "\x01\x00\x00\x00"
    result.add "\x07\x82\x08\xa2"
    for _ in 0 ..< 16: result.add char(0)
    result.add "\x0a\x00\x39\x38\x00\x00\x00\x0f"

  proc buildCredSspNtlmNegotiate(): string =
    let negoToken = derTlv(0xa0, derTlv(0x04, buildNtlmNegotiateRdp()))
    let negoDataItem = derTlv(0x30, negoToken)
    let negoData = derTlv(0x30, negoDataItem)
    let version = derTlv(0xa0, derTlv(0x02, "\x06"))
    let negoTokens = derTlv(0xa1, negoData)
    result = derTlv(0x30, version & negoTokens)

  proc utf16LeToAscii(data: string; offset, length: int): string =
    var index = offset
    let endIndex = offset + length
    while index + 1 < endIndex and index + 1 < data.len:
      let c = ord(data[index])
      if c >= 32 and c <= 126: result.add char(c)
      elif c == 0 and ord(data[index + 1]) == 0: discard
      else: result.add '?'
      index += 2

  type RdpNtlmInfo = object
    targetName: string
    netbiosComputer: string
    netbiosDomain: string
    dnsComputer: string
    dnsDomain: string
    dnsForest: string
    productVersion: string
    systemTime: string

  proc parseRdpNtlmInfo(blob: string): RdpNtlmInfo =
    let start = blob.find("NTLMSSP\0")
    if start < 0 or start + 56 > blob.len: return
    proc u16(at: int): int = (ord(blob[at + 1]) shl 8) or ord(blob[at])
    proc u32(at: int): int =
      (ord(blob[at + 3]) shl 24) or (ord(blob[at + 2]) shl 16) or
        (ord(blob[at + 1]) shl 8) or ord(blob[at])
    if u32(start + 8) != 2: return
    let targetLen = u16(start + 12)
    let targetOffset = u32(start + 16)
    if targetLen > 0 and start + targetOffset + targetLen <= blob.len:
      result.targetName = utf16LeToAscii(blob, start + targetOffset, targetLen)
    let infoLen = u16(start + 40)
    let infoOffset = u32(start + 44)
    if start + 56 <= blob.len:
      let major = ord(blob[start + 48])
      let minor = ord(blob[start + 49])
      let build = (ord(blob[start + 51]) shl 8) or ord(blob[start + 50])
      if major != 0 or minor != 0 or build != 0:
        result.productVersion = $major & "." & $minor & "." & $build
    if infoLen > 0 and start + infoOffset + infoLen <= blob.len:
      var cursor = start + infoOffset
      let endAt = cursor + infoLen
      while cursor + 4 <= endAt:
        let avId = u16(cursor)
        let avLen = u16(cursor + 2)
        cursor += 4
        if avId == 0 or cursor + avLen > endAt: break
        case avId
        of 1: result.netbiosComputer = utf16LeToAscii(blob, cursor, avLen)
        of 2: result.netbiosDomain = utf16LeToAscii(blob, cursor, avLen)
        of 3: result.dnsComputer = utf16LeToAscii(blob, cursor, avLen)
        of 4: result.dnsDomain = utf16LeToAscii(blob, cursor, avLen)
        of 5: result.dnsForest = utf16LeToAscii(blob, cursor, avLen)
        of 7:
          if avLen == 8:
            var ft: uint64 = 0
            for i in 0 ..< 8:
              ft = ft or (uint64(ord(blob[cursor + i])) shl (8 * i))
            let unixSecs = int64((ft div 10_000_000) - 11_644_473_600'u64)
            try:
              let dt = utc(fromUnix(unixSecs))
              result.systemTime = dt.format("yyyy-MM-dd HH:mm:ss") & "Z"
            except CatchableError: discard
        else: discard
        cursor += avLen

  proc fetchRdpNtlmInfo(socket: Socket; timeoutMs: int): RdpNtlmInfo =
    try:
      socket.applyRecvTimeout(max(timeoutMs, 1500))
      socket.send(buildCredSspNtlmNegotiate())
      var chunk = newString(4096)
      let got = socket.recv(chunk, 4096)
      if got <= 0: return
      result = parseRdpNtlmInfo(chunk[0 ..< got])
    except CatchableError:
      discard

  proc probeRdpTlsCertificate(host: string; port, timeoutMs: int): tuple[version, banner, rawBytes: string] =
    var socket = newTcpSyncSocket(host)
    let ctx = newContext(verifyMode = CVerifyNone)
    try:
      netproxy.connectTcpSync(socket, resolveHost(host), port, timeoutMs)
      socket.applyRecvTimeout(timeoutMs)
      socket.send(buildRdpProbe())
      var chunk = newString(512)
      let got = socket.recv(chunk, 512)
      if got <= 0:
        return
      let response = chunk[0 ..< got]
      let selected = parseRdpSelectedProtocol(response)
      if response.len < 7 or ord(response[0]) != 3:
        return
      let proto =
        case selected
        of 1: "TLS"
        of 2: "CredSSP"
        of 3: "TLS/CredSSP"
        of 8: "HybridEx"
        else: "RDP negotiation"
      result.version = "RDP " & proto
      result.banner = printable(response)
      result.rawBytes = response
      try:
        ctx.wrapConnectedSocket(socket, handshakeAsClient)
        let cert = certSummary(socket)
        var certCn = ""
        if cert.version.len > 0:
          result.version = proto & " " & cert.version
          result.banner = cert.banner
          certCn = sslCommonName(cert.banner)
        let ntlm = fetchRdpNtlmInfo(socket, timeoutMs)
        var parts: seq[string]
        if ntlm.dnsComputer.len > 0: parts.add "Host: " & ntlm.dnsComputer
        elif ntlm.netbiosComputer.len > 0: parts.add "Host: " & ntlm.netbiosComputer
        if ntlm.dnsDomain.len > 0: parts.add "Domain: " & ntlm.dnsDomain
        elif ntlm.netbiosDomain.len > 0: parts.add "Domain: " & ntlm.netbiosDomain
        if ntlm.dnsForest.len > 0 and ntlm.dnsForest != ntlm.dnsDomain:
          parts.add "Forest: " & ntlm.dnsForest
        if ntlm.productVersion.len > 0:
          parts.add "Windows " & ntlm.productVersion
        if certCn.len > 0:
          parts.add "TLS CN=" & certCn
        if ntlm.systemTime.len > 0:
          parts.add "time: " & ntlm.systemTime
        if parts.len > 0:
          result.version = "Microsoft Terminal Services (" & parts.join(", ") & ")"
      except CatchableError:
        discard
    finally:
      try:
        socket.close()
      except CatchableError:
        discard

  proc probeRdpTlsTcp*(host: string; port, timeoutMs: int): tuple[service, version, banner, rawBytes: string] =
    let tls = probeRdpTlsCertificate(host, port, timeoutMs)
    if tls.version.len > 0:
      result.service = "ms-wbt-server"
      result.version = tls.version
      result.banner = tls.banner
      result.rawBytes = tls.rawBytes
else:
  proc probeRdpTlsTcp*(host: string; port, timeoutMs: int): tuple[service, version, banner, rawBytes: string] =
    discard

proc buildMssqlPrelogin(): string =
  var payload = ""
  let versionOffset = 11
  let encryptionOffset = versionOffset + 6
  payload.add char(0)
  payload.addU16Be versionOffset.uint16
  payload.addU16Be 6
  payload.add char(1)
  payload.addU16Be encryptionOffset.uint16
  payload.addU16Be 1
  payload.add char(255)
  payload.add "\x00\x00\x00\x00\x00\x00"
  payload.add char(0)
  result.add char(18)
  result.add char(1)
  result.addU16Be (8 + payload.len).uint16
  result.add "\x00\x00\x00\x00"
  result.add payload

proc buildRdpProbe(): string =
  let cookie = "Cookie: mstshash=nimux\r\n"
  let totalLen = 4 + 7 + cookie.len + 8
  result.add char(3)
  result.add char(0)
  result.addU16Be totalLen.uint16
  result.add char(totalLen - 5)
  result.add char(0xe0)
  result.add "\x00\x00\x00\x00\x00"
  result.add cookie
  result.add char(1)
  result.add char(0)
  result.add char(8)
  result.add char(0)
  result.addU32Le 3'u32

proc parseRdpSelectedProtocol(response: string): int =
  for index in 0 .. max(0, response.len - 8):
    if ord(response[index]) == 2 and ord(response[index + 2]) == 8:
      return int(uint32(ord(response[index + 4])) or
        (uint32(ord(response[index + 5])) shl 8) or
        (uint32(ord(response[index + 6])) shl 16) or
        (uint32(ord(response[index + 7])) shl 24))
  -1

proc buildDceRpcEpmBind(): string =
  var body = ""
  body.addU16Le 4280'u16
  body.addU16Le 4280'u16
  body.addU32Le 0'u32
  body.add char(1)
  body.add "\x00\x00\x00"
  body.addU16Le 0'u16
  body.add char(1)
  body.add char(0)
  body.add "\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa"
  body.addU16Le 3'u16
  body.addU16Le 0'u16
  body.add "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
  body.addU16Le 2'u16
  body.addU16Le 0'u16

  result.add "\x05\x00"
  result.add char(0x0b)
  result.add char(0x03)
  result.add "\x10\x00\x00\x00"
  result.addU16Le uint16(16 + body.len)
  result.addU16Le 0'u16
  result.addU32Le 1'u32
  result.add body

proc parseDceRpcBindAck(response: string): string =
  if response.len < 16 or ord(response[0]) != 5:
    return ""
  case ord(response[2])
  of 12, 13:
    "Microsoft Windows RPC"
  else:
    ""

proc parseKerberosError(response: string): string
proc recvSome(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.}

proc buildKerberosAsReq(realmInput = ""): string =
  "\x00\x00\x00\x71\x6a\x81\x6e\x30\x81\x6b\xa1\x03\x02\x01\x05" &
    "\xa2\x03\x02\x01\x0a\xa4\x81\x5e\x30\x5c\xa0\x07\x03\x05" &
    "\x00\x50\x80\x00\x10\xa2\x04\x1b\x02NM\xa3\x17\x30\x15" &
    "\xa0\x03\x02\x01\x00\xa1\x0e\x30\x0c\x1b\x06krbtgt\x1b" &
    "\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04" &
    "\x1f\x1e\xb9\xd9\xa8\x17\x30\x15\x02\x01\x12\x02\x01" &
    "\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03" &
    "\x02\x01\x02"

proc probeKerberosTcp*(host: string; port, timeoutMs: int; realm = ""): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  var socket: AsyncSocket
  try:
    socket = newTcpAsyncSocket(host)
    let connected = await netproxy.connectTcpResolved(socket, host, port, timeoutMs)
    if not connected:
      return
    await socket.send(buildKerberosAsReq(realm))
    let response = await recvSome(socket, max(500, min(timeoutMs, 2000)))
    let krb = parseKerberosError(response)
    if krb.len > 0:
      result.service = if port == 464: "kpasswd" else: "kerberos-sec"
      result.version = krb
      result.banner = printable(response); result.rawBytes = response
    elif response.len > 0:
      result.service = if port == 464: "kpasswd" else: "kerberos-sec"
      result.version = "Microsoft Windows Kerberos"
      result.banner = printable(response); result.rawBytes = response
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeDceRpcTcp*(host: string; port, timeoutMs: int): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  var socket: AsyncSocket
  try:
    socket = newTcpAsyncSocket(host)
    let connected = await netproxy.connectTcpResolved(socket, host, port, timeoutMs)
    if not connected:
      return
    await socket.send(buildDceRpcEpmBind())
    let response = await recvSome(socket, max(500, min(timeoutMs, 2000)))
    let rpc = parseDceRpcBindAck(response)
    if rpc.len > 0:
      result.service = "msrpc"
      result.version = rpc
      result.banner = printable(response); result.rawBytes = response
    elif response.len > 0:
      result.service = "msrpc"
      result.version = "Microsoft Windows RPC"
      result.banner = printable(response); result.rawBytes = response
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeRpcOverHttpTcp*(host: string; port, timeoutMs: int): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  var socket: AsyncSocket
  proc reconnect(): Future[AsyncSocket] {.async.} =
    let s = newTcpAsyncSocket(host)
    let ok = await netproxy.connectTcp(s, host, port, timeoutMs)
    if not ok:
      s.close()
      return nil
    return s
  proc httpProbe(verb: string): string =
    verb & " /rpc/rpcproxy.dll?" & host & ":593 HTTP/1.1\r\n" &
      "Host: " & host & "\r\n" &
      "User-Agent: MSRPC\r\n" &
      "Cache-Control: no-cache\r\n" &
      "Connection: keep-alive\r\n" &
      "Content-Length: 1073741824\r\n\r\n"
  proc classify(response: string; result: var tuple[service, version, banner, rawBytes: string]) =
    if response.len == 0: return
    result.service = "ncacn_http"
    result.banner = printable(response)
    result.rawBytes = response
    let serverHdr = headerValue(response, "Server")
    let authHdr = headerValue(response, "WWW-Authenticate")
    if response.startsWith("ncacn_http/"):
      result.version = "Microsoft Windows RPC over HTTP " &
        printable(response.splitLines()[0]).replace("ncacn_http/", "")
    elif serverHdr.toLowerAscii().contains("microsoft-httpapi") or
         authHdr.toLowerAscii().contains("negotiate"):
      var bits = @["Microsoft Windows RPC over HTTP 1.0"]
      if serverHdr.len > 0: bits.add serverHdr
      result.version = bits.join(" / ")
    elif response.startsWith("HTTP/"):
      result.version = "Microsoft Windows RPC over HTTP (" &
        response.splitLines()[0].strip() & ")"
    else:
      result.version = "ncacn_http response"
  try:
    socket = await reconnect()
    if socket == nil: return
    var response = await recvSome(socket, max(400, min(timeoutMs, 1500)))
    classify(response, result)
    if result.version.len == 0:
      socket.close()
      socket = await reconnect()
      if socket != nil:
        await socket.send(httpProbe("RPC_IN_DATA"))
        response = await recvSome(socket, max(500, min(timeoutMs, 2000)))
        classify(response, result)
    if result.version.len == 0:
      socket.close()
      socket = await reconnect()
      if socket != nil:
        await socket.send(httpProbe("RPC_OUT_DATA"))
        response = await recvSome(socket, max(500, min(timeoutMs, 2000)))
        classify(response, result)
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeNetbiosSessionTcp*(host: string; port, timeoutMs: int): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  var socket: AsyncSocket
  try:
    socket = newTcpAsyncSocket(host)
    let connected = await netproxy.connectTcpResolved(socket, host, port, timeoutMs)
    if not connected:
      return
    let response = await recvSome(socket, max(500, min(timeoutMs, 2000)))
    if response.len > 0:
      result.service = "netbios-ssn"
      result.version = "Microsoft Windows netbios-ssn"
      result.banner = printable(response); result.rawBytes = response
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc rpcPtypeName(ptype: int): string =
  case ptype
  of 2: "response"
  of 3: "fault"
  of 12: "bind ack"
  of 13: "bind nack"
  else: "ptype " & $ptype

proc kerberosTimeFallback(response: string): string =
  var times: seq[string]
  var index = 0
  while index + 16 < response.len:
    if ord(response[index]) == 0x18 and ord(response[index + 1]) == 0x0f:
      let value = response[index + 2 ..< index + 17]
      var valid = value[^1] == 'Z'
      for ch in value[0 ..< value.len - 1]:
        if ch < '0' or ch > '9':
          valid = false
          break
      if valid:
        times.add value
    inc index
  if times.len > 0:
    "KRB-ERROR server-time=" & times[^1]
  else:
    ""

proc parseProbeEvidence(port: int; response: string): tuple[service, version, banner, rawBytes: string] =
  if response.len == 0:
    return
  result.banner = printable(response); result.rawBytes = response
  case port
  of 88, 464:
    result.service = if port == 464: "kpasswd" else: "kerberos-sec"
    let krb = parseKerberosError(response)
    if krb.len > 0:
      result.version = krb
    else:
      let stime = kerberosTimeFallback(response)
      result.version = if stime.len > 0: stime else: "Microsoft Windows Kerberos"
  of 135:
    result.service = "msrpc"
    if response.len >= 3 and ord(response[0]) == 5:
      result.version = "Microsoft Windows RPC"
    elif response.len >= 2 and ord(response[0]) == 4 and ord(response[1]) == 6:
      result.version = "Microsoft Windows RPC"
    else:
      result.version = "Microsoft Windows RPC"
  of 139:
    result.service = "netbios-ssn"
    result.version = "Microsoft Windows netbios-ssn"
  of 593:
    result.service = "ncacn_http"
    let parsed = parseHttpVersion(response)
    if response.startsWith("ncacn_http/"):
      result.version = printable(response)
    elif parsed.version.len > 0:
      result.version = parsed.version
    elif response.startsWith("HTTP/"):
      result.version = response.splitLines()[0].strip()
    else:
      result.version = printable(response)
  of 3389:
    result.service = "ms-wbt-server"
    let selected = parseRdpSelectedProtocol(response)
    result.version =
      case selected
      of 1: "RDP TLS"
      of 2: "RDP CredSSP"
      of 3: "RDP TLS/CredSSP"
      of 8: "RDP HybridEx"
      else:
        if response.len >= 7 and ord(response[0]) == 3: "RDP negotiation"
        else: "RDP response " & $response.len & " bytes"
  else:
    discard

proc buildSmbProgNeg(): string =
  "\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0"

proc buildTerminalServerCookie(): string =
  "\x03\0\0\x2a\x25\xe0\0\0\0\0\0Cookie: mstshash=nmap\r\n\x01\0\x08\0\x03\0\0\0"

proc buildTerminalServerProbe(): string =
  "\x03\0\0\x0b\x06\xe0\0\0\0\0\0"

proc nmapStylePayload(port: int): string =
  case port
  of 88, 464:
    buildKerberosAsReq()
  of 135, 139:
    buildSmbProgNeg()
  of 3389:
    buildTerminalServerCookie()
  else:
    ""

proc recvUdpKerberos*(host: string; port, timeoutMs: int): Future[string] {.async.} =
  var socket: AsyncSocket
  try:
    socket = newUdpAsyncSocket(host)
    let payload = buildKerberosAsReq()[4 .. ^1]
    await socket.sendTo(resolveHost(host), Port(port), payload)
    let recvFuture = socket.recvFrom(4096)
    if await withTimeout(recvFuture, timeoutMs):
      let packet = await recvFuture
      return packet.data
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeTcpPayload(host: string; port, timeoutMs: int; payload: string; passiveMs = 0): Future[string] {.async.} =
  var socket: AsyncSocket
  try:
    socket = newTcpAsyncSocket(host)
    let connected = await netproxy.connectTcpResolved(socket, host, port, timeoutMs)
    if not connected:
      return
    if passiveMs > 0:
      result = await recvSome(socket, passiveMs)
      if result.len > 0:
        return
    if payload.len > 0:
      await socket.send(payload)
      result = await recvSome(socket, max(700, min(timeoutMs, 3000)))
  except CatchableError:
    discard
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeNmapStyleTcp*(host: string; port, timeoutMs: int): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  var responses: seq[string]
  case port
  of 88, 464:
    responses.add await probeTcpPayload(host, port, timeoutMs, buildKerberosAsReq())
    responses.add await recvUdpKerberos(host, port, timeoutMs)
  of 593:
    responses.add await probeTcpPayload(host, port, timeoutMs, "", max(1500, min(timeoutMs, 5000)))
    responses.add await probeTcpPayload(host, port, timeoutMs,
      "RPC_CONNECT /rpc/rpcproxy.dll HTTP/1.1\r\nHost: " & host & "\r\nUser-Agent: nimux-rpc-probe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  of 3389:
    responses.add await probeTcpPayload(host, port, timeoutMs, buildTerminalServerCookie())
    responses.add await probeTcpPayload(host, port, timeoutMs, buildTerminalServerProbe())
    responses.add await probeTcpPayload(host, port, timeoutMs, buildRdpProbe())
  else:
    responses.add await probeTcpPayload(host, port, timeoutMs, nmapStylePayload(port))

  for response in responses:
    let parsed = parseProbeEvidence(port, response)
    if parsed.version.len > 0:
      return parsed

proc readDerLen(data: string; offset: var int): int =
  if offset >= data.len:
    return -1
  let first = ord(data[offset])
  inc offset
  if (first and 0x80) == 0:
    return first
  let count = first and 0x7f
  if count == 0 or count > 4 or offset + count > data.len:
    return -1
  for _ in 0 ..< count:
    result = (result shl 8) or ord(data[offset])
    inc offset

proc readDerTlv(data: string; offset: var int): tuple[tag: int, body: string] =
  if offset >= data.len:
    return (-1, "")
  result.tag = ord(data[offset])
  inc offset
  let length = readDerLen(data, offset)
  if length < 0 or offset + length > data.len:
    return (-1, "")
  result.body = data[offset ..< offset + length]
  offset += length

proc parseDerInt(body: string): int =
  for ch in body:
    result = (result shl 8) or ord(ch)

proc findContext(data: string; wanted: int): string =
  var offset = 0
  while offset < data.len:
    let tlv = readDerTlv(data, offset)
    if tlv.tag < 0:
      break
    if tlv.tag == 0xa0 + wanted:
      return tlv.body
    if (tlv.tag and 0x20) != 0:
      let nested = findContext(tlv.body, wanted)
      if nested.len > 0:
        return nested

proc contextInt(data: string; wanted: int): int =
  let body = findContext(data, wanted)
  var offset = 0
  let tlv = readDerTlv(body, offset)
  if tlv.tag == 0x02:
    return parseDerInt(tlv.body)
  -1

proc contextString(data: string; wanted: int): string =
  let body = findContext(data, wanted)
  var offset = 0
  let tlv = readDerTlv(body, offset)
  if tlv.tag in [0x18, 0x1b, 0x1c, 0x04]:
    return printable(tlv.body, 80)

proc parseKerberosError(response: string): string =
  if response.len < 8:
    return ""
  var payload = response
  let framedLen = (ord(response[0]) shl 24) or (ord(response[1]) shl 16) or
    (ord(response[2]) shl 8) or ord(response[3])
  if framedLen == response.len - 4:
    payload = response[4 .. ^1]
  var offset = 0
  let outer = readDerTlv(payload, offset)
  if outer.tag != 0x7e:
    return ""
  let code = contextInt(outer.body, 6)
  let stime = contextString(outer.body, 4)
  let realm = contextString(outer.body, 9)
  discard contextString(outer.body, 11)
  var formattedTime = stime
  if stime.len == 15 and stime[^1] == 'Z':
    formattedTime = stime[0 ..< 4] & "-" & stime[4 ..< 6] & "-" & stime[6 ..< 8] &
      " " & stime[8 ..< 10] & ":" & stime[10 ..< 12] & ":" & stime[12 ..< 14] & "Z"
  result = "Microsoft Windows Kerberos"
  var detail: seq[string]
  if formattedTime.len > 0: detail.add "server time: " & formattedTime
  if realm.len > 0 and realm != "NM": detail.add "realm: " & realm
  if code >= 0 and code != 68: detail.add "krb-error " & $code
  if detail.len > 0:
    result.add " (" & detail.join(", ") & ")"

proc recvSome(socket: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  let recvFuture = socket.recv(2048)
  if await withTimeout(recvFuture, timeoutMs):
    return await recvFuture

proc buildLdapRootDseSearch(): string =
  let filterAttr = "objectClass"
  let attrs = ["defaultNamingContext", "dnsHostName", "supportedLDAPVersion"]
  var attrSeq = ""
  for attr in attrs:
    attrSeq.add char(0x04)
    attrSeq.add char(attr.len)
    attrSeq.add attr

  var search = ""
  search.add "\x04\x00"
  search.add "\x0a\x01\x00"
  search.add "\x0a\x01\x00"
  search.add "\x02\x01\x00"
  search.add "\x02\x01\x00"
  search.add "\x01\x01\x00"
  search.add char(0x87)
  search.add char(filterAttr.len)
  search.add filterAttr
  search.add char(0x30)
  search.add char(attrSeq.len)
  search.add attrSeq

  var protocol = "\x02\x01\x02"
  protocol.add char(0x63)
  protocol.add char(search.len)
  protocol.add search

  result.add char(0x30)
  result.add char(protocol.len)
  result.add protocol

proc buildLdapAnonymousBind(): string =
  "\x30\x0c" &
    "\x02\x01\x01" &
    "\x60\x07" &
    "\x02\x01\x03" &
    "\x04\x00" &
    "\x80\x00"

proc detectOpenService(socket: AsyncSocket; host: string; port, timeoutMs: int): Future[tuple[service, version, banner, rawBytes: string]] {.async.} =
  result.service = scanServiceName(port)
  let shortTimeout = max(150, min(timeoutMs, 500))

  if port in [21, 22, 25, 110, 143, 465, 587, 993, 995]:
    let passive = await recvSome(socket, shortTimeout)
    if passive.len > 0:
      result.rawBytes = passive
      result.banner = printable(passive)
      let lower = passive.toLowerAscii()
      if passive.startsWith("SSH-"):
        result.service = "ssh"
        result.version = printable(passive)
        return
      if lower.contains("ftp"):
        result.service = "ftp"
        result.version = result.banner
        return
      if lower.contains("smtp") or passive.startsWith("220"):
        result.service = if port in [25, 465, 587]: "smtp" else: result.service
        result.version = result.banner
        return
      if lower.contains("imap"):
        result.service = "imap"
        result.version = result.banner
        return
      if lower.contains("pop3"):
        result.service = "pop3"
        result.version = result.banner
        return

  try:
    when defined(ssl):
      if port in [443, 465, 636, 993, 995, 3269, 5986, 8443] or result.service in ["https", "ldaps", "ldaps-gc", "winrm-ssl", "imaps", "pop3s"]:
        let tls = probeTlsCertificate(host, port, max(500, timeoutMs))
        if tls.version.len > 0:
          if port == 5986:
            result.service = "winrm-ssl"
          elif port == 636:
            result.service = "ldaps"
          elif port == 3269:
            result.service = "ldaps-gc"
          elif result.service == "unknown":
            result.service = "ssl"
          result.version = tls.version
          result.banner = tls.banner
          return
    when defined(ssl):
      if port == 3389 or result.service == "rdp":
        let rdpTls = probeRdpTlsCertificate(host, port, max(500, timeoutMs))
        if rdpTls.version.len > 0:
          result.service = "ms-wbt-server"
          result.version = rdpTls.version
          result.banner = rdpTls.banner
          return
    if port in [88, 464] or result.service in ["kerberos", "kpasswd"]:
      await socket.send(buildKerberosAsReq())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      let krb = parseKerberosError(response)
      if krb.len > 0:
        result.service = if port == 464: "kpasswd" else: "kerberos-sec"
        result.version = krb
        result.banner = printable(response); result.rawBytes = response
        return
      if response.len > 0:
        result.service = if port == 464: "kpasswd" else: "kerberos-sec"
        result.version = "Microsoft Windows Kerberos"
        result.banner = printable(response); result.rawBytes = response
        return
    elif port == 135 or result.service == "msrpc":
      await socket.send(buildDceRpcEpmBind())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      let rpc = parseDceRpcBindAck(response)
      if rpc.len > 0:
        result.service = "msrpc"
        result.version = rpc
        result.banner = printable(response); result.rawBytes = response
        return
      if response.len > 0:
        result.service = "msrpc"
        result.version = "Microsoft Windows RPC"
        result.banner = printable(response); result.rawBytes = response
        return
    elif port == 593 or result.service == "ncacn_http":
      var response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      if response.len == 0:
        await socket.send("RPC_CONNECT /rpc/rpcproxy.dll HTTP/1.1\r\nHost: " & host & "\r\nUser-Agent: nimux-rpc-probe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      if response.len > 0:
        let parsed = parseHttpVersion(response)
        result.service = "ncacn_http"
        result.version =
          if response.startsWith("ncacn_http/"): printable(response)
          elif parsed.version.len > 0: parsed.version
          else: printable(response)
        result.banner = printable(response); result.rawBytes = response
        return
    elif port == 53 or result.service == "dns":
      await socket.send(buildDnsVersionBind())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      let dnsVersion = parseDnsVersionResponse(response)
      if dnsVersion.len > 0:
        result.service = "dns"
        result.version = dnsVersion
        result.banner = printable(response); result.rawBytes = response
        return
    elif port in [80, 81, 443, 5985, 5986, 8000, 8008, 8080, 8081, 8443, 8888] or result.service in ["unknown", "http", "http-proxy", "winrm", "winrm-ssl"]:
      await socket.send("HEAD / HTTP/1.0\r\nHost: " & host & "\r\nUser-Agent: nimux-service-probe\r\n\r\n")
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      if response.len > 0:
        result.banner = printable(response); result.rawBytes = response
        let parsed = parseHttpVersion(response)
        if parsed.service.len > 0:
          result.service = parsed.service
          result.version = parsed.version
          return
    elif port == 1433 or result.service == "mssql":
      await socket.send(buildMssqlPrelogin())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      let version = parseMssqlVersion(response)
      if version.len > 0:
        result.service = "mssql"
        result.version = version
        result.banner = "TDS prelogin response"
        return
    elif port in [389, 3268] or result.service in ["ldap", "ldap-gc"]:
      await socket.send(buildLdapAnonymousBind())
      discard await recvSome(socket, max(300, min(timeoutMs, 1000)))
      await socket.send(buildLdapRootDseSearch())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      if response.len > 0 and ord(response[0]) == 0x30:
        result.service = if port == 3268: "ldap-gc" else: "ldap"
        result.version =
          if response.contains("dnsHostName") or response.contains("defaultNamingContext"):
            "LDAP RootDSE"
          else:
            "LDAP response"
        result.banner = printable(response); result.rawBytes = response
        return
    elif port == 3389 or result.service == "rdp":
      await socket.send(buildRdpProbe())
      let response = await recvSome(socket, max(300, min(timeoutMs, 1000)))
      if response.len >= 7 and ord(response[0]) == 3:
        result.service = "ms-wbt-server"
        let selected = parseRdpSelectedProtocol(response)
        result.version =
          case selected
          of 1: "RDP negotiation TLS"
          of 2: "RDP negotiation CredSSP"
          of 3: "RDP negotiation TLS/CredSSP"
          of 8: "RDP negotiation HybridEx"
          else: "RDP negotiation response"
        result.banner = printable(response); result.rawBytes = response
        return
  except CatchableError:
    discard

proc probeOnce(host: string; port, timeoutMs: int): Future[ProbeResult] {.async.} =
  let started = now()
  var socket: AsyncSocket
  try:
    socket = newTcpAsyncSocket(host)
    let connected = await netproxy.connectTcpResolved(socket, host, port, timeoutMs)
    if connected:
      result = ProbeResult(
        host: host,
        port: port,
        status: psOpen,
        elapsedMs: elapsedMillis(started),
        message: "tcp connect succeeded",
        service: scanServiceName(port),
      transport: "tcp"
      )
      let detected = await detectOpenService(socket, host, port, timeoutMs)
      result.service = detected.service
      result.version = detected.version
      result.banner = detected.banner
      result.rawBytes = detected.rawBytes
    else:
      result = ProbeResult(
        host: host,
        port: port,
        status: psClosed,
        elapsedMs: elapsedMillis(started),
        message: "timeout",
        service: scanServiceName(port),
      transport: "tcp"
      )
  except CatchableError as error:
    let msg = cleanError(error)
    let state =
      if msg == "Operation not permitted" or msg == "Too many open files":
        psError
      else:
        psClosed
    result = ProbeResult(
      host: host,
      port: port,
      status: state,
      elapsedMs: elapsedMillis(started),
      message: msg,
      service: scanServiceName(port),
      transport: "tcp"
    )
  finally:
    if socket != nil:
      try:
        socket.close()
      except CatchableError:
        discard

proc retryable(item: ProbeResult): bool =
  item.status == psError or item.message in ["timeout", "Operation not permitted",
    "Too many open files", "Network is unreachable", "No route to host"]

proc probeOne(host: string; port, timeoutMs, retries: int): Future[ProbeResult] {.async.} =
  result = await probeOnce(host, port, timeoutMs)
  var attempt = 0
  while attempt < retries and retryable(result):
    inc attempt
    result = await probeOnce(host, port, timeoutMs)

proc scanTargets*(targets: seq[string]; port, concurrency, timeoutMs: int): Future[seq[ProbeResult]] {.async.} =
  var nextIndex = 0

  proc worker(): Future[seq[ProbeResult]] {.async.} =
    while true:
      if nextIndex >= targets.len:
        break
      let current = nextIndex
      inc nextIndex
      result.add await probeOne(targets[current], port, timeoutMs, 0)

  var workers: seq[Future[seq[ProbeResult]]] = @[]
  let workerCount = min(concurrency, targets.len)
  for _ in 0 ..< workerCount:
    workers.add worker()

  for future in workers:
    let workerResults = await future
    for item in workerResults:
      result.add item

proc hostIsUp*(host: string; timeoutMs: int): Future[bool] {.async.} =
  const probes = [80, 443, 22, 445, 3389]
  let resolved = resolveHost(host)
  let perPortTimeout = max(200, timeoutMs div 2)
  proc check(p: int): Future[bool] {.async.} =
    var socket = newTcpAsyncSocket(host)
    try:
      result = await netproxy.connectTcp(socket, resolved, p, perPortTimeout)
    except CatchableError:
      result = true
    finally:
      try: socket.close()
      except CatchableError: discard
  var futures: seq[Future[bool]] = @[]
  for port in probes:
    futures.add check(port)
  for f in futures:
    if await f: return true
  return false

proc filterLiveTargets*(targets: seq[string]; concurrency, timeoutMs: int;
                       onSkip: proc(host: string) {.closure.} = nil): Future[seq[string]] {.async.} =
  var nextIndex = 0
  var liveFlag = newSeq[bool](targets.len)
  proc worker(): Future[void] {.async.} =
    while true:
      if nextIndex >= targets.len: break
      let current = nextIndex
      inc nextIndex
      let alive = await hostIsUp(targets[current], timeoutMs)
      liveFlag[current] = alive
      if not alive and onSkip != nil: onSkip(targets[current])
  var workers: seq[Future[void]] = @[]
  for _ in 0 ..< min(concurrency, max(1, targets.len)):
    workers.add worker()
  for f in workers: await f
  result = @[]
  for i in 0 ..< targets.len:
    if liveFlag[i]: result.add targets[i]

proc scanTargetsPorts*(targets: seq[string]; ports: seq[int]; concurrency, timeoutMs: int;
                       onProgress: ScanProgress = nil; retries = 0): Future[seq[ProbeResult]] {.async.} =
  var nextIndex = 0
  let total = targets.len * ports.len

  proc worker(): Future[seq[ProbeResult]] {.async.} =
    while true:
      if nextIndex >= total:
        break
      let current = nextIndex
      inc nextIndex
      let targetIndex = current div ports.len
      let portIndex = current mod ports.len
      result.add await probeOne(targets[targetIndex], ports[portIndex], timeoutMs, retries)
      if onProgress != nil:
        onProgress()

  var workers: seq[Future[seq[ProbeResult]]] = @[]
  let workerCount = min(concurrency, total)
  for _ in 0 ..< workerCount:
    workers.add worker()

  for future in workers:
    let workerResults = await future
    for item in workerResults:
      result.add item


proc buildSnmpGetSysDescr(): string =
  let oid = "\x2b\x06\x01\x02\x01\x01\x01\x00"
  let varbind = "\x06" & char(oid.len) & oid & "\x05\x00"
  let varbinds = "\x30" & char(varbind.len) & varbind
  let pdu = "\x02\x04\x01\x02\x03\x04" & "\x02\x01\x00" & "\x02\x01\x00" &
            "\x30" & char(varbinds.len) & varbinds
  let community = "public"
  let body = "\x02\x01\x00" & "\x04" & char(community.len) & community &
             "\xa0" & char(pdu.len) & pdu
  result = "\x30" & char(body.len) & body

proc buildNbstatRequest(): string =
  result.addU16Be 0x1234'u16
  result.addU16Be 0x0010'u16
  result.addU16Be 1'u16
  result.addU16Be 0'u16
  result.addU16Be 0'u16
  result.addU16Be 0'u16
  result.add char(32)
  result.add "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  result.add char(0)
  result.addU16Be 0x0021'u16
  result.addU16Be 0x0001'u16

proc buildNtpClient(): string =
  result.add char(0x23)
  for _ in 0 ..< 47:
    result.add char(0)

proc buildMdnsQuery(): string =
  result.addU16Be 0x0000'u16
  result.addU16Be 0x0000'u16
  result.addU16Be 1'u16
  result.addU16Be 0'u16
  result.addU16Be 0'u16
  result.addU16Be 0'u16
  for label in ["_services", "_dns-sd", "_udp", "local"]:
    result.add char(label.len)
    result.add label
  result.add char(0)
  result.addU16Be 0x000c'u16
  result.addU16Be 0x8001'u16

proc buildSsdpMsearch(): string =
  "M-SEARCH * HTTP/1.1\r\n" &
  "HOST: 239.255.255.250:1900\r\n" &
  "MAN: \"ssdp:discover\"\r\n" &
  "MX: 1\r\n" &
  "ST: ssdp:all\r\n\r\n"

proc buildMssqlBrowserList(): string = "\x02"

proc buildTftpRrq(): string =
  result.addU16Be 1'u16
  result.add "nimux-probe"
  result.add char(0)
  result.add "octet"
  result.add char(0)

proc buildSunRpcGetPort(): string =
  result.addU32Le 0x4e58d20a'u32
  result.addU32Le 0'u32
  result.addU32Le 2'u32
  proc addU32Be(data: var string; value: uint32) =
    data.add char((value shr 24) and 0xff)
    data.add char((value shr 16) and 0xff)
    data.add char((value shr 8) and 0xff)
    data.add char(value and 0xff)
  result = ""
  addU32Be(result, 0x4e58d20a'u32)
  addU32Be(result, 0'u32)
  addU32Be(result, 2'u32)
  addU32Be(result, 100000'u32)
  addU32Be(result, 2'u32)
  addU32Be(result, 3'u32)
  addU32Be(result, 0'u32); addU32Be(result, 0'u32)
  addU32Be(result, 0'u32); addU32Be(result, 0'u32)
  addU32Be(result, 100000'u32)
  addU32Be(result, 2'u32)
  addU32Be(result, 6'u32)
  addU32Be(result, 0'u32)

proc buildIkeMainMode(): string =
  result.add "\xde\xad\xbe\xef\xfe\xed\xfa\xce"
  result.add "\x00\x00\x00\x00\x00\x00\x00\x00"
  result.add char(0x01)
  result.add char(0x10)
  result.add char(0x02)
  result.add char(0x00)
  result.add "\x00\x00\x00\x00"
  result.addU16Be 0'u16; result.addU16Be 76'u16
  result.add char(0x00)
  result.add char(0x00)
  result.addU16Be 48'u16
  result.add "\x00\x00\x00\x01"
  result.add "\x00\x00\x00\x01"
  result.add char(0x00); result.add char(0x00)
  result.addU16Be 36'u16
  result.add char(0x01)
  result.add char(0x01)
  result.add char(0x00)
  result.add char(0x01)
  result.add char(0x00); result.add char(0x00)
  result.addU16Be 24'u16
  result.add char(0x01)
  result.add char(0x01)
  result.add "\x00\x00"
  result.add "\x80\x01\x00\x05"
  result.add "\x80\x02\x00\x02"
  result.add "\x80\x03\x00\x01"
  result.add "\x80\x04\x00\x02"

proc buildIpmiChannelAuth(): string =
  result.add "\x06\x00\xff\x07"
  result.add char(0x00)
  result.add "\x00\x00\x00\x00"
  result.add "\x00\x00\x00\x00"
  result.add char(0x09)
  result.add char(0x20)
  result.add char(0x18)
  result.add char(0xc8)
  result.add char(0x81)
  result.add char(0x04)
  result.add char(0x38)
  result.add char(0x0e)
  result.add char(0x04)
  let csum2 = (-(0x81 + 0x04 + 0x38 + 0x0e + 0x04)) and 0xff
  result.add char(csum2)

proc udpPayloadFor(port: int; host: string): string =
  case port
  of 53, 5353:
    if port == 5353: buildMdnsQuery()
    else: buildDnsVersionBind()[2 .. ^1]
  of 88, 464:
    buildKerberosAsReq()[4 .. ^1]
  of 123:
    buildNtpClient()
  of 137:
    buildNbstatRequest()
  of 161:
    buildSnmpGetSysDescr()
  of 1434:
    buildMssqlBrowserList()
  of 1900:
    buildSsdpMsearch()
  of 69:
    buildTftpRrq()
  of 111:
    buildSunRpcGetPort()
  of 500:
    buildIkeMainMode()
  of 623:
    buildIpmiChannelAuth()
  else:
    ""

proc parseNbstatResponse(response: string): string =
  if response.len < 57: return ""
  let answerStart = 56
  if response.len < 57:
    return ""
  let numNames = ord(response[56])
  if numNames == 0 or numNames > 32: return ""
  var names: seq[string]
  var domain = ""
  var computer = ""
  var offset = 57
  for _ in 0 ..< numNames:
    if offset + 18 > response.len: break
    let name = response[offset ..< offset + 15].strip()
    let suffix = ord(response[offset + 15])
    let flags = (ord(response[offset + 16]) shl 8) or ord(response[offset + 17])
    let isGroup = (flags and 0x8000) != 0
    names.add name & "<" & toHex(suffix, 2) & ">"
    if not isGroup and suffix == 0x20 and computer.len == 0:
      computer = name
    elif isGroup and suffix == 0x00 and domain.len == 0:
      domain = name
    offset += 18
  var parts: seq[string]
  if computer.len > 0: parts.add "Host: " & computer
  if domain.len > 0: parts.add "Workgroup: " & domain
  if parts.len > 0: parts.join(", ")
  else: "NetBIOS name service (" & $numNames & " names)"

proc parseSnmpResponse(response: string): string =
  if response.len < 4 or ord(response[0]) != 0x30: return ""
  var index = 0
  while index < response.len - 2:
    if ord(response[index]) == 0x04:
      let length = ord(response[index + 1])
      if length > 4 and length < 200 and index + 2 + length <= response.len:
        let value = response[index + 2 ..< index + 2 + length]
        if value != "public":
          return "SNMP sysDescr: " & printable(value, 160)
    inc index
  "SNMPv1 response"

proc parseNtpResponse(response: string): string =
  if response.len < 48: return ""
  let liVnMode = ord(response[0])
  let version = (liVnMode shr 3) and 0x07
  let stratum = ord(response[1])
  let refIdRaw = response[12 ..< 16]
  var refId = ""
  for ch in refIdRaw:
    if ord(ch) >= 32 and ord(ch) <= 126: refId.add ch
  var parts: seq[string]
  parts.add "NTPv" & $version
  parts.add "stratum " & $stratum
  if refId.len > 0: parts.add "refid=" & refId
  parts.join(", ")

proc parseMssqlBrowserResponse(response: string): string =
  if response.len < 3 or ord(response[0]) != 0x05: return ""
  let payloadLen = (ord(response[2]) shl 8) or ord(response[1])
  if payloadLen <= 0 or 3 + payloadLen > response.len: return ""
  let body = response[3 ..< 3 + payloadLen]
  let prn = printable(body, 200)
  "MSSQL Browser: " & prn

proc parseSsdpResponse(response: string): string =
  if not response.startsWith("HTTP/"): return ""
  let server = headerValue(response, "Server")
  if server.len > 0: "SSDP " & server
  else: "SSDP " & response.splitLines()[0].strip()

proc parseUdpResponse(port: int; response: string): tuple[service, version: string] =
  if response.len == 0: return
  case port
  of 53:
    let v = parseDnsVersionResponse(response)
    if v.len > 0: return ("dns", v)
    return ("dns", "DNS responder")
  of 5353:
    return ("mdns", "mDNS responder")
  of 88, 464:
    let krb = parseKerberosError(response)
    let svc = if port == 464: "kpasswd5" else: "kerberos-sec"
    if krb.len > 0: return (svc, krb)
    return (svc, "Microsoft Windows Kerberos")
  of 123:
    let v = parseNtpResponse(response)
    if v.len > 0: return ("ntp", v)
  of 137:
    let v = parseNbstatResponse(response)
    if v.len > 0: return ("netbios-ns", v)
    return ("netbios-ns", "NetBIOS name service")
  of 161:
    let v = parseSnmpResponse(response)
    if v.len > 0: return ("snmp", v)
  of 1434:
    let v = parseMssqlBrowserResponse(response)
    if v.len > 0: return ("ms-sql-m", v)
  of 1900:
    let v = parseSsdpResponse(response)
    if v.len > 0: return ("upnp", v)
  of 69:
    if response.len >= 4 and ord(response[0]) == 0 and ord(response[1]) == 5:
      let errCode = (ord(response[2]) shl 8) or ord(response[3])
      var msg = ""
      var i = 4
      while i < response.len and ord(response[i]) != 0:
        msg.add response[i]; inc i
      return ("tftp", "TFTP error " & $errCode & (if msg.len > 0: ": " & msg else: ""))
    return ("tftp", "TFTP responder")
  of 111:
    if response.len >= 28 and ord(response[7]) == 1:
      let portBytes = response[response.len - 4 ..< response.len]
      let port = (ord(portBytes[0]) shl 24) or (ord(portBytes[1]) shl 16) or
                 (ord(portBytes[2]) shl 8) or ord(portBytes[3])
      return ("rpcbind", "Sun RPC portmapper v2 (GETPORT → " & $port & ")")
    return ("rpcbind", "Sun RPC portmapper")
  of 500:
    if response.len >= 28 and response.startsWith("\xde\xad\xbe\xef\xfe\xed\xfa\xce"):
      let exch = ord(response[18])
      let exchName = case exch
        of 2: "Main Mode"
        of 4: "Aggressive Mode"
        of 5: "Informational"
        else: "exchange " & $exch
      return ("isakmp", "ISAKMP/IKEv1 " & exchName & " responder")
    return ("isakmp", "ISAKMP responder")
  of 623:
    if response.len >= 5 and ord(response[0]) == 0x06 and ord(response[3]) == 0x07:
      return ("ipmi", "IPMI v1.5 responder")
    return ("ipmi", "IPMI responder")
  else:
    return (udpServiceName(port), "responded " & $response.len & " bytes")

proc probeUdpOnce(host: string; port, timeoutMs: int): Future[ProbeResult] {.async.} =
  let started = now()
  result = ProbeResult(
    host: host, port: port, transport: "udp",
    service: udpServiceName(port)
  )
  var socket: AsyncSocket
  try:
    socket = newUdpAsyncSocket(host)
    let payload = udpPayloadFor(port, host)
    await socket.sendTo(resolveHost(host), Port(port), payload)
    let recvFuture = socket.recvFrom(4096)
    if await withTimeout(recvFuture, timeoutMs):
      let packet = await recvFuture
      let response = packet.data
      result.elapsedMs = elapsedMillis(started)
      result.rawBytes = response
      result.banner = printable(response)
      let parsed = parseUdpResponse(port, response)
      if parsed.service.len > 0:
        result.service = parsed.service
      result.version = parsed.version
      result.status = psOpen
      result.message = "udp response received"
    else:
      result.elapsedMs = elapsedMillis(started)
      result.status = psClosed
      result.message = "no udp response"
  except CatchableError as error:
    result.elapsedMs = elapsedMillis(started)
    result.status = psError
    result.message = cleanError(error)
  finally:
    if socket != nil:
      try: socket.close()
      except CatchableError: discard

proc probeUdp(host: string; port, timeoutMs, retries: int): Future[ProbeResult] {.async.} =
  result = await probeUdpOnce(host, port, timeoutMs)
  var attempt = 0
  while attempt < retries and result.status == psClosed:
    inc attempt
    result = await probeUdpOnce(host, port, timeoutMs)

proc scanUdpTargetsPorts*(targets: seq[string]; ports: seq[int]; concurrency, timeoutMs: int;
                          onProgress: ScanProgress = nil; retries = 0): Future[seq[ProbeResult]] {.async.} =
  var nextIndex = 0
  let total = targets.len * ports.len

  proc worker(): Future[seq[ProbeResult]] {.async.} =
    while true:
      if nextIndex >= total:
        break
      let current = nextIndex
      inc nextIndex
      let targetIndex = current div ports.len
      let portIndex = current mod ports.len
      result.add await probeUdp(targets[targetIndex], ports[portIndex], timeoutMs, retries)
      if onProgress != nil:
        onProgress()

  var workers: seq[Future[seq[ProbeResult]]] = @[]
  let workerCount = min(concurrency, total)
  for _ in 0 ..< workerCount:
    workers.add worker()

  for future in workers:
    let workerResults = await future
    for item in workerResults:
      result.add item
