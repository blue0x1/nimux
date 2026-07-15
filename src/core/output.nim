import std/[algorithm, json, os, strutils, terminal, times]

type
  ProbeStatus* = enum
    psOpen, psClosed, psError

  ProbeResult* = object
    host*: string
    port*: int
    status*: ProbeStatus
    elapsedMs*: int64
    message*: string
    service*: string
    version*: string
    banner*: string
    rawBytes*: string
    transport*: string

proc statusText*(status: ProbeStatus): string =
  case status
  of psOpen: "open"
  of psClosed: "closed"
  of psError: "error"

proc toJson*(item: ProbeResult): JsonNode =
  let truncated = item.banner.len > 0 and item.rawBytes.len > item.banner.len
  %*{
    "host": item.host,
    "port": item.port,
    "transport": (if item.transport.len > 0: item.transport else: "tcp"),
    "status": item.status.statusText,
    "elapsed_ms": item.elapsedMs,
    "message": item.message,
    "service": item.service,
    "version": item.version,
    "banner": item.banner,
    "banner_truncated": truncated,
    "raw_bytes_len": item.rawBytes.len,
    "raw_bytes_hex": item.rawBytes.toHex()
  }

proc renderText*(item: ProbeResult): string =
  let ms = $item.elapsedMs & "ms"
  item.host & ":" & $item.port & " " & item.status.statusText & " " & ms & " " & item.message

proc scanServiceName*(port: int): string =
  case port
  of 21: "ftp"
  of 22: "ssh"
  of 25: "smtp"
  of 53: "dns"
  of 80: "http"
  of 88: "kerberos"
  of 110: "pop3"
  of 135: "msrpc"
  of 139: "netbios-ssn"
  of 143: "imap"
  of 389: "ldap"
  of 443: "https"
  of 445: "microsoft-ds"
  of 464: "kpasswd5"
  of 465: "smtps"
  of 593: "ncacn_http"
  of 587: "submission"
  of 636: "ldaps"
  of 993: "imaps"
  of 995: "pop3s"
  of 1433: "mssql"
  of 2179: "vmrdp"
  of 3268: "ldap-gc"
  of 3269: "ldaps-gc"
  of 3389: "ms-wbt-server"
  of 5985: "winrm"
  of 5986: "winrm-ssl"
  of 8080: "http-proxy"
  else: "unknown"

proc udpServiceName*(port: int): string =
  case port
  of 53: "dns"
  of 67: "dhcps"
  of 68: "dhcpc"
  of 69: "tftp"
  of 88: "kerberos-sec"
  of 111: "rpcbind"
  of 123: "ntp"
  of 137: "netbios-ns"
  of 138: "netbios-dgm"
  of 161: "snmp"
  of 162: "snmptrap"
  of 389: "ldap"
  of 464: "kpasswd5"
  of 500: "isakmp"
  of 514: "syslog"
  of 520: "rip"
  of 623: "ipmi"
  of 1434: "ms-sql-m"
  of 1900: "upnp"
  of 4500: "nat-t-ike"
  of 5353: "mdns"
  of 5355: "llmnr"
  else: "unknown"

proc softServiceVersion*(port: int): string =
  case port
  of 88: "Microsoft Windows Kerberos"
  of 135: "Microsoft Windows RPC"
  of 139: "Microsoft Windows netbios-ssn"
  of 389: "Microsoft Windows Active Directory LDAP"
  of 445: "Microsoft Windows SMB"
  of 464: "kpasswd5"
  of 593: "Microsoft Windows RPC over HTTP 1.0"
  of 636: "Microsoft Windows Active Directory LDAPS"
  of 3268: "Microsoft Windows Active Directory Global Catalog"
  of 3269: "Microsoft Windows Active Directory Global Catalog over SSL"
  of 3389: "Microsoft Terminal Services"
  of 5985: "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)"
  of 5986: "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) over SSL"
  else: ""

var colorEnabled* =
  not (getEnv("NO_COLOR").len > 0) and isatty(stdout)

proc disableColor*() =
  colorEnabled = false

proc esc(code: string; text: string): string =
  if colorEnabled: "\e[" & code & "m" & text & "\e[0m"
  else: text

proc bold(text: string): string = esc("1", text)
proc dim(text: string): string = esc("2", text)
proc cyan(text: string): string = esc("36", text)
proc brightCyan(text: string): string = esc("1;36", text)
proc green(text: string): string = esc("32", text)
proc yellow(text: string): string = esc("33", text)
proc red(text: string): string = esc("31", text)
proc gray(text: string): string = esc("90", text)

proc hexDump*(data: string; indent = "    "): string =
  if data.len == 0:
    return indent & dim("(no bytes)")
  var offset = 0
  while offset < data.len:
    let take = min(16, data.len - offset)
    var hex = ""
    var asc = ""
    for i in 0 ..< 16:
      if i == 8: hex.add " "
      if i < take:
        let b = ord(data[offset + i])
        hex.add toHex(b, 2).toLowerAscii() & " "
        asc.add (if b >= 32 and b <= 126: data[offset + i] else: '.')
      else:
        hex.add "   "
    if result.len > 0: result.add "\n"
    result.add indent & dim(toHex(offset, 4).toLowerAscii() & "  ") &
      hex & " " & dim("|") & asc & dim("|")
    offset += 16

proc renderScanGrepable*(host: string; items: seq[ProbeResult]): string =
  result = "Host: " & host & " ()\tPorts: "
  var first = true
  for item in items:
    let transport = if item.transport.len > 0: item.transport else: "tcp"
    let state =
      case item.status
      of psOpen: "open"
      of psClosed: (if transport == "udp": "open|filtered" else: "closed")
      of psError: "error"
    let svc = if item.service.len > 0: item.service else: scanServiceName(item.port)
    let version = item.version.replace('/', '|').replace('\n', ' ')
    if not first: result.add ", "
    first = false
    result.add $item.port & "/" & state & "/" & transport & "//" & svc &
      "/" & version & "/"

proc renderScanCsv*(items: seq[ProbeResult]; emitHeader: bool): string =
  if emitHeader:
    result.add "host,port,transport,state,latency_ms,service,version\n"
  for item in items:
    let transport = if item.transport.len > 0: item.transport else: "tcp"
    proc quote(s: string): string =
      if s.contains(',') or s.contains('"') or s.contains('\n'):
        "\"" & s.replace("\"", "\"\"") & "\""
      else: s
    let svc = if item.service.len > 0: item.service else: scanServiceName(item.port)
    let state =
      case item.status
      of psOpen: "open"
      of psClosed: (if transport == "udp": "open|filtered" else: "closed")
      of psError: "error"
    result.add quote(item.host) & "," & $item.port & "," & transport & "," &
      state & "," & $item.elapsedMs & "," & quote(svc) & "," &
      quote(item.version) & "\n"

proc xmlEscape(s: string): string =
  for c in s:
    case c
    of '<': result.add "&lt;"
    of '>': result.add "&gt;"
    of '&': result.add "&amp;"
    of '"': result.add "&quot;"
    of '\'': result.add "&apos;"
    of '\0'..'\8', '\11'..'\12', '\14'..'\31':
      result.add ' '
    else: result.add c

proc renderScanXml*(host: string; items: seq[ProbeResult]): string =
  result.add "  <host>\n"
  result.add "    <address addr=\"" & xmlEscape(host) & "\" addrtype=\""
  result.add (if ':' in host: "ipv6" else: "ipv4") & "\"/>\n"
  result.add "    <ports>\n"
  for item in items:
    let transport = if item.transport.len > 0: item.transport else: "tcp"
    let state =
      case item.status
      of psOpen: "open"
      of psClosed: (if transport == "udp": "open|filtered" else: "closed")
      of psError: "error"
    let svc = if item.service.len > 0: item.service else: scanServiceName(item.port)
    result.add "      <port protocol=\"" & transport & "\" portid=\"" &
      $item.port & "\">\n"
    result.add "        <state state=\"" & state &
      "\" reason=\"" & xmlEscape(item.message) & "\"/>\n"
    if svc.len > 0 or item.version.len > 0:
      result.add "        <service name=\"" & xmlEscape(svc) & "\""
      if item.version.len > 0:
        result.add " product=\"" & xmlEscape(item.version) & "\""
      result.add "/>\n"
    if item.banner.len > 0:
      result.add "        <banner>" & xmlEscape(item.banner) & "</banner>\n"
    result.add "      </port>\n"
  result.add "    </ports>\n"
  result.add "  </host>\n"

proc renderScanXmlHeader*(): string =
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nimuxrun>\n"

proc renderScanXmlFooter*(): string =
  "</nimuxrun>\n"

proc renderScanText*(host: string; items: seq[ProbeResult]; openOnly = false;
                     debugProbe = false): string =
  const BoxWidth = 78
  proc visibleLen(text: string): int =
    var i = 0
    while i < text.len:
      if text[i] == '\e' and i + 1 < text.len and text[i + 1] == '[':
        while i < text.len and text[i] != 'm':
          inc i
        if i < text.len: inc i
      else:
        inc result
        inc i
  proc padR(text: string; width: int): string =
    let v = visibleLen(text)
    if v >= width: text else: text & repeat(' ', width - v)
  proc padL(text: string; width: int): string =
    let v = visibleLen(text)
    if v >= width: text else: repeat(' ', width - v) & text
  proc topBorder(label: string): string =
    let head = "┌─ " & label & " "
    gray("┌─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visibleLen(head))))
  proc midBorder(label: string): string =
    let head = "├─ " & label & " "
    gray("├─ ") & label & gray(" " & repeat("─", max(3, BoxWidth - visibleLen(head))))
  proc bottomBorder(): string =
    gray("└" & repeat("─", BoxWidth - 1))
  proc bodyLine(text: string): string =
    gray("│  ") & text
  proc kv(label, value: string): string =
    bodyLine(padR(dim(label), 11) & value)

  var displayItems = items
  displayItems.sort(proc(a, b: ProbeResult): int = cmp(a.port, b.port))

  var openCount = 0
  var closedCount = 0
  var errorCount = 0
  for item in displayItems:
    case item.status
    of psOpen: inc openCount
    of psClosed: inc closedCount
    of psError: inc errorCount

  let scanIsUdp = displayItems.len > 0 and displayItems[0].transport == "udp"
  let closedLabel = if scanIsUdp: " open|filtered" else: " closed"
  let portsHeader = if scanIsUdp: "udp ports" else: "tcp ports"
  result = topBorder(bold("SCAN") & "  " & brightCyan(host))
  result.add "\n" & kv("ports", brightCyan($displayItems.len) & dim(" scanned"))
  result.add "\n" & kv("summary",
    green($openCount & " open") & dim(" / ") &
    (if scanIsUdp: yellow($closedCount & closedLabel) else: red($closedCount & closedLabel)) &
    (if errorCount > 0: dim(" / ") & yellow($errorCount & " error") else: ""))
  result.add "\n" & midBorder(yellow(portsHeader))
  result.add "\n" & bodyLine(
    dim(padR("PORT", 10) & padR("STATE", 10) & padR("LATENCY", 9) &
    padR("SERVICE", 15) & "VERSION"))
  let showOnlyInteresting = openOnly or displayItems.len > 100
  var hiddenClosed = 0
  var hiddenError = 0
  for item in displayItems:
    if showOnlyInteresting:
      case item.status
      of psClosed:
        inc hiddenClosed
        continue
      of psError:
        inc hiddenError
        continue
      of psOpen:
        discard
    let isUdp = item.transport == "udp"
    let state =
      case item.status
      of psOpen: green("open")
      of psClosed:
        if isUdp: yellow("open|filtered") else: red("closed")
      of psError: yellow("error")
    let soft = softServiceVersion(item.port)
    let detailRaw =
      if item.status == psOpen and item.version.len > 0: item.version
      elif item.status == psOpen and soft.len > 0: soft & "?"
      elif item.status == psOpen and item.banner.len > 0:
        let extra = max(0, item.rawBytes.len - item.banner.len)
        let snippet =
          if item.banner.len > 120: item.banner[0 ..< 120] & "…" else: item.banner
        if extra > 0: "banner: " & snippet & dim(" (+" & $extra & " bytes)")
        else: "banner: " & snippet
      elif item.status == psOpen and item.rawBytes.len > 0:
        $item.rawBytes.len & " bytes, no printable banner"
      elif item.status == psOpen and item.message.len > 0 and item.message != "tcp connect succeeded": item.message
      elif item.status == psOpen: "no service response"
      elif item.message.len > 0: item.message
      else: "-"
    let detail =
      if item.status == psOpen: detailRaw
      else: dim(detailRaw)
    let proto = if isUdp: "/udp  " else: "/tcp  "
    let defaultSvc = if isUdp: udpServiceName(item.port) else: scanServiceName(item.port)
    let stateW = if isUdp: 14 else: 10
    result.add "\n" & bodyLine(
      padL(cyan($item.port), 5) & dim(proto) &
      padR(state, stateW) &
      padR($item.elapsedMs & "ms", 9) &
      padR(bold(if item.service.len > 0: item.service else: defaultSvc), 15) &
      detail)
    if debugProbe and item.status == psOpen:
      result.add "\n" & bodyLine(dim("  probe: ") &
        $item.rawBytes.len & " bytes received" &
        (if item.banner.len > 0: dim("  printable: ") & item.banner[0 ..< min(80, item.banner.len)] else: ""))
      if item.rawBytes.len > 0:
        for line in hexDump(item.rawBytes, indent = "    ").splitLines():
          result.add "\n" & bodyLine(line)
  if hiddenClosed > 0:
    result.add "\n" & bodyLine(dim("Not shown: " & $hiddenClosed & " closed ports"))
  if hiddenError > 0:
    result.add "\n" & bodyLine(dim("Not shown: " & $hiddenError & " error ports"))
  result.add "\n" & bottomBorder()

template elapsedMillis*(started: DateTime): int64 =
  (now() - started).inMilliseconds
