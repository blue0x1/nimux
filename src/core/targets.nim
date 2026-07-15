import std/[net, strutils, sequtils, os]

type
  TargetParseError* = object of CatchableError

proc ipv4ToInt(ip: string): uint32 =
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(TargetParseError, "invalid IPv4 address: " & ip)

  var value: uint32 = 0
  for part in parts:
    if part.len == 0:
      raise newException(TargetParseError, "invalid IPv4 address: " & ip)
    let octet = parseInt(part)
    if octet < 0 or octet > 255:
      raise newException(TargetParseError, "invalid IPv4 address: " & ip)
    value = (value shl 8) or uint32(octet)
  value

proc intToIpv4(value: uint32): string =
  let a = (value shr 24) and 0xff'u32
  let b = (value shr 16) and 0xff'u32
  let c = (value shr 8) and 0xff'u32
  let d = value and 0xff'u32
  $a & "." & $b & "." & $c & "." & $d

proc parseCidrV4(base: string; prefix: int): seq[string] =
  if prefix < 0 or prefix > 32:
    raise newException(TargetParseError, "invalid CIDR prefix: " & $prefix)
  let baseInt = ipv4ToInt(base)
  let hostBits = 32 - prefix
  let count =
    if hostBits == 32: uint64(uint32.high) + 1'u64
    else: 1'u64 shl hostBits
  if count > 65536'u64:
    raise newException(TargetParseError, "IPv4 CIDR is too large: /" & $prefix)
  let mask = if prefix == 0: 0'u32 else: uint32.high shl hostBits
  let network = baseInt and mask
  let firstOffset =
    if prefix < 31 and count > 2'u64: 1'u64
    else: 0'u64
  let lastOffset =
    if prefix < 31 and count > 2'u64: count - 1'u64
    else: count
  for offset in firstOffset ..< lastOffset:
    result.add intToIpv4(network + uint32(offset))

proc ipv6ToBytes(ip: string): array[16, byte] =
  try:
    let addr6 = parseIpAddress(ip)
    if addr6.family != IPv6:
      raise newException(TargetParseError, "expected IPv6 literal: " & ip)
    return addr6.address_v6
  except CatchableError as error:
    raise newException(TargetParseError, "invalid IPv6 address: " & ip & " (" & error.msg & ")")

proc bytesToIpv6(bytes: array[16, byte]): string =
  var ip = IpAddress(family: IPv6, address_v6: bytes)
  $ip

proc incrementIpv6(bytes: var array[16, byte]) =
  for index in countdown(15, 0):
    if bytes[index] == 0xff'u8:
      bytes[index] = 0'u8
    else:
      bytes[index] = byte(int(bytes[index]) + 1)
      return

proc parseCidrV6(base: string; prefix: int): seq[string] =
  if prefix < 0 or prefix > 128:
    raise newException(TargetParseError, "invalid IPv6 CIDR prefix: " & $prefix)
  let hostBits = 128 - prefix
  if hostBits > 16:
    raise newException(TargetParseError,
      "IPv6 CIDR /" & $prefix & " expands to too many hosts (limit /112)")
  let count = 1'u64 shl hostBits
  var bytes = ipv6ToBytes(base)
  var remaining = hostBits
  for index in countdown(15, 0):
    if remaining <= 0: break
    let bits = min(8, remaining)
    let mask = uint8((1 shl bits) - 1)
    bytes[index] = byte(uint8(bytes[index]) and not mask)
    remaining -= bits
  for _ in 0'u64 ..< count:
    result.add bytesToIpv6(bytes)
    incrementIpv6(bytes)

proc parseCidr(input: string): seq[string] =
  let parts = input.split('/')
  if parts.len != 2:
    raise newException(TargetParseError, "invalid CIDR target: " & input)
  let prefix = parseInt(parts[1])
  if ':' in parts[0]:
    return parseCidrV6(parts[0], prefix)
  return parseCidrV4(parts[0], prefix)

proc parseRange(input: string): seq[string] =
  let parts = input.split('-')
  if parts.len != 2:
    raise newException(TargetParseError, "invalid IPv4 range: " & input)

  let startIp = ipv4ToInt(parts[0])
  let endIp = ipv4ToInt(parts[1])
  if endIp < startIp:
    raise newException(TargetParseError, "range end is before range start: " & input)
  if uint64(endIp - startIp) > 65535'u64:
    raise newException(TargetParseError, "range is too large for this first release: " & input)

  for value in startIp .. endIp:
    result.add intToIpv4(value)

proc stripIpv6Brackets(token: string): string =
  if token.len >= 2 and token[0] == '[':
    let close = token.find(']')
    if close > 0: return token[1 ..< close]
  token

proc parseTargetToken*(token: string): seq[string] =
  let clean = token.strip()
  if clean.len == 0 or clean.startsWith("#"):
    return @[]

  if clean.startsWith("@"):
    let path = clean[1 .. ^1]
    if not fileExists(path):
      raise newException(TargetParseError, "target file not found: " & path)
    for line in lines(path):
      result.add parseTargetToken(line)
  elif "/" in clean:
    result = parseCidr(stripIpv6Brackets(clean))
  elif ':' in clean:
    let inner = stripIpv6Brackets(clean)
    discard ipv6ToBytes(inner)
    result = @[inner]
  elif "-" in clean and clean.count('.') >= 6:
    result = parseRange(clean)
  else:
    result = @[clean]

proc parseTargets*(tokens: seq[string]): seq[string] =
  for token in tokens:
    result.add parseTargetToken(token)
  result = result.deduplicate()

proc isIpv6Literal*(host: string): bool =
  ':' in host

proc displayHostPort*(host: string; port: int): string =
  if isIpv6Literal(host): "[" & host & "]:" & $port
  else: host & ":" & $port
