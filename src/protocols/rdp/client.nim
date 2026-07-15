import std/[asyncdispatch, asyncnet, net, strutils]
import ../smb/client as smbclient
import ../../core/proxy as netproxy

type
  RdpProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksRdp*: bool
    selectedProtocol*: int
    authenticated*: bool
    authChecked*: bool
    message*: string

const
  RdpProtocolSsl* = 1
  RdpProtocolCredSsp* = 2
  RdpProtocolHybridEx* = 8

proc cleanError(error: ref Exception): string =
  error.msg.splitLines()[0]

proc addU16Be(data: var string; value: uint16) =
  data.add char((value shr 8) and 0xff)
  data.add char(value and 0xff)

proc addU32Le(data: var string; value: uint32) =
  data.add char(value and 0xff)
  data.add char((value shr 8) and 0xff)
  data.add char((value shr 16) and 0xff)
  data.add char((value shr 24) and 0xff)

proc buildRdpConnectionRequest*(requestedProtocols: uint32): string =
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
  result.addU32Le requestedProtocols

proc parseSelectedProtocol(response: string): int =
  for index in 0 .. max(0, response.len - 8):
    if ord(response[index]) == 2 and ord(response[index + 2]) == 8:
      return int(uint32(ord(response[index + 4])) or
        (uint32(ord(response[index + 5])) shl 8) or
        (uint32(ord(response[index + 6])) shl 16) or
        (uint32(ord(response[index + 7])) shl 24))
  -1

proc probeRdp*(host: string; port, timeoutMs: int; requestedProtocols: uint32): Future[RdpProbe] {.async.} =
  var socket = newAsyncSocket(buffered = false)
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      return RdpProbe(host: host, port: port, reachable: false, message: "timeout")

    await socket.send(buildRdpConnectionRequest(requestedProtocols))
    let recvFuture = socket.recv(512)
    if not await withTimeout(recvFuture, timeoutMs):
      return RdpProbe(host: host, port: port, reachable: true, message: "connected, receive timeout")

    let response = await recvFuture
    if response.len >= 7 and ord(response[0]) == 3:
      return RdpProbe(
        host: host,
        port: port,
        reachable: true,
        speaksRdp: true,
        selectedProtocol: parseSelectedProtocol(response),
        message: "RDP negotiation response"
      )
    if response.len > 0:
      return RdpProbe(host: host, port: port, reachable: true, speaksRdp: false, message: "non-RDP response")
    result = RdpProbe(host: host, port: port, reachable: true, message: "connected, no response")
  except CatchableError as error:
    result = RdpProbe(host: host, port: port, reachable: false, message: cleanError(error))
  finally:
    socket.close()

when defined(ssl):
  import std/posix

  proc derLen(n: int): string =
    if n < 128: result.add char(n)
    elif n < 256:
      result.add char(0x81); result.add char(n)
    else:
      result.add char(0x82)
      result.add char((n shr 8) and 0xff)
      result.add char(n and 0xff)

  proc derTlv(tag: int; body: string): string =
    result.add char(tag)
    result.add derLen(body.len)
    result.add body

  proc buildTsRequest(ntlmToken: string): string =
    let negoToken  = derTlv(0xa0, derTlv(0x04, ntlmToken))
    let negoItem   = derTlv(0x30, negoToken)
    let negoData   = derTlv(0x30, negoItem)
    let version    = derTlv(0xa0, derTlv(0x02, "\x06"))
    let negoTokens = derTlv(0xa1, negoData)
    derTlv(0x30, version & negoTokens)

  proc applyRecvTimeout(socket: Socket; timeoutMs: int) =
    var tv = Timeval(tv_sec: posix.Time(max(1, timeoutMs div 1000)),
                     tv_usec: Suseconds((timeoutMs mod 1000) * 1000))
    discard setsockopt(socket.getFd, SOL_SOCKET, SO_RCVTIMEO,
                       addr tv, sizeof(tv).SockLen)

  proc buildRdpNtlmType1(): string =
    result.add "NTLMSSP\0"
    result.add "\x01\x00\x00\x00"
    result.add "\x07\x82\x08\xa0"
    for _ in 0 ..< 16: result.add char(0)

  proc checkRdpAuth*(host: string; port, timeoutMs: int;
                     username, password, ntlmHash, domain: string): tuple[ok: bool; msg: string] =
    let dialHost = netproxy.proxySocketHost(host)
    let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
    var socket = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
    try:
      netproxy.connectTcpSync(socket, host, port, timeoutMs)
      socket.applyRecvTimeout(timeoutMs)

      socket.send(buildRdpConnectionRequest(3))
      var buf = newString(512)
      let got = socket.recv(buf, 512)
      buf.setLen(max(0, got))
      if got < 7 or ord(buf[0]) != 3:
        return (false, "no RDP CC")

      let ctx = newContext(verifyMode = CVerifyNone)
      ctx.wrapConnectedSocket(socket, handshakeAsClient, host)
      socket.applyRecvTimeout(timeoutMs)

      socket.send(buildTsRequest(buildRdpNtlmType1()))

      buf = newString(4096)
      let got2 = socket.recv(buf, 4096)
      buf.setLen(max(0, got2))
      let ntlmStart = buf.find("NTLMSSP\0")
      if ntlmStart < 0:
        return (false, "no NTLM challenge")
      let challenge = smbclient.parseNtlmChallenge(buf[ntlmStart ..< buf.len])
      if not challenge.offered:
        return (false, "no NTLM challenge")

      let cred = smbclient.SmbCredential(
        username: username, password: password,
        ntlmHash: ntlmHash, domain: domain)
      let clientChallenge = smbclient.randomBytes(8)
      let type3 = smbclient.buildNtlmType3CredSsp(cred, challenge, clientChallenge)
      socket.send(buildTsRequest(type3))

      buf = newString(4096)
      let got3 = socket.recv(buf, 4096)
      buf.setLen(max(0, got3))
      if got3 <= 0:
        return (false, "auth failed")
      if buf.find("\xc0\x00\x00\x6d") >= 0 or buf.find("\xc0\x00\x00\x22") >= 0 or
         buf.find("\xc0\x00\x00\x6e") >= 0 or buf.find("\xc0\x00\x00\x70") >= 0:
        return (false, "auth failed")
      return (true, "authenticated")
    except CatchableError as e:
      return (false, e.msg.splitLines()[0])
    finally:
      try: socket.close()
      except CatchableError: discard
