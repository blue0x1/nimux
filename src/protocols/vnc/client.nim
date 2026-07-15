import std/[asyncdispatch, asyncnet, net, strutils]
import ../../core/proxy as netproxy

type
  DesKeySchedule {.importc: "DES_key_schedule", header: "<openssl/des.h>".} = object
    ks: array[32, uint32]

proc DES_set_key_unchecked(key: pointer; schedule: ptr DesKeySchedule)
    {.cdecl, importc, header: "<openssl/des.h>".}
proc DES_ecb_encrypt(inp, outp: pointer; schedule: ptr DesKeySchedule; enc: cint)
    {.cdecl, importc, header: "<openssl/des.h>".}

const DES_ENCRYPT = 1.cint

proc reverseBits(b: uint8): uint8 =
  var x = b
  var r: uint8 = 0
  for _ in 0..7:
    r = (r shl 1) or (x and 1)
    x = x shr 1
  r

proc vncDesKey(password: string): array[8, uint8] =
  for i in 0..7:
    let ch = if i < password.len: uint8(ord(password[i])) else: 0'u8
    result[i] = reverseBits(ch)

proc vncEncryptChallenge(password: string; challenge: string): string =
  var key = vncDesKey(password)
  var sched: DesKeySchedule
  DES_set_key_unchecked(addr key[0], addr sched)
  result = newString(16)
  var blk0: array[8, uint8]
  var blk1: array[8, uint8]
  var out0: array[8, uint8]
  var out1: array[8, uint8]
  for i in 0..7:
    blk0[i] = uint8(ord(challenge[i]))
    blk1[i] = uint8(ord(challenge[i + 8]))
  DES_ecb_encrypt(addr blk0[0], addr out0[0], addr sched, DES_ENCRYPT)
  DES_ecb_encrypt(addr blk1[0], addr out1[0], addr sched, DES_ENCRYPT)
  for i in 0..7:
    result[i]     = char(out0[i])
    result[i + 8] = char(out1[i])

type
  VncResult* = object
    host*:          string
    port*:          int
    reachable*:     bool
    rfbVersion*:    string
    authenticated*: bool
    authMessage*:   string
    securityTypes*: seq[int]
    desktopName*:   string

proc recvExact(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let f = sock.recv(n - buf.len)
    if not await withTimeout(f, timeoutMs):
      raise newException(IOError, "VNC: receive timeout")
    let chunk = await f
    if chunk.len == 0:
      raise newException(IOError, "VNC: connection closed")
    buf.add chunk
  result = buf

proc readU32Be(s: string; pos: int): uint32 =
  (uint32(ord(s[pos])) shl 24) or (uint32(ord(s[pos+1])) shl 16) or
  (uint32(ord(s[pos+2])) shl 8) or uint32(ord(s[pos+3]))

proc sendU8(sock: AsyncSocket; v: uint8): Future[void] {.async.} =
  await sock.send("" & char(v))

proc probeVnc*(host: string; port, timeoutMs: int;
               password = ""): Future[VncResult] {.async.} =
  result.host = host
  result.port = port
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok:
      sock.close()
      return
  except:
    sock.close()
    return
  result.reachable = true
  try:
    let serverHello = await recvExact(sock, 12, timeoutMs)
    result.rfbVersion = serverHello.strip()

    var rfbMajor = 3
    var rfbMinor = 8
    if serverHello.len >= 11:
      try:
        rfbMajor = parseInt(serverHello[4..6])
        rfbMinor = parseInt(serverHello[8..10])
      except: discard

    let clientVer =
      if rfbMinor >= 8: "RFB 003.008\n"
      elif rfbMinor >= 7: "RFB 003.007\n"
      else: "RFB 003.003\n"
    await sock.send(clientVer)

    if rfbMinor >= 7:
      let nTypes = ord((await recvExact(sock, 1, timeoutMs))[0])
      if nTypes == 0:
        let reasonLen = int(readU32Be(await recvExact(sock, 4, timeoutMs), 0))
        let reason = await recvExact(sock, reasonLen, timeoutMs)
        result.authMessage = reason
        sock.close()
        return
      let typeBytes = await recvExact(sock, nTypes, timeoutMs)
      for i in 0 ..< nTypes:
        result.securityTypes.add int(uint8(ord(typeBytes[i])))

      var chosen = 0
      if 2 in result.securityTypes and password.len > 0:
        chosen = 2
      elif 1 in result.securityTypes:
        chosen = 1
      elif 2 in result.securityTypes:
        chosen = 2
      else:
        chosen = result.securityTypes[0]

      await sendU8(sock, uint8(chosen))

      if chosen == 1:
        if rfbMinor >= 8:
          let secResult = readU32Be(await recvExact(sock, 4, timeoutMs), 0)
          result.authenticated = secResult == 0
          if not result.authenticated:
            let rlen = int(readU32Be(await recvExact(sock, 4, timeoutMs), 0))
            if rlen > 0:
              result.authMessage = await recvExact(sock, rlen, timeoutMs)
            else:
              result.authMessage = "security handshake failed"
        else:
          result.authenticated = true
      elif chosen == 2:
        let challenge = await recvExact(sock, 16, timeoutMs)
        let response =
          if password.len > 0: vncEncryptChallenge(password, challenge)
          else: newString(16)
        await sock.send(response)
        let secResult = readU32Be(await recvExact(sock, 4, timeoutMs), 0)
        result.authenticated = secResult == 0
        if not result.authenticated:
          if rfbMinor >= 8:
            let rlen = int(readU32Be(await recvExact(sock, 4, timeoutMs), 0))
            if rlen > 0:
              result.authMessage = await recvExact(sock, rlen, timeoutMs)
            else:
              result.authMessage = "authentication failed"
          else:
            result.authMessage = "authentication failed"
      else:
        result.authMessage = "unsupported security type " & $chosen
    else:
      let secType = readU32Be(await recvExact(sock, 4, timeoutMs), 0)
      result.securityTypes.add int(secType)
      if secType == 2:
        let challenge = await recvExact(sock, 16, timeoutMs)
        let response =
          if password.len > 0: vncEncryptChallenge(password, challenge)
          else: newString(16)
        await sock.send(response)
        let secResult = readU32Be(await recvExact(sock, 4, timeoutMs), 0)
        result.authenticated = secResult == 0
        if not result.authenticated:
          result.authMessage = "authentication failed"
      elif secType == 1:
        result.authenticated = true
      else:
        result.authMessage = "unsupported security type " & $secType

    if result.authenticated:
      await sock.send("\x01")
      let siLen = 24
      let serverInit = await recvExact(sock, siLen, timeoutMs)
      let nameLen = int(readU32Be(serverInit, 20))
      if nameLen > 0 and nameLen < 256:
        result.desktopName = await recvExact(sock, nameLen, timeoutMs)

  except Exception as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sock.close()
