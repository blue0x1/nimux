import std/[asyncdispatch, asyncnet, net, strutils]
import ../../core/proxy as netproxy

type
  FtpResult* = object
    host*:          string
    port*:          int
    reachable*:     bool
    banner*:        string
    authenticated*: bool
    authMessage*:   string
    anonymous*:     bool
    features*:      seq[string]
    system*:        string
    listing*:       seq[string]

  FtpSession* = ref object
    sock*:     AsyncSocket
    host*:     string
    port*:     int
    username*: string
    banner*:   string
    system*:   string
    cwd*:      string
    timeoutMs*: int

proc recvLine(sock: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  while true:
    let f = sock.recv(1)
    if not await withTimeout(f, timeoutMs): return result
    let ch = await f
    if ch.len == 0: return result
    if ch == "\n": return result.strip()
    if ch != "\r": result.add ch

proc recvResponse*(sock: AsyncSocket; timeoutMs: int): Future[tuple[code: int; text: string]] {.async.} =
  var firstCode = 0
  while true:
    let line = await recvLine(sock, timeoutMs)
    if line.len < 3:
      if firstCode != 0: return (firstCode, result.text)
      return (0, line)
    var lineCode = 0
    try: lineCode = parseInt(line[0..2])
    except: discard
    if lineCode == 0:
      if firstCode != 0:
        result.text.add "\n" & line
        continue
      return (0, line)
    if firstCode == 0:
      firstCode = lineCode
      result.code = lineCode
    if line.len > 3 and line[3] == ' ':
      result.text.add (if result.text.len > 0: "\n" else: "") & line[4 .. ^1]
      return
    else:
      result.text.add (if result.text.len > 0: "\n" else: "") & (if line.len > 4: line[4 .. ^1] else: "")

proc parsePasvAddr(text: string): tuple[host: string; port: int] =
  let s = text.find('(')
  let e = text.find(')')
  if s < 0 or e < 0: return
  let parts = text[s+1 ..< e].split(',')
  if parts.len < 6: return
  try:
    result.host = parts[0..3].join(".")
    result.port = parseInt(parts[4].strip()) * 256 + parseInt(parts[5].strip())
  except: discard

proc recvExactData(sock: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  var buf = ""
  while true:
    let f = sock.recv(4096)
    if not await withTimeout(f, timeoutMs): break
    let chunk = await f
    if chunk.len == 0: break
    buf.add chunk
  result = buf

proc probeFtp*(host: string; port, timeoutMs: int;
               username, password: string; doList = false): Future[FtpResult] {.async.} =
  result.host = host
  result.port = port
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok: sock.close(); return
  except: sock.close(); return
  result.reachable = true
  try:
    let greeting = await recvResponse(sock, timeoutMs)
    result.banner = greeting.text.splitLines()[0]
    if greeting.code != 220:
      result.authMessage = "unexpected greeting " & $greeting.code
      sock.close(); return

    await sock.send("FEAT\r\n")
    let featResp = await recvResponse(sock, timeoutMs)
    if featResp.code == 211:
      for line in featResp.text.splitLines():
        let f = line.strip()
        if f.len > 0 and f != "Features:" and f != "End":
          result.features.add f

    if username.len > 0:
      await sock.send("USER " & username & "\r\n")
      let userResp = await recvResponse(sock, timeoutMs)
      if userResp.code == 230:
        result.authenticated = true
        result.anonymous = username == "anonymous" or username == "ftp"
      elif userResp.code == 331:
        await sock.send("PASS " & password & "\r\n")
        let passResp = await recvResponse(sock, timeoutMs)
        if passResp.code == 230:
          result.authenticated = true
          result.anonymous = username == "anonymous" or username == "ftp"
        else:
          result.authMessage = passResp.text.splitLines()[0]
      else:
        result.authMessage = userResp.text.splitLines()[0]

    if result.authenticated:
      await sock.send("SYST\r\n")
      let systResp = await recvResponse(sock, timeoutMs)
      if systResp.code == 215:
        result.system = systResp.text.splitLines()[0]

      if doList:
        await sock.send("PASV\r\n")
        let pasvResp = await recvResponse(sock, timeoutMs)
        if pasvResp.code == 227:
          let (dataHost, dataPort) = parsePasvAddr(pasvResp.text)
          if dataPort > 0:
            let dataSock = newAsyncSocket(buffered = false)
            try:
              let dok = await netproxy.connectTcp(dataSock, dataHost, dataPort, timeoutMs)
              if dok:
                await sock.send("LIST\r\n")
                discard await recvResponse(sock, timeoutMs)
                let raw = await recvExactData(dataSock, timeoutMs)
                discard await recvResponse(sock, timeoutMs)
                for line in raw.splitLines():
                  let l = line.strip()
                  if l.len > 0: result.listing.add l
            except: discard
            finally: dataSock.close()

    await sock.send("QUIT\r\n")
    discard await recvResponse(sock, timeoutMs)
  except Exception as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sock.close()

proc ftpCmd*(sess: FtpSession; cmd: string): Future[tuple[code: int; text: string]] {.async.} =
  await sess.sock.send(cmd & "\r\n")
  result = await recvResponse(sess.sock, sess.timeoutMs)

proc ftpPasv*(sess: FtpSession): Future[AsyncSocket] {.async.} =
  let r = await ftpCmd(sess, "PASV")
  if r.code != 227: return nil
  let (dataHost, dataPort) = parsePasvAddr(r.text)
  if dataPort == 0: return nil
  let dataSock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(dataSock, dataHost, dataPort, sess.timeoutMs)
    if ok: return dataSock
    dataSock.close()
  except:
    try: dataSock.close() except: discard
  return nil

proc ftpPwd*(sess: FtpSession): Future[string] {.async.} =
  let r = await ftpCmd(sess, "PWD")
  if r.code != 257: return sess.cwd
  let s = r.text.find('"')
  let e = r.text.rfind('"')
  if s >= 0 and e > s: return r.text[s+1 ..< e]
  return r.text

proc ftpCd*(sess: FtpSession; path: string): Future[tuple[ok: bool; msg: string]] {.async.} =
  let r = await ftpCmd(sess, "CWD " & path)
  if r.code == 250:
    sess.cwd = await ftpPwd(sess)
    return (true, "")
  return (false, r.text.splitLines()[0])

proc ftpList*(sess: FtpSession; path = ""): Future[seq[string]] {.async.} =
  let dataSock = await ftpPasv(sess)
  if dataSock.isNil: return
  try:
    let cmd = if path.len > 0: "LIST " & path else: "LIST"
    let r = await ftpCmd(sess, cmd)
    if r.code != 150 and r.code != 125: return
    let raw = await recvExactData(dataSock, sess.timeoutMs)
    discard await recvResponse(sess.sock, sess.timeoutMs)
    for line in raw.splitLines():
      let l = line.strip()
      if l.len > 0: result.add l
  finally:
    try: dataSock.close() except: discard

proc ftpGet*(sess: FtpSession; remoteName, localPath: string): Future[tuple[ok: bool; bytes: int; msg: string]] {.async.} =
  let dataSock = await ftpPasv(sess)
  if dataSock.isNil: return (false, 0, "PASV failed")
  try:
    let r = await ftpCmd(sess, "RETR " & remoteName)
    if r.code != 150 and r.code != 125:
      return (false, 0, r.text.splitLines()[0])
    var f: File
    if not open(f, localPath, fmWrite):
      return (false, 0, "cannot open " & localPath)
    var total = 0
    try:
      while true:
        let chunk = await recvExactData(dataSock, sess.timeoutMs)
        if chunk.len == 0: break
        f.write(chunk)
        total += chunk.len
    finally:
      f.close()
    discard await recvResponse(sess.sock, sess.timeoutMs)
    return (true, total, "")
  finally:
    try: dataSock.close() except: discard

proc ftpPut*(sess: FtpSession; localPath, remoteName: string): Future[tuple[ok: bool; bytes: int; msg: string]] {.async.} =
  var data: string
  try:
    data = readFile(localPath)
  except:
    return (false, 0, "cannot read " & localPath)
  let dataSock = await ftpPasv(sess)
  if dataSock.isNil: return (false, 0, "PASV failed")
  try:
    let r = await ftpCmd(sess, "STOR " & remoteName)
    if r.code != 150 and r.code != 125:
      return (false, 0, r.text.splitLines()[0])
    await dataSock.send(data)
    dataSock.close()
    discard await recvResponse(sess.sock, sess.timeoutMs)
    return (true, data.len, "")
  finally:
    try: dataSock.close() except: discard

proc ftpMkdir*(sess: FtpSession; path: string): Future[tuple[ok: bool; msg: string]] {.async.} =
  let r = await ftpCmd(sess, "MKD " & path)
  if r.code == 257: return (true, "")
  return (false, r.text.splitLines()[0])

proc ftpRm*(sess: FtpSession; path: string): Future[tuple[ok: bool; msg: string]] {.async.} =
  var r = await ftpCmd(sess, "DELE " & path)
  if r.code == 250: return (true, "")
  r = await ftpCmd(sess, "RMD " & path)
  if r.code == 250: return (true, "")
  return (false, r.text.splitLines()[0])

proc openFtpSession*(host: string; port, timeoutMs: int;
                     username, password: string): Future[FtpSession] {.async.} =
  let sess = FtpSession(host: host, port: port, username: username, timeoutMs: timeoutMs)
  sess.sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sess.sock, host, port, timeoutMs)
    if not ok: sess.sock.close(); return nil
  except: sess.sock.close(); return nil
  try:
    let greeting = await recvResponse(sess.sock, timeoutMs)
    if greeting.code != 220: sess.sock.close(); return nil
    sess.banner = greeting.text.splitLines()[0]

    await sess.sock.send("USER " & username & "\r\n")
    let userResp = await recvResponse(sess.sock, timeoutMs)
    if userResp.code == 331:
      await sess.sock.send("PASS " & password & "\r\n")
      let passResp = await recvResponse(sess.sock, timeoutMs)
      if passResp.code != 230: sess.sock.close(); return nil
    elif userResp.code != 230:
      sess.sock.close(); return nil

    await sess.sock.send("SYST\r\n")
    let systResp = await recvResponse(sess.sock, timeoutMs)
    if systResp.code == 215:
      sess.system = systResp.text.splitLines()[0]

    sess.cwd = await ftpPwd(sess)
    return sess
  except:
    try: sess.sock.close() except: discard
    return nil
