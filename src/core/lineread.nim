import posix/termios

proc c_write(fd: cint; buf: pointer; count: csize_t): cint {.importc: "write", header: "<unistd.h>".}
proc c_read(fd: cint; buf: pointer; count: csize_t): cint {.importc: "read", header: "<unistd.h>".}

var lineHistory: seq[string]

proc writeErr(s: string) =
  discard c_write(2, s.cstring, s.len.csize_t)

proc initReadline*() = discard

proc readlineWithHistory*(prompt: string): string =
  var orig: Termios
  discard tcGetAttr(0.cint, addr orig)
  var raw = orig
  raw.c_lflag = raw.c_lflag and not (ECHO or ICANON or ISIG)
  raw.c_cc[VMIN] = char(1)
  raw.c_cc[VTIME] = char(0)
  discard tcSetAttr(0.cint, TCSAFLUSH, addr raw)
  defer: discard tcSetAttr(0.cint, TCSAFLUSH, addr orig)

  var buf = ""
  var cursor = 0
  var histIdx = lineHistory.len
  var saved = ""

  proc redraw() =
    writeErr("\r\x1b[K" & prompt & buf)
    if cursor < buf.len:
      writeErr("\x1b[" & $(buf.len - cursor) & "D")

  writeErr("\x1b[?2004h")
  defer: writeErr("\x1b[?2004l")
  writeErr(prompt)

  while true:
    var c: char
    if c_read(0, addr c, 1.csize_t) <= 0: break
    case c
    of '\r', '\n':
      writeErr("\r\n")
      break
    of '\x01':
      cursor = 0; redraw()
    of '\x05':
      cursor = buf.len; redraw()
    of '\x0b':
      buf = buf[0..<cursor]; redraw()
    of '\x15':
      buf = buf[cursor..^1]; cursor = 0; redraw()
    of '\x17':
      var i = cursor
      while i > 0 and buf[i-1] == ' ': dec i
      while i > 0 and buf[i-1] != ' ': dec i
      buf = buf[0..<i] & buf[cursor..^1]
      cursor = i; redraw()
    of '\x0c':
      writeErr("\x1b[2J\x1b[H"); redraw()
    of '\x03':
      writeErr("^C\r\n")
      if buf.len == 0:
        discard tcSetAttr(0.cint, TCSAFLUSH, addr orig)
        raise newException(EOFError, "interrupted")
      buf = ""; break
    of '\x04':
      if buf.len == 0:
        discard tcSetAttr(0.cint, TCSAFLUSH, addr orig)
        raise newException(EOFError, "EOF")
      elif cursor < buf.len:
        buf = buf[0..<cursor] & buf[cursor+1..^1]; redraw()
    of '\x7f', '\x08':
      if cursor > 0:
        buf = buf[0..<cursor-1] & buf[cursor..^1]
        dec cursor; redraw()
    of '\x1b':
      var c2, c3: char
      if c_read(0, addr c2, 1.csize_t) <= 0: break
      if c2 != '[':
        if c2 == '\x1b': discard
        continue
      if c_read(0, addr c3, 1.csize_t) <= 0: break
      case c3
      of 'A':
        if histIdx > 0:
          if histIdx == lineHistory.len: saved = buf
          dec histIdx
          buf = lineHistory[histIdx]; cursor = buf.len; redraw()
      of 'B':
        if histIdx < lineHistory.len:
          inc histIdx
          buf = if histIdx == lineHistory.len: saved else: lineHistory[histIdx]
          cursor = buf.len; redraw()
      of 'C':
        if cursor < buf.len: inc cursor; redraw()
      of 'D':
        if cursor > 0: dec cursor; redraw()
      of 'H':
        cursor = 0; redraw()
      of 'F':
        cursor = buf.len; redraw()
      of '2':
        var c4: char
        discard c_read(0, addr c4, 1.csize_t)
        if c4 == '0':
          var c5: char
          discard c_read(0, addr c5, 1.csize_t)
          if c5 == '0':
            var c6: char
            discard c_read(0, addr c6, 1.csize_t)
            if c6 == '~':
              var pasted = ""
              var pc: char
              while true:
                if c_read(0, addr pc, 1.csize_t) <= 0: break
                if pc == '\x1b':
                  var pb2, pb3, pb4, pb5, pb6: char
                  if c_read(0, addr pb2, 1.csize_t) <= 0: break
                  if c_read(0, addr pb3, 1.csize_t) <= 0: break
                  if c_read(0, addr pb4, 1.csize_t) <= 0: break
                  if c_read(0, addr pb5, 1.csize_t) <= 0: break
                  if c_read(0, addr pb6, 1.csize_t) <= 0: break
                  if pb2 == '[' and pb3 == '2' and pb4 == '0' and pb5 == '1' and pb6 == '~':
                    break
                  pasted.add pc
                  pasted.add pb2; pasted.add pb3; pasted.add pb4; pasted.add pb5; pasted.add pb6
                elif pc == '\r' or pc == '\n':
                  pasted.add ' '
                elif pc >= ' ':
                  pasted.add pc
              buf = buf[0..<cursor] & pasted & buf[cursor..^1]
              cursor += pasted.len
              redraw()
      of '1', '3', '4':
        var c4: char
        discard c_read(0, addr c4, 1.csize_t)
        case c3
        of '1': cursor = 0; redraw()
        of '4': cursor = buf.len; redraw()
        of '3':
          if cursor < buf.len:
            buf = buf[0..<cursor] & buf[cursor+1..^1]; redraw()
        else: discard
      else: discard
    else:
      if c >= ' ':
        buf = buf[0..<cursor] & $c & buf[cursor..^1]
        inc cursor; redraw()

  if buf.len > 0 and (lineHistory.len == 0 or lineHistory[^1] != buf):
    lineHistory.add buf
  result = buf
