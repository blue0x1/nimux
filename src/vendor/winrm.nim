## ======================================================================
## WinRM Library for Nim
## Author: Chokri Hammedi (blue0x1)
## Source: https://github.com/blue0x1/nim-winrm
## ======================================================================
## Compile: nim c -d:release -d:ssl winrm.nim
##
##
## Legal notice:
##   This tool is intended for lawful administration, security testing,
##   and research on systems you own or have explicit permission to
##   access. The author is not responsible for misuse or damage.

import std/[
  strutils, strformat, base64, os,
  httpclient, terminal, times, random, net,
  asyncdispatch, asyncnet
]
import ../core/proxy as netproxy
import ../protocols/exec/psexec as psexecmod


type
  WinRMError* = object of CatchableError

  WinRMAuthorizationError* = object of WinRMError

  InvalidShellError* = object of WinRMError

  WinRMWSManFault* = object of WinRMError
    faultCode*: string
    faultDescription*: string

  WinRMSoapFault* = object of WinRMError
    code*: string
    subcode*: string
    reason*: string

  WinRMWMIError* = object of WinRMError
    errorCode*: string
    error*: string

  WinRMHTTPTransportError* = object of WinRMError
    statusCode*: int

proc newWinRMWSManFault*(description, code: string): ref WinRMWSManFault =
  result = newException(WinRMWSManFault,
    "[WSMAN ERROR CODE: " & code & "]: " & description)
  result.faultCode = code
  result.faultDescription = description

proc newWinRMSoapFault*(code, subcode, reason: string): ref WinRMSoapFault =
  result = newException(WinRMSoapFault,
    "[SOAP ERROR CODE: " & code & " (" & subcode & ")]: " & reason)
  result.code = code
  result.subcode = subcode
  result.reason = reason

proc newWinRMWMIError*(err, code: string): ref WinRMWMIError =
  result = newException(WinRMWMIError,
    "[WMI ERROR CODE: " & code & "]: " & err)
  result.errorCode = code
  result.error = err

proc newWinRMHTTPTransportError*(msg: string, statusCode: int = 0): ref WinRMHTTPTransportError =
  result = newException(WinRMHTTPTransportError,
    msg & " (" & $statusCode & ").")
  result.statusCode = statusCode


const
  RESOURCE_URI_CMD* = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
  RESOURCE_URI_POWERSHELL* = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"


proc secToDur*(seconds: int): string =
  var secs = seconds
  result = "P"
  if secs > 604_800:
    let weeks = secs div 604_800
    secs -= 604_800 * weeks
    result.add $weeks & "W"
  if secs > 86_400:
    let days = secs div 86_400
    secs -= 86_400 * days
    result.add $days & "D"
  if secs > 0:
    result.add "T"
    if secs > 3600:
      let hours = secs div 3600
      secs -= 3600 * hours
      result.add $hours & "H"
    if secs > 60:
      let minutes = secs div 60
      secs -= 60 * minutes
      result.add $minutes & "M"
    result.add $secs & "S"


const
  WSManMaxEnvelope* = 153600
  WSManOperationTimeout* = 60
  WSManLocale* = "en-US"
  WSManUserAgent* = "nimrm/1.0"


const
  PSRP_SESSION_CAPABILITY*       = 0x00010002'u32
  PSRP_INIT_RUNSPACEPOOL*        = 0x00010004'u32
  PSRP_RUNSPACEPOOL_STATE*       = 0x00021005'u32
  PSRP_CREATE_PIPELINE*          = 0x00021006'u32
  PSRP_PIPELINE_OUTPUT*          = 0x00041004'u32
  PSRP_ERROR_RECORD*             = 0x00041005'u32
  PSRP_PIPELINE_STATE*           = 0x00041006'u32


const
  SHELL_TOO_MANY_COMMANDS* = "2150859174"
  SHELL_NOT_FOUND* = "2150858843"
  RECEIVE_TIMEOUT_FAULT_CODE* = "2150858793"

proc isRetryableFault*(faultCode: string): bool =
  result = faultCode in [SHELL_NOT_FOUND, "2147943418", SHELL_TOO_MANY_COMMANDS]


when defined(linux):
  const gssLib = "libgssapi_krb5.so.2"
elif defined(macosx):
  const gssLib = "libgssapi_krb5.dylib"
else:
  const gssLib = "libgssapi_krb5.so.2"

{.emit: "/*INCLUDESECTION*/\ntypedef void* gss_ctx_id_t;\ntypedef void* gss_cred_id_t;\ntypedef void* gss_name_t;".}

type
  GssUint32  = uint32
  GssOidDesc = object
    length*:   GssUint32
    elements*: pointer
  GssOid = ptr GssOidDesc

  GssBufferDesc = object
    length*: csize_t
    value*:  pointer
  GssBuffer = ptr GssBufferDesc

  GssIovBufferDesc = object
    typ*:    GssUint32
    buffer*: GssBufferDesc

  GssCtxId  = pointer
  GssCredId = pointer
  GssNameT  = pointer

const
  GSS_S_COMPLETE        = 0'u32
  GSS_S_CONTINUE_NEEDED = 1'u32

var
  GSS_C_NO_CREDENTIAL* : GssCredId = nil
  GSS_C_NO_OID*        : GssOid    = nil

proc gss_import_name(
  minor:    ptr GssUint32,
  input:    GssBuffer,
  nameType: GssOid,
  output:   ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_init_sec_context(
  minor:        ptr GssUint32,
  cred:         GssCredId,
  ctx:          ptr GssCtxId,
  target:       GssNameT,
  mechType:     GssOid,
  reqFlags:     GssUint32,
  timeReq:      GssUint32,
  chanBindings: pointer,
  input:        GssBuffer,
  actualMech:   ptr GssOid,
  output:       GssBuffer,
  retFlags:     ptr GssUint32,
  timeRec:      ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_buffer(
  minor: ptr GssUint32,
  buf:   GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_name(
  minor: ptr GssUint32,
  name:  ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_delete_sec_context(
  minor: ptr GssUint32,
  ctx:   ptr GssCtxId,
  buf:   GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_display_status(
  minor:      ptr GssUint32,
  status:     GssUint32,
  statusType: cint,
  mechType:   GssOid,
  msgCtx:     ptr GssUint32,
  output:     GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confReq:   cint,
  qopReq:    GssUint32,
  input:     GssBuffer,
  confState: ptr cint,
  output:    GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  input:     GssBuffer,
  output:    GssBuffer,
  confState: ptr cint,
  qopState:  ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap_iov(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confReq:   cint,
  qopReq:    GssUint32,
  confState: ptr cint,
  iov:       ptr GssIovBufferDesc,
  iovCount:  cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap_iov(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confState: ptr cint,
  qopState:  ptr GssUint32,
  iov:       ptr GssIovBufferDesc,
  iovCount:  cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_iov_buffer(
  minor:    ptr GssUint32,
  iov:      ptr GssIovBufferDesc,
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gssError(major, minor: GssUint32): string =
  var m2: GssUint32
  var ctx: GssUint32 = 0
  var buf = GssBufferDesc(length: 0, value: nil)
  discard gss_display_status(addr m2, major, 1.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    let p = cast[ptr UncheckedArray[byte]](buf.value)
    for i in 0..<int(buf.length): result.add char(p[i])
    discard gss_release_buffer(addr m2, addr buf)
  ctx = 0
  discard gss_display_status(addr m2, minor, 2.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    result.add " — "
    let p = cast[ptr UncheckedArray[byte]](buf.value)
    for i in 0..<int(buf.length): result.add char(p[i])
    discard gss_release_buffer(addr m2, addr buf)
  if result.len == 0:
    result = fmt"major={major} minor={minor}"


proc toLE16(s: string): seq[byte] =
  for c in s:
    result.add byte(ord(c))
    result.add 0x00'u8

proc toLE32(v: uint32): array[4, byte] =
  result[0] = byte(v and 0xFF)
  result[1] = byte((v shr  8) and 0xFF)
  result[2] = byte((v shr 16) and 0xFF)
  result[3] = byte((v shr 24) and 0xFF)

proc toBE32(v: uint32): array[4, byte] =
  result[0] = byte((v shr 24) and 0xFF)
  result[1] = byte((v shr 16) and 0xFF)
  result[2] = byte((v shr 8) and 0xFF)
  result[3] = byte(v and 0xFF)

proc toBE64(v: uint64): array[8, byte] =
  for i in 0..7:
    result[i] = byte((v shr ((7 - i) * 8)) and 0xFF)

proc toLE16u(v: uint16): array[2, byte] =
  result[0] = byte(v and 0xFF)
  result[1] = byte((v shr 8) and 0xFF)

proc readLE32(data: openArray[byte], offset: int): uint32 =
  result = uint32(data[offset]) or
           (uint32(data[offset+1]) shl  8) or
           (uint32(data[offset+2]) shl 16) or
           (uint32(data[offset+3]) shl 24)

proc readLE16(data: openArray[byte], offset: int): uint16 =
  result = uint16(data[offset]) or (uint16(data[offset+1]) shl 8)

proc readLE32Str(data: string, offset: int): uint32 =
  result = uint32(ord(data[offset])) or
           (uint32(ord(data[offset + 1])) shl 8) or
           (uint32(ord(data[offset + 2])) shl 16) or
           (uint32(ord(data[offset + 3])) shl 24)

proc hasBytes(data: string, offset, count: int): bool =
  offset >= 0 and count >= 0 and offset <= data.len and count <= data.len - offset

proc readLE16Str(data: string, offset: int): uint16 =
  result = uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)


proc rvaToOffset(data: string, peOffset, rva: int): int =
  if not hasBytes(data, peOffset + 20, 4): return -1
  let sectionCount = int(readLE16Str(data, peOffset + 6))
  let optionalSize = int(readLE16Str(data, peOffset + 20))
  let sectionOffset = peOffset + 24 + optionalSize
  for i in 0..<sectionCount:
    let off = sectionOffset + (i * 40)
    if not hasBytes(data, off, 40): return -1
    let virtualSize = int(readLE32Str(data, off + 8))
    let virtualAddress = int(readLE32Str(data, off + 12))
    let rawSize = int(readLE32Str(data, off + 16))
    let rawPointer = int(readLE32Str(data, off + 20))
    let span = max(virtualSize, rawSize)
    if span > 0 and rva >= virtualAddress and rva < virtualAddress + span:
      let fileOffset = rawPointer + (rva - virtualAddress)
      if hasBytes(data, fileOffset, 1): return fileOffset
      return -1
  result = -1

proc isManagedPe*(data: string): bool =
  if not hasBytes(data, 0, 0x40): return false
  if data[0] != 'M' or data[1] != 'Z': return false
  let peOffset = int(readLE32Str(data, 0x3c))
  if not hasBytes(data, peOffset, 24): return false
  if data[peOffset] != 'P' or data[peOffset + 1] != 'E' or data[peOffset + 2] != '\0' or data[peOffset + 3] != '\0':
    return false

  let optionalOffset = peOffset + 24
  if not hasBytes(data, optionalOffset, 2): return false
  let magic = readLE16Str(data, optionalOffset)
  let dataDirectoryOffset =
    case magic
    of 0x10b'u16: optionalOffset + 96
    of 0x20b'u16: optionalOffset + 112
    else: return false

  let clrDirectoryOffset = dataDirectoryOffset + (14 * 8)
  if not hasBytes(data, clrDirectoryOffset, 8): return false
  let clrRva = int(readLE32Str(data, clrDirectoryOffset))
  let clrSize = int(readLE32Str(data, clrDirectoryOffset + 4))
  if clrRva == 0 or clrSize == 0: return false
  result = rvaToOffset(data, peOffset, clrRva) >= 0


proc md4(msg: openArray[byte]): array[16, byte] =
  proc fF(x, y, z: uint32): uint32 = (x and y) or ((not x) and z)
  proc fG(x, y, z: uint32): uint32 = (x and y) or (x and z) or (y and z)
  proc fH(x, y, z: uint32): uint32 = x xor y xor z
  proc rol(x: uint32, n: int): uint32 = (x shl n) or (x shr (32 - n))

  var m: seq[byte]
  for b in msg: m.add b
  let origLen = m.len
  m.add 0x80'u8
  while (m.len mod 64) != 56: m.add 0x00'u8
  let bl = uint64(origLen) * 8
  for i in 0..7: m.add byte((bl shr (i*8)) and 0xFF)

  var A: uint32 = 0x67452301'u32
  var B: uint32 = 0xefcdab89'u32
  var C: uint32 = 0x98badcfe'u32
  var D: uint32 = 0x10325476'u32

  var i = 0
  while i < m.len:
    var X: array[16, uint32]
    for j in 0..15:
      let o = i + j*4
      X[j] = uint32(m[o]) or (uint32(m[o+1]) shl 8) or
             (uint32(m[o+2]) shl 16) or (uint32(m[o+3]) shl 24)
    let AA = A; let BB = B; let CC = C; let DD = D

    let s1 = [3,7,11,19]
    for idx in 0..15:
      let s = s1[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fF(B,C,D) + X[idx], s)
      of 1: D = rol(D + fF(A,B,C) + X[idx], s)
      of 2: C = rol(C + fF(D,A,B) + X[idx], s)
      else: B = rol(B + fF(C,D,A) + X[idx], s)

    let s2  = [3,5,9,13]
    let o2  = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    for idx in 0..15:
      let k = o2[idx]; let s = s2[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fG(B,C,D) + X[k] + 0x5A827999'u32, s)
      of 1: D = rol(D + fG(A,B,C) + X[k] + 0x5A827999'u32, s)
      of 2: C = rol(C + fG(D,A,B) + X[k] + 0x5A827999'u32, s)
      else: B = rol(B + fG(C,D,A) + X[k] + 0x5A827999'u32, s)

    let s3  = [3,9,11,15]
    let o3  = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    for idx in 0..15:
      let k = o3[idx]; let s = s3[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fH(B,C,D) + X[k] + 0x6ED9EBA1'u32, s)
      of 1: D = rol(D + fH(A,B,C) + X[k] + 0x6ED9EBA1'u32, s)
      of 2: C = rol(C + fH(D,A,B) + X[k] + 0x6ED9EBA1'u32, s)
      else: B = rol(B + fH(C,D,A) + X[k] + 0x6ED9EBA1'u32, s)

    A += AA; B += BB; C += CC; D += DD
    i += 64

  for idx in 0..3: result[idx]    = byte((A shr (idx*8)) and 0xFF)
  for idx in 0..3: result[4+idx]  = byte((B shr (idx*8)) and 0xFF)
  for idx in 0..3: result[8+idx]  = byte((C shr (idx*8)) and 0xFF)
  for idx in 0..3: result[12+idx] = byte((D shr (idx*8)) and 0xFF)


proc md5(data: openArray[byte]): array[16, byte] =
  const T: array[64, uint32] = [
    0xd76aa478'u32, 0xe8c7b756'u32, 0x242070db'u32, 0xc1bdceee'u32,
    0xf57c0faf'u32, 0x4787c62a'u32, 0xa8304613'u32, 0xfd469501'u32,
    0x698098d8'u32, 0x8b44f7af'u32, 0xffff5bb1'u32, 0x895cd7be'u32,
    0x6b901122'u32, 0xfd987193'u32, 0xa679438e'u32, 0x49b40821'u32,
    0xf61e2562'u32, 0xc040b340'u32, 0x265e5a51'u32, 0xe9b6c7aa'u32,
    0xd62f105d'u32, 0x02441453'u32, 0xd8a1e681'u32, 0xe7d3fbc8'u32,
    0x21e1cde6'u32, 0xc33707d6'u32, 0xf4d50d87'u32, 0x455a14ed'u32,
    0xa9e3e905'u32, 0xfcefa3f8'u32, 0x676f02d9'u32, 0x8d2a4c8a'u32,
    0xfffa3942'u32, 0x8771f681'u32, 0x6d9d6122'u32, 0xfde5380c'u32,
    0xa4beea44'u32, 0x4bdecfa9'u32, 0xf6bb4b60'u32, 0xbebfbc70'u32,
    0x289b7ec6'u32, 0xeaa127fa'u32, 0xd4ef3085'u32, 0x04881d05'u32,
    0xd9d4d039'u32, 0xe6db99e5'u32, 0x1fa27cf8'u32, 0xc4ac5665'u32,
    0xf4292244'u32, 0x432aff97'u32, 0xab9423a7'u32, 0xfc93a039'u32,
    0x655b59c3'u32, 0x8f0ccc92'u32, 0xffeff47d'u32, 0x85845dd1'u32,
    0x6fa87e4f'u32, 0xfe2ce6e0'u32, 0xa3014314'u32, 0x4e0811a1'u32,
    0xf7537e82'u32, 0xbd3af235'u32, 0x2ad7d2bb'u32, 0xeb86d391'u32
  ]
  const S: array[64, uint32] = [
    7'u32,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20,      5,9,14,20,  5,9,14,20,  5,9,14,20,
    4,11,16,23,     4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21,     6,10,15,21, 6,10,15,21, 6,10,15,21
  ]

  proc rol32(x, n: uint32): uint32 = (x shl n) or (x shr (32'u32 - n))

  var m: seq[byte]
  for b in data: m.add b
  let origLen = m.len
  m.add 0x80'u8
  while (m.len mod 64) != 56: m.add 0x00'u8
  let bl = uint64(origLen) * 8
  for i in 0..7: m.add byte((bl shr (i*8)) and 0xFF)

  var a0: uint32 = 0x67452301'u32
  var b0: uint32 = 0xefcdab89'u32
  var c0: uint32 = 0x98badcfe'u32
  var d0: uint32 = 0x10325476'u32

  var i = 0
  while i < m.len:
    var M: array[16, uint32]
    for j in 0..15:
      let o = i + j*4
      M[j] = uint32(m[o]) or (uint32(m[o+1]) shl 8) or
             (uint32(m[o+2]) shl 16) or (uint32(m[o+3]) shl 24)
    var a = a0; var b = b0; var c = c0; var d = d0
    for j in 0..63:
      var F: uint32
      var g: int
      if j < 16:
        F = (b and c) or ((not b) and d); g = j
      elif j < 32:
        F = (d and b) or ((not d) and c); g = (5*j + 1) mod 16
      elif j < 48:
        F = b xor c xor d; g = (3*j + 5) mod 16
      else:
        F = c xor (b or (not d)); g = (7*j) mod 16
      F = F + a + T[j] + M[g]
      a = d; d = c; c = b
      b = b + rol32(F, S[j])
    a0 += a; b0 += b; c0 += c; d0 += d
    i += 64

  for idx in 0..3: result[idx]    = byte((a0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[4+idx]  = byte((b0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[8+idx]  = byte((c0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[12+idx] = byte((d0 shr (idx*8)) and 0xFF)

proc hmacMd5(key, data: openArray[byte]): array[16, byte] =
  var k: array[64, byte]
  if key.len > 64:
    let h = md5(key)
    for i in 0..15: k[i] = h[i]
  else:
    for i in 0..<key.len: k[i] = key[i]
  var ipad, opad: array[64, byte]
  for i in 0..63:
    ipad[i] = k[i] xor 0x36'u8
    opad[i] = k[i] xor 0x5c'u8
  var inner = newSeq[byte](64 + data.len)
  for i in 0..63: inner[i] = ipad[i]
  for i, b in data: inner[64+i] = b
  let ih = md5(inner)
  var outer = newSeq[byte](80)
  for i in 0..63: outer[i] = opad[i]
  for i in 0..15: outer[64+i] = ih[i]
  result = md5(outer)

proc hexNibble(c: char): int =
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

proc parseNtHash(hashSpec: string): array[16, byte] =
  var h = hashSpec.strip()
  if ":" in h:
    h = h.split(':')[^1].strip()
  h = h.replace(" ", "")
  if h.len != 32:
    raise newException(ValueError, "NT hash must be 32 hex chars, or LM:NT")
  for i in 0..<16:
    let hi = hexNibble(h[i * 2])
    let lo = hexNibble(h[i * 2 + 1])
    if hi < 0 or lo < 0:
      raise newException(ValueError, "NT hash contains non-hex characters")
    result[i] = byte((hi shl 4) or lo)


const
  NTLM_SIG    = "NTLMSSP\x00"
  NTLM_FLAGS  = 0xe2088237'u32
  NTLM_AUTH_FLAGS = 0xe2088237'u32

proc derLen(n: int): seq[byte] =
  if n < 0x80:
    return @[byte(n)]
  var tmp: seq[byte]
  var v = n
  while v > 0:
    tmp.insert(byte(v and 0xff), 0)
    v = v shr 8
  result.add byte(0x80 or tmp.len)
  result.add tmp

proc derTLV(tag: byte, value: seq[byte]): seq[byte] =
  result.add tag
  result.add derLen(value.len)
  result.add value

proc bytesOf(s: string): seq[byte] =
  for ch in s:
    result.add byte(ord(ch))

proc spnegoInit(ntlmToken: string): string =
  let spnegoOid = @[0x06'u8, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
  let ntlmOid = derTLV(0x06'u8, @[0x2b'u8, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
  let mechTypes = derTLV(0xa0'u8, derTLV(0x30'u8, ntlmOid))
  let mechToken = derTLV(0xa2'u8, derTLV(0x04'u8, bytesOf(ntlmToken)))
  let negTokenInit = derTLV(0xa0'u8, derTLV(0x30'u8, mechTypes & mechToken))
  result = cast[string](derTLV(0x60'u8, spnegoOid & negTokenInit))

proc spnegoResp(ntlmToken: string): string =
  let negState = derTLV(0xa0'u8, derTLV(0x0a'u8, @[0x01'u8]))
  let responseToken = derTLV(0xa2'u8, derTLV(0x04'u8, bytesOf(ntlmToken)))
  result = cast[string](derTLV(0xa1'u8, derTLV(0x30'u8, negState & responseToken)))

proc unwrapNtlmToken(tok: string): string =
  let idx = tok.find(NTLM_SIG)
  if idx >= 0:
    return tok[idx..^1]
  result = tok

proc rc4(key, data: openArray[byte]): seq[byte] =
  var s: array[256, byte]
  for i in 0..255: s[i] = byte(i)
  var j = 0
  for i in 0..255:
    j = (j + int(s[i]) + int(key[i mod key.len])) and 0xff
    swap(s[i], s[j])
  var i = 0
  j = 0
  result = newSeq[byte](data.len)
  for n in 0..<data.len:
    i = (i + 1) and 0xff
    j = (j + int(s[i])) and 0xff
    swap(s[i], s[j])
    let k = s[(int(s[i]) + int(s[j])) and 0xff]
    result[n] = data[n] xor k

type RC4Handle = ref object
  s: array[256, byte]
  i, j: int

proc newRC4Handle(key: openArray[byte]): RC4Handle =
  result = RC4Handle()
  for i in 0..255: result.s[i] = byte(i)
  var j = 0
  for i in 0..255:
    j = (j + int(result.s[i]) + int(key[i mod key.len])) and 0xff
    swap(result.s[i], result.s[j])

proc rc4Update(h: RC4Handle, data: openArray[byte]): seq[byte] =
  result = newSeq[byte](data.len)
  for n in 0..<data.len:
    h.i = (h.i + 1) and 0xff
    h.j = (h.j + int(h.s[h.i])) and 0xff
    swap(h.s[h.i], h.s[h.j])
    let k = h.s[(int(h.s[h.i]) + int(h.s[h.j])) and 0xff]
    result[n] = data[n] xor k

proc buildNtlmNegotiate(): string =
  var msg: seq[byte]
  for c in NTLM_SIG: msg.add byte(ord(c))
  let t = toLE32(1'u32); msg.add t
  let f = toLE32(NTLM_FLAGS); msg.add f
  for _ in 0..1:
    msg.add 0'u8; msg.add 0'u8
    msg.add 0'u8; msg.add 0'u8
    msg.add 0x28'u8; msg.add 0'u8; msg.add 0'u8; msg.add 0'u8
  msg.add [0x06'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x0f]
  result = cast[string](msg)

type NtlmChallenge = object
  serverChallenge: array[8, byte]
  targetName:      string
  targetInfo:      seq[byte]
  flags:           uint32

proc ntlmAvValue(targetInfo: seq[byte], avIdNeed: uint16): seq[byte] =
  var off = 0
  while off + 4 <= targetInfo.len:
    let avId = readLE16(targetInfo, off)
    let avLen = int(readLE16(targetInfo, off + 2))
    off += 4
    if avId == 0'u16:
      break
    if off + avLen > targetInfo.len:
      break
    if avId == avIdNeed:
      return targetInfo[off ..< off + avLen]
    off += avLen

proc parseChallenge(raw: seq[byte]): NtlmChallenge =
  let sig = cast[string](raw[0..7])
  if sig != NTLM_SIG:
    raise newException(ValueError, "Bad NTLM challenge signature")
  let msgType = readLE32(raw, 8)
  if msgType != 2:
    raise newException(ValueError, "Expected NTLM type 2")
  let tnLen    = int(readLE16(raw, 12))
  let tnOffset = int(readLE32(raw, 16))
  var tn16: string
  for i in 0..<tnLen: tn16.add char(raw[tnOffset+i])
  var tn: string
  var i = 0
  while i + 1 < tn16.len:
    if tn16[i] != '\x00': tn.add tn16[i]
    i += 2
  result.targetName = tn
  result.flags = readLE32(raw, 20)
  for i in 0..7: result.serverChallenge[i] = raw[24+i]
  if raw.len >= 48:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] NTLM type2 flags: 0x" & result.flags.toHex(8))
      styledEcho(fgYellow, "[debug] NTLM target name: " & tn)
    let tiLen = int(readLE16(raw, 40))
    let tiOffset = int(readLE32(raw, 44))
    if tiLen > 0 and tiOffset >= 0 and tiOffset + tiLen <= raw.len:
      result.targetInfo = raw[tiOffset ..< tiOffset + tiLen]
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[debug] NTLM target info bytes: " & $tiLen)
        var avOff = 0
        while avOff + 4 <= result.targetInfo.len:
          let avId = readLE16(result.targetInfo, avOff)
          let avLen = int(readLE16(result.targetInfo, avOff + 2))
          avOff += 4
          if avId == 0'u16:
            styledEcho(fgYellow, "[debug] NTLM AV EOL")
            break
          if avOff + avLen > result.targetInfo.len:
            styledEcho(fgYellow, "[debug] NTLM AV malformed id=" & $avId & " len=" & $avLen)
            break
          var avText = ""
          if avId in {1'u16, 2'u16, 3'u16, 4'u16, 5'u16, 9'u16}:
            var j = avOff
            while j + 1 < avOff + avLen:
              if result.targetInfo[j] != 0'u8:
                avText.add char(result.targetInfo[j])
              j += 2
          elif avId == 6'u16 and avLen >= 4:
            avText = "0x" & readLE32(result.targetInfo, avOff).toHex(8)
          styledEcho(fgYellow, "[debug] NTLM AV id=" & $avId & " len=" & $avLen & (if avText != "": " val=" & avText else: ""))
          avOff += avLen

proc buildNtlmAuthenticate(
  username, password, domain, workstation, ntHashHex: string,
  chall: NtlmChallenge,
  outSessionKey: var array[16, byte]
): string =
  let authDomain = domain
  let nh = if ntHashHex != "": parseNtHash(ntHashHex) else: md4(toLE16(password))

  var cc: array[8, byte]
  for i in 0..7: cc[i] = byte(rand(255))

  var ts: array[8, byte]
  let serverTs = ntlmAvValue(chall.targetInfo, 7'u16)
  if serverTs.len == 8:
    for i in 0..7: ts[i] = serverTs[i]
  else:
    let epoch = getTime().toUnix()
    let wt    = uint64(epoch) * 10_000_000'u64 + 116_444_736_000_000_000'u64
    for i in 0..7: ts[i] = byte((wt shr (i*8)) and 0xFF)

  let utd   = toLE16(username.toUpperAscii() & authDomain)
  let nhKey = hmacMd5(nh, utd)

  var blob: seq[byte]
  blob.add [0x01'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x00]
  blob.add ts
  blob.add cc
  blob.add [0x00'u8,0x00,0x00,0x00]
  if chall.targetInfo.len > 0:
    blob.add chall.targetInfo
    if chall.targetInfo.len < 4 or chall.targetInfo[^4..^1] != @[0x00'u8, 0x00, 0x00, 0x00]:
      blob.add [0x00'u8,0x00,0x00,0x00]
  else:
    let tnb = toLE16(authDomain)
    blob.add [0x02'u8,0x00]
    let tnbLen = toLE16u(uint16(tnb.len))
    blob.add tnbLen[0]; blob.add tnbLen[1]
    blob.add tnb
    blob.add [0x00'u8,0x00,0x00,0x00]

  var challData: seq[byte]
  challData.add chall.serverChallenge
  challData.add blob
  let ntProof = hmacMd5(nhKey, challData)

  var ntResp: seq[byte]
  ntResp.add ntProof
  ntResp.add blob

  let sessionBaseKey = hmacMd5(nhKey, ntProof)
  var exportedSessionKey: array[16, byte]
  for i in 0..15: exportedSessionKey[i] = byte(rand(255))
  let encSessionKey = rc4(sessionBaseKey, exportedSessionKey)

  var lmData: seq[byte]
  lmData.add chall.serverChallenge
  lmData.add cc
  let lmProof = hmacMd5(nhKey, lmData)
  var lmResp: seq[byte]
  lmResp.add lmProof
  lmResp.add cc

  let domB  = toLE16(authDomain)
  let userB = toLE16(username)
  let wsB   = toLE16(workstation)

  let includeVersion = (chall.flags and 0x02000000'u32) != 0
  let baseOff: uint32 = if includeVersion: 72'u32 else: 64'u32
  var payload: seq[byte]
  var offs: array[6, uint32]

  offs[0] = baseOff + uint32(payload.len); payload.add lmResp
  offs[1] = baseOff + uint32(payload.len); payload.add ntResp
  offs[2] = baseOff + uint32(payload.len); payload.add domB
  offs[3] = baseOff + uint32(payload.len); payload.add userB
  offs[4] = baseOff + uint32(payload.len); payload.add wsB
  offs[5] = baseOff + uint32(payload.len); payload.add encSessionKey

  var msg: seq[byte]
  for c in NTLM_SIG: msg.add byte(ord(c))
  let t = toLE32(3'u32); msg.add t

  proc addSB(data: seq[byte], off: uint32) =
    let ln = toLE16u(uint16(data.len))
    let o4 = toLE32(off)
    msg.add ln[0]; msg.add ln[1]
    msg.add ln[0]; msg.add ln[1]
    msg.add o4[0]; msg.add o4[1]; msg.add o4[2]; msg.add o4[3]

  addSB(lmResp, offs[0])
  addSB(ntResp, offs[1])
  addSB(domB,   offs[2])
  addSB(userB,  offs[3])
  addSB(wsB,    offs[4])
  addSB(encSessionKey, offs[5])

  let negotiatedFlags = chall.flags and NTLM_AUTH_FLAGS
  let flags = toLE32(negotiatedFlags); msg.add flags
  if includeVersion:
    msg.add [0x06'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x0f]
  msg.add payload
  outSessionKey = exportedSessionKey
  result = cast[string](msg)


proc importSpn(host, realm, spnOverride: string): GssNameT =
  var minor: GssUint32

  var hostOnly = host.strip()
  if hostOnly.len > 0 and hostOnly[hostOnly.len-1] == '.':
    hostOnly = hostOnly[0..hostOnly.len-2]
  if ':' in hostOnly:
    hostOnly = hostOnly.split(':')[0]
  let hostForOverride = hostOnly
  hostOnly = hostOnly.toLowerAscii()

  var realmNorm = realm.strip()
  if realmNorm.len > 0:
    realmNorm = realmNorm.toUpperAscii()

  var krbPrincipalElems: array[10, byte] = [0x2a'u8, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01]
  var krbPrincipalDesc  = GssOidDesc(length: 10, elements: addr krbPrincipalElems[0])
  var svcElems: array[6, byte] = [0x2b'u8, 0x06, 0x01, 0x05, 0x06, 0x02]
  var svcDesc  = GssOidDesc(length: 6, elements: addr svcElems[0])

  let explicitSpn = spnOverride.strip()
  if explicitSpn != "":
    var candidates: seq[string]
    if "/" notin explicitSpn and "@" notin explicitSpn:
      if realmNorm.len > 0:
        candidates.add explicitSpn & "/" & hostForOverride & "@" & realmNorm
      candidates.add explicitSpn & "/" & hostForOverride
      candidates.add explicitSpn & "@" & hostForOverride
    elif "/" in explicitSpn and "@" notin explicitSpn and realmNorm.len > 0:
      candidates.add explicitSpn & "@" & realmNorm
    candidates.add explicitSpn

    var lastMaj: GssUint32 = 0
    var lastMin: GssUint32 = 0
    for candidate in candidates:
      var ibufExplicit = GssBufferDesc(length: csize_t(candidate.len), value: cstring(candidate))
      var impExplicit = gss_import_name(addr minor, addr ibufExplicit, addr krbPrincipalDesc, addr result)
      if impExplicit == GSS_S_COMPLETE:
        if getEnv("WINRMSHELL_DEBUG") == "1":
          styledEcho(fgYellow, "[*] importSpn: imported override " & candidate & " as Kerberos principal")
        return result
      if lastMaj == 0: lastMaj = impExplicit; lastMin = minor

      ibufExplicit = GssBufferDesc(length: csize_t(candidate.len), value: cstring(candidate))
      impExplicit = gss_import_name(addr minor, addr ibufExplicit, addr svcDesc, addr result)
      if impExplicit == GSS_S_COMPLETE:
        if getEnv("WINRMSHELL_DEBUG") == "1":
          styledEcho(fgYellow, "[*] importSpn: imported override " & candidate & " as host-based service")
        return result
    raise newException(OSError, "gss_import_name failed for SPN override " & explicitSpn & ": " & gssError(lastMaj, lastMin))

  var lastMaj: GssUint32 = 0
  var lastMin: GssUint32 = 0
  var chosenSpn = ""

  if realmNorm != "":
    chosenSpn = "HTTP/" & hostOnly & "@" & realmNorm
    var ibufRealm = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
    let impRealm = gss_import_name(addr minor, addr ibufRealm, GSS_C_NO_OID, addr result)
    if impRealm == GSS_S_COMPLETE:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as KRB5 principal (with realm)")
      return result
    else:
      if lastMaj == 0: lastMaj = impRealm; lastMin = minor

  chosenSpn = "HTTP/" & hostOnly
  var ibufSlash = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impSlash = gss_import_name(addr minor, addr ibufSlash, addr svcDesc, addr result)
  if impSlash == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as host-based service (svcDesc)")
    return result
  else:
    if lastMaj == 0: lastMaj = impSlash; lastMin = minor

  chosenSpn = "HTTP/" & hostOnly
  var ibufOld = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impOld = gss_import_name(addr minor, addr ibufOld, addr krbPrincipalDesc, addr result)
  if impOld == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as Kerberos principal without realm")
    return result
  else:
    if lastMaj == 0: lastMaj = impOld; lastMin = minor

  chosenSpn = "HTTP@" & hostOnly
  var ibufAt = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impAt = gss_import_name(addr minor, addr ibufAt, addr svcDesc, addr result)
  if impAt == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as host-based service (svcDesc)")
    return result
  else:
    if lastMaj == 0: lastMaj = impAt; lastMin = minor

  if realmNorm != "":
    chosenSpn = "http/" & hostOnly & "@" & realmNorm
    var ibufLcRealm = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
    let impLcRealm = gss_import_name(addr minor, addr ibufLcRealm, GSS_C_NO_OID, addr result)
    if impLcRealm == GSS_S_COMPLETE:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as KRB5 principal (lowercase http, with realm)")
      return result

  chosenSpn = "http/" & hostOnly
  var ibufLcSlash = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impLcSlash = gss_import_name(addr minor, addr ibufLcSlash, addr krbPrincipalDesc, addr result)
  if impLcSlash == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as Kerberos principal (lowercase http)")
    return result

  chosenSpn = "http@" & hostOnly
  var ibufLcAt = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impLcAt = gss_import_name(addr minor, addr ibufLcAt, addr svcDesc, addr result)
  if impLcAt == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as host-based service (lowercase http)")
    return result

  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgRed, "[*] importSpn: failed attempts, last error: " & gssError(if lastMaj != 0: lastMaj else: impAt, if lastMaj != 0: lastMin else: minor))

  raise newException(OSError, "gss_import_name failed: " & gssError(if lastMaj != 0: lastMaj else: impAt, if lastMaj != 0: lastMin else: minor))


proc wrapSoap(ctx: GssCtxId, soap: string): string =
  const
    GSS_IOV_BUFFER_TYPE_DATA = 1'u32
    GSS_IOV_BUFFER_TYPE_HEADER = 2'u32
    GSS_IOV_BUFFER_TYPE_PADDING = 9'u32
    GSS_IOV_BUFFER_FLAG_ALLOCATE = 0x10000'u32

  var minor: GssUint32
  var soapCopy = soap
  var iov: array[3, GssIovBufferDesc]
  iov[0].typ = GSS_IOV_BUFFER_TYPE_HEADER or GSS_IOV_BUFFER_FLAG_ALLOCATE
  iov[1].typ = GSS_IOV_BUFFER_TYPE_DATA
  iov[1].buffer = GssBufferDesc(
    length: csize_t(soapCopy.len),
    value:  if soapCopy.len > 0: cast[pointer](addr soapCopy[0]) else: nil)
  iov[2].typ = GSS_IOV_BUFFER_TYPE_PADDING or GSS_IOV_BUFFER_FLAG_ALLOCATE

  var confSt: cint = 0
  let maj = gss_wrap_iov(addr minor, ctx, 1.cint, 0'u32, addr confSt, addr iov[0], 3.cint)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_wrap_iov failed: " & gssError(maj, minor))

  var frame = ""
  let headerLen = uint32(iov[0].buffer.length)
  for b in toLE32(headerLen): frame.add char(b)
  if iov[0].buffer.value != nil and iov[0].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[0].buffer.value)
    for i in 0..<int(iov[0].buffer.length): frame.add char(p[i])
  if iov[1].buffer.value != nil and iov[1].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[1].buffer.value)
    for i in 0..<int(iov[1].buffer.length): frame.add char(p[i])
  if iov[2].buffer.value != nil and iov[2].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[2].buffer.value)
    for i in 0..<int(iov[2].buffer.length): frame.add char(p[i])
  let originalLen = soap.len + int(iov[2].buffer.length)

  discard gss_release_iov_buffer(addr minor, addr iov[0], 3.cint)

  result =
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/HTTP-Kerberos-session-encrypted\r\n" &
    "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" & $originalLen & "\r\n" &
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/octet-stream\r\n" &
    frame &
    "--Encrypted Boundary--\r\n"

proc unwrapResponse(ctx: GssCtxId, body: string): string =
  const
    GSS_IOV_BUFFER_TYPE_DATA = 1'u32
    GSS_IOV_BUFFER_TYPE_HEADER = 2'u32

  const octetMarker = "application/octet-stream"
  let octetIdx = body.find(octetMarker)
  if octetIdx < 0: return body

  var originalLen = -1
  let ocIdx = body.find("OriginalContent:")
  if ocIdx >= 0 and ocIdx < octetIdx:
    let lenIdx = body.find("Length=", ocIdx)
    if lenIdx >= 0 and lenIdx < octetIdx:
      var pos = lenIdx + "Length=".len
      var digits: string
      while pos < body.len and body[pos] in {'0'..'9'}:
        digits.add body[pos]
        inc pos
      if digits.len > 0:
        try: originalLen = parseInt(digits)
        except: originalLen = -1

  var dataStart = octetIdx + octetMarker.len

  let marker = "\r\n"
  let bodyStart = body.find(marker, dataStart)
  if bodyStart < 0: return body
  dataStart = bodyStart + marker.len

  let endMark = "\r\n--Encrypted Boundary"
  var binEnd  = body.find(endMark, dataStart)
  if binEnd < 0:
    binEnd = body.find("\n--Encrypted Boundary", dataStart)
  if binEnd < 0:
    binEnd = body.find("--Encrypted Boundary", dataStart)
  if binEnd < 0: binEnd = body.len

  if binEnd <= dataStart + 4: return body

  let headerLen = int(uint32(ord(body[dataStart])) or
                      (uint32(ord(body[dataStart + 1])) shl 8) or
                      (uint32(ord(body[dataStart + 2])) shl 16) or
                      (uint32(ord(body[dataStart + 3])) shl 24))
  let headerStart = dataStart + 4
  let dataPartStart = headerStart + headerLen
  if dataPartStart > binEnd: return body
  if originalLen >= 0 and dataPartStart + originalLen <= body.len:
    binEnd = dataPartStart + originalLen

  var headerBytes = body[headerStart..<dataPartStart]
  var encBytes = body[dataPartStart..<binEnd]
  var minor: GssUint32
  var iov: array[3, GssIovBufferDesc]
  iov[0].typ = GSS_IOV_BUFFER_TYPE_HEADER
  iov[0].buffer = GssBufferDesc(
    length: csize_t(headerBytes.len),
    value: if headerBytes.len > 0: cast[pointer](addr headerBytes[0]) else: nil)
  iov[1].typ = GSS_IOV_BUFFER_TYPE_DATA
  iov[1].buffer = GssBufferDesc(
    length: csize_t(encBytes.len),
    value: if encBytes.len > 0: cast[pointer](addr encBytes[0]) else: nil)
  iov[2].typ = GSS_IOV_BUFFER_TYPE_DATA
  var confSt: cint = 0
  var qopSt:  GssUint32 = 0
  let maj = gss_unwrap_iov(addr minor, ctx, addr confSt, addr qopSt, addr iov[0], 3.cint)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_unwrap_iov failed: " & gssError(maj, minor))

  if iov[1].buffer.value != nil and iov[1].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[1].buffer.value)
    for i in 0..<int(iov[1].buffer.length): result.add char(p[i])


proc genUuid*(): string =
  var b: array[16, byte]
  for i in 0..15: b[i] = byte(rand(255))
  b[6] = (b[6] and 0x0F) or 0x40
  b[8] = (b[8] and 0x3F) or 0x80
  result = fmt"{b[0]:02x}{b[1]:02x}{b[2]:02x}{b[3]:02x}-" &
           fmt"{b[4]:02x}{b[5]:02x}-{b[6]:02x}{b[7]:02x}-" &
           fmt"{b[8]:02x}{b[9]:02x}-" &
           fmt"{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}"

proc uuidToWindowsGuidBytes*(uuid: string): seq[byte] =
  if uuid == "" or uuid.len < 32:
    for _ in 0..<16: result.add 0'u8
    return
  let h = uuid.replace("-", "")
  if h.len != 32:
    for _ in 0..<16: result.add 0'u8
    return
  var raw: array[16, byte]
  for i in 0..<16:
    raw[i] = byte(parseHexInt(h[i * 2 .. i * 2 + 1]))
  for i in [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]:
    result.add raw[i]


proc xmlEscape(s: string): string =
  for c in s:
    case c
    of '&': result.add "&amp;"
    of '<': result.add "&lt;"
    of '>': result.add "&gt;"
    of '"': result.add "&quot;"
    of '\'': result.add "&apos;"
    else: result.add c

proc xmlVal(xml, tag: string): string =
  let open  = "<" & tag
  let close = "</" & tag & ">"
  let si = xml.find(open)
  if si < 0: return ""
  let vi = xml.find('>', si)
  if vi < 0: return ""
  let ei = xml.find(close, vi)
  if ei < 0: return ""
  result = xml[vi+1 ..< ei]

proc xmlAllVals(xml, tag: string): seq[string] =
  let close = "</" & tag & ">"
  var pos = 0
  while true:
    let open = "<" & tag
    let si = xml.find(open, pos)
    if si < 0: break
    let vi = xml.find('>', si)
    if vi < 0: break
    let ei = xml.find(close, vi)
    if ei < 0: break
    result.add xml[vi+1 ..< ei]
    pos = ei + close.len

proc xmlAllValsWithOpen(xml, tag: string): seq[tuple[openTag, value: string]] =
  let close = "</" & tag & ">"
  var pos = 0
  while true:
    let open = "<" & tag
    let si = xml.find(open, pos)
    if si < 0: break
    let vi = xml.find('>', si)
    if vi < 0: break
    let ei = xml.find(close, vi)
    if ei < 0: break
    result.add (xml[si..vi], xml[vi+1 ..< ei])
    pos = ei + close.len


proc psrpHexDecode*(text: string): string =
  var i = 0
  while i < text.len:
    if i + 7 <= text.len and text[i] == '_' and text[i+1] == 'x' and text[i+6] == '_':
      var valid = true
      var hex = ""
      for j in i+2..i+5:
        if text[j] in HexDigits:
          hex.add text[j]
        else:
          valid = false
          break
      if valid and hex.len == 4:
        let codepoint = parseHexInt(hex)
        if codepoint < 128:
          result.add chr(codepoint)
        else:
          if codepoint < 0x80:
            result.add chr(codepoint)
          elif codepoint < 0x800:
            result.add chr(0xC0 or (codepoint shr 6))
            result.add chr(0x80 or (codepoint and 0x3F))
          else:
            result.add chr(0xE0 or (codepoint shr 12))
            result.add chr(0x80 or ((codepoint shr 6) and 0x3F))
            result.add chr(0x80 or (codepoint and 0x3F))
        i += 7
        continue
    result.add text[i]
    inc i


proc uuidToPsrpBytes(uuid: string): seq[byte] =
  uuidToWindowsGuidBytes(uuid)

proc psrpMessage(runspaceId, pipelineId: string, msgType: uint32, data: string): seq[byte] =
  for b in toLE32(2'u32): result.add b
  for b in toLE32(msgType): result.add b
  result.add uuidToPsrpBytes(runspaceId)
  result.add uuidToPsrpBytes(pipelineId)
  result.add [0xEF'u8, 0xBB, 0xBF]
  for c in data: result.add byte(ord(c))

proc psrpFragment(objectId: uint64, blob: seq[byte], fragmentId: uint64 = 0,
                  startFragment: bool = true, endFragment: bool = true): seq[byte] =
  for b in toBE64(objectId): result.add b
  for b in toBE64(fragmentId): result.add b
  var flags: byte = 0
  if endFragment: flags = flags or 0x02
  if startFragment: flags = flags or 0x01
  result.add flags
  for b in toBE32(uint32(blob.len)): result.add b
  result.add blob


const PSRP_DEFAULT_BLOB_LENGTH* = 32_768


type
  DefragmentBuffer = object
    fragments: seq[seq[byte]]

  PsrpDefragmenter* = object
    messages: seq[tuple[objectId: uint64, buf: DefragmentBuffer]]

proc newPsrpDefragmenter*(): PsrpDefragmenter =
  result = PsrpDefragmenter(messages: @[])

proc defragment*(d: var PsrpDefragmenter, base64Data: string): tuple[complete: bool, msgType: uint32, data: string] =
  var raw: string
  try:
    raw = decode(base64Data)
  except:
    return (false, 0'u32, "")

  if raw.len < 21:
    return (false, 0'u32, "")

  let objectId = uint64(ord(raw[0])) shl 56 or uint64(ord(raw[1])) shl 48 or
                 uint64(ord(raw[2])) shl 40 or uint64(ord(raw[3])) shl 32 or
                 uint64(ord(raw[4])) shl 24 or uint64(ord(raw[5])) shl 16 or
                 uint64(ord(raw[6])) shl 8 or uint64(ord(raw[7]))
  let flags = byte(ord(raw[16]))
  let isStart = (flags and 0x01) != 0
  let isEnd = (flags and 0x02) != 0

  var blob: seq[byte]
  for i in 21..<raw.len:
    blob.add byte(ord(raw[i]))

  var found = -1
  for i in 0..<d.messages.len:
    if d.messages[i].objectId == objectId:
      found = i
      break

  if found < 0:
    d.messages.add (objectId, DefragmentBuffer(fragments: @[blob]))
    found = d.messages.len - 1
  else:
    d.messages[found].buf.fragments.add blob

  if isEnd:
    var fullBlob: seq[byte]
    for frag in d.messages[found].buf.fragments:
      fullBlob.add frag
    d.messages.delete(found)

    if fullBlob.len < 41:
      return (false, 0'u32, "")

    let byteStr = cast[string](fullBlob)
    let msgType = readLE32Str(byteStr, 4)
    let data = if byteStr.len > 40: byteStr[40..^1] else: ""
    return (true, msgType, data)

  return (false, 0'u32, "")


proc sessionCapabilityXml(): string =
  """<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>"""

proc initRunspaceXml(): string =
  """<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32><Obj N="PSThreadOptions" RefId="1"><TN RefId="0"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj><Obj N="ApartmentState" RefId="2"><TN RefId="1"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="ApplicationArguments" RefId="3"><TN RefId="2"><T>System.Management.Automation.PSPrimitiveDictionary</T><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">PSVersionTable</S><Obj N="Value" RefId="4"><TNRef RefId="2" /><DCT><En><S N="Key">PSVersion</S><Version N="Value">5.0.11082.1000</Version></En><En><S N="Key">PSRemotingProtocolVersion</S><Version N="Value">2.3</Version></En><En><S N="Key">SerializationVersion</S><Version N="Value">1.1.0.1</Version></En></DCT></Obj></En></DCT></Obj><Obj N="HostInfo" RefId="5"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj></MS></Obj>"""

proc pipelineXml(command: string): string =
  let cmd = xmlEscape(command & "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }")
  fmt"""<Obj RefId="0"><MS><Obj N="PowerShell" RefId="1"><MS><Obj N="Cmds" RefId="2"><TN RefId="0"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId="3"><MS><S N="Cmd">Invoke-expression</S><B N="IsScript">false</B><Nil N="UseLocalScope" /><Obj N="MergeMyResult" RefId="4"><TN RefId="1"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeToResult" RefId="5"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergePreviousResults" RefId="6"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeError" RefId="7"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeWarning" RefId="8"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeVerbose" RefId="9"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeDebug" RefId="10"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="Args" RefId="11"><TNRef RefId="0" /><LST><Obj RefId="12"><MS><S N="N">-Command</S><Nil N="V" /></MS></Obj><Obj RefId="13"><MS><Nil N="N" /><S N="V">{cmd}</S></MS></Obj></LST></Obj></MS></Obj><Obj RefId="14"><MS><S N="Cmd">Out-string</S><B N="IsScript">false</B><Nil N="UseLocalScope" /><Obj N="MergeMyResult" RefId="15"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeToResult" RefId="16"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergePreviousResults" RefId="17"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeError" RefId="18"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeWarning" RefId="19"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeVerbose" RefId="20"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeDebug" RefId="21"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="Args" RefId="22"><TNRef RefId="0" /><LST><Obj RefId="23"><MS><S N="N">-Stream</S><Nil N="V" /></MS></Obj></LST></Obj></MS></Obj></LST></Obj><B N="IsNested">false</B><Nil N="History" /><B N="RedirectShellErrorOutputPipe">true</B></MS></Obj><B N="NoInput">true</B><Obj N="ApartmentState" RefId="24"><TN RefId="2"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="RemoteStreamOptions" RefId="25"><TN RefId="3"><T>System.Management.Automation.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>0</ToString><I32>0</I32></Obj><B N="AddToHistory">true</B><Obj N="HostInfo" RefId="26"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj><B N="IsNested">false</B></MS></Obj>"""

proc initCreationXml(runspaceId: string): string =
  var bytes: seq[byte]
  bytes.add psrpFragment(1, psrpMessage(runspaceId, "", PSRP_SESSION_CAPABILITY, sessionCapabilityXml()))
  bytes.add psrpFragment(2, psrpMessage(runspaceId, "", PSRP_INIT_RUNSPACEPOOL, initRunspaceXml()))
  result = encode(bytes)

proc fragmentMessage*(objectId: uint64, msg: seq[byte],
                     maxBlobLen: int = PSRP_DEFAULT_BLOB_LENGTH): seq[seq[byte]] =
  var bytesFragmented = 0
  var fragmentId: uint64 = 0
  while bytesFragmented < msg.len:
    var lastByte = bytesFragmented + maxBlobLen
    if lastByte > msg.len: lastByte = msg.len
    let blob = msg[bytesFragmented ..< lastByte]
    result.add psrpFragment(objectId, blob, fragmentId,
                           bytesFragmented == 0, lastByte == msg.len)
    inc fragmentId
    bytesFragmented = lastByte

proc commandFragment(runspaceId, pipelineId, command: string, objectId: uint64): string =
  let msg = psrpMessage(runspaceId, pipelineId, PSRP_CREATE_PIPELINE, pipelineXml(command))
  result = encode(psrpFragment(objectId, msg))

proc commandFragments(runspaceId, pipelineId, command: string, objectId: uint64,
                     maxBlobLen: int = PSRP_DEFAULT_BLOB_LENGTH): seq[string] =
  let msg = psrpMessage(runspaceId, pipelineId, PSRP_CREATE_PIPELINE, pipelineXml(command))
  for frag in fragmentMessage(objectId, msg, maxBlobLen):
    result.add encode(frag)


proc encodePs*(cmd: string): string =
  var utf16: seq[byte]
  for c in cmd:
    utf16.add byte(ord(c))
    utf16.add 0x00'u8
  result = encode(utf16)


proc soapCreate(host: string, port: int, ssl: bool, sessionId, runspaceId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  let creationXml = initCreationXml(runspaceId)
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:Locale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <p:DataLocale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
  <w:OptionSet env:mustUnderstand="true">
    <w:Option Name="protocolversion" MustComply="true">2.3</w:Option>
  </w:OptionSet>
</env:Header>
<env:Body>
  <rsp:Shell ShellId="{runspaceId}" Name="Runspace">
    <rsp:InputStreams>stdin pr</rsp:InputStreams>
    <rsp:OutputStreams>stdout</rsp:OutputStreams>
    <creationXml xmlns="http://schemas.microsoft.com/powershell">{creationXml}</creationXml>
  </rsp:Shell>
</env:Body>
</env:Envelope>"""

proc soapRun(host: string, port: int, ssl: bool, sessionId, shellId, pipelineId, commandArg: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:Locale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <p:DataLocale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:CommandLine CommandId="{pipelineId}">
    <rsp:Command>Invoke-Expression</rsp:Command>
    <rsp:Arguments>{commandArg}</rsp:Arguments>
  </rsp:CommandLine>
</env:Body>
</env:Envelope>"""

proc soapSendData(host: string, port: int, ssl: bool, sessionId, shellId, commandId, fragmentB64: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:Locale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <p:DataLocale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:Send><rsp:Stream Name="stdin" CommandId="{commandId}">{fragmentB64}</rsp:Stream></rsp:Send>
</env:Body>
</env:Envelope>"""

proc soapReceive(host: string, port: int, ssl: bool, sessionId, shellId, cmdId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:Locale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <p:DataLocale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
  <w:OptionSet>
    <w:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">TRUE</w:Option>
  </w:OptionSet>
</env:Header>
<env:Body>
  <rsp:Receive><rsp:DesiredStream CommandId="{cmdId}">stdout</rsp:DesiredStream></rsp:Receive>
</env:Body>
</env:Envelope>"""

proc soapKeepAlive(host: string, port: int, ssl: bool, sessionId, shellId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
  <w:OptionSet>
    <w:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">TRUE</w:Option>
  </w:OptionSet>
</env:Header>
<env:Body>
  <rsp:Receive><rsp:DesiredStream>stdout</rsp:DesiredStream></rsp:Receive>
</env:Body>
</env:Envelope>"""

proc soapDelete(host: string, port: int, ssl: bool, sessionId, shellId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
</env:Header>
<env:Body/>
</env:Envelope>"""

proc soapCreateCmd(host: string, port: int, ssl: bool, sessionId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:Locale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <p:DataLocale mustUnderstand="false" xml:lang="{WSManLocale}"/>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
  <w:OptionSet>
    <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
    <w:Option Name="WINRS_CODEPAGE">65001</w:Option>
  </w:OptionSet>
</env:Header>
<env:Body>
  <rsp:Shell>
    <rsp:InputStreams>stdin</rsp:InputStreams>
    <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
  </rsp:Shell>
</env:Body>
</env:Envelope>"""

proc soapRunCmd(host: string, port: int, ssl: bool, sessionId, shellId, cmdId, exe, args: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
  <w:OptionSet>
    <w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option>
    <w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option>
  </w:OptionSet>
</env:Header>
<env:Body>
  <rsp:CommandLine>
    <rsp:Command>{xmlEscape(exe)}</rsp:Command>
    <rsp:Arguments>{xmlEscape(args)}</rsp:Arguments>
  </rsp:CommandLine>
</env:Body>
</env:Envelope>"""

proc soapReceiveCmd(host: string, port: int, ssl: bool, sessionId, shellId, cmdId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:Receive><rsp:DesiredStream CommandId="{cmdId}">stdout stderr</rsp:DesiredStream></rsp:Receive>
</env:Body>
</env:Envelope>"""

proc soapSendCmd(host: string, port: int, ssl: bool, sessionId, shellId, cmdId, data: string, done: bool): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  let endAttr = if done: " End=\"true\"" else: ""
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:Send><rsp:Stream Name="stdin" CommandId="{cmdId}"{endAttr}>{data}</rsp:Stream></rsp:Send>
</env:Body>
</env:Envelope>"""

proc soapCleanupCmd(host: string, port: int, ssl: bool, sessionId, shellId, cmdId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:Signal CommandId="{cmdId}">
    <rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code>
  </rsp:Signal>
</env:Body>
</env:Envelope>"""

proc soapCleanupPsrp(host: string, port: int, ssl: bool, sessionId, shellId, cmdId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_POWERSHELL}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
  <p:SessionId mustUnderstand="false">uuid:{sessionId}</p:SessionId>
  <w:OperationTimeout>{secToDur(WSManOperationTimeout)}</w:OperationTimeout>
  <w:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</w:MaxEnvelopeSize>
</env:Header>
<env:Body>
  <rsp:Signal CommandId="{cmdId}">
    <rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code>
  </rsp:Signal>
</env:Body>
</env:Envelope>"""

proc soapDeleteCmd(host: string, port: int, ssl: bool, sessionId, shellId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer">
<env:Header>
  <a:To>{url}</a:To>
  <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
  <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
  <a:MessageID>uuid:{genUuid()}</a:MessageID>
  <w:ResourceURI mustUnderstand="true">{RESOURCE_URI_CMD}</w:ResourceURI>
  <w:SelectorSet><w:Selector Name="ShellId">{shellId}</w:Selector></w:SelectorSet>
</env:Header>
<env:Body/>
</env:Envelope>"""


proc decodeStreams(xml: string): string =
  for tag in ["rsp:Stream", "p:Stream", "Stream"]:
    let streams = xmlAllVals(xml, tag)
    for s in streams:
      if s.len > 0:
        try: result.add decode(s)
        except: discard
    if result.len > 0: return

proc extractShellId(xml: string): string =
  for needle in ["<w:Selector Name=\"ShellId\"", "<wsman:Selector Name=\"ShellId\"", "<Selector Name=\"ShellId\""]:
    let si = xml.find(needle)
    if si >= 0:
      let vi = xml.find('>', si)
      let ei = xml.find("</", vi)
      if vi >= 0 and ei > vi:
        return xml[vi+1 ..< ei]
  for tag in ["rsp:ShellId", "ShellId"]:
    result = xmlVal(xml, tag)
    if result != "": return

proc extractCommandId(xml: string): string =
  for tag in ["rsp:CommandId", "CommandId"]:
    result = xmlVal(xml, tag)
    if result != "": return

proc isDone(xml: string): bool =
  var state = xmlVal(xml, "rsp:CommandState")
  if state == "": state = xmlVal(xml, "CommandState")
  result = "Done" in state or ("CommandState" in xml and "/Done" in xml)

proc faultText(xml: string): string =
  for tag in ["env:Text", "s:Text", "f:Message", "p:Message", "Message"]:
    let v = xmlVal(xml, tag)
    if v != "": return v
  let code = xmlVal(xml, "f:WSManFault")
  if code != "": return code
  result = ""

proc faultCode(xml: string): string =
  let marker = "Code=\""
  let si = xml.find(marker)
  if si >= 0:
    let start = si + marker.len
    let ei = xml.find('"', start)
    if ei > start:
      return xml[start..<ei]
  result = ""

proc isWinrmReceiveTimeout(xml: string): bool =
  result = "faultDetail/TimedOut" in xml or faultCode(xml) == RECEIVE_TIMEOUT_FAULT_CODE


proc wwwAuth(resp: Response): string =
  for key, val in resp.headers:
    if key.toLowerAscii() == "www-authenticate":
      return $val
  result = ""

proc headerVal(resp: Response, name: string): string =
  for key, val in resp.headers:
    if key.toLowerAscii() == name.toLowerAscii():
      return $val
  result = ""

proc debugHttpFailure(whereAt: string, resp: Response) =
  if getEnv("WINRMSHELL_DEBUG") != "1": return
  styledEcho(fgYellow, "[debug] " & whereAt & " HTTP status: " & resp.status)
  let auth = wwwAuth(resp)
  if auth != "":
    styledEcho(fgYellow, "[debug] WWW-Authenticate: " & auth)
  let ctype = headerVal(resp, "content-type")
  if ctype != "":
    styledEcho(fgYellow, "[debug] Content-Type: " & ctype)
  if resp.body.len > 0:
    let preview = resp.body[0..min(300, resp.body.len - 1)]
    styledEcho(fgYellow, "[debug] Body preview: " & preview)


type
  AuthMethod* = enum amNtlm, amKerberos
  MessageEncryption* = enum meAuto, meAlways, meNever

  WinRMClient* = object
    host:         string
    username:     string
    password:     string
    ntHash:       string
    spn:          string
    domain:       string
    auth:         AuthMethod
    msgEnc:       MessageEncryption
    useSSL:       bool
    port:         int
    shellId*:     string
    sessionId:    string
    hc:           HttpClient
    ntlmSock:     Socket
    ntlmReady:    bool
    ntlmRawScheme: bool
    ctx:          GssCtxId
    authenticated: bool
    runspaceId:   string
    cmdShellId:   string
    nextObjectId: uint64
    remoteCwd*:    string
    cmdShellDenied*: bool
    ntlmEncKey:     array[16, byte]
    ntlmEncrypt:    bool
    ntlmSeqNum:     uint32
    ntlmCliSignKey: array[16, byte]
    ntlmCliSealRC4: RC4Handle
    ntlmSrvSignKey: array[16, byte]
    ntlmSrvSealRC4: RC4Handle
    pendingCleanupCmdId: string
    delegate*:          bool

proc newClient*(host, user, pass, ntHash, spn, domain: string,
               auth: AuthMethod, ssl: bool, port: int,
               msgEnc = meAuto): WinRMClient =
  let ioTimeout = parseInt(getEnv("NIMUX_WINRM_LIB_TIMEOUT_MS", "30000"))
  result = WinRMClient(host: host, username: user, password: pass,
                       ntHash: ntHash,
                       spn: spn,
                       domain: domain, auth: auth, msgEnc: msgEnc, useSSL: ssl,
                       port: port,
                       sessionId: genUuid().toUpperAscii(),
                       hc: (if auth == amNtlm and not ssl: nil else:
                              newHttpClient(timeout = ioTimeout, sslContext = newContext(verifyMode = CVerifyNone))),
                       ntlmSock: nil,
                       ntlmReady: false,
                       ntlmRawScheme: false,
                       ctx: nil,
                       authenticated: false,
                       runspaceId: "",
                       cmdShellId: "",
                       nextObjectId: 3'u64,
                       remoteCwd: "",
                       cmdShellDenied: false,
                       ntlmEncrypt: (not ssl) and msgEnc != meNever,
                       ntlmSeqNum: 0,
                       ntlmCliSealRC4: nil,
                       ntlmSrvSealRC4: nil)


proc ntlmDeriveKey(sessionKey: array[16, byte], magic: string): array[16, byte] =
  var input: seq[byte]
  for b in sessionKey: input.add b
  for ch in magic: input.add byte(ord(ch))
  result = md5(input)

proc initNtlmEncryption(c: var WinRMClient) =
  const
    cliSignMagic = "session key to client-to-server signing key magic constant\x00"
    srvSignMagic = "session key to server-to-client signing key magic constant\x00"
    cliSealMagic = "session key to client-to-server sealing key magic constant\x00"
    srvSealMagic = "session key to server-to-client sealing key magic constant\x00"
  c.ntlmCliSignKey = ntlmDeriveKey(c.ntlmEncKey, cliSignMagic)
  c.ntlmSrvSignKey = ntlmDeriveKey(c.ntlmEncKey, srvSignMagic)
  let cliSealKey = ntlmDeriveKey(c.ntlmEncKey, cliSealMagic)
  let srvSealKey = ntlmDeriveKey(c.ntlmEncKey, srvSealMagic)
  c.ntlmCliSealRC4 = newRC4Handle(cliSealKey)
  c.ntlmSrvSealRC4 = newRC4Handle(srvSealKey)
  c.ntlmSeqNum = 0

proc wrapNtlmSoap(c: var WinRMClient, soap: string): string =
  var soapBytes = newSeq[byte](soap.len)
  for i, ch in soap: soapBytes[i] = byte(ord(ch))
  let seqBytes = toLE32(c.ntlmSeqNum)
  var forHmac: seq[byte]
  for b in seqBytes: forHmac.add b
  for b in soapBytes: forHmac.add b
  let hmac16 = hmacMd5(c.ntlmCliSignKey, forHmac)
  var hmac8: array[8, byte]
  for i in 0..7: hmac8[i] = hmac16[i]
  let encrypted = rc4Update(c.ntlmCliSealRC4, soapBytes)
  let encHmac8 = rc4Update(c.ntlmCliSealRC4, hmac8)
  inc c.ntlmSeqNum
  var frame = ""
  for b in toLE32(16'u32): frame.add char(b)
  frame.add char(0x01); frame.add char(0x00); frame.add char(0x00); frame.add char(0x00)
  for b in encHmac8: frame.add char(b)
  for b in seqBytes: frame.add char(b)
  for b in encrypted: frame.add char(b)
  result =
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n" &
    "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" & $soap.len & "\r\n" &
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/octet-stream\r\n" &
    frame &
    "--Encrypted Boundary--\r\n"

proc unwrapNtlmSoap(c: var WinRMClient, body: string): string =
  const octetMarker = "application/octet-stream"
  let octetIdx = body.find(octetMarker)
  if octetIdx < 0: return body
  var dataStart = octetIdx + octetMarker.len
  let bodyStart = body.find("\r\n", dataStart)
  if bodyStart < 0: return body
  dataStart = bodyStart + 2
  var binEnd = body.find("\r\n--Encrypted Boundary", dataStart)
  if binEnd < 0: binEnd = body.find("--Encrypted Boundary", dataStart)
  if binEnd < 0: binEnd = body.len
  if binEnd <= dataStart + 20: return body
  let sigLen = int(readLE32Str(body, dataStart))
  let dataPartStart = dataStart + 4 + sigLen
  if dataPartStart > binEnd: return body
  var checksumBytes: seq[byte]
  if sigLen >= 12:
    for i in (dataStart + 8)..<(dataStart + 16):
      if i < dataStart + 4 + sigLen:
        checksumBytes.add byte(ord(body[i]))
  var encBytes: seq[byte]
  for i in dataPartStart..<binEnd: encBytes.add byte(ord(body[i]))
  let decrypted = rc4Update(c.ntlmSrvSealRC4, encBytes)
  if sigLen >= 12:
    discard rc4Update(c.ntlmSrvSealRC4, checksumBytes)
  result = cast[string](decrypted)


proc baseUrl(c: WinRMClient): string =
  let s = if c.useSSL: "https" else: "http"
  fmt"{s}://{c.host}:{c.port}/wsman"

proc endpoint(c: WinRMClient): string =
  c.baseUrl()

proc soapHdrs(): HttpHeaders =
  newHttpHeaders({
    "Content-Type": "application/soap+xml;charset=UTF-8",
    "User-Agent":   WSManUserAgent,
    "Accept":       "*/*",
    "Connection":   "Keep-Alive"
  })

type RawHttpResponse = object
  status: string
  headers: seq[(string, string)]
  body: string

proc rawHeaderVal(resp: RawHttpResponse, name: string): string =
  for item in resp.headers:
    if item[0].toLowerAscii() == name.toLowerAscii():
      if result != "": result.add ", "
      result.add item[1]

proc recvHttp(sock: Socket): RawHttpResponse =
  let ioTimeout = parseInt(getEnv("NIMUX_WINRM_LIB_TIMEOUT_MS", "30000"))
  var data = ""
  while "\r\n\r\n" notin data:
    let chunk = sock.recv(1, ioTimeout)
    if chunk.len == 0:
      raise newException(IOError, "connection closed before HTTP headers")
    data.add chunk

  let splitAt = data.find("\r\n\r\n")
  let head = data[0 ..< splitAt]
  result.body = data[(splitAt + 4) .. ^1]
  let lines = head.split("\r\n")
  if lines.len == 0:
    raise newException(IOError, "empty HTTP response")
  let statusParts = lines[0].splitWhitespace()
  if statusParts.len >= 2:
    result.status = statusParts[1]
    if statusParts.len >= 3:
      result.status.add " " & statusParts[2..^1].join(" ")
  else:
    result.status = lines[0]

  for i in 1 ..< lines.len:
    let p = lines[i].find(':')
    if p > 0:
      result.headers.add((lines[i][0 ..< p].strip(), lines[i][p + 1 .. ^1].strip()))

  let clenStr = rawHeaderVal(result, "Content-Length")
  if clenStr != "":
    let clen = parseInt(clenStr.split(',')[0].strip())
    while result.body.len < clen:
      let want = min(65536, clen - result.body.len)
      let chunk = sock.recv(want, ioTimeout)
      if chunk.len == 0:
        raise newException(IOError, "connection closed before HTTP body")
      result.body.add chunk
    if result.body.len > clen:
      result.body = result.body[0 ..< clen]

proc rawNtlmPost(c: WinRMClient, body, authz: string, sock: Socket,
                 contentType = "application/soap+xml;charset=UTF-8"): RawHttpResponse =
  var authLine = ""
  if authz != "":
    authLine = "Authorization: " & authz & "\r\n"
  let req =
    "POST /wsman HTTP/1.1\r\n" &
    "Host: " & c.host & ":" & $c.port & "\r\n" &
    "Content-Type: " & contentType & "\r\n" &
    "User-Agent: " & WSManUserAgent & "\r\n" &
    "Accept: */*\r\n" &
    "Connection: Keep-Alive\r\n" &
    authLine &
    "Content-Length: " & $body.len & "\r\n" &
    "\r\n" &
    body
  if getEnv("WINRMSHELL_DEBUG") == "1":
    let mode = if authz == "": "cached" else: "auth"
    styledEcho(fgYellow, "[debug] NTLM raw POST " & mode & " bytes=" & $req.len)
    if getEnv("WINRMSHELL_DUMP") == "1":
      styledEcho(fgYellow, "[debug] NTLM raw POST content (base64): " & encode(req))
  sock.send(req)
  result = recvHttp(sock)
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] NTLM raw POST response: " & result.status & " body=" & $result.body.len)

proc connectWinrmSocket(c: WinRMClient): Socket =
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] NTLM connect " & c.host & ":" & $c.port)
  let timeoutMs = parseInt(getEnv("NIMUX_WINRM_LIB_TIMEOUT_MS", "5000"))
  let dialHost = netproxy.proxySocketHost(c.host)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  result = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  netproxy.connectTcpSync(result, c.host, c.port, timeoutMs)
  try: result.setSockOpt(OptNoDelay, true, level = cint(6))
  except: discard

proc closeNtlm*(c: var WinRMClient) =
  if c.ntlmSock != nil:
    try: c.ntlmSock.close()
    except: discard
  c.ntlmSock = nil
  c.ntlmReady = false
  c.ntlmRawScheme = false

proc ntlmHandshake(c: var WinRMClient, body: string): RawHttpResponse =
  closeNtlm(c)
  c.ntlmSock = connectWinrmSocket(c)
  let neg = buildNtlmNegotiate()
  let initialBody = if c.ntlmEncrypt: "" else: body
  var r1: RawHttpResponse
  try:
    r1 = rawNtlmPost(c, initialBody, "Negotiate " & encode(spnegoInit(neg)), c.ntlmSock)
  except CatchableError as e:
    let em = e.msg.toLowerAscii()
    if "connection closed before http headers" notin em and
       "recv' timed out" notin em and
       "timed out" notin em:
      raise
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] NTLM Negotiate Type1 did not receive a response; retrying raw NTLM scheme")
    closeNtlm(c)
    c.ntlmSock = connectWinrmSocket(c)
    c.ntlmRawScheme = true
    r1 = rawNtlmPost(c, initialBody, "NTLM " & encode(neg), c.ntlmSock)
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] NTLM type1 HTTP status: " & r1.status)
    let conn1 = rawHeaderVal(r1, "connection")
    if conn1 != "": styledEcho(fgYellow, "[debug] NTLM type1 Connection: " & conn1)
    let keep1 = rawHeaderVal(r1, "keep-alive")
    if keep1 != "": styledEcho(fgYellow, "[debug] NTLM type1 Keep-Alive: " & keep1)

  let wa = rawHeaderVal(r1, "WWW-Authenticate")
  if wa == "":
    raise newException(WinRMAuthorizationError, "Server did not send WWW-Authenticate (auth not required?)")

  var challB64: string
  for part in wa.split(','):
    let p = part.strip()
    if p.startsWith("NTLM ") or p.startsWith("Negotiate "):
      challB64 = p.split(' ')[^1]
      break
  if challB64 == "":
    raise newException(WinRMAuthorizationError, "No NTLM challenge token in: " & wa)

  let challRaw = cast[seq[byte]](unwrapNtlmToken(decode(challB64)))
  let chall    = parseChallenge(challRaw)
  var sessionKey: array[16, byte]
  let auth = buildNtlmAuthenticate(c.username, c.password, c.domain, "", c.ntHash, chall, sessionKey)
  c.ntlmEncKey = sessionKey

  if c.ntlmEncrypt:
    initNtlmEncryption(c)
    let encCt = "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\""
    let encBody = wrapNtlmSoap(c, body)
    let authHeader =
      if c.ntlmRawScheme: "NTLM " & encode(auth)
      else: "Negotiate " & encode(spnegoResp(auth))
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] NTLM sending type3+encrypted SOAP len=" & $encBody.len)
    result = rawNtlmPost(c, encBody, authHeader, c.ntlmSock, encCt)
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] NTLM type3+data response: " & result.status)
    let code3 = parseInt(result.status.splitWhitespace()[0])
    if code3 == 401:
      closeNtlm(c)
      raise newException(WinRMAuthorizationError, "NTLM auth failed (401)")
    if "--Encrypted Boundary" in result.body:
      try: result.body = unwrapNtlmSoap(c, result.body)
      except CatchableError as e:
        if getEnv("WINRMSHELL_DEBUG") == "1":
          styledEcho(fgYellow, "[debug] NTLM unwrap response failed: " & e.msg)
    c.ntlmReady = code3 in [200, 201, 202, 500]
    return

  let authHeader =
    if c.ntlmRawScheme: "NTLM " & encode(auth)
    else: "Negotiate " & encode(spnegoResp(auth))
  result = rawNtlmPost(c, body, authHeader, c.ntlmSock)
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] NTLM type3 HTTP status: " & result.status)
    let conn2 = rawHeaderVal(result, "connection")
    if conn2 != "": styledEcho(fgYellow, "[debug] NTLM type3 Connection: " & conn2)
  let code = parseInt(result.status.splitWhitespace()[0])
  c.ntlmReady = code in [200, 201, 202, 500]

proc doNtlm(c: var WinRMClient, body: string): tuple[status, body: string] =
  if c.useSSL:
    let neg = buildNtlmNegotiate()
    var h1  = soapHdrs()
    h1["Authorization"] = "Negotiate " & encode(spnegoInit(neg))
    let r1  = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = body, headers = h1)

    let wa = wwwAuth(r1)
    if wa == "":
      raise newException(WinRMAuthorizationError, "Server did not send WWW-Authenticate (auth not required?)")

    var challB64: string
    for part in wa.split(','):
      let p = part.strip()
      if p.startsWith("NTLM ") or p.startsWith("Negotiate "):
        challB64 = p.split(' ')[^1]
        break
    if challB64 == "":
      raise newException(WinRMAuthorizationError, "No NTLM challenge token in: " & wa)

    let challRaw = cast[seq[byte]](unwrapNtlmToken(decode(challB64)))
    let chall    = parseChallenge(challRaw)
    var sslSessionKey: array[16, byte]
    let auth = buildNtlmAuthenticate(c.username, c.password, c.domain, "", c.ntHash, chall, sslSessionKey)
    var h2   = soapHdrs()
    h2["Authorization"] = "Negotiate " & encode(spnegoResp(auth))
    let r2 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = body, headers = h2)
    return (r2.status, r2.body)

  if c.ntlmReady and c.ntlmSock != nil:
    var sendBody = body
    var ct = "application/soap+xml;charset=UTF-8"
    if c.ntlmEncrypt:
      sendBody = wrapNtlmSoap(c, body)
      ct = "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\""
    let r = rawNtlmPost(c, sendBody, "", c.ntlmSock, ct)
    let code = parseInt(r.status.splitWhitespace()[0])
    if code != 401:
      var respBody = r.body
      if c.ntlmEncrypt and "--Encrypted Boundary" in respBody:
        try: respBody = unwrapNtlmSoap(c, respBody)
        except CatchableError as e:
          if getEnv("WINRMSHELL_DEBUG") == "1":
            styledEcho(fgYellow, "[debug] NTLM unwrap response failed: " & e.msg)
      return (r.status, respBody)
    closeNtlm(c)

  let r2 = ntlmHandshake(c, body)
  result = (r2.status, r2.body)

proc doKerb(c: var WinRMClient, body: string): tuple[status, body: string] =
  var minor: GssUint32
  let kerbFlags = if c.delegate: 0x3B'u32 else: 0x3A'u32

  if not c.authenticated:
    var tgt = importSpn(c.host, c.domain, c.spn)

    var obuf = GssBufferDesc(length: 0, value: nil)
    var retf, trec: GssUint32
    let maj1 = gss_init_sec_context(
      addr minor, GSS_C_NO_CREDENTIAL, addr c.ctx,
      tgt, GSS_C_NO_OID, kerbFlags, 0, nil,
      nil, nil, addr obuf, addr retf, addr trec)

    if maj1 != GSS_S_COMPLETE and maj1 != GSS_S_CONTINUE_NEEDED:
      let errMsg = gssError(maj1, minor).toLowerAscii()
      if "matching credential not found" in errMsg and c.spn.strip() == "":
        var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
        var hostLc = c.host.strip().toLowerAscii()
        if ':' in hostLc: hostLc = hostLc.split(':')[0]
        var lcSpn = "http/" & hostLc
        if c.domain.strip() != "":
          lcSpn = lcSpn & "@" & c.domain.strip().toUpperAscii()
        tgt = importSpn(c.host, c.domain, lcSpn)
        c.ctx = nil
        obuf = GssBufferDesc(length: 0, value: nil)
        let maj1r = gss_init_sec_context(
          addr minor, GSS_C_NO_CREDENTIAL, addr c.ctx,
          tgt, GSS_C_NO_OID, kerbFlags, 0, nil,
          nil, nil, addr obuf, addr retf, addr trec)
        if maj1r != GSS_S_COMPLETE and maj1r != GSS_S_CONTINUE_NEEDED:
          var m3: GssUint32; discard gss_release_name(addr m3, addr tgt)
          raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj1r, minor))
      else:
        var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
        raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj1, minor))

    var outTok = ""
    if obuf.value != nil and obuf.length > 0:
      let p = cast[ptr UncheckedArray[byte]](obuf.value)
      for i in 0..<int(obuf.length): outTok.add char(p[i])
      discard gss_release_buffer(addr minor, addr obuf)

    var h0 = soapHdrs()
    h0["Authorization"] = "Kerberos " & encode(outTok)
    let r0 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = "", headers = h0)
    let wa = wwwAuth(r0)
    var serverTokB64 = ""
    for part in wa.split(','):
      let p = part.strip()
      if p.startsWith("Kerberos ") or p.startsWith("Negotiate "):
        serverTokB64 = p.split(' ')[^1]
        break
    if serverTokB64 == "":
      debugHttpFailure("Kerberos bootstrap", r0)
      var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
      raise newException(WinRMAuthorizationError, "Kerberos bootstrap failed: " & r0.status)

    let serverTok = decode(serverTokB64)
    var inBuf = GssBufferDesc(
      length: csize_t(serverTok.len),
      value: if serverTok.len > 0: cast[pointer](unsafeAddr serverTok[0]) else: nil)
    obuf = GssBufferDesc(length: 0, value: nil)
    let maj2 = gss_init_sec_context(
      addr minor, GSS_C_NO_CREDENTIAL, addr c.ctx,
      tgt, GSS_C_NO_OID, kerbFlags, 0, nil,
      addr inBuf, nil, addr obuf, addr retf, addr trec)

    var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
    if obuf.value != nil:
      discard gss_release_buffer(addr minor, addr obuf)
    if maj2 != GSS_S_COMPLETE:
      if maj2 == GSS_S_CONTINUE_NEEDED:
        raise newException(OSError, "gss_init_sec_context needs another Kerberos leg")
      raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj2, minor))

    c.authenticated = true

  var headers = soapHdrs()
  let encBody = wrapSoap(c.ctx, body)
  headers["Content-Type"] = "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""

  let r1 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = encBody, headers = headers)

  var respBody = r1.body
  let cTypeHead = r1.headers.getOrDefault("content-type").toLowerAscii()

  if "multipart/encrypted" in cTypeHead or "--Encrypted Boundary" in respBody:
    try:
      respBody = unwrapResponse(c.ctx, respBody)
    except CatchableError as e:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[debug] unwrapResponse failed: " & e.msg)

  result = (r1.status, respBody)

proc resetTransport*(c: var WinRMClient) =
  if c.hc != nil:
    try: c.hc.close()
    except: discard
  closeNtlm(c)
  if c.auth == amNtlm and not c.useSSL:
    c.hc = nil
  else:
    c.hc = newHttpClient(timeout = parseInt(getEnv("NIMUX_WINRM_LIB_TIMEOUT_MS", "5000")),
                         sslContext = newContext(verifyMode = CVerifyNone))
  c.ctx = nil
  c.authenticated = false
  c.cmdShellId = ""
  c.ntlmCliSealRC4 = nil
  c.ntlmSrvSealRC4 = nil
  c.ntlmRawScheme = false
  c.ntlmSeqNum = 0

proc isTransportError(e: ref CatchableError): bool =
  let m = e.msg.toLowerAscii()
  result = "connection reset" in m or
           "broken pipe" in m or
           "could not send all data" in m or
           "connection refused" in m or
           "connection closed" in m or
           "socket" in m or
           "no route to host" in m or
           "host unreachable" in m or
           "timed out" in m or
           "no such device" in m or
           "name or service not known" in m or
           "temporary failure in name resolution" in m

proc isConnectionLostMessage*(msg: string): bool =
  let m = msg.toLowerAscii()
  result = "connection lost" in m or
           "target unavailable" in m or
           "connection reset" in m or
           "connection closed" in m or
           "broken pipe" in m or
           "could not send all data" in m or
           "no route to host" in m or
           "host unreachable" in m or
           "timed out" in m or
           "no such device" in m or
           "name or service not known" in m or
           "temporary failure in name resolution" in m

proc send(c: var WinRMClient, body: string): string =
  var status, respBody: string
  try:
    (status, respBody) = case c.auth
      of amNtlm:     doNtlm(c, body)
      of amKerberos: doKerb(c, body)
  except CatchableError as e:
    if not isTransportError(e):
      raise
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] transport reset, reopening HTTP/Kerberos session and retrying request: " & e.msg)
    resetTransport(c)
    try:
      (status, respBody) = case c.auth
        of amNtlm:     doNtlm(c, body)
        of amKerberos: doKerb(c, body)
    except CatchableError as e2:
      if isTransportError(e2):
        raise newException(IOError, "Connection lost or target unavailable: " & e2.msg)
      raise
  let code = parseInt(status.split(' ')[0])
  if code == 401:
    raise newException(WinRMAuthorizationError, "Authentication failed (401)")
  if code notin [200, 201, 202]:
    if code == 500 and c.auth == amNtlm and
       not c.ntlmEncrypt and not c.useSSL and c.msgEnc != meNever:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[debug] NTLM: server requires message encryption, retrying with NTLM sealing")
      c.ntlmEncrypt = true
      closeNtlm(c)
      try:
        (status, respBody) = doNtlm(c, body)
      except CatchableError as e:
        if isTransportError(e):
          raise newException(IOError, "Connection lost: " & e.msg)
        raise
      let code2 = parseInt(status.split(' ')[0])
      if code2 in [200, 201, 202]:
        result = respBody
        return
      if code2 == 500 and ("<s:Envelope" in respBody or "<env:Envelope" in respBody or "<Envelope" in respBody):
        result = respBody
        return
      let preview2 = if respBody.len > 0: respBody[0..min(400, respBody.len-1)] else: "(empty body)"
      raise newWinRMHTTPTransportError(fmt"WinRM error {code2}: " & preview2, code2)
    if code == 500 and ("<s:Envelope" in respBody or "<env:Envelope" in respBody or "<Envelope" in respBody):
      result = respBody
      return
    let preview = if respBody.len > 0: respBody[0..min(400, respBody.len-1)] else: "(empty body)"
    raise newWinRMHTTPTransportError(fmt"WinRM error {code}: " & preview, code)
  result = respBody


proc psrpTextValue*(v: string): string =
  result = v.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", "\"").replace("&apos;", "'")
  if result.startsWith("\xEF\xBB\xBF"):
    result = result[3..^1]
  result = psrpHexDecode(result)

proc isPsrpInternalText(text: string): bool =
  result = text == "" or
           "CallSite.Target" in text or
           "System.Runtime.CompilerServices" in text or
           "System.Management.Automation.Interpreter" in text or
           "InterpretedFrame" in text or
           "Anonymously Hosted DynamicMethods Assembly" in text

proc isPsrpLocationOnly(text: string): bool =
  let t = text.strip()
  result = t.startsWith("At line:") or t.startsWith("+ ") or t.startsWith("CategoryInfo") or t.startsWith("FullyQualifiedErrorId")

proc cleanPsrpErrorText(text: string): string =
  result = text
  let atLine = result.find("\nAt line:")
  if atLine > 0:
    result = result[0..<atLine]
  result = result.strip()
  if isPsrpLocationOnly(result):
    result = ""

proc isPsrpMetadataString(openTag: string): bool =
  result = " N=\"Cmd\"" in openTag or
           " N=\"V\"" in openTag or
           " N=\"N\"" in openTag or
           " N=\"History\"" in openTag

proc decodePsrpMessage(msgType: uint32, data: string): string =
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] PSRP msgType=0x" & msgType.toHex(8) & " dataLen=" & $data.len)
  if msgType != PSRP_PIPELINE_OUTPUT and msgType != PSRP_ERROR_RECORD and msgType != PSRP_PIPELINE_STATE:
    return ""
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] PSRP data: " & data[0..min(240, data.len - 1)])
  if msgType == PSRP_ERROR_RECORD:
    let vals = xmlAllValsWithOpen(data, "S")
    var msg = ""
    for item in vals:
      if isPsrpMetadataString(item.openTag):
        continue
      let v = item.value
      let text = psrpTextValue(v)
      if isPsrpInternalText(text) or isPsrpLocationOnly(text):
        continue
      let cleaned = cleanPsrpErrorText(text)
      if cleaned.len > msg.len and not ("System.Management.Automation" in cleaned):
        msg = cleaned
    if msg == "":
      let vals2 = xmlAllVals(data, "ToString")
      if vals2.len > 0:
        let t = psrpTextValue(vals2[0])
        if not isPsrpInternalText(t):
          msg = cleanPsrpErrorText(t)
    if msg.len > 0:
      result.add msg
      result.add "\n"
    return
  if msgType == PSRP_PIPELINE_STATE:
    if "<I32>5</I32>" in data or "<I32 N=\"PipelineState\">5</I32>" in data:
      let vals = xmlAllValsWithOpen(data, "S")
      var msg = ""
      for item in vals:
        if isPsrpMetadataString(item.openTag): continue
        let text = psrpTextValue(item.value)
        if isPsrpInternalText(text) or isPsrpLocationOnly(text): continue
        let cleaned = cleanPsrpErrorText(text)
        if cleaned.len > msg.len and not ("System.Management.Automation" in cleaned):
          msg = cleaned
      if msg.len > 0:
        result.add msg
        result.add "\n"
    return
  for item in xmlAllValsWithOpen(data, "S"):
    if isPsrpMetadataString(item.openTag):
      continue
    let text = psrpTextValue(item.value)
    if isPsrpInternalText(text) or isPsrpLocationOnly(text):
      continue
    result.add text
    result.add "\n"
  for v in xmlAllVals(data, "ToString"):
    let text = psrpTextValue(v)
    if isPsrpInternalText(text) or isPsrpLocationOnly(text):
      continue
    result.add text
    result.add "\n"

proc decodePsrpText(xml: string, defrag: var PsrpDefragmenter, pipelineDone: var bool): string =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] PSRP streams: " & $streams.len)
    if streams.len == 0:
      styledEcho(fgYellow, "[debug] Receive preview: " & xml[0..min(500, xml.len - 1)])
  for s in streams:
    if s.len == 0: continue
    let (complete, msgType, data) = defrag.defragment(s)
    if not complete: continue
    if msgType == PSRP_PIPELINE_STATE:
      if "<I32 N=\"PipelineState\">4</I32>" in data or "<I32>4</I32>" in data:
        pipelineDone = true
    result.add decodePsrpMessage(msgType, data)

proc decodePsrpText(xml: string, defrag: var PsrpDefragmenter): string =
  var dummy = false
  result = decodePsrpText(xml, defrag, dummy)

proc decodePsrpText(xml: string): string =
  var defrag = newPsrpDefragmenter()
  result = decodePsrpText(xml, defrag)

proc psrpRunspaceOpened(xml: string, defrag: var PsrpDefragmenter): bool =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  for s in streams:
    if s.len == 0: continue
    let (complete, msgType, data) = defrag.defragment(s)
    if not complete: continue
    if msgType != PSRP_RUNSPACEPOOL_STATE: continue
    if "<I32>2</I32>" in data or "<I32 N=\"RunspaceState\">2</I32>" in data:
      return true

proc psrpRunspaceOpened(xml: string): bool =
  var defrag = newPsrpDefragmenter()
  result = psrpRunspaceOpened(xml, defrag)

proc psrpPipelineDone(xml: string, defrag: var PsrpDefragmenter): bool =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  for s in streams:
    if s.len == 0: continue
    let (complete, msgType, data) = defrag.defragment(s)
    if not complete: continue
    if msgType != PSRP_PIPELINE_STATE: continue
    if "<I32 N=\"PipelineState\">4</I32>" in data or "<I32>4</I32>" in data:
      return true

proc psrpPipelineDone(xml: string): bool =
  var defrag = newPsrpDefragmenter()
  result = psrpPipelineDone(xml, defrag)


proc waitRunspace(c: var WinRMClient)

proc createShell(c: var WinRMClient, waitOpened = true): string =
  let dbg = getEnv("WINRMSHELL_DEBUG") == "1"
  let interactiveStatus = getEnv("WINRMSHELL_STATUS") != "0"
  var t0: float
  if dbg:
    t0 = epochTime()
    styledEcho(fgYellow, "[debug] PSRP create shell start")
  if c.runspaceId == "":
    c.runspaceId = genUuid().toUpperAscii()
  let xml = c.send(soapCreate(c.host, c.port, c.useSSL, c.sessionId, c.runspaceId))
  if dbg:
    styledEcho(fgYellow, fmt"[debug] PSRP create shell response +{(epochTime()-t0)*1000:.0f}ms bytes={xml.len}")
    styledEcho(fgYellow, "[debug] PSRP fault: " & xml[0..min(400,xml.len-1)])
  result  = extractShellId(xml)
  if result == "":
    raise newException(InvalidShellError, "Could not find ShellId in:\n" & xml[0..min(2000,xml.len-1)])
  c.shellId = result
  if waitOpened:
    if interactiveStatus:
      stdout.write("\r\e[K")
      stdout.flushFile()
      styledEcho(fgWhite, "[*] Opening PowerShell runspace...")
    waitRunspace(c)
    if dbg:
      styledEcho(fgYellow, fmt"[debug] PSRP shell ready +{(epochTime()-t0)*1000:.0f}ms")

proc ensureShell*(c: var WinRMClient, waitOpened = true) =
  if c.shellId == "":
    c.shellId = createShell(c, waitOpened)

proc waitRunspace(c: var WinRMClient) =
  let dbg = getEnv("WINRMSHELL_DEBUG") == "1"
  let t0 = epochTime()
  var defrag = newPsrpDefragmenter()
  for i in 0..<160:
    let ti = epochTime()
    let xml = c.send(soapKeepAlive(c.host, c.port, c.useSSL, c.sessionId, c.shellId))
    if dbg:
      styledEcho(fgYellow, fmt"[debug] PSRP runspace poll={i} +{(epochTime()-ti)*1000:.0f}ms bytes={xml.len}")
    if psrpRunspaceOpened(xml, defrag):
      if dbg:
        styledEcho(fgYellow, fmt"[debug] PSRP runspace opened +{(epochTime()-t0)*1000:.0f}ms polls={i + 1}")
      return
    if isWinrmReceiveTimeout(xml):
      continue
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] Runspace did not report Opened before timeout")

proc firstCommandToken(cmd: string): string =
  var s = cmd.strip()
  if s == "": return ""
  if s[0] in {'"', '\''}:
    let q = s[0]
    let ei = s.find(q, 1)
    if ei > 0: return s[1..<ei]
  let sp = s.find({' ', '\t'})
  if sp > 0: result = s[0..<sp] else: result = s

proc isNativeCommand(cmd: string): bool =
  let tok = firstCommandToken(cmd).toLowerAscii()
  result = tok.endsWith(".exe") or tok.startsWith(".\\") or tok.startsWith("./")

proc shouldRunViaCmd(cmd: string): bool =
  let stripped = cmd.strip()
  if stripped == "":
    return false
  if stripped.contains({'|', ';', '`'}) or
     stripped.contains("&&") or stripped.contains("||") or
     stripped.contains("$") or stripped.contains("*>&") or
     stripped.contains("2>&") or stripped.contains(">") or
     stripped.contains("<"):
    return false
  let tok = firstCommandToken(stripped).toLowerAscii()
  if tok == "":
    return false
  const cmdBuiltins = [
    "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date",
    "del", "dir", "echo", "endlocal", "erase", "exit", "for", "ftype", "goto",
    "if", "md", "mkdir", "mklink", "move", "path", "pause", "popd", "prompt",
    "pushd", "rd", "rem", "ren", "rename", "rmdir", "set", "setlocal",
    "shift", "start", "time", "title", "type", "ver", "verify", "vol"
  ]
  const nativeTools = [
    "arp", "certutil", "cmd", "dsquery", "hostname", "ipconfig", "klist",
    "net", "netstat", "nltest", "nslookup", "ping", "quser", "qwinsta",
    "reg", "route", "sc", "schtasks", "systeminfo", "tasklist", "taskkill",
    "tracert", "wevtutil", "where", "whoami", "wmic"
  ]
  result = tok.endsWith(".exe") or tok.endsWith(".bat") or tok.endsWith(".cmd") or
           tok.startsWith(".\\") or tok.startsWith("./") or tok in cmdBuiltins or
           tok in nativeTools

type ChunkCallback* = proc(chunk: string)

proc drawProgress*(label: string, current, total: int)

proc flushPendingCleanup(c: var WinRMClient) =
  if c.pendingCleanupCmdId != "" and c.shellId != "":
    try:
      discard c.send(soapCleanupPsrp(c.host, c.port, c.useSSL, c.sessionId, c.shellId, c.pendingCleanupCmdId))
    except CatchableError:
      discard
    c.pendingCleanupCmdId = ""

proc runCmdCollect*(c: var WinRMClient, cmd: string, isCmd: bool, onChunk: ChunkCallback = nil, mergeStreams = false): string =
  let dbg = getEnv("WINRMSHELL_DEBUG") == "1"
  var t0: float
  if dbg:
    t0 = epochTime()
    styledEcho(fgYellow, "[debug] runCmdCollect start")
  flushPendingCleanup(c)
  if dbg:
    styledEcho(fgYellow, fmt"[debug] cleanup done +{(epochTime()-t0)*1000:.0f}ms")
  var tries = 2
  while tries > 0:
    dec tries
    ensureShell(c)
    var actualCmd = if isCmd: "cmd.exe /c " & cmd else: cmd
    if not isCmd and isNativeCommand(cmd):
      actualCmd = "& { " & cmd & " } 2>&1 | ForEach-Object { $_.ToString() }"
    let pipelineId = genUuid().toUpperAscii()
    let frags = commandFragments(c.runspaceId, pipelineId, actualCmd, c.nextObjectId)
    inc c.nextObjectId
    var cmdXml: string
    try:
      cmdXml = c.send(soapRun(c.host, c.port, c.useSSL, c.sessionId, c.shellId, pipelineId, frags[0]))
      if frags.len > 1:
        let cmdId = extractCommandId(cmdXml)
        for i in 1..<frags.len:
          discard c.send(soapSendData(c.host, c.port, c.useSSL, c.sessionId, c.shellId, cmdId, frags[i]))
    except CatchableError as e:
      let fc = if e of WinRMWSManFault: (ref WinRMWSManFault)(e).faultCode else: faultCode(e.msg)
      if isRetryableFault(fc) and tries > 0:
        if fc == SHELL_TOO_MANY_COMMANDS:
          try: discard c.send(soapDelete(c.host, c.port, c.useSSL, c.sessionId, c.shellId))
          except: discard
        c.shellId = ""
        c.runspaceId = ""
        continue
      raise
    if dbg:
      styledEcho(fgYellow, fmt"[debug] pipeline sent +{(epochTime()-t0)*1000:.0f}ms")
    let cmdId   = extractCommandId(cmdXml)
    if cmdId == "":
      raise newException(IOError, "Could not get CommandId from: " & cmdXml[0..min(2000,cmdXml.len-1)])

    var output: string
    var retries = 0
    var defrag = newPsrpDefragmenter()
    var pipelineDone = false
    while retries < 240:
      var tRecv: float
      if dbg: tRecv = epochTime()
      let recvXml = c.send(soapReceive(c.host, c.port, c.useSSL, c.sessionId, c.shellId, cmdId))
      if dbg:
        styledEcho(fgYellow, fmt"[debug] recv iter={retries} +{(epochTime()-tRecv)*1000:.0f}ms bytes={recvXml.len}")
      var psrpDone = false
      let chunk   = decodePsrpText(recvXml, defrag, psrpDone)
      if chunk.len > 0:
        output.add chunk
        if onChunk != nil:
          onChunk(chunk)
      if dbg and "fault" in recvXml.toLowerAscii():
        let ft = faultText(recvXml)
        if ft != "":
          styledEcho(fgYellow, "[debug] Fault text: " & ft)
      let soapDone = isDone(recvXml)
      if dbg:
        styledEcho(fgYellow, fmt"[debug] isDone={soapDone} psrpDone={psrpDone} chunkLen={chunk.len}")
      if soapDone or psrpDone:
        pipelineDone = true
        break
      if isWinrmReceiveTimeout(recvXml):
        inc retries
        continue
      inc retries
    if dbg:
      styledEcho(fgYellow, fmt"[debug] receive done +{(epochTime()-t0)*1000:.0f}ms iters={retries} pipelineDone={pipelineDone}")
    c.pendingCleanupCmdId = cmdId
    return output

proc runCmd*(c: var WinRMClient, cmd: string, isCmd: bool, mergeStreams = false): string =
  result = runCmdCollect(c, cmd, isCmd, nil, mergeStreams)

proc createCmdShell(c: var WinRMClient): string =
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] WinRS create shell")
  let xml = c.send(soapCreateCmd(c.host, c.port, c.useSSL, c.sessionId))
  let createFault = faultText(xml)
  if createFault.len > 0 and getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] WinRS create fault: " & createFault)
  result = extractShellId(xml)
  if result == "":
    raise newException(InvalidShellError, "Could not find ShellId in:\n" & xml[0..min(2000, xml.len-1)])
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] WinRS shell id: " & result)

proc deleteCmdShell(c: var WinRMClient, shellId: string) =
  if shellId != "":
    try:
      discard c.send(soapDeleteCmd(c.host, c.port, c.useSSL, c.sessionId, shellId))
    except:
      discard

proc ensureCmdShell(c: var WinRMClient): string =
  if c.cmdShellId == "":
    c.cmdShellId = createCmdShell(c)
  result = c.cmdShellId

proc deleteCachedCmdShell(c: var WinRMClient) =
  if c.cmdShellId != "":
    deleteCmdShell(c, c.cmdShellId)
    c.cmdShellId = ""

proc decodeWinrsText(xml: string): string =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  for s in streams:
    if s.len == 0: continue
    try:
      result.add decode(s)
    except:
      result.add psrpTextValue(s)
  result = result.replace("#< CLIXML\r\n", "").replace("#< CLIXML\n", "").replace("#< CLIXML", "")
  while true:
    let start = result.find("<Objs ")
    if start < 0: break
    let stopRel = result[start..^1].find("</Objs>")
    if stopRel < 0: break
    let stop = start + stopRel + "</Objs>".len
    let frag = result[start..<stop]
    if "S=\"progress\"" notin frag:
      var text = ""
      for item in xmlAllValsWithOpen(frag, "S"):
        if " S=\"Error\"" in item.openTag:
          text.add psrpTextValue(item.value)
      if text == "":
        break
      result = result[0..<start] & text & result[stop..^1]
    else:
      result = result[0..<start] & result[stop..^1]

proc decodeWinrsBytes(xml: string): tuple[data, err: string] =
  let streams = xmlAllValsWithOpen(xml, "rsp:Stream") &
                xmlAllValsWithOpen(xml, "p:Stream") &
                xmlAllValsWithOpen(xml, "Stream")
  for item in streams:
    if item.value.len == 0: continue
    var raw: string
    try:
      raw = decode(item.value)
    except:
      raw = psrpTextValue(item.value)
    if "Name=\"stderr\"" in item.openTag or "Name='stderr'" in item.openTag:
      result.err.add raw
    else:
      result.data.add raw

proc cleanWinrsErrorText(s: string): string =
  result = s.replace("#< CLIXML\r\n", "").replace("#< CLIXML\n", "").replace("#< CLIXML", "")
  while true:
    let start = result.find("<Objs ")
    if start < 0: break
    let stopRel = result[start..^1].find("</Objs>")
    if stopRel < 0: break
    let stop = start + stopRel + "</Objs>".len
    let frag = result[start..<stop]
    if "S=\"progress\"" in frag:
      result = result[0..<start] & result[stop..^1]
      continue
    var text = ""
    for item in xmlAllValsWithOpen(frag, "S"):
      if " S=\"Error\"" in item.openTag:
        text.add psrpTextValue(item.value)
    if text == "":
      break
    result = result[0..<start] & text & result[stop..^1]

proc runCmdOnShell(c: var WinRMClient, shellId, cmd: string, isCmd: bool,
                   onChunk: ChunkCallback = nil): string =
  let exe = if isCmd: "cmd.exe" else: "powershell.exe"
  let args = if isCmd:
    "/c " & cmd
  else:
    let script = "$ProgressPreference='SilentlyContinue';$VerbosePreference='SilentlyContinue';$DebugPreference='SilentlyContinue';" & cmd
    "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand " & encodePs(script)
  let requestedCmdId = genUuid().toUpperAscii()
  let cmdXml = c.send(soapRunCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, requestedCmdId, exe, args))
  let runFault = faultText(cmdXml)
  if runFault.len > 0:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] WinRS command fault: " & runFault)
    raise newException(IOError, "WinRS command fault: " & runFault)
  var cmdId = extractCommandId(cmdXml)
  if cmdId == "":
    raise newException(IOError, "Could not get CommandId from: " & cmdXml[0..min(2000, cmdXml.len-1)])
  try:
    var retries = 0
    while retries < 120:
      let recvXml = c.send(soapReceiveCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId))
      if isWinrmReceiveTimeout(recvXml):
        if getEnv("WINRMSHELL_DEBUG") == "1":
          styledEcho(fgYellow, "[debug] WinRS receive timeout fault; retrying")
        inc retries
        continue
      let recvFault = faultText(recvXml)
      if recvFault.len > 0:
        raise newException(IOError, "WinRS receive fault: " & recvFault)
      let chunk = decodeWinrsText(recvXml)
      if chunk.len > 0:
        result.add chunk
        if onChunk != nil:
          onChunk(chunk)
      let done = isDone(recvXml)
      if getEnv("WINRMSHELL_DEBUG") == "1":
        let ft = faultText(recvXml)
        styledEcho(fgYellow, "[debug] WinRS receive iter=" & $retries &
          " bytes=" & $recvXml.len & " chunk=" & $chunk.len & " done=" & $done &
          (if ft != "": " fault=" & ft else: ""))
      if done:
        break
      sleep(15)
      inc retries
  finally:
    try:
      discard c.send(soapCleanupCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId))
    except CatchableError:
      discard

proc runPowershellBinaryOnShell(c: var WinRMClient, shellId, script: string,
                                onChunk: ChunkCallback = nil): string =
  let args = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " & encodePs(script)
  let requestedCmdId = genUuid().toUpperAscii()
  let cmdXml = c.send(soapRunCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, requestedCmdId, "powershell.exe", args))
  var cmdId = extractCommandId(cmdXml)
  if cmdId == "":
    cmdId = requestedCmdId
  if cmdId == "":
    raise newException(IOError, "Could not get CommandId from: " & cmdXml[0..min(2000, cmdXml.len-1)])
  var errText = ""
  try:
    var retries = 0
    while retries < 240:
      let recvXml = c.send(soapReceiveCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId))
      if isWinrmReceiveTimeout(recvXml):
        inc retries
        continue
      let decoded = decodeWinrsBytes(recvXml)
      if decoded.data.len > 0:
        result.add decoded.data
        if onChunk != nil:
          onChunk(decoded.data)
      if decoded.err.len > 0:
        errText.add decoded.err
      if isDone(recvXml):
        break
      sleep(15)
      inc retries
    let cleanedErr = cleanWinrsErrorText(errText).strip()
    if cleanedErr != "":
      raise newException(IOError, cleanedErr)
  finally:
    try:
      discard c.send(soapCleanupCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId))
    except CatchableError:
      discard

proc runCmdFast*(c: var WinRMClient, cmd: string, isCmd: bool): string =
  let shellId = createCmdShell(c)
  try:
    result = runCmdOnShell(c, shellId, cmd, isCmd)
  finally:
    deleteCmdShell(c, shellId)

proc runCmdFastCached*(c: var WinRMClient, cmd: string, isCmd: bool,
                       onChunk: ChunkCallback = nil): string =
  if c.cmdShellDenied:
    return runCmdCollect(c, cmd, isCmd, onChunk, true)
  try:
    let useCmd = isCmd or shouldRunViaCmd(cmd)
    result = runCmdOnShell(c, ensureCmdShell(c), cmd, useCmd, onChunk)
  except Exception as e:
    let msg = e.msg.toLowerAscii()
    c.cmdShellId = ""
    if "access is denied" in msg or "could not find shellid" in msg or
       "winrm error 500" in msg or "not supported" in msg or
       "operation not permitted" in msg or
       "gss_init_sec_context failed" in msg or
       "no context has been established" in msg or
       "invalid token was supplied" in msg or
       "wsman" in msg or "invalid selectors" in msg or "winrs" in msg:
      c.cmdShellDenied = true
      resetTransport(c)
      return runCmdCollect(c, cmd, isCmd, onChunk, true)
    raise

proc warmSmartShell*(c: var WinRMClient) =
  let interactiveStatus = getEnv("WINRMSHELL_STATUS") != "0"
  if c.cmdShellDenied:
    ensureShell(c)
    return
  try:
    if interactiveStatus:
      styledEcho(fgWhite, "[*] Checking WinRM shell support...")
    discard ensureCmdShell(c)
  except Exception as e:
    let msg = e.msg.toLowerAscii()
    c.cmdShellId = ""
    if "access is denied" in msg or "could not find shellid" in msg or
       "winrm error 500" in msg or "not supported" in msg or
       "operation not permitted" in msg or
       "gss_init_sec_context failed" in msg or
       "no context has been established" in msg or
       "invalid token was supplied" in msg or
       "wsman" in msg or "invalid selectors" in msg or "winrs" in msg:
      c.cmdShellDenied = true
      resetTransport(c)
      ensureShell(c)
      return
    raise

proc runCmdFastOrPsrp*(c: var WinRMClient, cmd: string, isCmd = false): string =
  if not c.cmdShellDenied:
    try:
      return runCmdFast(c, cmd, isCmd)
    except Exception as e:
      let msg = e.msg.toLowerAscii()
      if "access is denied" in msg or "could not find shellid" in msg or
         "winrm error 500" in msg or "not supported" in msg or
         "operation not permitted" in msg or
         "gss_init_sec_context failed" in msg or
         "no context has been established" in msg or
         "invalid token was supplied" in msg or
         "wsman" in msg or "invalid selectors" in msg or "winrs" in msg:
        c.cmdShellDenied = true
        resetTransport(c)
      elif "command line is too long" in msg:
        discard
      else:
        raise
  result = runCmd(c, cmd, isCmd, true)

proc runBinaryFastCached*(c: var WinRMClient, script: string,
                          onChunk: ChunkCallback = nil): string =
  if c.cmdShellDenied:
    raise newException(IOError, "WinRS binary stream unavailable for this session")
  try:
    result = runPowershellBinaryOnShell(c, ensureCmdShell(c), script, onChunk)
  except Exception as e:
    let msg = e.msg.toLowerAscii()
    c.cmdShellId = ""
    if "access is denied" in msg or "could not find shellid" in msg or
       "winrm error 500" in msg or "not supported" in msg or
       "operation not permitted" in msg or
       "gss_init_sec_context failed" in msg or
       "no context has been established" in msg or
       "invalid token was supplied" in msg or
       "wsman" in msg:
      c.cmdShellDenied = true
      resetTransport(c)
    raise

proc uploadFilePsrp*(c: var WinRMClient, data: string, setup: string, total: int) =
  proc psLiteral(s: string): string = "'" & s.replace("'", "''") & "'"
  let b64 = encode(data)
  let token = psexecmod.randomToken()
  let chunkSize = 24000
  let prep =
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" &
    setup &
    "$dir = Split-Path -Parent $p; " &
    "if($dir -and -not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}; " &
    "$b64 = $p + '." & token & ".b64'; " &
    "if(Test-Path -LiteralPath $b64){Remove-Item -LiteralPath $b64 -Force}; " &
    "New-Item -ItemType File -Path $b64 -Force | Out-Null"
  discard runCmdCollect(c, prep, false)
  drawProgress("upload", 0, total)
  var off = 0
  while off < b64.len:
    let stop = min(off + chunkSize, b64.len)
    let chunk = b64[off ..< stop]
    let append =
      setup &
      "$b64 = $p + '." & token & ".b64'; " &
      "[IO.File]::AppendAllText($b64, " & psLiteral(chunk) & ")"
    discard runCmdCollect(c, append, false)
    off = stop
    let sentBytes = min(total, (off * 3) div 4)
    drawProgress("upload", sentBytes, total)
  let finalize =
    setup &
    "$b64 = $p + '." & token & ".b64'; " &
    "$txt = [IO.File]::ReadAllText($b64); " &
    "$bytes = [Convert]::FromBase64String($txt); " &
    "[IO.File]::WriteAllBytes($p, $bytes); " &
    "Remove-Item -LiteralPath $b64 -Force -ErrorAction SilentlyContinue"
  discard runCmdCollect(c, finalize, false)
  drawProgress("upload", total, total)

proc uploadFileStream*(c: var WinRMClient, data: string, setup: string, total: int) =
  var shellId = ""
  try:
    shellId = createCmdShell(c)
    let writer =
      "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" &
      setup &
      "$dir = Split-Path -Parent $p; " &
      "if($dir -and -not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}; " &
      "$in = [Console]::OpenStandardInput(); " &
      "$out = [IO.File]::Open($p, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None); " &
      "$buf = New-Object byte[] 65536; " &
      "try { while(($n = $in.Read($buf, 0, $buf.Length)) -gt 0){ $out.Write($buf, 0, $n) } } finally { $out.Close(); $in.Close() }"
    let args = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " & encodePs(writer)
    let requestedCmdId = genUuid().toUpperAscii()
    let cmdXml = c.send(soapRunCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, requestedCmdId, "powershell.exe", args))
    var cmdId = extractCommandId(cmdXml)
    if cmdId == "":
      cmdId = requestedCmdId
    if cmdId == "":
      raise newException(IOError, "Could not get CommandId from: " & cmdXml[0..min(2000, cmdXml.len-1)])

    var off = 0
    let chunkSize = 262144
    drawProgress("upload", 0, total)
    while off < data.len:
      let stop = min(off + chunkSize, data.len)
      discard c.send(soapSendCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId, encode(data[off ..< stop]), false))
      off = stop
      drawProgress("upload", off, total)
    discard c.send(soapSendCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId, "", true))

    var retries = 0
    var output = ""
    while retries < 240:
      let recvXml = c.send(soapReceiveCmd(c.host, c.port, c.useSSL, c.sessionId, shellId, cmdId))
      let chunk = decodeWinrsText(recvXml)
      if chunk.len > 0:
        output.add chunk
      if isDone(recvXml):
        break
      sleep(15)
      inc retries
    if output.strip() != "":
      raise newException(IOError, output.strip())
  except CatchableError as e:
    let msg = e.msg.toLowerAscii()
    if "operation not permitted" in msg or "access is denied" in msg or
       "could not find shellid" in msg or "winrm error 500" in msg or
       "not supported" in msg or "gss_init_sec_context failed" in msg or
       "no context has been established" in msg or
       "invalid token was supplied" in msg or
       "wsman" in msg or "winrs" in msg:
      c.cmdShellDenied = true
      resetTransport(c)
      uploadFilePsrp(c, data, setup, total)
    else:
      raise
  finally:
    if shellId.len > 0:
      deleteCmdShell(c, shellId)


proc drawProgress*(label: string, current, total: int) =
  const spinFrames = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]
  const barWidth   = 34

  var spinIdx {.global.}: int   = 0
  var t0      {.global.}: float = 0.0

  if current == 0:
    t0      = epochTime()
    spinIdx = 0

  let elapsed = max(epochTime() - t0, 0.001)
  let pct     = if total > 0: (current * 100) div total else: 100
  let nFill   = if total > 0: (current * barWidth) div total else: barWidth
  let done    = current >= total

  proc fmtBytes(b: int): string =
    if b < 1024:      $b & " B"
    elif b < 1048576: formatFloat(b.float / 1024.0,    ffDecimal, 1) & " KB"
    else:             formatFloat(b.float / 1048576.0, ffDecimal, 2) & " MB"

  let spin = if done: "\e[1;33m✔\e[0m"
             else: "\e[36m" & spinFrames[spinIdx mod spinFrames.len] & "\e[0m"
  inc spinIdx

  var bar = ""
  for i in 0..<barWidth:
    if i < nFill:                 bar.add("\e[36m━")
    elif i == nFill and not done: bar.add("\e[33m╸")
    else:                         bar.add("\e[90m╌")
  bar.add("\e[0m")

  let pctStr = (if done: "\e[1;33m" else: "\e[33m") & align($pct & "%", 4) & "\e[0m"

  let sizeStr = "\e[37m" & fmtBytes(current) & "\e[90m/\e[37m" & fmtBytes(total) & "\e[0m"

  var extras = ""
  if done:
    extras = "  \e[90mdone in \e[33m" & formatFloat(elapsed, ffDecimal, 1) & "s\e[0m"
  elif elapsed > 0.3 and current > 0:
    let bps = current.float / elapsed
    extras = "  \e[33m" & fmtBytes(int(bps)) & "/s\e[0m"
    let eta = int((total - current).float / bps)
    if eta > 0:
      extras.add("  \e[90meta \e[37m" & $eta & "s\e[0m")

  stdout.write("\r\e[K" &
    spin & "  \e[1;37m" & label & "\e[0m  " &
    "\e[90m[\e[0m" & bar & "\e[90m]\e[0m  " &
    pctStr & "  " & sizeStr & extras)
  stdout.flushFile()


proc deleteShell*(c: var WinRMClient) =
  flushPendingCleanup(c)
  deleteCachedCmdShell(c)
  if c.shellId == "": return
  try: discard c.send(soapDelete(c.host, c.port, c.useSSL, c.sessionId, c.shellId))
  except: discard
  c.shellId = ""

type
  WinRmProbe* = object
    host*: string
    port*: int
    reachable*: bool
    speaksWinRm*: bool
    statusCode*: int
    authHeader*: string
    serverHeader*: string
    message*: string

  WinRmCommandResult* = object
    host*: string
    port*: int
    success*: bool
    output*: string
    message*: string

  WinRmAuthMethod* = enum
    wamNtlm, wamKerberos

const wamToAuthMethod: array[WinRmAuthMethod, AuthMethod] = [amNtlm, amKerberos]

proc buildWinRmProbeRequest(host: string; path = "/wsman"): string =
  "GET " & path & " HTTP/1.1\r\nHost: " & host &
    "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"

proc probeHeaderValue(response, name: string): string =
  let lower = name.toLowerAscii() & ":"
  for line in response.splitLines():
    if line.toLowerAscii().startsWith(lower):
      return line[lower.len .. ^1].strip()

proc probeStatusCode(response: string): int =
  let parts = response.splitLines()[0].splitWhitespace()
  if parts.len >= 2:
    try: result = parseInt(parts[1]) except ValueError: discard

proc probeWinRm*(host: string; port, timeoutMs: int; path = "/wsman"): Future[WinRmProbe] {.async.} =
  var socket = newAsyncSocket()
  try:
    let connected = await netproxy.connectTcp(socket, host, port, timeoutMs)
    if not connected:
      return WinRmProbe(host: host, port: port, reachable: false, message: "timeout")
    await socket.send(buildWinRmProbeRequest(host, path))
    let recvFuture = socket.recv(2048)
    if not await withTimeout(recvFuture, timeoutMs):
      return WinRmProbe(host: host, port: port, reachable: true, message: "connected, receive timeout")
    let response = await recvFuture
    if response.len == 0:
      return WinRmProbe(host: host, port: port, reachable: true, message: "connected, no response")
    let statusCode = probeStatusCode(response)
    result = WinRmProbe(
      host: host, port: port, reachable: true,
      speaksWinRm: statusCode in [200, 401, 405],
      statusCode: statusCode,
      authHeader: probeHeaderValue(response, "WWW-Authenticate"),
      serverHeader: probeHeaderValue(response, "Server"),
      message: "HTTP response")
  except CatchableError as error:
    result = WinRmProbe(host: host, port: port, reachable: false, message: error.msg.splitLines()[0])
  finally:
    socket.close()

proc probeRawHttpResponse(sock: Socket; timeoutMs: int; closeOnEof: bool): tuple[status: int; headers, body: string] =
  var raw = ""
  var chunk = newString(4096)
  while true:
    let split = raw.find("\r\n\r\n")
    if split >= 0:
      result.headers = raw[0 ..< split]
      raw = raw[split + 4 .. ^1]
      break
    let n = sock.recv(chunk, 4096, timeoutMs)
    if n <= 0: break
    raw.add chunk[0 ..< n]
  if result.headers.len > 0:
    let parts = result.headers.splitLines()[0].splitWhitespace()
    if parts.len >= 2:
      try: result.status = parseInt(parts[1]) except ValueError: discard
  var cl = -1
  for line in result.headers.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      try: cl = parseInt(line["content-length:".len .. ^1].strip()) except ValueError: discard
      break
  if cl >= 0:
    while raw.len < cl:
      let n = sock.recv(chunk, min(4096, cl - raw.len), timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
  elif closeOnEof:
    while true:
      let n = sock.recv(chunk, 4096, timeoutMs)
      if n <= 0: break
      raw.add chunk[0 ..< n]
  result.body = raw

proc probeWinRmSync*(host: string; port, timeoutMs: int; path = "/wsman"): WinRmProbe =
  let dialHost = netproxy.proxySocketHost(host)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  var sock = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  try:
    netproxy.connectTcpSync(sock, host, port, timeoutMs)
    sock.send(buildWinRmProbeRequest(host, path))
    let resp = probeRawHttpResponse(sock, timeoutMs, closeOnEof = true)
    result = WinRmProbe(
      host: host, port: port, reachable: true,
      speaksWinRm: resp.status in [200, 401, 405],
      statusCode: resp.status,
      authHeader: probeHeaderValue(resp.headers, "WWW-Authenticate"),
      serverHeader: probeHeaderValue(resp.headers, "Server"),
      message: "HTTP response")
  except CatchableError as error:
    result = WinRmProbe(host: host, port: port, reachable: false,
      message: error.msg.splitLines()[0])
  finally:
    sock.close()

proc probeHttpSend(sock: Socket; host: string; port: int; path, authHeader, body: string) =
  var req = "POST " & path & " HTTP/1.1\r\n"
  req.add "Host: " & host & ":" & $port & "\r\n"
  req.add "Content-Type: application/soap+xml;charset=UTF-8\r\n"
  req.add "User-Agent: Microsoft WinRM Client\r\n"
  req.add "Accept: */*\r\n"
  req.add "Connection: Keep-Alive\r\n"
  if authHeader.len > 0:
    req.add "Authorization: " & authHeader & "\r\n"
  req.add "Content-Length: " & $body.len & "\r\n\r\n"
  req.add body
  sock.send(req)

proc extractNtlmChallenge(headers: string): seq[byte] =
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("www-authenticate:"):
      let value = line["www-authenticate:".len .. ^1].strip()
      if value.toLowerAscii().startsWith("negotiate "):
        try: return cast[seq[byte]](base64.decode(value[10 .. ^1].strip()))
        except: discard

const IdentifyBody = """<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>"""

proc checkWinRmAuthFast*(host: string; port: int;
                          username, password, ntlmHash, domain: string;
                          path = "/wsman"; timeoutMs = 8000): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  let dialHost = netproxy.proxySocketHost(host)
  let af = if ':' in dialHost: Domain.AF_INET6 else: Domain.AF_INET
  var sock = newSocket(af, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
  try:
    netproxy.connectTcpSync(sock, host, port, timeoutMs)
    try: sock.setSockOpt(OptNoDelay, true, level = cint(6))
    except CatchableError: discard
    let type1 = spnegoInit(cast[string](buildNtlmNegotiate()))
    probeHttpSend(sock, host, port, path, "Negotiate " & base64.encode(type1), IdentifyBody)
    let resp1 = probeRawHttpResponse(sock, timeoutMs, closeOnEof = false)
    if resp1.status == 200:
      result.success = true
      result.message = "auth ok"
      return
    if resp1.status != 401:
      result.message = "unexpected HTTP " & $resp1.status & " on Type1"
      return
    let challengeBytes = extractNtlmChallenge(resp1.headers)
    if challengeBytes.len == 0:
      result.message = "server did not return NTLM challenge"
      return
    let challenge = parseChallenge(challengeBytes)
    var sessionKey: array[16, byte]
    let type3 = buildNtlmAuthenticate(username, password, domain, "", ntlmHash,
      challenge, sessionKey)
    let type3spnego = spnegoResp(cast[string](type3))
    probeHttpSend(sock, host, port, path, "Negotiate " & base64.encode(type3spnego), IdentifyBody)
    let resp3 = probeRawHttpResponse(sock, timeoutMs, closeOnEof = true)
    if resp3.status == 200:
      result.success = true
      result.message = "auth ok"
    elif resp3.status == 401:
      result.message = "auth rejected (HTTP 401) — wrong credentials or --domain"
    else:
      result.message = "HTTP " & $resp3.status & " on Identify"
  except CatchableError as error:
    result.message = error.msg.splitLines()[0]
  finally:
    sock.close()

proc isAuthFailure(msg: string): bool =
  let lower = msg.toLowerAscii()
  "401" in lower or "unauthorized" in lower or "auth failed" in lower or
    "authentication failed" in lower or "authorizationerror" in lower or
    "ntlm auth failed" in lower or ("kerberos" in lower and "fail" in lower)

proc isTransientShellError(msg: string): bool =
  "ShellId" in msg or "MaxConcurrentOperations" in msg or
    "MaxShellsPerUser" in msg or msg.strip().endsWith(":") or
    "timed out" in msg.toLowerAscii() or "connection" in msg.toLowerAscii()

proc isWinRmShellQuotaError(msg: string): bool =
  "ShellId" in msg or "MaxConcurrentOperations" in msg or
    "MaxShellsPerUser" in msg or "quota" in msg.toLowerAscii()

proc newWinRmClient*(host: string; port: int;
                    username, password, ntlmHash, domain: string;
                    useSsl: bool; authMethod: WinRmAuthMethod;
                    delegate = false; spnOverride = ""): WinRMClient =
  result = newClient(host, username, password, ntlmHash, spnOverride, domain,
    wamToAuthMethod[authMethod], useSsl, port, meAuto)
  result.delegate = delegate

proc normalizedKrb5Cache(cache: string): string =
  let clean = cache.strip()
  if clean.len == 0:
    return ""
  if clean.startsWith("FILE:") or clean.startsWith("MEMORY:") or clean.startsWith("API:"):
    return clean
  "FILE:" & expandFilename(clean)

template withKrb5Env(ccache, krb5Config: string; body: untyped) =
  let oldCc = if existsEnv("KRB5CCNAME"): getEnv("KRB5CCNAME") else: ""
  let hadCc = existsEnv("KRB5CCNAME")
  let oldCfg = if existsEnv("KRB5_CONFIG"): getEnv("KRB5_CONFIG") else: ""
  let hadCfg = existsEnv("KRB5_CONFIG")
  if ccache.strip().len > 0:
    putEnv("KRB5CCNAME", normalizedKrb5Cache(ccache))
  if krb5Config.strip().len > 0:
    putEnv("KRB5_CONFIG", expandFilename(krb5Config.strip()))
  try:
    body
  finally:
    if hadCc: putEnv("KRB5CCNAME", oldCc) else: delEnv("KRB5CCNAME")
    if hadCfg: putEnv("KRB5_CONFIG", oldCfg) else: delEnv("KRB5_CONFIG")

proc tryWinRmAuthOnce(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      useSsl: bool; authMethod: WinRmAuthMethod;
                      ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  try:
    withKrb5Env(ccache, krb5Config):
      discard runCmdFast(client, "rem", isCmd = true)
    result = WinRmCommandResult(host: host, port: port, success: true, message: "auth ok")
  except CatchableError as error:
    result = WinRmCommandResult(host: host, port: port, success: false,
      message: error.msg.splitLines()[0])
  finally:
    try: deleteShell(client) except CatchableError: discard

proc checkWinRmAuth*(host: string; port: int;
                     username, password, ntlmHash, domain: string;
                     useSsl = false; authMethod: WinRmAuthMethod = wamNtlm; attempts = 3;
                     ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  let maxAttempts = max(1, attempts)
  for attempt in 1 .. maxAttempts:
    result = tryWinRmAuthOnce(host, port, username, password, ntlmHash, domain,
      useSsl, authMethod, ccache, krb5Config, spnOverride)
    if result.success: return
    if "401" in result.message or "Unauthorized" in result.message:
      result.message = "auth rejected (HTTP 401) — wrong credentials or --domain"
      return
    if not isTransientShellError(result.message) or attempt == maxAttempts:
      if isTransientShellError(result.message):
        if isWinRmShellQuotaError(result.message):
          result.success = true
          result.message = "shell create failed after " & $maxAttempts &
            " tries — auth ok, but server is out of shell quota"
        else:
          result.message = "shell create failed after " & $maxAttempts &
            " tries — server out of shell quota or WinRM rejecting"
      return
    sleep(700 * attempt)

proc runWinRmCommand*(host: string; port: int;
                      username, password, ntlmHash, domain, command: string;
                      useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                      delegate = false; ccache = ""; krb5Config = "";
                      spnOverride = ""): WinRmCommandResult =
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, delegate, spnOverride)
  try:
    withKrb5Env(ccache, krb5Config):
      result = WinRmCommandResult(host: host, port: port, success: true,
        output: runCmdFastOrPsrp(client, command),
        message: "command completed")
  except CatchableError as error:
    var msg = error.msg.splitLines()[0]
    if "401" in msg or "Unauthorized" in msg:
      msg = "auth rejected (HTTP 401) — wrong credentials or --domain"
    elif "ShellId" in msg or msg.strip().endsWith(":"):
      msg = "shell create failed — likely max shells per user reached, or WinRM rejected the request"
    result = WinRmCommandResult(host: host, port: port, success: false, message: msg)
  finally:
    try: deleteShell(client) except CatchableError: discard

proc psQuotePath(path: string): string = "'" & path.replace("'", "''") & "'"
proc psQuote(text: string): string = "'" & text.replace("'", "''") & "'"
proc psArray(args: seq[string]): string =
  result = "@("
  for i, a in args:
    if i > 0: result.add ","
    result.add psQuote(a)
  result.add ")"

proc cmdQuoteArg(arg: string): string =
  "\"" & arg.replace("\"", "\\\"") & "\""

proc cleanAssemblyOutput(output: string): string =
  for line in output.splitLines():
    let t = line.strip()
    if t.len > 0 and not t.startsWith("#< CLIXML"):
      result.add t & "\n"

proc winRmUploadFile*(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      localPath, remotePath: string;
                      useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                      ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  try:
    withKrb5Env(ccache, krb5Config):
      let data = readFile(localPath)
      let setup = "$p = " & psQuotePath(remotePath) & "; "
      try:
        uploadFileStream(client, data, setup, data.len)
      except CatchableError as uploadError:
        let msg = uploadError.msg.toLowerAscii()
        if "operation not permitted" in msg or
           "gss_init_sec_context failed" in msg or
           "no context has been established" in msg or
           "invalid token was supplied" in msg:
          try: deleteShell(client) except CatchableError: discard
          client = newWinRmClient(host, port, username, password, ntlmHash,
            domain, useSsl, authMethod, spnOverride = spnOverride)
          client.cmdShellDenied = true
          uploadFilePsrp(client, data, setup, data.len)
        else:
          raise
      result.message = "uploaded " & $data.len & " bytes"
    result.success = true
    result.output = remotePath
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    try: deleteShell(client) except CatchableError: discard

proc winRmDownloadFile*(host: string; port: int;
                        username, password, ntlmHash, domain: string;
                        remotePath, localPath: string;
                        useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                        ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  var outFile: File
  try:
    withKrb5Env(ccache, krb5Config):
      let setup = "$p = " & psQuotePath(remotePath) & "; "
      let sizeText = runCmdFastOrPsrp(client, setup & "[int64]((Get-Item -LiteralPath $p).Length)", false).strip()
      var total = 0
      try: total = parseInt(sizeText) except ValueError: discard
      outFile = open(localPath, fmWrite)
      var written = 0
      if total > 0: drawProgress("download", 0, total)
      let script =
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" & setup &
        "$fs=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);" &
        "try{$out=[Console]::OpenStandardOutput();$buf=New-Object byte[] 65536;" &
        "while(($n=$fs.Read($buf,0,$buf.Length)) -gt 0){$out.Write($buf,0,$n)}}finally{$fs.Close()}"
      discard runBinaryFastCached(client, script,
        proc(chunk: string) =
          outFile.write(chunk)
          inc written, chunk.len
          if total > 0: drawProgress("download", written, total))
      if total > 0: drawProgress("download", total, total)
      result.message = "downloaded " & $written & " bytes"
      result.output = localPath
    result.success = true
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    if outFile != nil:
      try: outFile.close() except CatchableError: discard
    try: deleteShell(client) except CatchableError: discard

proc executeManagedAssemblyFromMemory*(host: string; port: int;
                                        username, password, ntlmHash, domain: string;
                                        localPath: string; runArgs: seq[string];
                                        useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                                        ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  let data = readFile(localPath)
  if not isManagedPe(data):
    result.message = "file is not a managed .NET assembly"
    return
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  let encoded = base64.encode(data)
  let cmd =
    "$ErrorActionPreference = 'Stop'; " &
    "$b64 = '" & encoded & "'; " &
    "$bytes = [Convert]::FromBase64String($b64); " &
    "try { $asm = [Reflection.Assembly]::Load($bytes) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
    "$entry = $asm.EntryPoint; " &
    "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
    "$params = $entry.GetParameters(); " &
    "$argv = " & psArray(runArgs) & "; " &
    "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
    "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
    "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
    "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
    "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
    "try { [Console]::SetOut($out); [Console]::SetError($err); $ret = $entry.Invoke($null, $invokeArgs); if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()} } finally { [Console]::SetOut($oldOut); [Console]::SetError($oldErr) }; " &
    "$stdout = $out.ToString(); $stderr = $err.ToString(); if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"
  try:
    var output = ""
    withKrb5Env(ccache, krb5Config):
      output = runCmd(client, cmd, false)
    if output.len > 0: result.output = cleanAssemblyOutput(output)
    result.success = true
    result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    try: deleteShell(client) except CatchableError: discard

proc executeManagedAssemblyViaRunner*(host: string; port: int;
                                       username, password, ntlmHash, domain: string;
                                       localPath: string; runArgs: seq[string];
                                       useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                                       ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  let asmBytes =
    try: readFile(localPath)
    except CatchableError as e:
      result.message = "cannot read assembly: " & e.msg
      return
  let runner =
    try: psexecmod.buildRunnerBinary()
    except CatchableError as e:
      result.message = e.msg
      return

  var rng = initRand(int(getTime().toUnixFloat() * 1e9))
  var key = newString(32)
  for i in 0 ..< 32:
    key[i] = char(rng.rand(255))
  var keyHex = ""
  for b in key:
    keyHex.add b.uint8.toHex(2).toLowerAscii()
  var encBytes = newString(asmBytes.len)
  for i in 0 ..< asmBytes.len:
    encBytes[i] = char(uint8(ord(asmBytes[i])) xor uint8(ord(key[i mod 32])))

  let token = psexecmod.randomToken()
  let token2 = psexecmod.randomToken()
  let exePath = "C:\\Windows\\Temp\\ne" & token & ".exe"
  let blobPath = "C:\\Windows\\Temp\\ne" & token2 & ".dat"
  let runnerPath = getTempDir() / ("nimux_runner_" & token & ".exe")
  let blobLocalPath = getTempDir() / ("nimux_blob_" & token2 & ".dat")
  writeFile(runnerPath, runner)
  writeFile(blobLocalPath, encBytes)
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  try:
    withKrb5Env(ccache, krb5Config):
      let runnerUpload = winRmUploadFile(host, port, username, password, ntlmHash,
        domain, runnerPath, exePath, useSsl, authMethod, ccache, krb5Config, spnOverride)
      if not runnerUpload.success:
        raise newException(IOError, "runner upload failed: " & runnerUpload.message)
      let blobUpload = winRmUploadFile(host, port, username, password, ntlmHash,
        domain, blobLocalPath, blobPath, useSsl, authMethod, ccache, krb5Config, spnOverride)
      if not blobUpload.success:
        raise newException(IOError, "blob upload failed: " & blobUpload.message)
      var invokeCmd = exePath & " " & keyHex & " " & blobPath
      for arg in runArgs:
        invokeCmd.add " " & cmdQuoteArg(arg)
      let output = runCmdFastCached(client, invokeCmd, true)
      if output.len > 0:
        result.output = cleanAssemblyOutput(output)
      else:
        result.output = "no output from assembly"
      result.success = true
      result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    try:
      withKrb5Env(ccache, krb5Config):
        discard runCmdFastCached(client,
          "del /F /Q " & cmdQuoteArg(exePath) & " " & cmdQuoteArg(blobPath) & " 2>nul",
          true)
    except CatchableError:
      discard
    try: removeFile(runnerPath) except CatchableError: discard
    try: removeFile(blobLocalPath) except CatchableError: discard
    try: deleteShell(client) except CatchableError: discard

proc executeManagedAssemblyDirectExe*(host: string; port: int;
                                       username, password, ntlmHash, domain: string;
                                       localPath: string; runArgs: seq[string];
                                       useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                                       ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if not fileExists(localPath):
    result.message = "local file not found: " & localPath
    return
  let data =
    try: readFile(localPath)
    except CatchableError as e:
      result.message = "cannot read assembly: " & e.msg
      return
  let token = psexecmod.randomToken()
  let remotePath = "C:\\Windows\\Temp\\ne" & token & ".exe"
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  try:
    withKrb5Env(ccache, krb5Config):
      let upload = winRmUploadFile(host, port, username, password, ntlmHash,
        domain, localPath, remotePath, useSsl, authMethod, ccache, krb5Config, spnOverride)
      if not upload.success:
        raise newException(IOError, "direct upload failed: " & upload.message)
      var invokeCmd = remotePath
      for arg in runArgs:
        invokeCmd.add " " & cmdQuoteArg(arg)
      var output = ""
      try:
        output = runCmdFastCached(client, invokeCmd, true)
      except CatchableError as e:
        raise newException(IOError, "direct execute failed: " & e.msg)
      if output.len > 0:
        result.output = cleanAssemblyOutput(output)
      else:
        result.output = "no output from assembly"
      result.success = true
      result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    try:
      withKrb5Env(ccache, krb5Config):
        discard runCmdFastCached(client, "del /F /Q " & cmdQuoteArg(remotePath) & " 2>nul", true)
    except CatchableError:
      discard
    try: deleteShell(client) except CatchableError: discard

proc runManagedAssemblyFromRemotePath*(host: string; port: int;
                                        username, password, ntlmHash, domain: string;
                                        remotePath: string; runArgs: seq[string];
                                        useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                                        ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = WinRmCommandResult(host: host, port: port)
  if remotePath.len == 0:
    result.message = "remote path must not be empty"
    return
  var client = newWinRmClient(host, port, username, password, ntlmHash, domain,
    useSsl, authMethod, spnOverride = spnOverride)
  let setup = "$p = " & psQuotePath(remotePath) & "; "
  let cmd =
    "$ErrorActionPreference = 'Stop'; " & setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
    "Set-Location -LiteralPath (Split-Path -Parent $p); " &
    "$argv = " & psArray(runArgs) & "; " &
    "try { $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($p)) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
    "$entry = $asm.EntryPoint; " &
    "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
    "$params = $entry.GetParameters(); " &
    "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
    "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
    "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
    "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
    "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
    "try { [Console]::SetOut($out); [Console]::SetError($err); $ret = $entry.Invoke($null, $invokeArgs); if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()} } finally { [Console]::SetOut($oldOut); [Console]::SetError($oldErr) }; " &
    "$stdout = $out.ToString(); $stderr = $err.ToString(); if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"
  try:
    var output = ""
    withKrb5Env(ccache, krb5Config):
      output = runCmd(client, cmd, false)
    if output.len > 0: result.output = cleanAssemblyOutput(output)
    result.success = true
    result.message = "assembly executed"
  except CatchableError as error:
    result.success = false
    result.message = error.msg.splitLines()[0]
  finally:
    try: deleteShell(client) except CatchableError: discard

proc looksLikeAssemblyFsDependencyError(output: string): bool =
  let lower = output.toLowerAscii()
  "fileiopermission" in lower or "internallreadallbytes" in lower or
    "internalreadallbytes" in lower or "could not find file" in lower or
    "the system cannot find the file specified" in lower or
    "path not found" in lower or "directorynotfoundexception" in lower

proc looksLikeRunnerExecError(output: string): bool =
  let lower = output.toLowerAscii()
  "the system cannot execute the specified program" in lower or
    "the filename, directory name, or volume label syntax is incorrect" in lower

proc executeAssembly*(host: string; port: int;
                      username, password, ntlmHash, domain: string;
                      localPath: string; runArgs: seq[string];
                      useSsl = false; authMethod: WinRmAuthMethod = wamNtlm;
                      ccache = ""; krb5Config = ""; spnOverride = ""): WinRmCommandResult =
  result = executeManagedAssemblyDirectExe(host, port, username, password, ntlmHash,
    domain, localPath, runArgs, useSsl, authMethod, ccache, krb5Config, spnOverride)
  if result.success and not looksLikeRunnerExecError(result.output):
    return
  result = executeManagedAssemblyViaRunner(host, port, username, password, ntlmHash,
    domain, localPath, runArgs, useSsl, authMethod, ccache, krb5Config, spnOverride)
  if result.success and not looksLikeAssemblyFsDependencyError(result.output) and
      not looksLikeRunnerExecError(result.output):
    return
  result = executeManagedAssemblyFromMemory(host, port, username, password, ntlmHash,
    domain, localPath, runArgs, useSsl, authMethod, ccache, krb5Config, spnOverride)
  if result.success and not looksLikeAssemblyFsDependencyError(result.output):
    return
  let stagedRemote = "C:\\Windows\\Temp\\" & extractFilename(localPath)
  var upload: WinRmCommandResult
  withKrb5Env(ccache, krb5Config):
    upload = winRmUploadFile(host, port, username, password, ntlmHash, domain,
      localPath, stagedRemote, useSsl, authMethod, ccache, krb5Config, spnOverride)
  if not upload.success:
    if result.success: return
    result = upload
    return
  let remoteRun = runManagedAssemblyFromRemotePath(host, port, username, password,
    ntlmHash, domain, stagedRemote, runArgs, useSsl, authMethod,
    ccache, krb5Config, spnOverride)
  if remoteRun.success or remoteRun.output.len > 0:
    result = remoteRun
  try:
    withKrb5Env(ccache, krb5Config):
      var cleanupClient = newWinRmClient(host, port, username, password, ntlmHash,
        domain, useSsl, authMethod, spnOverride = spnOverride)
      discard runCmd(cleanupClient,
        "Remove-Item -LiteralPath " & psQuotePath(stagedRemote) & " -Force -ErrorAction SilentlyContinue", false)
      deleteShell(cleanupClient)
  except CatchableError: discard
