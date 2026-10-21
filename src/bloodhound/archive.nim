## Read ZIP entries in memory. Never extract archive paths to the filesystem.
import std/[os, sets, strutils]
import zippy
import zippy/crc

const
  MaxArchiveBytes* = 32 * 1024 * 1024
  MaxEntryBytes* = 32 * 1024 * 1024
  MaxTotalBytes* = 128 * 1024 * 1024
  # Zippy has no output limit during inflation. Bound compressed input as well
  # as advertised/actual output (DEFLATE expansion is at most ~1032:1).
  MaxCompressedEntry* = 128 * 1024
  MaxEntries* = 1024

proc fail(message: string) =
  raise newException(ValueError, "ZIP: " & message)

proc number(s: string; pos, size: int): int =
  if pos < 0 or pos > s.len - size: fail("truncated header")
  for i in 0 ..< size:
    result = result or (ord(s[pos + i]) shl (8 * i))

proc safeName(name: string): bool =
  if name.len == 0 or name[0] in {'/', '\\'}: return false
  if '\x00' in name or ':' in name or '\\' in name: return false
  for part in name.split('/'):
    if part == "..": return false
  true

iterator jsonEntries*(path: string): tuple[name, contents: string] =
  if getFileSize(path) > MaxArchiveBytes: fail("archive exceeds 32 MiB limit")
  let data = readFile(path)
  if data.len > MaxArchiveBytes: fail("archive exceeds 32 MiB limit")
  var eocd = -1
  if data.len >= 22:
    for pos in countdown(data.len - 22, max(0, data.len - 65557)):
      if number(data, pos, 4) == 0x06054b50 and
          pos + 22 + number(data, pos + 20, 2) == data.len:
        eocd = pos
        break
  if eocd < 0: fail("end of directory missing")
  if number(data, eocd + 4, 2) != 0 or number(data, eocd + 6, 2) != 0:
    fail("split archives are unsupported")
  let count = number(data, eocd + 10, 2)
  let directorySize = number(data, eocd + 12, 4)
  let directoryStart = number(data, eocd + 16, 4)
  if count == 65535 or directorySize == 0xffffffff or directoryStart == 0xffffffff:
    fail("ZIP64 is unsupported in this version")
  if count > MaxEntries: fail("too many entries")
  if count != number(data, eocd + 8, 2): fail("inconsistent entry count")
  if directoryStart + directorySize != eocd: fail("invalid directory bounds")
  var pos = directoryStart
  var total = 0
  var names = initHashSet[string]()
  for i in 0 ..< count:
    if pos + 46 > eocd or number(data, pos, 4) != 0x02014b50:
      fail("invalid directory entry")
    let flags = number(data, pos + 8, 2)
    let meth = number(data, pos + 10, 2)
    let checksum = number(data, pos + 16, 4).uint32
    let compressed = number(data, pos + 20, 4)
    let expanded = number(data, pos + 24, 4)
    let nameLen = number(data, pos + 28, 2)
    let extraLen = number(data, pos + 30, 2)
    let commentLen = number(data, pos + 32, 2)
    let offset = number(data, pos + 42, 4)
    if number(data, pos + 34, 2) != 0: fail("split entry")
    if pos + 46 + nameLen + extraLen + commentLen > eocd: fail("truncated entry")
    let name = data[pos + 46 ..< pos + 46 + nameLen]
    pos += 46 + nameLen + extraLen + commentLen
    if not safeName(name): fail("unsafe entry name")
    if name.toLowerAscii() in names: fail("duplicate entry name")
    names.incl name.toLowerAscii()
    if (flags and 1) != 0: fail("encrypted archives are unsupported")
    if not name.toLowerAscii().endsWith(".json"): continue
    if meth notin [0, 8]: fail("unsupported compression method")
    if expanded > MaxEntryBytes or total + expanded > MaxTotalBytes:
      fail("JSON exceeds decompressed size limits")
    if meth == 8 and compressed > MaxCompressedEntry:
      fail("compressed JSON entry exceeds 128 KiB safety limit; use a smaller collection")
    if offset + 30 > directoryStart or number(data, offset, 4) != 0x04034b50:
      fail("invalid local header")
    if number(data, offset + 6, 2) != flags or number(data, offset + 8, 2) != meth:
      fail("local and central headers disagree")
    let localNameLen = number(data, offset + 26, 2)
    let start = offset + 30 + localNameLen + number(data, offset + 28, 2)
    if start > directoryStart or compressed > directoryStart - start:
      fail("entry exceeds archive bounds")
    if data[offset + 30 ..< offset + 30 + localNameLen] != name:
      fail("local entry name mismatch")
    let payload = data[start ..< start + compressed]
    let contents = if meth == 0: payload else: uncompress(payload, dfDeflate)
    if contents.len != expanded: fail("uncompressed size mismatch")
    if crc32(contents) != checksum: fail("checksum mismatch")
    total += contents.len
    yield (name, contents)
  if pos != eocd: fail("directory length mismatch")
