import strutils, math, terminal, parseopt, std/endians, std/memfiles, os, unicode, prufer

when defined(posix):
  import posix

# (v1.1.0) change: horizontal sub-block characters (0/8 to 8/8 width) instead of the former vertical thing
const HorizontalBlockChars = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]

# bind standard c tmpfile for safe anonymous buffers
proc c_tmpfile(): File {.importc: "tmpfile", header: "<stdio.h>".}

when defined(windows):
  proc c_popen(cmd: cstring, mode: cstring): File {.importc: "_popen", header: "<stdio.h>".}
  proc c_pclose(f: File): cint {.importc: "_pclose", header: "<stdio.h>".}
else:
  proc c_popen(cmd: cstring, mode: cstring): File {.importc: "popen", header: "<stdio.h>".}
  proc c_pclose(f: File): cint {.importc: "pclose", header: "<stdio.h>".}

type Pager = object
  file: File
  isPipe: bool

proc openPager(disabled: bool, outputFile: string): Pager =
  if disabled or outputFile != "" or not stdout.isatty():
    return Pager(file: stdout, isPipe: false)

  when not defined(windows):
    signal(SIGPIPE, SIG_IGN)

  var pagerCmd = getEnv("PAGER")
  if pagerCmd.strip() == "":
    pagerCmd = "less -RFX"
  elif pagerCmd == "less":
    pagerCmd = "less -RFX"

  let pipeFile = c_popen(cstring(pagerCmd), "w")
  if pipeFile.isNil:
    return Pager(file: stdout, isPipe: false)
    
  return Pager(file: pipeFile, isPipe: true)

proc close(p: Pager) =
  if p.isPipe and not p.file.isNil:
    discard c_pclose(p.file)

# some common magic byte signatures
const MagicHeaders = [
  ("\x7FELF\x02\x01\x01", "ELF Executable (64-bit)"),
  ("MZ\x90\x00\x03\x00", "DOS/PE Executable"),
  ("\x89PNG\x0D\x0A\x1A\x0A", "PNG Image"),
  ("\xFF\xD8\xFF\xE0", "JPEG Image (JFIF)"),
  ("\xFF\xD8\xFF\xE1", "JPEG Image (EXIF)"),
  ("PK\x03\x04", "ZIP Archive"),
  ("Rar!\x1A\x07\x00", "RAR Archive v4"),
  ("Rar!\x1A\x07\x01\x00", "RAR Archive v5"),
  ("\x1F\x8B\x08", "GZIP Compressed"),
  ("%PDF-1.", "PDF Document"),
  ("\xCA\xFE\xBA\xBE", "Java Class File"),
  ("SQLite format 3\x00", "SQLite Database"),
  ("OggS\x00\x02", "Ogg Vorbis Media"),
  ("\x52\x49\x46\x46", "RIFF / WAV / AVI"),
  # v1.1.0 add: added more magic headers to deafult set including mach-o support
  ("7z\xBC\xAF\x27\x1C", "7-Zip Archive"),
  ("fLaC", "FLAC Audio Stream"),
  ("BZh", "BZIP2 Compressed File"),
  ("\xFE\xED\xFA\xCE", "Mach-O Executable (32-bit BE)"),
  ("\xCE\xFA\xED\xFE", "Mach-O Executable (32-bit LE)"),
  ("\xFE\xED\xFA\xCF", "Mach-O Executable (64-bit BE)"),
  ("\xCF\xFA\xED\xFE", "Mach-O Executable (64-bit LE)")
]

var HexLUT: array[256, array[2, char]]
var searchBytes: seq[byte] = @[]
var groupSize: int = 8

proc initHexLUT() =
  const hexChars = "0123456789ABCDEF"
  for i in 0 .. 255:
    HexLUT[i][0] = hexChars[i div 16]
    HexLUT[i][1] = hexChars[i mod 16]

proc addHex8(buf: var string, val: int) {.inline.} =
  const hexChars = "0123456789ABCDEF"
  for shift in countdown(28, 0, 4):
    buf.add(hexChars[(val shr shift) and 0xF])

proc addEntropyStr(buf: var string, val: float) {.inline.} =
  let v = int(round(val * 100.0))
  let whole = v div 100
  let frac = abs(v mod 100)
  buf.add(char(ord('0') + whole))
  buf.add('.')
  buf.add(char(ord('0') + (frac div 10)))
  buf.add(char(ord('0') + (frac mod 10)))

type RollingEntropy = object
  ring: seq[byte]
  counts: array[256, int]
  head: int
  activeLen: int
  windowSize: int
  sumCLogC: float64
  lut: seq[float64]

proc initRollingEntropy(windowSize: int): RollingEntropy =
  result.windowSize = windowSize
  result.ring = newSeq[byte](windowSize)
  result.lut = newSeq[float64](windowSize + 1)
  result.lut[0] = 0.0
  for c in 1 .. windowSize:
    result.lut[c] = float64(c) * log2(float64(c))
  result.head = 0
  result.activeLen = 0
  result.sumCLogC = 0.0

proc push(e: var RollingEntropy, newByte: byte) {.inline.} =
  if e.activeLen == e.windowSize:
    let oldByte = e.ring[e.head]
    let oldC = e.counts[oldByte]
    e.sumCLogC += e.lut[oldC - 1] - e.lut[oldC]
    e.counts[oldByte] -= 1
  else:
    e.activeLen += 1

  e.ring[e.head] = newByte
  let newC = e.counts[newByte]
  e.sumCLogC += e.lut[newC + 1] - e.lut[newC]
  e.counts[newByte] += 1
  
  e.head += 1
  if e.head >= e.windowSize:
    e.head = 0

proc getEntropy(e: RollingEntropy): float64 {.inline.} =
  if e.activeLen == 0: return 0.0
  let w = float64(e.activeLen)
  return log2(w) - (e.sumCLogC / w)

type MagicFilter = array[256, bool]

# now changed to here so processSummary can see it
type FileRegion = tuple[startPos, endPos: int]

proc initMagicFilter(magicList: openArray[tuple[sig: string, label: string]]): MagicFilter =
  for magic in magicList:
    if magic.sig.len > 0:
      result[byte(magic.sig[0])] = true

func detectMagic(buffer: openArray[byte], bytesRead: int, magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter): tuple[label: string, offset: int] =
  for start in 0 ..< bytesRead:
    if not filter[buffer[start]]:
      continue
    for magic in magicList:
      let sig = magic.sig
      if start + sig.len <= bytesRead:
        var match = true
        for i in 0 ..< sig.len:
          if buffer[start + i] != byte(sig[i]):
            match = false
            break
        if match: return (magic.label, start)
  return ("", 0)

# (v1.1.0) change: add unified procedures for handling all broken pipe handling across all subroutines instead of the former method of each subroutine having its own checks
proc handleIoError(e: ref IOError, contextMsg: string = "Output stream write failed") =
  if "Broken pipe" notin e.msg and "errno: 32" notin e.msg and "broken pipe" notin e.msg:
    stderr.writeLine("neoxd: error: " & contextMsg & " - " & e.msg)
  quit(1)

proc safeWrite(stream: File, s: string, contextMsg: string = "Output stream write failed") {.inline.} =
  try:
    stream.write(s)
  except IOError as e:
    handleIoError(e, contextMsg)

type FastWriter* = object
  stream: File
  buf: array[65536, char]
  pos: int

proc initFastWriter*(stream: File): FastWriter =
  result.stream = stream
  result.pos = 0

# updated these two procedures for the new unified broken pipe checking(v1.1.0)
proc flush*(w: var FastWriter) =
  if w.pos > 0:
    try:
      if w.stream.writeBuffer(addr w.buf[0], w.pos) != w.pos:
        raise newException(IOError, "Failed to write buffer to stream")
    except IOError as e:
      handleIoError(e, "Failed to flush final buffer")
    w.pos = 0

proc writeStr*(w: var FastWriter, s: string) {.inline.} =
  if s.len == 0: return
  
  # if the new string exceeds remaining capacity flush the buffer first
  if w.pos + s.len > w.buf.len:
    w.flush()
  
  # if the string itself is larger than the entire buffer (rare, but safe) write directly
  if s.len > w.buf.len:
    try:
      if w.stream.writeBuffer(unsafeAddr s[0], s.len) != s.len:
        raise newException(IOError, "Failed to write large string to stream")
    except IOError as e:
      handleIoError(e, "Failed to write large string")
  else:
    # otherwise copy it into the buffer fast
    copyMem(addr w.buf[w.pos], unsafeAddr s[0], s.len)
    w.pos += s.len

proc printVersion() =
  echo """neoxd by nulsie under GNU GPL v3"""

func calculateEntropy(window: openArray[byte]): float =
  if window.len == 0: return 0.0
  var counts: array[256, int] 
  for b in window: counts[b] += 1
  var entropy = 0.0
  let length = float(window.len)
  for c in counts:
    if c > 0:
      let p = float(c) / length
      entropy -= p * log2(p)
  return entropy

# (v1.1.0) fix: enhanced this procedure to correctly parses negative numbers and neg hex strings for the reversal/neg seeking support
proc parseOffset(s: string): int =
  let clean = s.strip()
  if clean.startsWith("-"):
    return -parseOffset(clean[1..^1])
  if clean.toLowerAscii().startsWith("0x"):
    return parseHexInt(clean[2..^1])
  else:
    return parseInt(clean)

# (v1.1.0) add: added a search and highlight feature which that takes a hex string or text string  which automatically filters out non-matching blocks or highlights matching lines in color
proc parseSearchBytes(s: string): seq[byte] =
  result = @[]
  let clean = s.strip()
  if clean.len == 0: return
  
  # check if string is valid hex (even length and all hex digits)
  var isHex = clean.len mod 2 == 0
  if isHex:
    for c in clean:
      if c notin HexDigits:
        isHex = false
        break
  
  if isHex:
    var i = 0
    while i + 1 < clean.len:
      result.add(parseHexInt(clean[i .. i+1]).byte)
      i += 2
  else:
    # treat as plain text ascii bytes
    for c in clean:
      result.add(byte(c))

proc getEntropyColor(entropy: float): ForegroundColor =
  if entropy < 2.0: return fgCyan     
  elif entropy < 5.5: return fgGreen  
  elif entropy < 7.2: return fgYellow 
  else: return fgRed                

proc getEntropyBar(ratio: float, width: int = 8): string =
  let totalSteps = float(width * 8)
  let filledSteps = clamp(ratio * totalSteps, 0.0, totalSteps)
  result = newStringOfCap(width)
  for i in 0 ..< width:
    let cellSteps = clamp(filledSteps - float(i * 8), 0.0, 8.0)
    let idx = int(round(cellSteps))
    result.add(HorizontalBlockChars[idx])

proc printProgressBar(outStream: File, label: string, count, total: int, color: ForegroundColor, useColor: bool) =
  let pct = if total == 0: 0.0 else: float(count) / float(total) * 100.0
  let barCount = int(pct / 2.0)
  let bars = "█".repeat(barCount)
  let padding = max(0, 50 - barCount)
  let paddedBars = bars & " ".repeat(padding)
  let line = alignLeft(label, 15) & " | " & paddedBars & " " & formatFloat(pct, ffDecimal, 1) & "%\n"

  if useColor and outStream == stdout:
    stdout.setForegroundColor(color)
    try:
      stdout.write(line)
    except IOError as e:
      handleIoError(e, "Progress bar write failed")
    stdout.resetAttributes()
  else:
    safeWrite(outStream, line, "Progress bar write failed")

proc loadCustomMagic(filename: string, dest: var seq[tuple[sig: string, label: string]]) =
  if not fileExists(filename):
    stderr.writeLine("Error: Custom magic file not found: " & filename)
    quit(1)
    
  for line in lines(filename):
    let stripped = line.strip()
    if stripped == "" or stripped.startsWith("#"): continue
    
    let parts = stripped.split(',', maxsplit=1)
    if parts.len == 2:
      let hexStr = parts[0].strip()
      let label = parts[1].strip()
      try:
        var binSig = ""
        var i = 0
        while i + 1 < hexStr.len:
          binSig.add(char(parseHexInt(hexStr[i .. i+1])))
          i += 2
        dest.add((binSig, label))
      except ValueError:
        stderr.writeLine("Warning: Invalid hex in custom magic file (skipping): " & hexStr)

# (v1.1.0) fix: fixed processSummary to prevent false +ves in detecting embedded file signs, processStream had alr prevented dis by querying getReadOnlyRegions to identify executable code and data sections and skipping magic detection inside them, processSummary wasn't using those ignored regions
proc processSummary(f: File, ignoredRegions: openArray[FileRegion], magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, outStream: File = stdout, useColor: bool = true, cols: int = 16) =
  var buffer = newSeq[byte](cols)
  var totalBytes = 0
  var totalBlocks = 0
  var globalCounts: array[256, int]
  var blocksLow, blocksMedLow, blocksMedHigh, blocksHigh = 0
  var foundSignatures: seq[string] = @[]

  while true:
    let bytesRead = f.readBuffer(addr buffer[0], cols)
    if bytesRead <= 0: break
  
    var skipMagic = false
    for reg in ignoredRegions:
      if totalBytes >= reg.startPos and totalBytes < reg.endPos:
        skipMagic = true
        break

    if not skipMagic:
      let (magic, magicOffset) = detectMagic(buffer, bytesRead, magicList, filter)
      if magic != "": 
        foundSignatures.add(magic & " at 0x" & toHex(totalBytes + magicOffset, 8))
  
    for i in 0 ..< bytesRead:
       globalCounts[buffer[i]] += 1
      
    totalBytes += bytesRead
    totalBlocks += 1
  
    let chunkEntropy = calculateEntropy(buffer.toOpenArray(0, bytesRead - 1))
    let dynamicMax = if bytesRead > 1: min(8.0, log2(float(bytesRead))) else: 0.0
    let ratio = if dynamicMax > 0: chunkEntropy / dynamicMax else: 0.0
      
    if ratio < 0.25: blocksLow += 1
    elif ratio < 0.60: blocksMedLow += 1
    elif ratio < 0.85: blocksMedHigh += 1
    else: blocksHigh += 1

  if totalBytes == 0: quit("File is empty.")
  
  var globalEntropy = 0.0
  for c in globalCounts:
    if c > 0:
      let p = float(c) / float(totalBytes)
      globalEntropy -= p * log2(p)
  
  var buckets: array[16, int]
  for i in 0 .. 255:
    buckets[i div 16] += globalCounts[i]
  
  safeWrite(outStream, "\n=======================================================================\n", "Summary report write failed")
  safeWrite(outStream, " FILE SUMMARY REPORT\n", "Summary report write failed")
  safeWrite(outStream, "=======================================================================\n", "Summary report write failed")
  safeWrite(outStream, " Total Size     : " & $totalBytes & " bytes\n", "Summary report write failed")
  safeWrite(outStream, " Overall Entropy: " & formatFloat(globalEntropy, ffDecimal, 3) & " / 8.000\n", "Summary report write failed")
    
  if foundSignatures.len > 0:
    safeWrite(outStream, "\n Embedded Files Detected:\n", "Summary report write failed")
    for sig in foundSignatures: safeWrite(outStream, "   -> " & sig & "\n", "Summary report write failed")
  safeWrite(outStream, "=======================================================================\n\n", "Summary report write failed")
  
  safeWrite(outStream, "--- Block Distribution (Structural Density) ---\n", "Summary report write failed")
  printProgressBar(outStream, "Padding/Nulls", blocksLow, totalBlocks, fgCyan, useColor)
  printProgressBar(outStream, "Text/Sparse", blocksMedLow, totalBlocks, fgGreen, useColor)
  printProgressBar(outStream, "Code/Data", blocksMedHigh, totalBlocks, fgYellow, useColor)
  printProgressBar(outStream, "Packed/Crypto", blocksHigh, totalBlocks, fgRed, useColor)
    
  safeWrite(outStream, "\n--- Global Byte Frequency Histogram ---\n", "Summary report write failed")
  for i in 0 ..< 16:
    let label = "0x" & toHex(i * 16, 2) & " - 0x" & toHex((i * 16) + 15, 2)
    printProgressBar(outStream, label, buckets[i], totalBytes, fgWhite, useColor)
  safeWrite(outStream, "\n", "Summary report write failed")

proc getAnsiColor(entropy: float, useColor: bool): string =
  if not useColor: return ""
  if entropy < 2.0: return "\e[36m"     
  elif entropy < 5.5: return "\e[32m"   
  elif entropy < 7.2: return "\e[33m"   
  else: return "\e[31m"

proc readU16(f: File, isBigEndian: bool): uint16 =
  var raw: uint16
  if f.readBuffer(addr raw, 2) != 2: return 0
  if isBigEndian: bigEndian16(addr result, addr raw)
  else: littleEndian16(addr result, addr raw)

proc readU32(f: File, isBigEndian: bool): uint32 =
  var raw: uint32
  if f.readBuffer(addr raw, 4) != 4: return 0
  if isBigEndian: bigEndian32(addr result, addr raw)
  else: littleEndian32(addr result, addr raw)

proc readU64(f: File, isBigEndian: bool): uint64 =
  var raw: uint64
  if f.readBuffer(addr raw, 8) != 8: return 0
  if isBigEndian: bigEndian64(addr result, addr raw)
  else: littleEndian64(addr result, addr raw)

proc logDebug(msg: string, debugMode: bool) =
  if debugMode:
    stderr.writeLine("[DEBUG] " & msg)

# v1.1.0 add and a bitta change: added support for PE and Mach-O header bytes, i had to change the getReadOnlyRegions for this
# as i have turned the single method into separate methods for ELF, Mach-O and PE, stil the former method exists to gue them together
proc getPEReadOnlyRegions(f: File, startPos: int64, fileSize: int64, debugMode: bool): seq[FileRegion] =
  var regions: seq[FileRegion] = @[]
  try:
    f.setFilePos(startPos + 0x3C)
    let peOffset = readU32(f, false) # pe headers are always little-endian
    if int64(peOffset) + 4 > fileSize: return regions

    f.setFilePos(startPos + int64(peOffset))
    var peSig: array[4, byte]
    if f.readBuffer(addr peSig[0], 4) != 4 or peSig != [byte 0x50, 0x45, 0x00, 0x00]: 
      return regions

    # number of sections is at peoffset + 6
    f.setFilePos(startPos + int64(peOffset) + 6)
    let numSections = readU16(f, false)

    # size of optional header is at peoffset + 20
    f.setFilePos(startPos + int64(peOffset) + 20)
    let optHeaderSize = readU16(f, false)

    # section headers follow: pe signature (4) + coff header (20) + optional header size
    let sectionsOffset = int64(peOffset) + 4 + 20 + int64(optHeaderSize)

    for i in 0 ..< int(numSections):
      let secOffset = sectionsOffset + (i * 40)
      if secOffset + 40 > fileSize: break

      f.setFilePos(startPos + secOffset + 16)
      let sizeOfRawData = readU32(f, false)
      f.setFilePos(startPos + secOffset + 20)
      let pointerToRawData = readU32(f, false)
      f.setFilePos(startPos + secOffset + 36) # characteristics flags
      let characteristics = readU32(f, false)

      # IMAGE_SCN_MEM_WRITE = 0x80000000 if write bit is not set, it's read-only.
      let isWritable = (characteristics and 0x80000000'u32) != 0
      if not isWritable and sizeOfRawData > 0:
        let endOffset = int64(pointerToRawData) + int64(sizeOfRawData)
        if endOffset <= fileSize and int64(pointerToRawData) >= 0:
          regions.add((int(pointerToRawData), int(endOffset)))
  except CatchableError as e:
    logDebug("PE Section Parsing Exception: " & e.msg, debugMode)
  return regions

proc getMachOReadOnlyRegions(f: File, startPos: int64, fileSize: int64, magic: uint32, debugMode: bool): seq[FileRegion] =
  var regions: seq[FileRegion] = @[]
  try:
    let isBigEndian = (magic == 0xFEEDFACE'u32 or magic == 0xFEEDFACF'u32)
    let is64Bit = (magic == 0xFEEDFACF'u32 or magic == 0xCFFAEDFE'u32)

    f.setFilePos(startPos + 16)
    let ncmds = readU32(f, isBigEndian)

    var cmdPos = startPos + (if is64Bit: 32 else: 28)
    for i in 0 ..< int(ncmds):
      if cmdPos + 8 > startPos + fileSize: break
      f.setFilePos(cmdPos)
      let cmd = readU32(f, isBigEndian)
      let cmdsize = readU32(f, isBigEndian)
      if cmdsize < 8 or cmdPos + int64(cmdsize) > startPos + fileSize: break

      # LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
      if cmd == 0x1 or cmd == 0x19:
        let initprotOffset = cmdPos + 24 + (if is64Bit: 32 else: 16) + 4
        f.setFilePos(initprotOffset)
        let initprot = readU32(f, isBigEndian)

        # VM_PROT_WRITE = 0x2
        let isWritable = (initprot and 0x2) != 0
        if not isWritable:
          let fileoffOffset = cmdPos + 24 + (if is64Bit: 16 else: 8)
          f.setFilePos(fileoffOffset)
          let fileoff = if is64Bit: readU64(f, isBigEndian) else: uint64(readU32(f, isBigEndian))
          let segSize = if is64Bit: readU64(f, isBigEndian) else: uint64(readU32(f, isBigEndian))

          if segSize > 0 and int64(fileoff) + int64(segSize) <= fileSize:
            regions.add((int(fileoff), int(fileoff + segSize)))

      cmdPos += int64(cmdsize)
  except CatchableError as e:
    logDebug("Mach-O Parsing Exception: " & e.msg, debugMode)
  return regions

proc getELFReadOnlyRegions(f: File, startPos: int64, fileSize: int64, debugMode: bool): seq[FileRegion] =
  var regions: seq[FileRegion] = @[]
  try:
    var e_ident: array[16, byte]
    f.setFilePos(startPos)
    if f.readBuffer(addr e_ident[0], 16) != 16: return regions

    let eiClass = e_ident[4]
    let eiData = e_ident[5]
    if eiClass notin {byte 1, byte 2} or eiData notin {byte 1, byte 2}: return regions

    let is64Bit = (eiClass == 2)
    let isBigEndian = (eiData == 2)

    var e_shoff: uint64
    var e_shentsize, e_shnum: uint16

    if not is64Bit:
      f.setFilePos(startPos + 32)
      e_shoff = uint64(readU32(f, isBigEndian))
      f.setFilePos(startPos + 46)
      e_shentsize = readU16(f, isBigEndian)
      e_shnum = readU16(f, isBigEndian)
    else:
      f.setFilePos(startPos + 40)
      e_shoff = readU64(f, isBigEndian)
      f.setFilePos(startPos + 58)
      e_shentsize = readU16(f, isBigEndian)
      e_shnum = readU16(f, isBigEndian)

    let expectedEntSize = if is64Bit: 64 else: 40
    if int(e_shentsize) < expectedEntSize or e_shoff == 0: return regions

    var actualShNum = int(e_shnum)
    if e_shnum == 0 or e_shnum == 0xFFFF:
      if int64(e_shoff) + int64(e_shentsize) <= fileSize:
        if not is64Bit:
          f.setFilePos(startPos + int64(e_shoff) + 20)
          actualShNum = int(readU32(f, isBigEndian))
        else:
          f.setFilePos(startPos + int64(e_shoff) + 32)
          actualShNum = int(readU64(f, isBigEndian))

    for i in 0 ..< actualShNum:
      let entryOffset = int64(e_shoff) + (i * int64(e_shentsize))
      if entryOffset < 0 or entryOffset + int64(e_shentsize) > fileSize: continue

      var sh_type, sh_flags, sh_offset, sh_size: uint64
      if not is64Bit:
        f.setFilePos(startPos + entryOffset + 4)
        sh_type = uint64(readU32(f, isBigEndian))
        sh_flags = uint64(readU32(f, isBigEndian))
        f.setFilePos(f.getFilePos() + 4)
        sh_offset = uint64(readU32(f, isBigEndian))
        sh_size = uint64(readU32(f, isBigEndian))
      else:
        f.setFilePos(startPos + entryOffset + 4)
        sh_type = uint64(readU32(f, isBigEndian))
        sh_flags = readU64(f, isBigEndian)
        f.setFilePos(f.getFilePos() + 8)
        sh_offset = uint64(readU64(f, isBigEndian))
        sh_size = readU64(f, isBigEndian)

      if sh_type != 0 and (sh_flags and 0x5) == 0:
        let endOffset = int64(sh_offset) + int64(sh_size)
        if endOffset <= fileSize and endOffset > 0 and int64(sh_offset) >= 0:
          regions.add((int(sh_offset), int(endOffset)))
  except CatchableError as e:
    logDebug("ELF Section Parsing Exception: " & e.msg, debugMode)
  return regions

proc getReadOnlyRegions(f: File, debugMode: bool = false): seq[FileRegion] =
  var startPos: int64 = 0
  try:
    startPos = f.getFilePos()
    let fileSize = f.getFileSize()
    if fileSize < 64: return @[]

    var magicHeader: array[4, byte]
    if f.readBuffer(addr magicHeader[0], 4) != 4: return @[]

    # 1. check ELF Magic (\x7FELF)
    if magicHeader[0..3] == [byte 0x7F, 0x45, 0x4C, 0x46]:
      return getELFReadOnlyRegions(f, startPos, fileSize, debugMode)

    # 2. check PE / DOS Magic (MZ -> 0x4D 0x5A)
    if magicHeader[0..1] == [byte 0x4D, 0x5A]:
      return getPEReadOnlyRegions(f, startPos, fileSize, debugMode)

    # 3. check Mach-O magics using explicit comparisons instead of a set literal
    let machMagic = cast[ptr uint32](addr magicHeader[0])[]
    if machMagic == 0xFEEDFACE'u32 or machMagic == 0xCEFAEDFE'u32 or 
       machMagic == 0xFEEDFACF'u32 or machMagic == 0xCFFAEDFE'u32:
      return getMachOReadOnlyRegions(f, startPos, fileSize, machMagic, debugMode)

  except CatchableError as e:
    logDebug("Header Dispatch Exception: " & e.msg, debugMode)
  finally:
    try: f.setFilePos(startPos) except: discard

  return @[]

proc processStream(f: File, minEntropy: float, maxEntropy: float, ignoredRegions: seq[FileRegion], magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, outStream: File = stdout, useColor: bool = true, seekPos: int = 0, readLength: int = 0, cols: int = 16, windowSize: int = 256) =
  # initialize the buffered writer and ensure it flushes when the function returns
  var writer = initFastWriter(outStream)
  defer: 
    try:
      writer.flush() 
    except IOError as e: 
      handleIoError(e, "Failed to flush final buffer")

  if seekPos > 0:
    try:
      f.setFilePos(int64(seekPos))
    except IOError:
      var discardBuf: array[4096, byte]
      var remainingSeek = seekPos
      while remainingSeek > 0:
        let toRead = min(4096, remainingSeek)
        if f.readBuffer(addr discardBuf[0], toRead) <= 0: break
        remainingSeek -= toRead

  var buffer = newSeq[byte](cols)
  var prevBuffer = newSeq[byte](cols)
  var prevLen = 0
  var offset = seekPos
  var bytesProcessed = 0

  var entropyCalc = initRollingEntropy(windowSize)
  var lineBuf = newStringOfCap(256)

  let Reset = if useColor: "\e[0m" else: ""
  let BrightMagenta = if useColor: "\e[95m" else: ""
  let HighlightCode = if useColor: "\e[43;30m" else: ""

  while true:
    var toRead = cols
    if readLength > 0:
      let remaining = readLength - bytesProcessed
      if remaining <= 0: break
      toRead = min(cols, remaining)

    let bytesRead = f.readBuffer(addr buffer[0], toRead)
    if bytesRead <= 0: break

    for i in 0 ..< bytesRead:
      entropyCalc.push(buffer[i])

    let rawChunkEntropy = entropyCalc.getEntropy()
    let chunkEntropy = round(rawChunkEntropy * 100.0) / 100.0
    let entropyRatio = chunkEntropy / 8.0

    # search pattern matching across prevBuffer + buffer
    var matchedRanges: seq[tuple[startOffset, endOffset: int]] = @[]
    if searchBytes.len > 0:
      var combined = newSeq[byte](prevLen + bytesRead)
      for i in 0 ..< prevLen: combined[i] = prevBuffer[i]
      for i in 0 ..< bytesRead: combined[prevLen + i] = buffer[i]
          
      let combinedLen = combined.len
      if combinedLen >= searchBytes.len:
        for start in 0 .. combinedLen - searchBytes.len:
          var match = true
          for i in 0 ..< searchBytes.len:
            if combined[start + i] != searchBytes[i]:
              match = false
              break
          if match:
            let actualStart = offset - prevLen + start
            matchedRanges.add((actualStart, actualStart + searchBytes.len))

    var skipMagic = false
    for reg in ignoredRegions:
      if offset >= reg.startPos and offset < reg.endPos:
        skipMagic = true
        break
    
    var magicLabel = ""
    if not skipMagic:
      let (detectedLabel, _) = detectMagic(buffer, bytesRead, magicList, filter)
      magicLabel = detectedLabel

    if magicLabel == "" and prevLen > 0 and not skipMagic:
      var combined = newSeq[byte](cols * 2)
      let combinedLen = prevLen + bytesRead
      for i in 0 ..< prevLen: combined[i] = prevBuffer[i]
      for i in 0 ..< bytesRead: combined[prevLen + i] = buffer[i]
      
      for magic in magicList:
        let sig = magic.sig
        if combinedLen >= sig.len:
          let minStart = max(0, prevLen - sig.len + 1)
          let maxStart = prevLen - 1
          
          for start in minStart .. maxStart:
            if not filter[combined[start]]: continue
            if start + sig.len <= combinedLen:
              var match = true
              for i in 0 ..< sig.len:
                if combined[start + i] != byte(sig[i]):
                  match = false
                  break
              if match: 
                let actualOffset = offset - prevLen + start
                magicLabel = magic[1] & " (at 0x" & toHex(actualOffset, 8) & ")"
                break
        if magicLabel != "": break

    if magicLabel == "" and (chunkEntropy < minEntropy or chunkEntropy > maxEntropy):
      prevBuffer = buffer
      prevLen = bytesRead
      offset += bytesRead
      bytesProcessed += bytesRead
      continue
    
    let colorCode = getAnsiColor(chunkEntropy, useColor)
    let bar = getEntropyBar(entropyRatio)
    let splitIndex = (cols div 2) - 1

    lineBuf.setLen(0)
    if colorCode.len > 0: lineBuf.add(colorCode)
    lineBuf.addHex8(offset)
    lineBuf.add(": ")

    # hex column with highlighting
    for i in 0 ..< cols:
      if i < bytesRead:
        let b = buffer[i]
        let absByteOffset = offset + i
        var isHighlighted = false
        for r in matchedRanges:
          if absByteOffset >= r.startOffset and absByteOffset < r.endOffset:
            isHighlighted = true
            break
            
        if isHighlighted and HighlightCode.len > 0: lineBuf.add(HighlightCode)
        lineBuf.add(HexLUT[b][0])
        lineBuf.add(HexLUT[b][1])
        if isHighlighted and HighlightCode.len > 0:
          if colorCode.len > 0: lineBuf.add(colorCode) else: lineBuf.add(Reset)
        lineBuf.add(' ')
      else:
        lineBuf.add("   ")

      if (i + 1) mod groupSize == 0 and i < cols - 1:
        lineBuf.add(' ')
        
      if i == splitIndex and cols > 1: lineBuf.add(' ')

    # ascii Column with Highlighting
    for i in 0 ..< cols:
      if i < bytesRead:
        let c = char(buffer[i])
        let absByteOffset = offset + i
        var isHighlighted = false
        for r in matchedRanges:
          if absByteOffset >= r.startOffset and absByteOffset < r.endOffset:
            isHighlighted = true
            break
    
        if isHighlighted and HighlightCode.len > 0: lineBuf.add(HighlightCode)
        if c in ' ' .. '~': lineBuf.add(c)
        else: lineBuf.add('.')
        if isHighlighted and HighlightCode.len > 0:
          if colorCode.len > 0: lineBuf.add(colorCode) else: lineBuf.add(Reset)
      else:
        lineBuf.add(' ')

    lineBuf.add(" | H: ")
    lineBuf.addEntropyStr(chunkEntropy)
    lineBuf.add(" [")
    lineBuf.add(bar) # (v1.1.0): adds the full horizontal bar directly
    lineBuf.add(']')
    if Reset.len > 0: lineBuf.add(Reset)
        
    if magicLabel != "":
      if BrightMagenta.len > 0: lineBuf.add(BrightMagenta)
      lineBuf.add(" <== [ ")
      lineBuf.add(magicLabel)
      lineBuf.add(" ]")
      if Reset.len > 0: lineBuf.add(Reset)
          
    lineBuf.add('\n')
        
    try:
      writer.writeStr(lineBuf)
    except IOError as e:
      handleIoError(e, "Output stream write failed")
        
    prevBuffer = buffer
    prevLen = bytesRead
    offset += bytesRead
    bytesProcessed += bytesRead

proc processStreamMmap(filename: string, minEntropy: float, maxEntropy: float, ignoredRegions: seq[FileRegion], magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, outStream: File = stdout, useColor: bool = true, seekPos: int = 0, readLength: int = 0, cols: int = 16, windowSize: int = 256) =
  let fileSize = try: getFileSize(filename) except CatchableError: 0
  if fileSize == 0: return
  
  var mm = memfiles.open(filename, mode = fmRead)
  defer: mm.close()

  when defined(posix):
    discard posix_madvise(mm.mem, mm.size, POSIX_MADV_SEQUENTIAL)
  
  let fileLimit = mm.size
  var offset = seekPos
  if offset < 0 or offset >= fileLimit: return 
    
  let totalBytes = if readLength > 0 and (fileLimit - offset > readLength): 
                     offset + readLength 
                   else: 
                     fileLimit
  let data = cast[ptr UncheckedArray[byte]](mm.mem)
  
  var prevBuffer = newSeq[byte](cols)
  var prevLen = 0

  var entropyCalc = initRollingEntropy(windowSize)
  var lineBuf = newStringOfCap(256)

  let prefillStart = max(0, offset - windowSize)
  for i in prefillStart ..< offset:
    entropyCalc.push(data[i])

  let Reset = if useColor: "\e[0m" else: ""
  let BrightMagenta = if useColor: "\e[95m" else: ""
  let HighlightCode = if useColor: "\e[43;30m" else: ""

  while offset < totalBytes:
    let bytesRead = min(cols, totalBytes - offset)
    
    for i in 0 ..< bytesRead:
      entropyCalc.push(data[offset + i])

    let rawChunkEntropy = entropyCalc.getEntropy()
    let chunkEntropy = round(rawChunkEntropy * 100.0) / 100.0
    let entropyRatio = chunkEntropy / 8.0

    # search pattern matching across prevBuffer + buffer
    var matchedRanges: seq[tuple[startOffset, endOffset: int]] = @[]
    if searchBytes.len > 0:
      var combined = newSeq[byte](prevLen + bytesRead)
      for i in 0 ..< prevLen: combined[i] = prevBuffer[i]
      for i in 0 ..< bytesRead: combined[prevLen + i] = data[offset + i]
          
      let combinedLen = combined.len
      if combinedLen >= searchBytes.len:
        for start in 0 .. combinedLen - searchBytes.len:
          var match = true
          for i in 0 ..< searchBytes.len:
            if combined[start + i] != searchBytes[i]:
              match = false
              break
          if match:
            let actualStart = offset - prevLen + start
            matchedRanges.add((actualStart, actualStart + searchBytes.len))
    
    var skipMagic = false
    for reg in ignoredRegions:
      if offset >= reg.startPos and offset < reg.endPos:
        skipMagic = true
        break
    
    var magicLabel = ""
    if not skipMagic:
      let (detectedLabel, _) = detectMagic(data.toOpenArray(offset, offset + bytesRead - 1), bytesRead, magicList, filter)
      magicLabel = detectedLabel

    if magicLabel == "" and prevLen > 0 and not skipMagic:
      var combined = newSeq[byte](cols * 2)
      let combinedLen = prevLen + bytesRead
      for i in 0 ..< prevLen: combined[i] = prevBuffer[i]
      for i in 0 ..< bytesRead: combined[prevLen + i] = data[offset + i]
      
      for magic in magicList:
        let sig = magic.sig
        if combinedLen >= sig.len:
          let minStart = max(0, prevLen - sig.len + 1)
          let maxStart = prevLen - 1
          
          for start in minStart .. maxStart:
            if not filter[combined[start]]: continue
            if start + sig.len <= combinedLen:
              var match = true
              for i in 0 ..< sig.len:
                if combined[start + i] != byte(sig[i]):
                  match = false
                  break
              if match: 
                let actualOffset = offset - prevLen + start
                magicLabel = magic[1] & " (at 0x" & toHex(actualOffset, 8) & ")"
                break
        if magicLabel != "": break

    if magicLabel == "" and (chunkEntropy < minEntropy or chunkEntropy > maxEntropy):
      for i in 0 ..< bytesRead: prevBuffer[i] = data[offset + i]
      prevLen = bytesRead
      offset += bytesRead
      continue
    
    let colorCode = getAnsiColor(chunkEntropy, useColor)
    let bar = getEntropyBar(entropyRatio)
    let splitIndex = (cols div 2) - 1
    
    lineBuf.setLen(0)
    if colorCode.len > 0: lineBuf.add(colorCode)
    lineBuf.addHex8(offset)
    lineBuf.add(": ")
    
    # hex column with highlighting for mmap
    for i in 0 ..< cols:
      if i < bytesRead:
        let b = data[offset + i]
        let absByteOffset = offset + i
        var isHighlighted = false
        for r in matchedRanges:
          if absByteOffset >= r.startOffset and absByteOffset < r.endOffset:
            isHighlighted = true
            break
                
        if isHighlighted and HighlightCode.len > 0: lineBuf.add(HighlightCode)
        lineBuf.add(HexLUT[b][0])
        lineBuf.add(HexLUT[b][1])
        if isHighlighted and HighlightCode.len > 0:
          if colorCode.len > 0: lineBuf.add(colorCode) else: lineBuf.add(Reset)
        lineBuf.add(' ')
      else:
        lineBuf.add("   ")

      # (v1.1.0) add: added a feature for devising the grouping of bytes in output
      if (i + 1) mod groupSize == 0 and i < cols - 1:
        lineBuf.add(' ')
        
      if i == splitIndex and cols > 1: lineBuf.add(' ')
    
    # ascii column with highlighting for mmap
    for i in 0 ..< cols:
      if i < bytesRead:
        let c = char(data[offset + i])
        let absByteOffset = offset + i
        var isHighlighted = false
        for r in matchedRanges:
          if absByteOffset >= r.startOffset and absByteOffset < r.endOffset:
            isHighlighted = true
            break
        
        if isHighlighted and HighlightCode.len > 0: lineBuf.add(HighlightCode)
        if c in ' ' .. '~': lineBuf.add(c)
        else: lineBuf.add('.')
        if isHighlighted and HighlightCode.len > 0:
          if colorCode.len > 0: lineBuf.add(colorCode) else: lineBuf.add(Reset)
      else:
        lineBuf.add(' ')

    lineBuf.add(" | H: ")
    lineBuf.addEntropyStr(chunkEntropy)
    lineBuf.add(" [")
    lineBuf.add(bar) # (v1.1.0): same thing as the thing in processStream
    lineBuf.add(']')
    if Reset.len > 0: lineBuf.add(Reset)
        
    if magicLabel != "":
      if BrightMagenta.len > 0: lineBuf.add(BrightMagenta)
      lineBuf.add(" <== [ ")
      lineBuf.add(magicLabel)
      lineBuf.add(" ]")
      if Reset.len > 0: lineBuf.add(Reset)
          
    lineBuf.add('\n')
        
    try:
      outStream.write(lineBuf)
    except IOError as e:
      handleIoError(e, "Output stream write failed")
        
    for i in 0 ..< bytesRead: prevBuffer[i] = data[offset + i]
    prevLen = bytesRead
    offset += bytesRead

proc writeByteChecked(outStream: File, b: byte) {.inline.} =
  var buf = [b]
  try:
    if outStream.writeBuffer(addr buf[0], 1) != 1:
      raise newException(IOError, "Failed to write byte to output stream (disk full or broken pipe)")
  except IOError as e:
    handleIoError(e, "Failed to write byte")

proc reverseHexDump(inStream, outStream: File, cols: int = 16) =
  var line: string
  var hexBuffer = ""
  
  while inStream.readLine(line):
    let colonPos = line.find(':')
    if colonPos < 0: continue
    
    var i = colonPos + 1
    var bytesParsed = 0
    var consecutiveSpaces = 0
    
    while i < line.len and bytesParsed < cols:
      let c = line[i]
      
      if c in {' ', '\t'}:
        consecutiveSpaces += 1
        if consecutiveSpaces > 2 and bytesParsed > 0:
          break
        i += 1
        continue
        
      if c == '|': break
        
      if c in HexDigits:
        hexBuffer.add(c)
        consecutiveSpaces = 0
        if hexBuffer.len == 2:
          let b = parseHexInt(hexBuffer).byte
          writeByteChecked(outStream, b)
          hexBuffer.setLen(0)
          bytesParsed += 1
        i += 1
      else:
        break
        
    hexBuffer.setLen(0)

proc processPlainStream(f: File, outStream: File, cols: int = 30) =
  var buffer = newSeq[byte](cols)
  while true:
    let bytesRead = f.readBuffer(addr buffer[0], cols)
    if bytesRead <= 0: break
    var hexStr = ""
    for i in 0 ..< bytesRead:
      hexStr.add(toHex(buffer[i], 2).toLowerAscii())
    safeWrite(outStream, hexStr & "\n", "Plain stream write failed")

proc reversePlainHexDump(inStream, outStream: File) =
  var hexBuffer = ""
  var line: string
  while inStream.readLine(line):
    for c in line:
      if c in HexDigits:
        hexBuffer.add(c)
        if hexBuffer.len == 2:
          let b = parseHexInt(hexBuffer).byte
          writeByteChecked(outStream, b)
          hexBuffer.setLen(0)

proc restoreDump(inStream, outStream: File, plainMode: bool, useColor: bool, magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, cols: int = 16) =
  var tempFile = c_tmpfile()
  if tempFile.isNil:
    quit("Error: Could not allocate anonymous temporary file for restoration.")
      
  defer: tempFile.close()

  proc stripAnsi(s: string): string =
    var res = ""
    var i = 0
    while i < s.len:
      if s[i] == '\e' and i + 1 < s.len and s[i+1] == '[':
        i += 2
        while i < s.len and s[i] notin {'a'..'z', 'A'..'Z'}: i += 1
        if i < s.len: i += 1
      else:
        res.add(s[i])
        i += 1
    return res

  var line: string
  var currentOffset = 0
  
  while inStream.readLine(line):
    let cleanLine = stripAnsi(line)
    let colonPos = cleanLine.find(':')
    let hexStart = if colonPos >= 0: colonPos + 1 else: 0
    
    if colonPos > 0:
      try:
        let parsedOffset = parseOffset(cleanLine[0 ..< colonPos].strip())
        if parsedOffset > currentOffset:
          let padLen = parsedOffset - currentOffset
          for _ in 0 ..< padLen: 
            writeByteChecked(tempFile, 0)
          currentOffset = parsedOffset
      except ValueError:
        discard
    
    var hexEnd = cleanLine.len
    let barPos = cleanLine.find('|', hexStart)
    if barPos > 0: 
      hexEnd = barPos
    
    let hexSection = cleanLine[hexStart ..< hexEnd]
    var pureHex = ""
    var consecutiveSpaces = 0
    
    for c in hexSection:
      if c in HexDigits:
        pureHex.add(c)
        consecutiveSpaces = 0
      elif c in {' ', '\t'}:
        consecutiveSpaces += 1
        if consecutiveSpaces > 2 and pureHex.len > 0:
          break
      else:
        break
      
    var i = 0
    while i + 1 < pureHex.len:
      let b = parseHexInt(pureHex[i .. i+1]).byte
      writeByteChecked(tempFile, b)
      currentOffset += 1
      i += 2
      
  tempFile.setFilePos(0)
    
  if plainMode:
    processPlainStream(tempFile, outStream, cols)
  else:
    processStream(tempFile, 0.0, 8.0, @[], magicList, filter, outStream, useColor, 0, 0, cols)

proc printHelp() =
  echo """
neoxd - hex dumper and analyzer

Usage:
  neoxd [options] [file]

Options:
  -c, --cols:INT               Number of octets per line (default: 16)
  -w, --window:INT             Set the sliding window size for entropy calculation (default: 256)
  -s, --summary                Scan file and output an overall distribution summary
  -S, --search:PATTERN         Highlight occurrences of a hex pattern (e.g., 414243) or text # the argument for the search and highlight
  -o, --output:FILE            Save the hex dump output to a file for editing/analysis
  --no-color                   Disable ANSI colors (automatically set when saving to a file)
  --color                      Force ANSI colors even when writing to a file
  --no-pager                   Disable automatic terminal pager when outputting interactively
  --min, --min-entropy:FLOAT   Only show blocks with entropy >= this value (0.0 to 8.0)
  --max, --max-entropy:FLOAT   Only show blocks with entropy <= this value (0.0 to 8.0)
  -p, --plain                  Output in plain hex format (continuous hex with no offsets or formatting)
  -k, --seek:OFFSET            Start reading at a specific offset (e.g., 0x1000 or 4096)
  -n, --length:BYTES           Stop reading after BYTES are processed
  -g, --group:INT              Number of bytes per hex group (default: 8, e.g., 2 for words, 4 for dwords)
  -r, --reverse                Reverses hex dumps to its original medium
  -R, --restore                Restore a malformed hex dump back into a clean formatted dump
  -m, --magic:FILE             Load additional magic headers from a CSV file (Format: HEX,Label)
  --nop, --no-prufer           Disable PRUFER argument validation (typo guessing, file-swap checks & diagnosis if you command stupidly)
  -d, --debug                  Enable debug diagnostics and detailed error logging to stderr
  -h, --help                   What do you think it will do...
  -v, --version                Show tool version

Examples:
  neoxd -c 32 firmware.bin                - Output 32 octets per line(crappy example for laptops)
  neoxd -c 8 --min=3.8 firmware.bin       - Inspect 8-byte aligned dense blocks
  neoxd -o dump.txt image.jpg             - Safely extract dump without overwriting source image

Note:
  * Even if you try to filter the score of the hex dump, the first line of the filtered dump will always be the first line of the actual dump regardless of it's own score(a file type flagging quirk)
  * By default, PRUFER validation prevents catastrophic file truncation from argument swapping (-o target) and suggests typo corrections. Use --nop to bypass.
  * If you're doing negative/reverse seeking(like -512), be sure to add an equal sign(=).(eg: neoxd -k=-512)
"""

proc main() =
  var minEntropy = 0.0
  var maxEntropy = 8.0
  var cols = 16
  var windowSize = 256
  var targetFile = ""
  var outputFile = ""
  var summaryMode = false
  var reverseMode = false
  var restoreMode = false
  var plainMode = false
  var useColor = true
  var seekPos = 0
  var readLength = 0
  var explicitColorFlag = false
  var noPager = false
  var customMagicFile = ""
  var debugMode = false
  var noPrufer = false
  var searchPattern = ""

  var positionalArgs: seq[string] = @[]
  var p = initOptParser()
    
  while true:
    p.next()
    case p.kind
    of cmdArgument: 
      positionalArgs.add(p.key)
    of cmdLongOption, cmdShortOption:
      case p.key
      of "c", "cols", "columns":
        cols = parseInt(p.requireVal(p.key))
        if cols <= 0: quit("Error: Column count must be greater than 0.")
      of "w", "window":
        windowSize = parseInt(p.requireVal(p.key))
        if windowSize <= 0: quit("Error: Window size must be greater than 0.")
      of "no-pager": noPager = true
      of "p", "plain": plainMode = true
      of "s", "summary": summaryMode = true
      of "r", "reverse": reverseMode = true
      of "R", "restore": restoreMode = true
      of "d", "debug": debugMode = true
      of "S", "search":
        searchPattern = p.requireVal(p.key)
      of "g", "group":
        groupSize = parseInt(p.requireVal(p.key))
        if groupSize <= 0 or (cols mod groupSize != 0 and groupSize notin {1, 2, 4, 8, 16}):
          quit("Error: Group size must be a valid divisor of column count (e.g., 1, 2, 4, 8).")
      of "k", "seek": 
        seekPos = parseOffset(p.requireVal(p.key))
      of "n", "length": 
        readLength = parseOffset(p.requireVal(p.key))
      of "o", "output":
        outputFile = p.requireVal(p.key)
      of "no-color": 
        useColor = false
        explicitColorFlag = true
      of "color":
        useColor = true
        explicitColorFlag = true
      of "h", "help": printHelp(); quit(0)
      of "v", "version": printVersion(); quit(0)
      of "min", "min-entropy": 
        minEntropy = parseFloat(p.requireVal(p.key))
      of "max", "max-entropy": 
        maxEntropy = parseFloat(p.requireVal(p.key))
      of "m", "magic":
        customMagicFile = p.requireVal(p.key)
      of "nop", "no-prufer":
        noPrufer = true
      else: 
        checkFlagTypo(p.key)
    of cmdEnd: break
  
  if positionalArgs.len > 0:
    targetFile = positionalArgs[0]

  searchBytes = parseSearchBytes(searchPattern)
  
  # run prufer validations (unless bypassed)
  if not noPrufer:
    checkSyntaxSanity(positionalArgs)
    checkFileSwap(targetFile, outputFile, isRestoreMode = (restoreMode or reverseMode))

  if not explicitColorFlag:
    useColor = stdout.isatty() and outputFile == ""

  var activeMagicHeaders: seq[tuple[sig: string, label: string]] = @[]
  for m in MagicHeaders:
    activeMagicHeaders.add((m[0], m[1]))
      
  if customMagicFile != "":
    loadCustomMagic(customMagicFile, activeMagicHeaders)

  let magicFilter = initMagicFilter(activeMagicHeaders)
  initHexLUT()
  
  var f: File
  var inputIsOpen = false
    
  if targetFile != "" and targetFile != "-":
    if not open(f, targetFile): 
      quit("Error: Cannot open target file: " & targetFile)
    inputIsOpen = true

    # (v1.1.0) fix: support for negative/reverse seeking
    # resolve negative seeks relative to the file size
    if seekPos < 0:
      let fileSize = f.getFileSize()
      seekPos = int(fileSize) + seekPos
      if seekPos < 0:
        seekPos = 0 # clamp to start of file if negative offset exceeds file size
  else:
    if seekPos < 0:
      quit("Error: Negative seek (-s) is not supported for stdin or non-seekable streams.")
      
  defer: 
    if inputIsOpen: close(f)
  
  var outStream: File = stdout
  var pager: Pager
  var isPagerActive = false
  
  if outputFile != "":
    if not open(outStream, outputFile, fmWrite):
      quit("Error: Cannot open output file for writing: " & outputFile)
  else:
    let disablePager = noPager or summaryMode or reverseMode or restoreMode
    pager = openPager(disablePager, outputFile)
    outStream = pager.file
    isPagerActive = pager.isPipe
  
  defer:
    if isPagerActive:
      pager.close()
    elif outStream != stdout:
      close(outStream)
  
  if not inputIsOpen:
    if restoreMode: restoreDump(stdin, outStream, plainMode, useColor, activeMagicHeaders, magicFilter, cols)
    elif reverseMode and plainMode: reversePlainHexDump(stdin, outStream)
    elif reverseMode: reverseHexDump(stdin, outStream, cols)
    elif summaryMode: processSummary(stdin, @[], activeMagicHeaders, magicFilter, outStream, useColor, cols)
    elif plainMode: processPlainStream(stdin, outStream, cols)
    else: processStream(stdin, minEntropy, maxEntropy, @[], activeMagicHeaders, magicFilter, outStream, useColor, seekPos, readLength, cols, windowSize)
  else:
    if restoreMode:
      restoreDump(f, outStream, plainMode, useColor, activeMagicHeaders, magicFilter, cols)
    elif reverseMode and plainMode:
      reversePlainHexDump(f, outStream)
    elif reverseMode:
      reverseHexDump(f, outStream, cols)
    elif plainMode:
      processPlainStream(f, outStream, cols)
    else:
      let ignoredRegions = getReadOnlyRegions(f, debugMode)
      close(f) 
      inputIsOpen = false 
                  
      if summaryMode: 
        var tempF: File
        if open(tempF, targetFile):
          processSummary(tempF, ignoredRegions, activeMagicHeaders, magicFilter, outStream, useColor, cols)  # <--- new line with ignoredRegions(v1.1.0)
          close(tempF)
      else:
        let isRegularFile = try:
          let k = getFileInfo(targetFile).kind
          k == pcFile or k == pcLinkToFile
        except CatchableError:
          false
                
        if not isRegularFile:
          var fallbackF: File
          if open(fallbackF, targetFile):
            processStream(fallbackF, minEntropy, maxEntropy, ignoredRegions, activeMagicHeaders, magicFilter, outStream, useColor, seekPos, readLength, cols, windowSize)
            close(fallbackF)
        else:
          try:
            processStreamMmap(targetFile, minEntropy, maxEntropy, ignoredRegions, activeMagicHeaders, magicFilter, outStream, useColor, seekPos, readLength, cols, windowSize)
          except CatchableError:
            var fallbackF: File
            if open(fallbackF, targetFile):
              processStream(fallbackF, minEntropy, maxEntropy, ignoredRegions, activeMagicHeaders, magicFilter, outStream, useColor, seekPos, readLength, cols, windowSize)
              close(fallbackF)

when isMainModule:
  try:
    main()
  except IOError as e:
    if "Broken pipe" notin e.msg and "errno: 32" notin e.msg and "broken pipe" notin e.msg:
      stderr.writeLine("neoxd: error: " & e.msg)
    quit(1)
  except CatchableError as e:
    stderr.writeLine("neoxd: error: " & e.msg)
    quit(1)
