import strutils, math, terminal, parseopt, std/endians, std/memfiles, os, unicode, prufer

when defined(posix):
  import posix

const BlockChars = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

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
  ("\x52\x49\x46\x46", "RIFF / WAV / AVI")
]

var HexLUT: array[256, array[2, char]]

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

type FastWriter* = object
  stream: File
  buf: array[65536, char]
  pos: int

proc initFastWriter*(stream: File): FastWriter =
  result.stream = stream
  result.pos = 0

proc flush*(w: var FastWriter) =
  if w.pos > 0:
    if w.stream.writeBuffer(addr w.buf[0], w.pos) != w.pos:
      raise newException(IOError, "Failed to write buffer to stream")
    w.pos = 0

proc writeStr*(w: var FastWriter, s: string) {.inline.} =
  if s.len == 0: return
  
  # if the new string exceeds remaining capacity flush the buffer first
  if w.pos + s.len > w.buf.len:
    w.flush()
  
  # if the string itself is larger than the entire buffer (rare, but safe) write directly
  if s.len > w.buf.len:
    if w.stream.writeBuffer(unsafeAddr s[0], s.len) != s.len:
      raise newException(IOError, "Failed to write large string to stream")
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

proc parseOffset(s: string): int =
  if s.toLowerAscii().startsWith("0x"):
    return parseHexInt(s[2..^1])
  else:
    return parseInt(s)

proc getEntropyColor(entropy: float): ForegroundColor =
  if entropy < 2.0: return fgCyan     
  elif entropy < 5.5: return fgGreen  
  elif entropy < 7.2: return fgYellow 
  else: return fgRed                

proc getEntropyBar(ratio: float): string =
  let idx = clamp(int(ratio * float(BlockChars.high)), 0, BlockChars.high)
  return BlockChars[idx]

proc printProgressBar(outStream: File, label: string, count, total: int, color: ForegroundColor, useColor: bool) =
  let pct = if total == 0: 0.0 else: float(count) / float(total) * 100.0
  let barCount = int(pct / 2.0)
  let bars = "█".repeat(barCount)
  let padding = max(0, 50 - barCount)
  let paddedBars = bars & " ".repeat(padding)
  let line = alignLeft(label, 15) & " | " & paddedBars & " " & formatFloat(pct, ffDecimal, 1) & "%\n"

  if useColor and outStream == stdout:
    stdout.setForegroundColor(color)
    stdout.write(line)
    stdout.resetAttributes()
  else:
    outStream.write(line)

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

proc processSummary(f: File, magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, outStream: File = stdout, useColor: bool = true, cols: int = 16) =
  var buffer = newSeq[byte](cols)
  var totalBytes = 0
  var totalBlocks = 0
  var globalCounts: array[256, int]
  var blocksLow, blocksMedLow, blocksMedHigh, blocksHigh = 0
  var foundSignatures: seq[string] = @[]

  while true:
    let bytesRead = f.readBuffer(addr buffer[0], cols)
    if bytesRead <= 0: break
  
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

  outStream.write("\n=======================================================================\n")
  outStream.write(" FILE SUMMARY REPORT\n")
  outStream.write("=======================================================================\n")
  outStream.write(" Total Size     : " & $totalBytes & " bytes\n")
  outStream.write(" Overall Entropy: " & formatFloat(globalEntropy, ffDecimal, 3) & " / 8.000\n")
  
  if foundSignatures.len > 0:
    outStream.write("\n Embedded Files Detected:\n")
    for sig in foundSignatures: outStream.write("   -> " & sig & "\n")
  outStream.write("=======================================================================\n\n")

  outStream.write("--- Block Distribution (Structural Density) ---\n")
  printProgressBar(outStream, "Padding/Nulls", blocksLow, totalBlocks, fgCyan, useColor)
  printProgressBar(outStream, "Text/Sparse", blocksMedLow, totalBlocks, fgGreen, useColor)
  printProgressBar(outStream, "Code/Data", blocksMedHigh, totalBlocks, fgYellow, useColor)
  printProgressBar(outStream, "Packed/Crypto", blocksHigh, totalBlocks, fgRed, useColor)
  
  outStream.write("\n--- Global Byte Frequency Histogram ---\n")
  for i in 0 ..< 16:
    let label = "0x" & toHex(i * 16, 2) & " - 0x" & toHex((i * 16) + 15, 2)
    printProgressBar(outStream, label, buckets[i], totalBytes, fgWhite, useColor)
  outStream.write("\n")

proc getAnsiColor(entropy: float, useColor: bool): string =
  if not useColor: return ""
  if entropy < 2.0: return "\e[36m"     
  elif entropy < 5.5: return "\e[32m"   
  elif entropy < 7.2: return "\e[33m"   
  else: return "\e[31m"

type FileRegion = tuple[startPos, endPos: int]

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

proc getReadOnlyRegions(f: File, debugMode: bool = false): seq[FileRegion] =
  var regions: seq[FileRegion] = @[]
  var startPos: int64
  
  try:
    startPos = f.getFilePos()
    let fileSize = f.getFileSize()

    if fileSize < 64: return regions

    var e_ident: array[16, byte]
    if f.readBuffer(addr e_ident[0], 16) != 16: return regions
    if e_ident[0..3] != [byte 0x7F, 0x45, 0x4C, 0x46]: return regions

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
        sh_offset = readU64(f, isBigEndian)
        sh_size = readU64(f, isBigEndian)
      
      if sh_type != 0 and (sh_flags and 0x5) == 0:
        let endOffset = int64(sh_offset) + int64(sh_size)
        if endOffset <= fileSize and endOffset > 0 and int64(sh_offset) >= 0:
          regions.add((int(sh_offset), int(endOffset)))
            
  except CatchableError as e:
    logDebug("ELF Section Parsing Exception: " & e.msg, debugMode)
  finally:
    try: f.setFilePos(startPos) except: discard
    
  return regions

proc processStream(f: File, minEntropy: float, maxEntropy: float, ignoredRegions: seq[FileRegion], magicList: openArray[tuple[sig: string, label: string]], filter: MagicFilter, outStream: File = stdout, useColor: bool = true, seekPos: int = 0, readLength: int = 0, cols: int = 16, windowSize: int = 256) =
  # initialize the buffered writer and ensure it flushes when the function returns
  var writer = initFastWriter(outStream)
  defer: 
    try: 
      writer.flush() 
    except IOError as e: 
      if "Broken pipe" notin e.msg and "errno: 32" notin e.msg and "broken pipe" notin e.msg:
        stderr.writeLine("neoxd: error: Failed to flush final buffer - " & e.msg)
      quit(1)

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

    for i in 0 ..< cols:
      if i < bytesRead:
        let b = buffer[i]
        lineBuf.add(HexLUT[b][0])
        lineBuf.add(HexLUT[b][1])
        lineBuf.add(' ')
      else:
        lineBuf.add("   ")
      if i == splitIndex and cols > 1: lineBuf.add(' ') 

    for i in 0 ..< cols:
      if i < bytesRead:
        let c = char(buffer[i])
        if c in ' ' .. '~': lineBuf.add(c)
        else: lineBuf.add('.')
      else:
        lineBuf.add(' ')

    lineBuf.add(" | H: ")
    lineBuf.addEntropyStr(chunkEntropy)
    lineBuf.add(" [")
    for _ in 0 ..< 8: lineBuf.add(bar)
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
      if "Broken pipe" notin e.msg and "errno: 32" notin e.msg and "broken pipe" notin e.msg:
        stderr.writeLine("neoxd: error: Output stream write failed - " & e.msg)
      quit(1)
        
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

  while offset < totalBytes:
    let bytesRead = min(cols, totalBytes - offset)
    
    for i in 0 ..< bytesRead:
      entropyCalc.push(data[offset + i])

    let rawChunkEntropy = entropyCalc.getEntropy()
    let chunkEntropy = round(rawChunkEntropy * 100.0) / 100.0
    let entropyRatio = chunkEntropy / 8.0
    
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

    for i in 0 ..< cols:
      if i < bytesRead:
        let b = data[offset + i]
        lineBuf.add(HexLUT[b][0])
        lineBuf.add(HexLUT[b][1])
        lineBuf.add(' ')
      else:
        lineBuf.add("   ")
      if i == splitIndex and cols > 1: lineBuf.add(' ') 

    for i in 0 ..< cols:
      if i < bytesRead:
        let c = char(data[offset + i])
        if c in ' ' .. '~': lineBuf.add(c)
        else: lineBuf.add('.')
      else:
        lineBuf.add(' ')

    lineBuf.add(" | H: ")
    lineBuf.addEntropyStr(chunkEntropy)
    lineBuf.add(" [")
    for _ in 0 ..< 8: lineBuf.add(bar)
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
      if "Broken pipe" notin e.msg and "errno: 32" notin e.msg and "broken pipe" notin e.msg:
        stderr.writeLine("neoxd: error: Output stream write failed - " & e.msg)
      quit(1)
        
    for i in 0 ..< bytesRead: prevBuffer[i] = data[offset + i]
    prevLen = bytesRead
    offset += bytesRead

proc writeByteChecked(outStream: File, b: byte) {.inline.} =
  var buf = [b]
  if outStream.writeBuffer(addr buf[0], 1) != 1:
    raise newException(IOError, "Failed to write byte to output stream (disk full or broken pipe)")

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
    outStream.write(hexStr & "\n")

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
  -o, --output:FILE            Save the hex dump output to a file for editing/analysis
  --no-color                   Disable ANSI colors (automatically set when saving to a file)
  --color                      Force ANSI colors even when writing to a file
  --no-pager                   Disable automatic terminal pager when outputting interactively
  --min, --min-entropy:FLOAT   Only show blocks with entropy >= this value (0.0 to 8.0)
  --max, --max-entropy:FLOAT   Only show blocks with entropy <= this value (0.0 to 8.0)
  -p, --plain                  Output in plain hex format (continuous hex with no offsets or formatting)
  -k, --seek:OFFSET            Start reading at a specific offset (e.g., 0x1000 or 4096)
  -n, --length:BYTES           Stop reading after BYTES are processed
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
    elif summaryMode: processSummary(stdin, activeMagicHeaders, magicFilter, outStream, useColor, cols)
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
        discard open(tempF, targetFile)
        processSummary(tempF, activeMagicHeaders, magicFilter, outStream, useColor, cols)
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
