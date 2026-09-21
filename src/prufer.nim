import std/[os, strutils, editdistance, parseopt]

const ValidFlags = [
  "c", "cols", "columns", "w", "window", "s", "summary", 
  "o", "output", "no-color", "color", "no-pager", "p", 
  "plain", "k", "seek", "n", "length", "r", "reverse", 
  "R", "restore", "m", "magic", "d", "debug", "h", "help", 
  "v", "version", "min", "min-entropy", "max", "max-entropy",
  "nop", "no-prufer"
]

const BinaryExts = [
  ".jpg", ".jpeg", ".png", ".elf", ".exe", ".bin", 
  ".zip", ".rar", ".pdf", ".so", ".dll", ".sqlite", ".wav"
]

proc checkFlagTypo*(key: string) =
  if key notin ValidFlags:
    var bestMatch = ""
    var minDist = 999
    
    for cand in ValidFlags:
      let dist = editDistance(key, cand)
      if dist < minDist and dist <= 2: 
        minDist = dist
        bestMatch = cand
        
    var errMsg = "neoxd: error: Unknown option '" & key & "'."
    if bestMatch != "":
      let prefix = if bestMatch.len == 1: "-" else: "--"
      errMsg &= "\nDid you mean: " & prefix & bestMatch & "?"
    
    stderr.writeLine(errMsg)
    quit(1)

proc requireVal*(p: var OptParser, currentFlag: string): string =
  if p.val != "": 
    return p.val
  
  let origFlag = currentFlag
  p.next()
  
  if p.kind == cmdEnd:
    stderr.writeLine("neoxd: error: Option '-" & origFlag & "' requires a value, but none was provided.")
    quit(1)
  elif p.kind in {cmdShortOption, cmdLongOption}:
    let prefix = if p.kind == cmdShortOption: "-" else: "--"
    stderr.writeLine("neoxd: error: Option '-" & origFlag & "' requires a value. Found '" & prefix & p.key & "' instead.\n" &
                     "Did you forget the value for '-" & origFlag & "'? (e.g., -" & origFlag & " <value> " & prefix & p.key & ")")
    quit(1)
  
  return p.key

proc checkSyntaxSanity*(positionalArgs: seq[string]) =
  if positionalArgs.len > 1:
    let msg = "neoxd: error: Too many positional arguments: " & positionalArgs.join(", ") & "\n" &
              "Expected only one target file. This usually happens if you placed a flag in the wrong order."
    stderr.writeLine(msg)
    quit(1)

proc checkFileSwap*(targetFile, outputFile: string, isRestoreMode: bool = false) =
  if outputFile == "" or targetFile == "":
    return

  if not fileExists(targetFile) and fileExists(outputFile):
    let msg = "neoxd: error: Potential argument swap detected.\n" &
              "  Input file '" & targetFile & "' does not exist.\n" &
              "  Output target '" & outputFile & "' already exists.\n\n" &
              "Did you mean: neoxd -o " & targetFile & " " & outputFile & "\n" &
              "Use --nop or --no-prufer to bypass."
    stderr.writeLine(msg)
    quit(1)
  
  if not isRestoreMode:
    let outExt = outputFile.splitFile().ext.toLowerAscii()
    let inExt = targetFile.splitFile().ext.toLowerAscii()
    
    if outExt in BinaryExts and inExt notin BinaryExts:
      let msg = "neoxd: error: Dangerous output target detected.\n" &
                "  Attempting to write raw hex text into binary format ('" & outputFile & "').\n\n" &
                "If argument order was inverted, run:\n" &
                "  neoxd -o " & targetFile & " " & outputFile & "\n" &
                "Use --nop or --no-prufer to bypass this check."
      stderr.writeLine(msg)
      quit(1)
