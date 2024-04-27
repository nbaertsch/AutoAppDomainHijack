import std/[os,sequtils, strutils, bitops] 

import regex
import winim

proc readFileBytes(fullName: string): seq[byte] =
    var
        file = open(fullName, fmRead)
        b = cast[seq[byte]](file.readAll())
    file.close()
    return b

proc isManagedPe(filePath: string): bool =
    var fileBytes: seq[byte]
    fileBytes = readFileBytes(filePath)

    if fileBytes.len() == 0: return false

    # validate magic bytes
    var mzMagic = (fileBytes[0].char & fileBytes[1].char)
    if mzMagic != "MZ":
        return false

    # validate optHeaederOffset leads to valid PE signature
    var optHeaderOffset: LONG = cast[ptr LONG](addr fileBytes[60])[]
    var peSignature: string
    try:
        peSignature = join(cast[seq[char]](fileBytes[optHeaderOffset..(optHeaderOffset + 4)]))
    except:
        return false
    if peSignature[0] != 'P' or peSignature[1] != 'E':
        return false
    
     # Read COFF header
    var coffset = optHeaderOffset.int + 4

    # Read file arch from PE magic bytes
    var peMagic: WORD = cast[ptr WORD](addr fileBytes[coffset + sizeof(IMAGE_FILE_HEADER)])[]
    var isX64:bool
    if peMagic == WORD 0x10B:
        isX64 = false
    elif peMagic == WORD 0x20B:
        isX64 = true
    else:
        return false

    # If we made it here, the file is indeed a PE file and we can go ahead with further analysis
    if isX64:
        var ntHeader = cast[ptr IMAGE_NT_HEADERS64](addr fileBytes[optHeaderOffset])[]
        if ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress == 0:
            return false
        else:
            return true
    else:
        var ntHeader = cast[ptr IMAGE_NT_HEADERS32](addr fileBytes[optHeaderOffset])[]
        if ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress == 0:
            return false
        else:
            return true

proc isWritable(dir: string): bool =
  ## Checks if the given directory is writable by the current user
  ## by writing a temp file there.
  try:
    let sfile = dir / "test.tmp"  # Create a temporary file path
    var file = open(sfile, fmWrite)   # Attempt to create a temporary file
    file.close() 
    removeFile(sfile) # Remove the temporary file
    return true
  except IOError:
    return false


when isMainModule:
    for entry in walkDirRec(r"C:\"):
        var p = r"^(.*)\.exe$"
        if entry.match(re2(p)): # this is perl-style regex
            if entry.isManagedPe():
                var (path, name, ext) = entry.splitFile()
                if path.isWritable():
                    echo entry, " is AppDomainHijack-able!"