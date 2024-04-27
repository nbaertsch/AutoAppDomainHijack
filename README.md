# AutoDomainHijack
Tools to automate finding AppDomain hijacks and generating payloads from shellcode.

## HijackHunt
Run this tool on the target. It will search recursively in the `C:\` directory for .NET managed `.exe`s and test if the folder is writeable - indicating that the PE is AppDomainHijack-able.

## AutoDomainHijack
Generate AppDomainHijack payloads given a shellcode file or url.

```
Usage:
  AutoDomainHijack.exe
  AutoDomainHijack.exe (--version | -h | --help)

Options:
  -t, --target-name=<target-name>  Name of the target managed .exe to hijack.
  -n, --hijack-name=<hijack-name>  Name of the hijacker .dll.
  -u, --url=<url>                  URL of the remote shellcode to run.
  -f, --file=<file>                File containing the shellcode to embed.
  -o, --output=<output>            Full directory to write files to.
  -e, --etw=<etw>                  Disable ETW. [default: true]
      --version                    Prints version
  -h, --help                       Show help message
```

## Build
`nimble build`