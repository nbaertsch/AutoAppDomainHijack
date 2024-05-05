# Package
version       = "1.0.0"
author        = "nbaertsch"
description   = "Automated .NET AppDomain hijack payload generation"
license       = "GPL-3.0"
srcDir        = "src"
binDir        = "bin"
bin           = @["AutoDomainHijack, HijackHunt"]


# Dependencies

requires "nim >= 2.0.0"
requires "winim >= 3.9.2"
requires "mustache"
requires "https://bitbucket.org/maxgrenderjones/therapist.git#head"
requires "nimcrypto"
requires "regex"
