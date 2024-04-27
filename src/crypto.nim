#[
    crypto
]#
import base64
import bitops
import random; randomize()
export random
import strutils

export base64

import winim/clr
import nimcrypto

var
    ectx, dctx: CBC[aes256]

const
    colors = slurp(r"./rsc/colors.txt").split("\n")
    adjectives = slurp(r"./rsc/adjectives.txt").split("\n")
    nouns = slurp(r"./rsc/nouns.txt").split("\n")

proc toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc xorBytes*(bytes: seq[byte], key: string): seq[byte] =
    var keyHash: array[aes256.sizeKey, byte] = cast[array[aes256.sizeKey, byte]](sha256.digest(key))
    var xorBytes = newSeq[byte](len(bytes))
    for i in {0..bytes.len()-1}:
        xorBytes[i] = bytes[i].bitxor(keyHash[i mod aes256.sizeKey])
    return xorBytes

proc encryptBytes*(bytes: seq[byte], key: string, iv: array[16, byte]): seq[byte] =
    # AES256 block size is 16 bytes
    var keyHash: array[aes256.sizeKey, byte] = cast[array[aes256.sizeKey, byte]](sha256.digest(key))
    var r = bytes.len mod 16
    var pad = 16 - r
    var plainBytes = bytes
    plainBytes.setLen(bytes.len + pad)
    var encBytes = newSeq[byte](len(bytes) + pad)
    ectx.init(keyHash, iv)
    ectx.encrypt(plainBytes, encBytes)
    ectx.clear()
    return encBytes

proc decryptBytes*(bytes: seq[byte], key: string, iv: array[16, byte]): seq[byte] =
    var keyHash: array[aes256.sizeKey, byte] = cast[array[aes256.sizeKey, byte]](sha256.digest(key))
    var decBytes = newSeq[byte](len(bytes))
    dctx.init(keyHash, iv)
    dctx.decrypt(bytes, decBytes)
    dctx.clear()
    return decBytes

proc randString*(len: int): string =
    for _ in 1..len:
        result.add(char(rand(int('a')..int('z'))))
        
proc randName*(): string =
    result = result & colors[rand(colors.low..colors.high)]
    result = result  & adjectives[rand(adjectives.low..adjectives.high)]
    result = result & nouns[rand(nouns.low..nouns.high)]
    for _ in 1..5:
        result.add(char(rand(int('0')..int('9'))))
    result = result.replace("\n", "")
    result = result.replace("\r", "")
    result = result.replace(" ", "")
    result = result.replace("-", "")

when isMainModule:
    var iv: array[16, byte] = [ #[Res Ipsa Loquitur]#
        byte 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF]
    var enc = toByteSeq("testing123testing123").encryptBytes("my_secret_key", iv).encode()
    echo enc
    echo cast[string](decode(enc).toByteSeq().decryptBytes("my_secret_key", iv))

    
