# Twitter X-Xp-Forwarded-For Header Reverse Engineering & Generator
A few days ago, Twitter quietly added a new header: "X-Xp-Forwarded-For".

As soon as I noticed it, I started digging in, turns out it's being generated inside a WASM. I poked around the WASM and some of the JS, and saw it was pulling in some basic fingerprint data and grabbing stuff from cookies.

Hold up... did Twitter just build their own anti-bot system?

# Generator

The code block below allows you to generate or decrypt any XPFF header.

To understand how the base_key works, refer to the Reverse Engineering section. This key is hardcoded inside the WASM, so as long as you provide a valid guest_id, everything should function correctly. For now, there's no need for additional scraping since the key is not dynamic.

Your guest_id should be the one found in your Twitter cookies, and it must be URL-encoded.

The reason guest_id is used is because the AES key is derived from a SHA-256 hash of base_key + guest_id. The payload is quite simple at this stage: just include your user agent and a timestamp in milliseconds, encrypt it.

Also keep in mind: the encrypted value is only valid for 300,000 milliseconds (5 minutes).


Disclaimer:

For research purposes only. Don’t use this to mess with real systems.

```python
from twitter_xpff import XPFFHeaderGenerator

base_key = "0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05"
xpff_gen = XPFFHeaderGenerator(base_key)

guest_id = "v1%3A174849298500261196"
xpff_plain = '{"webgl_fingerprint":"","canvas_fingerprint":"","navigator_properties":{"hasBeenActive":"false","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0","webdriver":"false"},"codec_fingerprint":"","audio_fingerprint":"","audio_properties":null,"created_at":1748492990477}'

encrypted = xpff_gen.generate_xpff(xpff_plain, guest_id)
print("Encrypted:", encrypted)

decrypted = xpff_gen.decode_xpff(encrypted, guest_id)
print("Decrypted:", decrypted)
```

# Reverse Engineering
This setup manages Twitter’s XPForwardedFor SDK, which is used to generate a encrypted header (XPFF). You can find the files I mentioned in the reverse engineering folder.

## Part 1 – loader.FwdForSdk-ae793f77.7aea6cda.js: WASM controller (runtime logic)
This file bootstraps and executes a Go-based WASM:
- Creates a Go runtime (class Go):
  - JS <> Go bridge using syscall/js (e.g. valueGet, valueSet, finalizeRef, valuePrepareString)
- The WASM side defines window.getForwardedForStr() at runtime. JS then uses this exposed function like so:
```js
getForwardedForStr: async function() {
    if (window && "function" == typeof window.getForwardedForStr) {
        const t = await window.getForwardedForStr()
          , e = Number(t.expiryTimeMillis);
        return isNaN(e),
        t
    }
    throw new Error("Wasm module did not set window.getForwardedForStr")
}
```

## Part 2 – loader.FwdForSdk-594367b3.f0d8f13a.js: WASM binary

## Part 3 - WASM
The WASM side pulls some data from JS API (valueGet). Like Date, navigator.userAgent, navigator.webdriver, navigator.userActivation.hasBeenActive.
Even though the final JSON structure includes fields like:

audio_properties

audio_fingerprint

codec_fingerprint

webgl_fingerprint

canvas_fingerprint

...those are all empty for now. Twitter lazy as hell bro. 

After that, the module builds a JSON payload ($func410) and moves into the AES-GCM key derivation phase.

The WASM generates the AES-GCM key by extracting guest_id from cookies and combining it with a static base_key. This base_key isn’t fetched from anywhere, it’s hardcoded directly inside the WASM data section. The concatenation (base_key + guest_id) is handled internally by $func20, producing a single string. That string is then passed into the SHA-256 hashing process: it goes first through $func207 (SHA-256 update), and once all data is processed, $func208 finalizes the hash. Typical SHA-256 cycle, nothing fancy, just buried in WASM bullshit. The resulting 32-byte SHA-256 digest is what becomes the actual AES-GCM key used in encryption.

Once the key is ready, execution continues with $func250, which performs AES key expansion using the derived key to set up the AES context. Then $func266 handles the core AES-GCM encryption, it encrypts the plaintext JSON using the key and IV. During encryption (the process between $func250 and $func266), the module writes the IV to memory first, followed by the ciphertext, and finally the authentication tag. Once all three (IV + ciphertext + tag) are laid out consecutively in memory, the entire buffer is converted to hex and returned as the final output.

All of this happens inside $func428, which acts as the main for the entire process.
Flow Overview:
```
$func428 (main)
 ├── pulls JS data via valueGet
 ├── builds JSON payload -> $func410
 ├── derives AES-GCM key
 │    ├─ hardcoded base_key
 │    ├─ + guest_id from cookies
 │    └─ -> $func20 -> SHA-256 $func207 -> $func208
 ├── AES key expansion → $func250
 ├── writes IV to memory
 ├── encryption -> $func266 (CT)
 ├── writes (IV + CT + TAG) to memory
 └── final output -> hex string
```
Extra:
If you're starting from scratch with a WASM binary, you can reverse the overall structure by debugging memory and reviewing code step by step.
Alternatively, inspect the strings in the WASM's data section, you’ll often find clues about which language and libraries were used. Based on that, you can recreate a similar environment yourself and compile your own WASM. This makes the reverse engineering process much easier.
For example, the use of AES-GCM is usually obvious from string literals. In this case, $func250 actually originates from Go’s standard library:
https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/internal/fips140/aes/aes_generic.go;l=148
If you explore those libraries inside your own WASM build first, many functions will look familiar, no need to torture yourself with Twitter’s WASM from the start.

#

Example plain text payload:
```json
{"webgl_fingerprint":"","canvas_fingerprint":"","navigator_properties":{"hasBeenActive":"false","userAgent":"youruseragent","webdriver":"false"},"codec_fingerprint":"","audio_fingerprint":"","audio_properties":null,"created_at":timestamp_milliseconds}
```
Example encrypted output:
```
63123fea0dd5a95ed72c957943c000a8da5f84094979ea4b881c5c51ac2a9df5cff20a1c73cfadd6f0ff3d8e9f4bc79978c42a5fa0a20efd18eca9d3001b0dc5d6e01950e595898d1b643c8f10bfd7b3883ac19a44dacfc16e620f79aa5a581057a64f09f5617eeaad211d0901ecd11b02f669925abb1538aea444044ede57be72b0b764eb28e951674ba01d986618ea6d313c47a06ef170fab06f5cdb5bd66fb3ed5cc689ca352073a4ff0f183f5bb73566ec6bf8ce01054178f3bd11f495e6e269830dc8be2c59205a35876de50732b930d4a5fdb4c612324a982de72069fb27f3ebbae7e7787aea354769f49cb8fb64c46935690d8e7b73c9c454ea525b482822b535fd4e46ce047b850089b13bac45d1a78499d80841bd08ff542a7dd3220d23b78e45da5c32cf3b2f2600f2cf0d83f4bf98c6d5d306e5a6d03b18eff86461c83c4cd6cdeb2a0ce912c92612eb4460
```
Current base key:
```
0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05
```
#

Twitter will develop this soon. In its current state, the protections are pretty weak. I’m sure they’ll update it, and we’ll see what changes they bring. If this header is meant to serve as an anti-bot measure, then there’s a lot more work they need to do both on the JS and WASM sides (deep fingerprint techniques, obfuscation, anti-sandbox, dynamic js/wasm). On top of that, processing fingerprint data on the backend, like building user/fingerprint profiles, analyzing detailed browser, device and low level connection info, and using AI to spot patterns, makes the system a lot more complex. However, based on the current implementation, I anticipate they’ll likely stick to a relatively simplistic approach.

I will also publish this in more detail and in a cleaner format on my blog soon. Thank you for reading.


Disclaimer:

For research purposes only. Don’t use this to mess with real systems.
