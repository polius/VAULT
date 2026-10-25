# Third-party notices

VAULT includes the following third-party components. They are copied into `src/js/vendor/` by `scripts/vendor.mjs` from pinned sources, and served with the app.

| Component                                                                    | Used for                                | License      | File                                |
| ---------------------------------------------------------------------------- | --------------------------------------- | ------------ | ----------------------------------- |
| [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0                     | Argon2id key derivation                 | MIT          | `src/js/vendor/argon2.js`           |
| [EFF Large Wordlist](https://www.eff.org/dice)                               | Passphrase generator, strength estimate | CC BY 3.0 US | `src/js/vendor/eff-wordlist.js`     |
| [SecLists](https://github.com/danielmiessler/SecLists) `10k-most-common.txt` | Strength estimate (common passwords)    | MIT          | `src/js/vendor/common-passwords.js` |

The README video's build pipeline (`scripts/explainer`, not part of the app or the Docker image) bundles two fonts, both under the SIL Open Font License 1.1: [Inter](https://github.com/rsms/inter) and [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono). See `scripts/explainer/web/fonts/README.md`.

## hash-wasm

    MIT License

    Copyright (c) 2020 Dani Biró

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

The WebAssembly module in hash-wasm's Argon2 build includes:

- An Argon2 implementation based on the Go project's `golang.org/x/crypto/argon2`, distributed under the BSD 3-Clause license below.
- The BLAKE2 reference implementation, Copyright 2012 Samuel Neves, used under the CC0 1.0 Universal dedication (also offered under the OpenSSL License and Apache License 2.0).

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## EFF Large Wordlist for Passphrases

By the [Electronic Frontier Foundation](https://www.eff.org/dice), licensed under [Creative Commons Attribution 3.0 United States](https://creativecommons.org/licenses/by/3.0/us/). VAULT uses the list unmodified, except that the four words containing a hyphen are left out of generated passphrases.

## SecLists

    MIT License

    Copyright (c) 2018 Daniel Miessler

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

VAULT uses `Passwords/Common-Credentials/10k-most-common.txt` at commit `913b327`, lower-cased and de-duplicated.
