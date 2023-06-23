asmCrypto (openpgp.js fork)
=========

JavaScript implementation of AES cryptographic utilities with performance in mind.
As of v3, compatibility with upstream repo (now deprecated) is broken: non-AES functions have been removed, and legacy targets (ES5) are no longer supported.

This library is primarily needed as fallback for the WebCrypto API for AES-CFB (only implemented by Safari), as well as AES-GCM for 192-bit keys (not implemented by Chrome).

Build & Test
------------

Then download and build the stuff:

    git clone https://github.com/asmcrypto/asmcrypto.js.git
    cd asmcrypto.js/
    npm install

Running tests is always a good idea:

    npm test

Congratulations! Now you have your `asmcrypto.js` ready to use ☺
