jkurwa
======

GF2m ellipcit curves library in javascript. 

* Supports short Weierstrass curves used in Ukrainian standard DSTU 4145;
* Provides key deriviation for DSTU block ciphers (see https://github.com/muromec/em-gost);
* Encypted containers, including structural PKCS#12/PFX PBES2 containers, can be parsed and decrypted if respective cipher implementation is passed. See gost89 and dstucrypt/agent for reference;
* Encrypted and signed messages in wicked PKCS#7 format used by tax office (sta.gov.ua) are supported for both read and write (see jk.Box, jk.util.transport);
* Includes parsers for signed and encrypted messages, X509.v3 certificates, JKS and Key-6.dat key containers, TSP, CMP, OCSP requests and responses.

Warning
-------

* Jkurwa does not guarranty constant-time calculcation;
* Jkurwa only verifies signature against public key and does not actually check X.509 certificate validity unless CA list is loaded.
  See dstucrypt/agent repo readme for details.
   
![cej repo je strefa wolna wid Kaczyńskiego](https://raw.githubusercontent.com/muromec/jkurwa/master/kdpv.jpg)

[![Build Status](https://travis-ci.org/dstucrypt/jkurwa.svg?branch=master)](https://travis-ci.org/dstucrypt/jkurwa)
[![codecov](https://codecov.io/gh/dstucrypt/jkurwa/branch/master/graph/badge.svg)](https://codecov.io/gh/dstucrypt/jkurwa)
[![npm module](https://badge.fury.io/js/jkurwa.svg)](https://www.npmjs.org/package/jkurwa)
[![dependencies](https://david-dm.org/dstucrypt/jkurwa.png)](https://david-dm.org/dstucrypt/jkurwa)

Usage
-----

See ./test/ and ./examples/ directories. See dstucrypt/agent repo for example app.

To run the Kupyna/Kalyna cross-repository provider test, check out `gost89` beside this repository and run `JKURWA_GOST89_PROVIDER=../gost89/lib/compat.js npm run test:local-provider`. The explicit command fails if `JKURWA_GOST89_PROVIDER` is missing or does not name a file; the regular test suite skips this optional cross-repository check when no provider is configured. The tested provider must report version 0.1.12; publishing and pinning that provider release is a separate deployment step.

The Kupyna/Kalyna PFX parser requires structurally valid authenticated `MacData` using either DSTU 7564-256 or UAPKI's GOST 34.311 outer-MAC profile. PBES2 and PFX salts must be non-empty and no larger than 1024 bytes; individual KDF and PFX MAC iteration counts are limited to 100000. A PFX may contain at most 16 protected stores, with combined protected-store plus PFX MAC KDF work capped at 300000 iterations. Cryptographic MAC verification and equivalent DTO-level enforcement require the reviewed `gost89` profile provider; arbitrary injected `storeload` implementations do not provide that guarantee. Legacy GOST PBES2 and IIT containers remain supported, while unknown outer-MAC algorithms, unsupported authenticated-safe content, and PFX files without a protected key store are rejected.

Sister libraries: 

* https://github.com/dstucrypt/ukurwa4145 - DSTU 4145 in Python;
* https://github.com/dstucrypt/gost89 - GOST cipher, hash, mac, key wrapper and container loader in pure js;
* https://github.com/dstucrypt/python-gost89 - gost hash for python (2 and 3);
* https://github.com/dstucrypt/jksreader - library to parse java-style key containers used by privatbank;
* https://github.com/muromec/zozol - dumb ASN.1 parser and serialisator for python with X509 and wicked CMS schemas;
* https://github.com/dstucrypt/openssl-dstu - patched OpenSSL with DSTU 4145 and GOST family support (outdated, unmaintained).

Demo site: https://dstucrypt.github.io/signerbox2/

Demo apps:

* https://github.com/dstucrypt/agent -- command line utility and daemon service to sign, encrypt and decrypt files;
* https://github.com/dstucrypt/dstukeys -- web interface with examples of authentication;
* https://github.com/dstucrypt/signerbox2/ -- another web app;
* https://github.com/max1gu/e-rro -- cash register app (прогрманий рро).
* https://github.com/p2p-sys/OpenPRRO -- another cash register app (рро).

To cross-verifiy signatures use https://czo.gov.ua/verify .

References
----------

* Certificate format (in Ukrainian), basically kind of X.509v3: http://zakon4.rada.gov.ua/laws/show/z1398-12
* Private key container format, PBES2-like (effective from 01.01.2016): http://zakon3.rada.gov.ua/laws/show/z2227-13
* See https://github.com/dstucrypt/agent repo for tax report format and implementation details
* Law on Trust Services - http://zakon.rada.gov.ua/laws/show/2155-19

Bonus
---

First known use of the word Kurwa was recorded in 1415. Happy 600 birthday Kurwa!
