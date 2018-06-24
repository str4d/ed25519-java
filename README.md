EdDSA-Java
==========

[![Build Status](https://travis-ci.org/Warchant/ed25519-sha3-java.svg?branch=master)](https://travis-ci.org/Warchant/ed25519-sha3-java)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fd277321c4664e93a33b6e7d7fce56d2)](https://www.codacy.com/app/Warchant/ed25519-sha3-java?utm_source=github.com&utm_medium=referral&utm_content=Warchant/ed25519-sha3-java&utm_campaign=Badge_Grade)


This is an implementation of EdDSA (SHA3) in Java. Structurally, it is based on the ref10 implementation in SUPERCOP
(see https://ed25519.cr.yp.to/software.html).

There are two internal implementations:
- A port of the radix-2^51 operations in ref10 - fast and constant-time, but only useful for Ed25519.
- A generic version using BigIntegers for calculation - a bit slower and not constant-time, but compatible
  with any EdDSA parameter specification.


To use
------

Gradle users:

```
repositories {
    jcenter()
    maven { url "https://jitpack.io" }
}

dependencies {
    compile 'com.github.warchant:ed25519-sha3-java:1.0'
```

The code requires Java 6 (for e.g. the `Arrays.copyOfRange()` calls in `EdDSAEngine.engineVerify()`).

The JUnit4 tests require the Hamcrest library `hamcrest-all.jar`.

This code is released to the public domain and can be used for any purpose. See `LICENSE.txt` for details.

Disclaimer
----------

There are **no** guarantees that this is secure for all cases, and users should
review the code themselves before depending on it. PRs that fix bugs or improve
reviewability are very welcome. Additionally:

- The unit test suite includes tests against
  [the data from the original Python implementation](https://ed25519.cr.yp.to/python/sign.input) modified for use of SHA3-512 [(original)](https://github.com/hyperledger/iroha-ed25519/tree/master/test/ed25519).

