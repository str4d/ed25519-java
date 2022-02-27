EdDSA-Java
==========

[![Build Status](https://travis-ci.org/str4d/ed25519-java.svg?branch=master)](https://travis-ci.org/str4d/ed25519-java)

This is an implementation of EdDSA in Java. Structurally, it is based on the ref10 implementation in SUPERCOP
(see https://ed25519.cr.yp.to/software.html).

There are two internal implementations:
- A port of the radix-2^51 operations in ref10 - fast and constant-time, but only useful for Ed25519.
- A generic version using BigIntegers for calculation - a bit slower and not constant-time, but compatible
  with any EdDSA parameter specification.


To use
------

Download the latest .jar from the releases tab and place it in your classpath.

Gradle users:

```
compile 'net.i2p.crypto:eddsa:0.3.1'
```

Java 7 and above are supported.

The JUnit4 tests require the Hamcrest library `hamcrest-all.jar`.

This code is released to the public domain and can be used for any purpose. See `LICENSE.txt` for details.

Disclaimer
----------

There are **no** guarantees that this is secure for all cases, and users should
review the code themselves before depending on it. PRs that fix bugs or improve
reviewability are very welcome. Additionally:

- The unit test suite includes tests against
  [the data from the original Python implementation](https://ed25519.cr.yp.to/python/sign.input).
- The code (as of 97cea3f0d910fc627c7b57b1bc4d783cdd0c2a4a) was reviewed by
  [an independent developer](https://github.com/BloodyRookie).
- The code (as of dc9f58f2c874463c15465326efc040d17a627b3a) was audited by an independent third party,
  and the one issue found [was fixed](https://github.com/str4d/ed25519-java/pull/31).

Code comparison
---------------

For ease of following, here are the main methods in ref10 and their equivalents in this codebase:

| EdDSA Operation | ref10 function | Java function |
| --------------- | -------------- | ------------- |
| Generate keypair | `crypto_sign_keypair` | `EdDSAPrivateKeySpec` constructor |
| Sign message | `crypto_sign` | `EdDSAEngine.engineSign` |
| Verify signature | `crypto_sign_open` | `EdDSAEngine.engineVerify` |

| EdDSA point arithmetic | ref10 function | Java function |
| ---------------------- | -------------- | ------------- |
| `R = b * B` | `ge_scalarmult_base` | `GroupElement.scalarMultiply` |
| `R = a*A + b*B` | `ge_double_scalarmult_vartime` | `GroupElement.doubleScalarMultiplyVariableTime` |
| `R = 2 * P` | `ge_p2_dbl` | `GroupElement.dbl` |
| `R = P + Q` | `ge_madd`, `ge_add` | `GroupElement.madd`, `GroupElement.add` |
| `R = P - Q` | `ge_msub`, `ge_sub` | `GroupElement.msub`, `GroupElement.sub` |


Important changes
-----------------

### 0.3.1 - Build improvements

- Upgraded JUnit to remove CVE-2020-15250 vulnerability
- Added OWASP plugin to check vulnerabilities

### 0.3.0

- The library has been extensively profiled for contention issues in a multi-threaded environment.  The only
  remaining potential contention is in `EdDSANamedCurveTable.defineCurve()`, which will be rarely called.
- The public constant for the curve name has returned as `ED_25519`, and the curve specification has a public
  constant `ED_25519_CURVE_SPEC` to avoid repeated lookups when converting to and from encoded form for the
  public or private keys.
- `GroupElement` is now completely immutable, and all fields final, to avoid the need for `synchronized`
  blocks over mutable fields. This required some new constructors and paths to construction.
- `EdDSAPublicKeySpec.getNegativeA()` and `EdDSAPublicKey.getNegativeA()` now evaluate lazily, taking
  advantage of the immutability of `GroupElement.negate()`. This boosts the performance of the public key
  constructor when the key is just being passed around rather than used.
- Support for X509Key wrapped EdDSA public keys.

### 0.2.0

- Ed25519 is now named `Ed25519` in `EdDSANamedCurveTable`, and the previous public constant (containing the
  older inaccurate name) has been removed.

Credits
-------

- The Ed25519 class was originally ported by k3d3 from
  [the Python Ed25519 reference implementation](https://ed25519.cr.yp.to/python/ed25519.py).
- Useful comments and tweaks were found in
  [the GNUnet implementation of Ed25519](https://gnunet.org/svn/gnunet-java/src/main/java/org/gnunet/util/crypto/)
  (based on k3d3's class).
- [BloodyRookie](https://github.com/BloodyRookie) reviewed the code, adding many useful comments, unit tests
  and literature.
