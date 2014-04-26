ed25519-java
============

This is an implementation of Ed25519 in Java. Structurally, it is based on the ref10 implementation in SUPERCOP (see http://ed25519.cr.yp.to/software.html). Internally, it uses BigIntegers for calculation.

There are no guarantees that this is secure for use. Tests against [the data from the Python implementation](http://ed25519.cr.yp.to/python/sign.input) are passing, but this has not yet been audited by a professional cryptographer. In particular, this implementation is unlikely to have the constant-time properties of ref10 (for now).

To run the tests, place `junit4.jar` and `hamcrest-all.jar` in a folder `lib`.

This code is released to the public domain and can be used for any purpose.

Credits
-------

The Ed25519 class was originally ported by k3d3 from the Python Ed25519 reference implementation, located at http://ed25519.cr.yp.to/python/ed25519.py
