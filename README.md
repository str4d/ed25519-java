ed25519-java
============

This is an implementation of Ed25519 in Java. Structurally, it is based on the ref10 implementation in SUPERCOP (see http://ed25519.cr.yp.to/software.html). Internally, it uses BigIntegers for calculation.

Compile and run test.java, and compare the output to validtest.txt - if it matches, you have a working Ed25519 library.

This code is released to the public domain and can be used for any purpose.

Credits
-------

This class was originally ported by k3d3 from the Python Ed25519 reference implementation, located at http://ed25519.cr.yp.to/python/ed25519.py
