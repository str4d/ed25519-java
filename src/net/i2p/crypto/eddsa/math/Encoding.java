package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

/**
 * Common interface for all (b-1)-bit encodings of elements
 * of EdDSA finite fields.
 * @author str4d
 *
 */
public interface Encoding {
    public byte[] encode(BigInteger x, int len);
    public BigInteger decode(byte[] in);

    /**
     * From the Ed25519 paper:
     * x is negative if the (b-1)-bit encoding of x is lexicographically larger
     * than the (b-1)-bit encoding of -x. If q is an odd prime and the encoding
     * is the little-endian representation of {0, 1,..., q-1} then the negative
     * elements of F_q are {1, 3, 5,..., q-2}.
     * @return
     */
    public boolean isNegative(BigInteger x);
}
