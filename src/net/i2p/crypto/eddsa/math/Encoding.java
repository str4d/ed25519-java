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
}
