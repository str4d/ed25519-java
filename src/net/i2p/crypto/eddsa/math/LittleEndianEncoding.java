package net.i2p.crypto.eddsa.math;

import java.io.Serializable;
import java.math.BigInteger;

public class LittleEndianEncoding implements Encoding, Serializable {
    private static final long serialVersionUID = 3984579843759837L;

    /**
     *  Convert x to little endian.
     *  Constant time.
     *
     *  @param len must be big enough
     *  @return array of length len
     *  @throws ArrayIndexOutOfBoundsException if len not big enough
     */
    public byte[] encode(BigInteger x, int len) {
        byte[] in = x.toByteArray();
        byte[] out = new byte[len];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        for (int i = in.length; i < out.length; i++) {
            out[i] = 0;
        }
        return out;
    }

    /**
     *  Convert in to big endian
     */
    public BigInteger decode(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return new BigInteger(1, out);
    }
}
