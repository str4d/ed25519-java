package net.i2p.crypto.eddsa.math;

import java.io.Serializable;
import java.math.BigInteger;

public class LittleEndianEncoding implements Encoding, Serializable {
    private static final long serialVersionUID = 3984579843759837L;

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

    public BigInteger decode(byte[] in) {
        // Convert 'in' to big endian
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return new BigInteger(1, out);
    }
}
