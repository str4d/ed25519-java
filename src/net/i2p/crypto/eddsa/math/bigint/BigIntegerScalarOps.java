package net.i2p.crypto.eddsa.math.bigint;

import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.ScalarOps;

public class BigIntegerScalarOps implements ScalarOps {
    private final BigIntegerFieldElement l;
    private final BigIntegerLittleEndianEncoding enc;

    public BigIntegerScalarOps(Field f, BigIntegerFieldElement l) {
        this.l = l;
        enc = new BigIntegerLittleEndianEncoding();
        enc.setField(f);
    }

    public byte[] reduce(byte[] s) {
        return enc.encode(enc.decode(s, false).mod(l));
    }

    public byte[] multiplyAndAdd(byte[] a, byte[] b, byte[] c) {
        return enc.encode(enc.decode(a, false).multiply(enc.decode(b, false)).add(enc.decode(c, false)).mod(l));
    }

}
