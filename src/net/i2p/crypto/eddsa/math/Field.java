package net.i2p.crypto.eddsa.math;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 *
 */
public class Field implements Serializable {
    private static final long serialVersionUID = 8746587465875676L;
    private final int b;
    private final BigInteger q;
    /**
     * q-2
     */
    private final BigInteger qm2;
    /**
     * (q-5) / 8
     */
    private final BigInteger qm5d8;
    /**
     * Mask where only the first b-1 bits are set.
     */
    private final BigInteger mask;
    private final Encoding enc;

    public Field(int b, BigInteger q, Encoding enc) {
        this.b = b;
        this.q = q;
        this.qm2 = q.subtract(Constants.TWO);
        this.qm5d8 = q.subtract(Constants.FIVE).divide(Constants.EIGHT);
        this.mask = Constants.ONE.shiftLeft(b-1).subtract(Constants.ONE);
        this.enc = enc;
    }

    public int getb() {
        return b;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getQm2() {
        return qm2;
    }

    public BigInteger getQm5d8() {
        return qm5d8;
    }

    public BigInteger getMask() {
        return mask;
    }

    public Encoding getEncoding(){
        return enc;
    }

    @Override
    public int hashCode() {
        return q.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Field))
            return false;
        Field f = (Field) obj;
        return b == f.b && q.equals(f.q);
    }
}
