package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

/**
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 *
 */
public class Field {
    private final int b;
    private final BigInteger q;
    /**
     * q-2
     */
    private final BigInteger qm2;
    /**
     * q-5
     */
    private final BigInteger qm5;
    /**
     * q+3
     */
    private final BigInteger qp3;
    /**
     * Mask where only the first b-1 bits are set.
     */
    private final BigInteger mask;
    private final Encoding enc;

    public Field(int b, BigInteger q, Encoding enc) {
        this.b = b;
        this.q = q;
        this.qm2 = q.subtract(Constants.TWO);
        this.qm5 = q.subtract(Constants.FIVE);
        this.qp3 = q.add(Constants.THREE);
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

    public BigInteger getQm5() {
        return qm5;
    }

    public BigInteger getQp3() {
        return qp3;
    }

    public BigInteger getMask() {
        return mask;
    }

    public Encoding getEncoding(){
        return enc;
    }
}
