package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

/**
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 *
 */
public class Field {
    private int b;
    private BigInteger q;
    private BigInteger qm2;
    private BigInteger qm5;
    private BigInteger qp3;

    public Field(int b, BigInteger q) {
        this.b = b;
        this.q = q;
        this.qm2 = q.subtract(Constants.TWO);
        this.qm5 = q.subtract(Constants.FIVE);
        this.qp3 = q.add(Constants.THREE);
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
}
