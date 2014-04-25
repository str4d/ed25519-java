package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

/**
 * A twisted Edwards curve.
 * @author str4d
 *
 */
public class Curve {
    int b;
    BigInteger q;
    private BigInteger qm2;
    private BigInteger qp3;
    FieldElement d;
    private FieldElement d2;

    public Curve(int b, BigInteger q, FieldElement d) {
        this.b = b;
        this.q = q;
        this.qm2 = q.subtract(Constants.TWO);
        this.qp3 = q.add(Constants.THREE);
        this.d = d;
        this.d2 = d.multiply(fromBigInteger(Constants.TWO));
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

    public BigInteger getQp3() {
        return qp3;
    }

    public FieldElement getD() {
        return d;
    }

    public FieldElement get2D() {
        return d2;
    }

    public FieldElement fromBigInteger(BigInteger x) {
        return new FieldElement(b, q, x);
    }

    public FieldElement fromByteArray(byte[] x) {
        return new FieldElement(b, q, x);
    }

    public GroupElement createPoint(BigInteger x, BigInteger y) {
        return GroupElement.p2(this, fromBigInteger(x), fromBigInteger(y), fromBigInteger(Constants.ONE));
    }
}
