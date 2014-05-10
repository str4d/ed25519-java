package net.i2p.crypto.eddsa.math;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy -x^2 + y^2 = 1 + d x^2y^2
 * @author str4d
 *
 */
public class Curve implements Serializable {
    private static final long serialVersionUID = 4578920872509827L;
    private final Field f;
    private final FieldElement d;
    private final FieldElement d2;
    private final FieldElement I;
    private final FieldElement one;

    private final GroupElement zeroP2;
    private final GroupElement zeroP3;
    private final GroupElement zeroPrecomp;

    public Curve(Field f, BigInteger d) {
        this.f = f;
        this.d = fromBigInteger(d);
        this.d2 = this.d.add(this.d);
        this.I = fromBigInteger(Constants.TWO).modPow(f.getQ().subtract(Constants.ONE).divide(Constants.FOUR), f.getQ());

        FieldElement zero = fromBigInteger(Constants.ZERO);
        one = fromBigInteger(Constants.ONE);
        zeroP2 = GroupElement.p2(this, zero, one, one);
        zeroP3 = createPoint(Constants.ZERO, Constants.ONE);
        zeroPrecomp = GroupElement.precomp(this, one, one, zero);
    }

    public Field getField() {
        return f;
    }

    public FieldElement getD() {
        return d;
    }

    public FieldElement get2D() {
        return d2;
    }

    public FieldElement getI() {
        return I;
    }

    public FieldElement getOne() {
        return one;
    }

    public GroupElement getZero(GroupElement.Representation repr) {
        switch (repr) {
        case P2:
            return zeroP2;
        case P3:
            return zeroP3;
        case PRECOMP:
            return zeroPrecomp;
        default:
            return null;
        }
    }

    public FieldElement fromBigInteger(BigInteger x) {
        return new FieldElement(f, x);
    }

    public FieldElement fromByteArray(byte[] x) {
        return new FieldElement(f, x);
    }

    public GroupElement createPoint(BigInteger x, BigInteger y) {
        return createPoint(x, y, false);
    }

    public GroupElement createPoint(BigInteger x, BigInteger y, boolean precompute) {
        FieldElement X = fromBigInteger(x);
        FieldElement Y = fromBigInteger(y);
        GroupElement ge = GroupElement.p3(this, X, Y, one, X.multiply(Y));
        if (precompute)
            ge.precompute(true);
        return ge;
    }
}
