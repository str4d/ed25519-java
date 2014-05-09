package net.i2p.crypto.eddsa.math;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 *
 */
public class FieldElement implements Serializable {
    private static final long serialVersionUID = 4890398908392808L;
    private final Field f;
    /**
     * Variable is package private only so that tests run.
     */
    final BigInteger bi;

    public FieldElement(Field f, BigInteger bi) {
        this.f = f;
        this.bi = bi;
    }

    /**
     * Decode a FieldElement from its (b-1)-bit encoding.
     * The highest bit is masked out.
     * @param val the (b-1)-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     */
    public FieldElement(Field f, byte[] val) {
        if (val.length != f.getb()/8)
            throw new IllegalArgumentException("Not a valid encoding");

        this.f = f;
        this.bi = f.getEncoding().decode(val).and(f.getMask());
    }

    /**
     * Encode a FieldElement in its (b-1)-bit encoding.
     * @return the (b-1)-bit encoding of this FieldElement.
     */
    public byte[] toByteArray() {
        return f.getEncoding().encode(bi.and(f.getMask()), f.getb()/8);
    }

    public boolean isNonZero() {
        return !bi.equals(BigInteger.ZERO);
    }

    public boolean isNegative() {
        return f.getEncoding().isNegative(bi);
    }

    public FieldElement add(FieldElement val) {
        return new FieldElement(f, bi.add(val.bi).mod(f.getQ()));
    }

    public FieldElement addOne() {
        return new FieldElement(f, bi.add(Constants.ONE).mod(f.getQ()));
    }

    public FieldElement subtract(FieldElement val) {
        return new FieldElement(f, bi.subtract(val.bi).mod(f.getQ()));
    }

    public FieldElement subtractOne() {
        return new FieldElement(f, bi.subtract(Constants.ONE).mod(f.getQ()));
    }

    public FieldElement negate() {
        return new FieldElement(f, f.getQ().subtract(bi));
    }

    public FieldElement divide(FieldElement val) {
        return divide(val.bi);
    }

    public FieldElement divide(BigInteger val) {
        return new FieldElement(f, bi.divide(val).mod(f.getQ()));
    }

    public FieldElement multiply(FieldElement val) {
        return new FieldElement(f, bi.multiply(val.bi).mod(f.getQ()));
    }

    public FieldElement square() {
        return multiply(this);
    }

    public FieldElement squareAndDouble() {
        FieldElement sq = square();
        return sq.add(sq);
    }

    public FieldElement invert() {
        // Euler's theorem
        //return modPow(f.getQm2(), f.getQ());
        return new FieldElement(f, bi.modInverse(f.getQ()));
    }

    public FieldElement modPow(BigInteger e, BigInteger m) {
        return new FieldElement(f, bi.modPow(e, m));
    }

    public FieldElement pow(BigInteger i){
        return modPow(i, f.getQ());
    }

    public FieldElement pow(FieldElement e){
        return pow(e.bi);
    }

    @Override
    public int hashCode() {
        return bi.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FieldElement))
            return false;
        FieldElement fe = (FieldElement) obj;
        return f.equals(fe.f) && bi.equals(fe.bi);
    }

    @Override
    public String toString() {
        return "[FieldElement val="+bi+"]";
    }
}
