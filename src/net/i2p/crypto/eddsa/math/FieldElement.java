package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 *
 */
public class FieldElement {
    final int b;
    final BigInteger q;

    final BigInteger bi;

    public FieldElement(int b, BigInteger q, BigInteger bi) {
        this.b = b;
        this.q = q;
        this.bi = bi;
    }

    /**
     * Translates a byte array containing the two's-complement binary
     * representation of a FieldElement into a FieldElement. The input array is
     * assumed to be in little-endian byte-order: the least significant byte is
     * in the zeroth element.
     * @param val
     */
    public FieldElement(int b, BigInteger q, byte[] val) {
        if (val.length != b/8)
            throw new IllegalArgumentException("Not a valid encoding");
        byte[] out = new byte[val.length];
        for (int i = 0; i < val.length; i++) {
            out[i] = val[val.length-1-i];
        }
        out[0] &= 0x7f; // Ignore highest bit
        this.b = b;
        this.q = q;
        this.bi = new BigInteger(out);
    }

    /**
     * Returns a byte array containing the two's-complement representation of
     * this FieldElement. The byte array will be in little-endian byte-order:
     * the least significant byte is in the zeroth element. The array will
     * contain b/8 bytes.
     * @return a byte array containing the two's-complement representation of
     * this FieldElement.
     */
    public byte[] toByteArray() {
        byte[] in = bi.toByteArray();
        byte[] out = new byte[b/8];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        for (int i = in.length; i < out.length; i++) {
            out[i] = 0;
        }
        return out;
    }

    public boolean isNonZero() {
        return bi.compareTo(BigInteger.ZERO) != 0;
    }

    public boolean isNegative() {
        return bi.compareTo(BigInteger.ZERO) == -1;
    }

    public FieldElement add(FieldElement val) {
        return new FieldElement(b, q, bi.add(val.bi).mod(q));
    }

    public FieldElement addOne() {
        return new FieldElement(b, q, bi.add(Constants.ONE).mod(q));
    }

    public FieldElement subtract(FieldElement val) {
        return new FieldElement(b, q, bi.subtract(val.bi).mod(q));
    }

    public FieldElement subtractOne() {
        return new FieldElement(b, q, bi.subtract(Constants.ONE).mod(q));
    }

    public FieldElement negate() {
        return new FieldElement(b, q, q.subtract(bi));
    }
    
    public FieldElement divide(FieldElement val) {
    	return divide(val.bi);
    }
    public FieldElement divide(BigInteger val) {
    	return new FieldElement(b, q, bi.divide(val).mod(q));
    }

    public FieldElement multiply(FieldElement val) {
        return new FieldElement(b, q, bi.multiply(val.bi).mod(q));
    }

    public FieldElement square() {
        return modPow(BigInteger.valueOf(2), q);
    }

    public FieldElement squareAndDouble() {
        return square().multiply(new FieldElement(b, q, Constants.TWO));
    }

    public FieldElement invert() {
        return modPow(q.subtract(Constants.TWO), q);
    }

    public FieldElement modPow(BigInteger e, BigInteger m) {
        return new FieldElement(b, q, bi.modPow(e, m));
    }
    
    public FieldElement pow(BigInteger i){
    	return modPow(i, q);
    }
    
    public FieldElement pow(FieldElement e){
    	return pow(e.bi);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FieldElement))
            return false;
        FieldElement fe = (FieldElement) obj;
        return bi.equals(fe.bi);
    }
    
    @Override
    public String toString() {
    	return "[FieldElement val="+bi+"]";
    }
}
