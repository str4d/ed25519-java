package net.i2p.crypto.eddsa.math;

public abstract class FieldElement {
    protected final Field f;

    public FieldElement(Field f) {
        this.f = f;
    }

    /**
     * Encode a FieldElement in its (b-1)-bit encoding.
     * @return the (b-1)-bit encoding of this FieldElement.
     */
    public abstract byte[] toByteArray();

    public abstract boolean isNonZero();

    public abstract boolean isNegative();

    public abstract FieldElement add(FieldElement val);

    public abstract FieldElement addOne();

    public abstract FieldElement subtract(FieldElement val);

    public abstract FieldElement subtractOne();

    public abstract FieldElement negate();

    public abstract FieldElement divide(FieldElement val);

    public abstract FieldElement multiply(FieldElement val);

    public abstract FieldElement square();

    public abstract FieldElement squareAndDouble();

    public abstract FieldElement invert();

    public abstract FieldElement mod(FieldElement m);

    public abstract FieldElement modPow(FieldElement e, FieldElement m);

    public abstract FieldElement pow(FieldElement e);
}
