package net.i2p.crypto.eddsa.math;


/**
 * Common interface for all (b-1)-bit encodings of elements
 * of EdDSA finite fields.
 * @author str4d
 *
 */
public interface Encoding {
    public byte[] toEncoding(FieldElement x);
    public FieldElement toElement(Field f, byte[] in);
}
