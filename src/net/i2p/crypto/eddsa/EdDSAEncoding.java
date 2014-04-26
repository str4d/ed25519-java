package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.FieldElement;

/**
 * Common interface for all (b-1)-bit encodings of elements
 * of EdDSA finite fields.
 * @author str4d
 *
 */
public interface EdDSAEncoding {
    public byte[] toEncoding(FieldElement x);
    public FieldElement toElement(Curve curve, byte[] in);
}
