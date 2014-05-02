package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * Parameter specification for an EdDSA algorithm.
 * @author str4d
 *
 */
public class EdDSAParameterSpec implements AlgorithmParameterSpec {
    private final Curve curve;
    private final String hashAlgo;
    private final BigInteger l;
    private final GroupElement B;

    public EdDSAParameterSpec(Curve curve, String hashAlgo,
            BigInteger l, GroupElement B) {
        try {
            MessageDigest hash = MessageDigest.getInstance(hashAlgo);
            // EdDSA hash function must produce 2b-bit output
            if (curve.getField().getb()/4 != hash.getDigestLength())
                throw new IllegalArgumentException("Hash output is not 2b-bit");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }

        this.curve = curve;
        this.hashAlgo = hashAlgo;
        this.l = l;
        this.B = B;
    }

    public Curve getCurve() {
        return curve;
    }

    public String getHashAlgorithm() {
        return hashAlgo;
    }

    public BigInteger getL() {
        return l;
    }

    public GroupElement getB() {
        return B;
    }
}
