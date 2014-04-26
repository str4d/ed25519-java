package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import net.i2p.crypto.eddsa.EdDSAEncoding;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * Parameter specification for an EdDSA algorithm.
 * @author str4d
 *
 */
public class EdDSAParameterSpec implements AlgorithmParameterSpec {
    private Curve curve;
    private String hashAlgo;
    private EdDSAEncoding enc;
    private BigInteger l;
    private GroupElement B;

    public EdDSAParameterSpec(Curve curve,
            String hashAlgo, EdDSAEncoding enc,
            BigInteger l, GroupElement B) {
        try {
            MessageDigest hash = MessageDigest.getInstance(hashAlgo);
            // EdDSA hash function must produce 2b-bit output
            if (curve.getb()/4 != hash.getDigestLength())
                throw new IllegalArgumentException("Hash output is not 2b-bit");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }

        this.curve = curve;
        this.hashAlgo = hashAlgo;
        this.enc = enc;
        this.l = l;
        this.B = B;
    }

    public Curve getCurve() {
        return curve;
    }

    public String getHashAlgorithm() {
        return hashAlgo;
    }

    public EdDSAEncoding getEncoding() {
        return enc;
    }

    public BigInteger getL() {
        return l;
    }

    public GroupElement getB() {
        return B;
    }
}
