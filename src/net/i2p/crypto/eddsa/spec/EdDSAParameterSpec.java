package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import net.i2p.crypto.eddsa.EdDSAEncoding;
import net.i2p.crypto.eddsa.FieldElement;
import net.i2p.crypto.eddsa.GroupElement;

/**
 * @author str4d
 *
 */
public class EdDSAParameterSpec implements AlgorithmParameterSpec {
    private int b;
    private String hashAlgo;
    private BigInteger q;
    private EdDSAEncoding enc;
    private FieldElement d;
    private BigInteger l;
    private GroupElement B;

    public EdDSAParameterSpec(int b,
            String hashAlgo, BigInteger q,
            EdDSAEncoding enc, FieldElement d,
            BigInteger l, GroupElement B) {
        try {
            MessageDigest hash = MessageDigest.getInstance(hashAlgo);
            // EdDSA hash function must produce 2b-bit output
            if (b/4 != hash.getDigestLength())
                throw new IllegalArgumentException("Hash output is not 2b-bit");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }

        this.b = b;
        this.hashAlgo = hashAlgo;
        this.q = q;
        this.enc = enc;
        this.d = d;
        this.l = l;
        this.B = B;
    }

    public int getb() {
        return b;
    }

    public String getHashAlgorithm() {
        return hashAlgo;
    }

    public BigInteger getQ() {
        return q;
    }

    public EdDSAEncoding getEncoding() {
        return enc;
    }

    public FieldElement getD() {
        return d;
    }

    public BigInteger getL() {
        return l;
    }

    public GroupElement getB() {
        return B;
    }
}
