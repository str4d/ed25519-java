package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * @author str4d
 *
 */
public class EdDSAPrivateKeySpec implements KeySpec {
    private byte[] h;
    private BigInteger a;
    private GroupElement A;
    private EdDSAParameterSpec spec;

    public EdDSAPrivateKeySpec(byte[] seed, EdDSAParameterSpec spec) {
        this.spec = spec;

        try {
            MessageDigest hash = MessageDigest.getInstance(spec.getHashAlgorithm());
            int b = spec.getCurve().getField().getb();

            // H(k)
            h = hash.digest(seed);

            a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
            }

            A = spec.getB().scalarmult(a);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }
    }

    public EdDSAPrivateKeySpec(byte[] h, BigInteger a, GroupElement A, EdDSAParameterSpec spec) {
        this.h = h;
        this.a = a;
        this.A = A;
        this.spec = spec;
        
    }

    public byte[] getH() {
        return h;
    }

    public BigInteger geta() {
        return a;
    }

    public GroupElement getA() {
        return A;
    }

    public EdDSAParameterSpec getParams() {
        return spec;
    }

    private static int bit(byte[] h, int i) {
        return h[i/8] >> (i%8) & 1;
    }
}
