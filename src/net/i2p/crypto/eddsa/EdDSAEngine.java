package net.i2p.crypto.eddsa;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * @author str4d
 *
 */
public class EdDSAEngine extends Signature {
    private MessageDigest digest;
    private byte[] message;
    private EdDSAKey key;

    EdDSAEngine(MessageDigest digest) {
        super("EdDSA");
        this.digest = digest;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        digest.reset();
        message = new byte[0];

        if (privateKey instanceof EdDSAPrivateKey) {
            EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
            key = privKey;

            if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
                throw new InvalidKeyException("Key hash algorithm does not match chosen digest");

            // Preparing for hash
            // r = H(h_b,...,h_2b-1,M)
            int b = privKey.getParams().getCurve().getField().getb();
            digest.update(privKey.getH(), b/8, b/4 - b/8);
        } else
            throw new InvalidKeyException("cannot identify EdDSA private key.");
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        digest.reset();
        message = new byte[0];

        if (publicKey instanceof EdDSAPublicKey) {
            key = (EdDSAPublicKey) publicKey;

            if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
                throw new InvalidKeyException("Key hash algorithm does not match chosen digest");
        } else
            throw new InvalidKeyException("cannot identify EdDSA public key.");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        // We need to store the message because it is used in several hashes
        // XXX Can this be done more efficiently?
        byte[] msg = new byte[message.length + 1];
        for (int i = 0; i < message.length; i++) {
            msg[i] = message[i];
        }
        msg[message.length] = b;
        message = msg;
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        // We need to store the message because it is used in several hashes
        // XXX Can this be done more efficiently?
        byte[] msg = new byte[message.length + len];
        for (int i = 0; i < message.length; i++) {
            msg[i] = message[i];
        }
        for (int i = 0; i < len; i++) {
            msg[i] = b[off+i];
        }
        message = msg;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        Curve curve = key.getParams().getCurve();
        BigInteger l = key.getParams().getL();
        BigInteger a = ((EdDSAPrivateKey) key).geta();

        // r = H(h_b,...,h_2b-1,M)
        BigInteger r = Hint(digest.digest(message));

        // R = rB
        GroupElement R = key.getParams().getB().scalarmult(r);
        byte[] Rbyte = R.toByteArray();

        // S = (r + H(Rbar,Abar,M)*a) mod l
        digest.update(Rbyte);
        digest.update(((EdDSAPrivateKey) key).getAbyte());
        FieldElement S = curve.fromBigInteger(Hint(digest.digest(message)).multiply(a).add(r).mod(l));

        // R+S
        ByteBuffer out = ByteBuffer.allocate(64);
        out.put(Rbyte).put(S.toByteArray());
        return out.array();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        Curve curve = key.getParams().getCurve();
        int b = curve.getField().getb();
        if (sigBytes.length != b/4)
            throw new IllegalArgumentException("signature length is wrong");

        byte[] Rbyte = Arrays.copyOfRange(sigBytes, 0, b/8);
        GroupElement R = new GroupElement(curve, Rbyte);

        byte[] Sbyte = Arrays.copyOfRange(sigBytes, b/8, b/4);
        FieldElement S = curve.fromByteArray(Sbyte);

        // If we get to here, Rbyte is valid
        digest.update(Rbyte);
        digest.update(((EdDSAPublicKey) key).getAbyte());
        // h = H(Rbar,Abar,M)
        BigInteger h = Hint(digest.digest(message));
        // SB
        GroupElement ra = key.getParams().getB().scalarmult(S);
        // R + H(Rbar,Abar,M)A
        GroupElement rb = R.add(((EdDSAPublicKey) key).getA().scalarmult(h).toCached());

        // SB = R + H(Rbar,Abar,M)A
        if (!ra.equals(rb))
            return false;
        return true;
    }

    /**
     * @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    @Override
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    @Override
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * From the Ed25519 paper:
     * Here we interpret 2b-bit strings in little-endian form as integers in
     * {0, 1,..., 2^(2b)-1}.
     * @param h the output of a hash function.
     * @return 2^h
     */
    private BigInteger Hint(byte[] h) {
        if (h.length != key.getParams().getCurve().getField().getb()/4)
            throw new IllegalArgumentException("invalid hash output length");
        // Reverse h
        for (int i = 0; i < h.length/2; i++) {
            byte tmp = h[i];
            h[i] = h[h.length-1-i];
            h[h.length-1-i] = tmp;
        }
        return new BigInteger(1, h);
    }
}
