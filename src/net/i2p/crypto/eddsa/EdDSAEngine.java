package net.i2p.crypto.eddsa;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.LittleEndianEncoding;

/**
 * @author str4d
 *
 */
public class EdDSAEngine extends Signature {
    private MessageDigest digest;
    private byte[] message;
    private EdDSAKey key;

    /**
     * No specific hash requested, allows any EdDSA key.
     */
    public EdDSAEngine() {
        super("EdDSA");
    }

    /**
     * Specific hash requested, only matching keys will be allowed.
     * @param digest the hash algorithm that keys must have to sign or verify.
     */
    public EdDSAEngine(MessageDigest digest) {
        super("EdDSA");
        this.digest = digest;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (digest != null)
            digest.reset();
        message = new byte[0];

        if (privateKey instanceof EdDSAPrivateKey) {
            EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
            key = privKey;

            if (digest == null) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getParams().getHashAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getParams().getHashAlgorithm() + " for private key.");
                }
            } else if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
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
        if (digest != null)
            digest.reset();
        message = new byte[0];

        if (publicKey instanceof EdDSAPublicKey) {
            key = (EdDSAPublicKey) publicKey;

            if (digest == null) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getParams().getHashAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getParams().getHashAlgorithm() + " for private key.");
                }
            } else if (!key.getParams().getHashAlgorithm().equals(digest.getAlgorithm()))
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
        LittleEndianEncoding leEnc = new LittleEndianEncoding();

        // r = H(h_b,...,h_2b-1,M)
        byte[] r = digest.digest(message);
        // From the Ed25519 paper:
        // Here we interpret 2b-bit strings in little-endian form as integers in
        // {0, 1,..., 2^(2b)-1}.
        BigInteger rBI = leEnc.decode(r);

        // r mod l
        // Reduces r from 64 bytes to 32 bytes
        r = leEnc.encode(rBI.mod(l), curve.getField().getb()/8);

        // R = rB
        GroupElement R = key.getParams().getB().scalarMultiply(r);
        byte[] Rbyte = R.toByteArray();

        // S = (r + H(Rbar,Abar,M)*a) mod l
        digest.update(Rbyte);
        digest.update(((EdDSAPrivateKey) key).getAbyte());
        FieldElement S = curve.fromBigInteger(leEnc.decode(digest.digest(message)).multiply(a).add(rBI).mod(l));

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
        byte[] Sbyte = Arrays.copyOfRange(sigBytes, b/8, b/4);

        // If we get to here, Rbyte is valid
        digest.update(Rbyte);
        digest.update(((EdDSAPublicKey) key).getAbyte());
        // h = H(Rbar,Abar,M)
        byte[] h = digest.digest(message);

        // h mod l
        LittleEndianEncoding leEnc = new LittleEndianEncoding();
        h = leEnc.encode(leEnc.decode(h).mod(key.getParams().getL()), b/8);

        // R = SB - H(Rbar,Abar,M)A
        // TODO: Where is the negation of A supposed to happen?
        GroupElement R = key.getParams().getB().doubleScalarMultiplyVariableTime(
                ((EdDSAPublicKey) key).getA().negate(), h, Sbyte);

        byte[] Rcalc = R.toByteArray();
        int result = 1;
        for (int i = 0; i < Rcalc.length; i++) {
            result &= Utils.equal(Rcalc[i], Rbyte[i]);
        }
        return result == 1;
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
}
