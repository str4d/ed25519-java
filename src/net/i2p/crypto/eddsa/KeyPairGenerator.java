package net.i2p.crypto.eddsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import net.i2p.crypto.eddsa.math.Constants;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class KeyPairGenerator extends KeyPairGeneratorSpi {
    int strength = 25519;
    EdDSAParameterSpec edParams;
    SecureRandom random;
    boolean initialized = false;

    static private Hashtable<Integer, AlgorithmParameterSpec> edParameters;

    static {
        edParameters = new Hashtable<Integer, AlgorithmParameterSpec>();

        edParameters.put(Integer.valueOf(25519), new EdDSAParameterSpec(
                new Curve(Constants.b, Constants.q, Constants.d),
                "SHA-512",
                null,
                Constants.l,
                Constants.B));
    }

    @Override
    public void initialize(int strength, SecureRandom random) {
        AlgorithmParameterSpec edParams = edParameters.get(Integer.valueOf(strength));
        if (edParams == null)
            throw new InvalidParameterException("unknown key type.");
        try {
            initialize(edParams, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("key type not configurable.");
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof EdDSAParameterSpec) {
            edParams = (EdDSAParameterSpec) params;
        } else
            throw new InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec");

        this.random = random;
        initialized = true;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!initialized)
            initialize(strength, new SecureRandom());

        byte[] seed = new byte[edParams.getCurve().getb()];
        random.nextBytes(seed);

        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, edParams);
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getA(), edParams);

        return new KeyPair(new EdDSAPublicKey(pubKey), new EdDSAPrivateKey(privKey));
    }
}
