package net.i2p.crypto.eddsa;

import java.security.PublicKey;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * An EdDSA public key.
 * @author str4d
 *
 */
public class EdDSAPublicKey implements EdDSAKey, PublicKey {
    private transient GroupElement A;
    private transient byte[] Abyte;
    private transient EdDSAParameterSpec edDsaSpec;

    public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
        this.A = spec.getA();
        this.Abyte = this.A.toByteArray();
        this.edDsaSpec = spec.getParams();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public EdDSAParameterSpec getParams() {
        return edDsaSpec;
    }

    public GroupElement getA() {
        return A;
    }

    public byte[] getAbyte() {
        return Abyte;
    }
}
