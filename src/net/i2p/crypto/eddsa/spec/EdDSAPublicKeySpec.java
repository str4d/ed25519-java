package net.i2p.crypto.eddsa.spec;

import java.security.spec.KeySpec;

import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * @author str4d
 *
 */
public class EdDSAPublicKeySpec implements KeySpec {
    private GroupElement A;
    private EdDSAParameterSpec spec;

    public EdDSAPublicKeySpec(byte[] pk, EdDSAParameterSpec spec) {
        if (pk.length != spec.getb()/8)
            throw new IllegalArgumentException("public-key length is wrong");

        this.A = new GroupElement(pk);
        this.spec = spec;
    }

    public EdDSAPublicKeySpec(GroupElement A, EdDSAParameterSpec spec) {
        this.A = A;
        this.spec = spec;
    }

    public GroupElement getA() {
        return A;
    }

    public EdDSAParameterSpec getParams() {
        return spec;
    }
}
