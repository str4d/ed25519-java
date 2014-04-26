package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * EdDSA Curve specification that can also be referred to by name.
 * @author str4d
 *
 */
public class EdDSANamedCurveSpec extends EdDSAParameterSpec {
    private String name;

    public EdDSANamedCurveSpec(String name, Curve curve,
            String hashAlgo, BigInteger l, GroupElement B) {
        super(curve, hashAlgo, l, B);
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
