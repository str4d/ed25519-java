package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.util.Hashtable;

import net.i2p.crypto.eddsa.math.Constants;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

/**
 * The named EdDSA curves.
 * @author str4d
 *
 */
public class EdDSANamedCurveTable {
    static Curve ed25519curve = new Curve(
            new Field(256, // b
                    new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949")), // q
            new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740")); // d
    static FieldElement ed25519Bx = ed25519curve.fromBigInteger(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
    static FieldElement ed25519By = ed25519curve.fromBigInteger(new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    static EdDSANamedCurveSpec ed25519 = new EdDSANamedCurveSpec(
            "ed25519",
            ed25519curve,
            "SHA-512", // H
            null,
            new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"), // l
            GroupElement.p3(ed25519curve, ed25519Bx, ed25519By,
                    ed25519curve.fromBigInteger(Constants.ONE),
                    ed25519Bx.multiply(ed25519By))); // B

    static final Hashtable<String, EdDSANamedCurveSpec> curves = new Hashtable<String, EdDSANamedCurveSpec>();

    static void defineCurve(String name, EdDSANamedCurveSpec curve) {
        curves.put(name, curve);
    }

    static {
        defineCurve("ed25519", ed25519);
    }

    public static EdDSANamedCurveSpec getByName(String name) {
        return curves.get(name);
    }
}
