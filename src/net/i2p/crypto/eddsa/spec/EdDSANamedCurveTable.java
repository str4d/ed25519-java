package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.util.Hashtable;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps;

/**
 * The named EdDSA curves.
 * @author str4d
 *
 */
public class EdDSANamedCurveTable {
    public static final String CURVE_ED25519_SHA512 = "ed25519-sha-512";

    private static final Field ed25519field = new Field(
                    256, // b
                    Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                    new BigIntegerLittleEndianEncoding());

    private static final Curve ed25519curve = new Curve(ed25519field,
            Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352")); // d

    private static final EdDSANamedCurveSpec ed25519sha512 = new EdDSANamedCurveSpec(
            CURVE_ED25519_SHA512,
            ed25519curve,
            "SHA-512", // H
            new BigIntegerScalarOps(ed25519field,
                    new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")), // l
            ed25519curve.createPoint( // B
                    Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
                    true)); // Precompute tables for B

    private static final Hashtable<String, EdDSANamedCurveSpec> curves = new Hashtable<String, EdDSANamedCurveSpec>();

    public static void defineCurve(String name, EdDSANamedCurveSpec curve) {
        curves.put(name, curve);
    }

    static {
        defineCurve(CURVE_ED25519_SHA512, ed25519sha512);
    }

    public static EdDSANamedCurveSpec getByName(String name) {
        return curves.get(name);
    }
}
