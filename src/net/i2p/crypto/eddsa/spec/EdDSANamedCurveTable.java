package net.i2p.crypto.eddsa.spec;

import java.math.BigInteger;
import java.util.Hashtable;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.LittleEndianEncoding;
import net.i2p.crypto.eddsa.math.Field;

/**
 * The named EdDSA curves.
 * @author str4d
 *
 */
public class EdDSANamedCurveTable {
    static Curve ed25519curve = new Curve(
            new Field(256, // b
                    new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949"), // q
                    new LittleEndianEncoding()),
            new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740")); // d
    static EdDSANamedCurveSpec ed25519sha512 = new EdDSANamedCurveSpec(
            "ed25519-sha-512",
            ed25519curve,
            "SHA-512", // H
            new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"), // l
            ed25519curve.createPoint( // B
                    new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
                    new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960")));

    static final Hashtable<String, EdDSANamedCurveSpec> curves = new Hashtable<String, EdDSANamedCurveSpec>();

    static void defineCurve(String name, EdDSANamedCurveSpec curve) {
        curves.put(name, curve);
    }

    static {
        defineCurve("ed25519-sha-512", ed25519sha512);
    }

    public static EdDSANamedCurveSpec getByName(String name) {
        return curves.get(name);
    }
}
