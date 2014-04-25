package net.i2p.crypto.eddsa.math;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

import org.junit.Test;

/**
 * Based on the tests in checkparams.py from the Python Ed25519 implementation.
 * @author str4d
 *
 */
public class ConstantsTest {
    static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("ed25519");
    static final Curve curve = ed25519.getCurve();

    static final FieldElement ZERO = curve.fromBigInteger(Constants.ZERO);
    static final FieldElement ONE = curve.fromBigInteger(Constants.ONE);
    static final FieldElement TWO = curve.fromBigInteger(Constants.TWO);

    static final GroupElement P3_ZERO = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO);

    @Test
    public void testb() {
        int b = curve.getb();
        assertThat(b, is(greaterThanOrEqualTo(10)));
        try {
            MessageDigest h = MessageDigest.getInstance(ed25519.getHashAlgorithm());
            assertThat(8 * h.getDigestLength(), is(equalTo(2 * b)));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testq() {
        BigInteger q = curve.getQ();
        assertThat(TWO.modPow(q.subtract(BigInteger.ONE), q), is(equalTo(ONE)));
        assertThat(q.mod(BigInteger.valueOf(4)), is(equalTo(BigInteger.ONE)));
    }

    @Test
    public void testl() {
        int b = curve.getb();
        BigInteger l = ed25519.getL();
        assertThat(TWO.modPow(l.subtract(BigInteger.ONE), l), is(equalTo(ONE)));
        assertThat(l, is(greaterThanOrEqualTo(BigInteger.valueOf(2).pow(b-4))));
        assertThat(l, is(lessThanOrEqualTo(BigInteger.valueOf(2).pow(b-3))));
    }

    @Test
    public void testd() {
        BigInteger q = curve.getQ();
        BigInteger qm1 = q.subtract(BigInteger.ONE);
        assertThat(curve.getD().modPow(qm1.divide(BigInteger.valueOf(2)), q), is(equalTo(curve.fromBigInteger(qm1))));
    }

    @Test
    public void testI() {
        BigInteger q = curve.getQ();
        assertThat(Constants.I.modPow(BigInteger.valueOf(2), q), is(equalTo(curve.fromBigInteger(q.subtract(BigInteger.ONE)))));
    }

    @Test
    public void testB() {
        GroupElement B = ed25519.getB();
        assertThat(GroupElement.isOnCurve(B), is(true));
        assertThat(GroupElement.scalarmult(B, ed25519.getL()), is(equalTo(P3_ZERO)));
    }
}
