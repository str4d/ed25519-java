package net.i2p.crypto.eddsa.math;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import net.i2p.crypto.eddsa.Ed25519TestVectors;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * @author str4d
 *
 */
public class GroupElementTest {
    static final byte[] BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080");
    static final byte[] BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080");

    static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("ed25519-sha-512");
    static final Curve curve = ed25519.getCurve();

    static final FieldElement ZERO = curve.fromBigInteger(Constants.ZERO);
    static final FieldElement ONE = curve.fromBigInteger(Constants.ONE);
    static final FieldElement TWO = curve.fromBigInteger(Constants.TWO);
    static final FieldElement TEN = curve.fromBigInteger(BigInteger.valueOf(10));

    static final GroupElement P2_ZERO = GroupElement.p2(curve, ZERO, ONE, ONE);

    static final FieldElement[] PKR = new FieldElement[] {
        curve.fromBigInteger(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")),
        curve.fromBigInteger(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291"))
        };
    static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    @Rule
    public ExpectedException exception = ExpectedException.none();

    /**
     * Test method for {@link GroupElement#p2(FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP2() {
        GroupElement t = GroupElement.p2(curve, ZERO, ONE, ONE);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P2));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is((FieldElement) null));
    }

    /**
     * Test method for {@link GroupElement#p3(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP3() {
        GroupElement t = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P3));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Test method for {@link GroupElement#p1p1(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP1p1() {
        GroupElement t = GroupElement.p1p1(curve, ZERO, ONE, ONE, ONE);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P1P1));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ONE));
    }

    /**
     * Test method for {@link GroupElement#precomp(Curve, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testPrecomp() {
        GroupElement t = GroupElement.precomp(curve, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.PRECOMP));
        assertThat(t.X, is(ONE));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ZERO));
        assertThat(t.T, is((FieldElement) null));
    }

    /**
     * Test method for {@link GroupElement#cached(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testCached() {
        GroupElement t = GroupElement.cached(curve, ONE, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.CACHED));
        assertThat(t.X, is(ONE));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Test method for {@link GroupElement#GroupElement(Curve, GroupElement.Representation, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testGroupElementCurveRepresentationFieldElementFieldElementFieldElementFieldElement() {
        GroupElement t = new GroupElement(curve, GroupElement.Representation.P3, ZERO, ONE, ONE, ZERO);
        assertThat(t.curve, is(equalTo(curve)));
        assertThat(t.repr, is(GroupElement.Representation.P3));
        assertThat(t.X, is(ZERO));
        assertThat(t.Y, is(ONE));
        assertThat(t.Z, is(ONE));
        assertThat(t.T, is(ZERO));
    }

    /**
     * Tests {@link GroupElement#GroupElement(Curve, byte[])} and
     * {@link GroupElement#toByteArray()} against valid public keys.
     */
    @Test
    public void testToAndFromByteArray() {
        GroupElement t;
        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
            t = new GroupElement(curve, testCase.pk);
            assertThat("Test case " + testCase.caseNum + " failed",
                    t.toByteArray(), is(equalTo(testCase.pk)));
        }
    }

    /**
     * Test method for {@link GroupElement#GroupElement(byte[])}.
     */
    @Test
    public void testGroupElementByteArray() {
        GroupElement t;

        t = new GroupElement(curve, BYTES_PKR);
        assertThat(t, is(equalTo(GroupElement.p3(curve, PKR[0], PKR[1], ONE, PKR[0].multiply(PKR[1])))));
    }

    /**
     * Test method for {@link GroupElement#toByteArray()}.
     */
    @Test
    public void testToByteArray() {
        byte[] zerozero = GroupElement.p2(curve, ZERO, ZERO, ONE).toByteArray();
        assertThat(zerozero.length, is(equalTo(BYTES_ZEROZERO.length)));
        assertThat(zerozero, is(equalTo(BYTES_ZEROZERO)));

        byte[] oneone = GroupElement.p2(curve, ONE, ONE, ONE).toByteArray();
        assertThat(oneone.length, is(equalTo(BYTES_ONEONE.length)));
        assertThat(oneone, is(equalTo(BYTES_ONEONE)));

        byte[] tenzero = GroupElement.p2(curve, TEN, ZERO, ONE).toByteArray();
        assertThat(tenzero.length, is(equalTo(BYTES_TENZERO.length)));
        assertThat(tenzero, is(equalTo(BYTES_TENZERO)));

        byte[] oneten = GroupElement.p2(curve, ONE, TEN, ONE).toByteArray();
        assertThat(oneten.length, is(equalTo(BYTES_ONETEN.length)));
        assertThat(oneten, is(equalTo(BYTES_ONETEN)));

        byte[] pkr = GroupElement.p2(curve, PKR[0], PKR[1], ONE).toByteArray();
        assertThat(pkr.length, is(equalTo(BYTES_PKR.length)));
        assertThat(pkr, is(equalTo(BYTES_PKR)));
    }

    /**
     * Test method for {@link GroupElement#toP2()}.
     */
    @Test
    public void testToP2() {
        GroupElement p3zero = curve.getZero(GroupElement.Representation.P3);
        GroupElement t = p3zero.toP2();
        assertThat(t.repr, is(GroupElement.Representation.P2));
        assertThat(t.X, is(p3zero.X));
        assertThat(t.Y, is(p3zero.Y));
        assertThat(t.Z, is(p3zero.Z));
        assertThat(t.T, is((FieldElement) null));

        GroupElement B = ed25519.getB();
        t = B.toP2();
        assertThat(t.repr, is(GroupElement.Representation.P2));
        assertThat(t.X, is(B.X));
        assertThat(t.Y, is(B.Y));
        assertThat(t.Z, is(B.Z));
        assertThat(t.T, is((FieldElement) null));
    }

    /**
     * Test method for {@link GroupElement#toP3()}.
     */
    @Test
    public void testToP3() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#toCached()}.
     */
    @Test
    public void testToCached() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#precompute()}.
     */
    @Test
    public void testPrecompute() {
        GroupElement B = ed25519.getB();
        assertThat(B.precmp, is(equalTo(PrecomputationTestVectors.testPrecmp)));
        assertThat(B.dblPrecmp, is(equalTo(PrecomputationTestVectors.testDblPrecmp)));
    }

    /**
     * Test method for {@link GroupElement#dbl()}.
     */
    @Test
    public void testDbl() {
        GroupElement B = ed25519.getB();
        // 2 * B = B + B
        assertThat(B.dbl(), is(equalTo(B.add(B.toCached()))));
    }

    /**
     * Test method for {@link GroupElement#madd(GroupElement)}.
     */
    @Test
    public void testMadd() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#msub(GroupElement)}.
     */
    @Test
    public void testMsub() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#add(GroupElement)}.
     */
    @Test
    public void testAdd() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#sub(GroupElement)}.
     */
    @Test
    public void testSub() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() {
        assertThat(GroupElement.p2(curve, ZERO, ONE, ONE),
                is(equalTo(P2_ZERO)));
    }

    /**
     * Test method for {@link GroupElement#cmov(GroupElement, int)}.
     */
    @Test
    public void testCmov() {
        GroupElement a = curve.getZero(GroupElement.Representation.PRECOMP);
        GroupElement b = GroupElement.precomp(curve, TWO, ZERO, TEN);
        assertThat(a.cmov(b, 0), is(equalTo(a)));
        assertThat(a.cmov(b, 1), is(equalTo(b)));
    }

    /**
     * Test method for {@link GroupElement#select(int, int)}.
     */
    @Test
    public void testSelect() {
        GroupElement B = ed25519.getB();
        for (int i = 0; i < 32; i++) {
            // 16^i 0 B
            assertThat(i + ",0", B.select(i, 0),
                    is(equalTo(GroupElement.precomp(curve, ONE, ONE, ZERO))));
            for (int j = 1; j < 8; j++) {
                // 16^i r_i B
                GroupElement t = B.select(i, j);
                assertThat(i + "," + j,
                        t, is(equalTo(B.precmp[i][j-1])));
                // -16^i r_i B
                t = B.select(i, -j);
                GroupElement neg = GroupElement.precomp(curve,
                        B.precmp[i][j-1].Y,
                        B.precmp[i][j-1].X,
                        B.precmp[i][j-1].Z.negate());
                assertThat(i + "," + -j,
                        t, is(equalTo(neg)));
            }
        }
    }

    /**
     * Test method for {@link GroupElement#scalarMultiply(byte[])}.
     * Test values generated with Python Ed25519 implementation.
     */
    @Test
    public void testScalarMultiplyByteArray() {
        // Little-endian
        byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        GroupElement A = new GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));

        assertThat("scalarMultiply(0) failed",
                ed25519.getB().scalarMultiply(zero), is(equalTo(curve.getZero(GroupElement.Representation.P3))));
        assertThat("scalarMultiply(1) failed",
                ed25519.getB().scalarMultiply(one), is(equalTo(ed25519.getB())));
        assertThat("scalarMultiply(2) failed",
                ed25519.getB().scalarMultiply(two), is(equalTo(ed25519.getB().dbl())));

        assertThat("scalarMultiply(a) failed",
                ed25519.getB().scalarMultiply(a), is(equalTo(A)));
    }

    @Test
    public void testDoubleScalarMultiplyVariableTime() {
        // Little-endian
        byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        GroupElement A = new GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        GroupElement B = ed25519.getB();
        GroupElement geZero = curve.getZero(GroupElement.Representation.P3);
        geZero.precompute(false);

        // 0 * GE(0) + 0 * GE(0) = GE(0)
        assertThat(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 0 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 1 * B = B
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, one),
                is(equalTo(B)));
        // 1 * B + 1 * B = 2 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, one),
                is(equalTo(B.dbl())));
        // 1 * B + 2 * B = 3 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, two),
                is(equalTo(B.dbl().toP3().add(B.toCached()))));
        // 2 * B + 2 * B = 4 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, two, two),
                is(equalTo(B.dbl().toP3().dbl())));

        // 0 * B + a * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, zero, a),
                is(equalTo(A)));
        // a * B + 0 * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, zero),
                is(equalTo(A)));
        // a * B + a * B = 2 * A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, a),
                is(equalTo(A.dbl())));
    }

    /**
     * Test method for {@link GroupElement#isOnCurve(GroupElement)}.
     */
    @Test
    public void testIsOnCurve() {
        assertThat(P2_ZERO.isOnCurve(curve),
                is(true));
        assertThat(GroupElement.p2(curve, ZERO, ZERO, ONE).isOnCurve(curve),
                is(false));
        assertThat(GroupElement.p2(curve, ONE, ONE, ONE).isOnCurve(curve),
                is(false));
        assertThat(GroupElement.p2(curve, TEN, ZERO, ONE).isOnCurve(curve),
                is(false));
        assertThat(GroupElement.p2(curve, ONE, TEN, ONE).isOnCurve(curve),
                is(false));
        assertThat(GroupElement.p2(curve, PKR[0], PKR[1], ONE).isOnCurve(curve),
                is(true));
    }

}
