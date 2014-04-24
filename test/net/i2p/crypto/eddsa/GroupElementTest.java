package net.i2p.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class GroupElementTest {
    static final byte[] BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080");
    static final byte[] BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080");

    static final FieldElement[] PKR = new FieldElement[] {new FieldElement(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")), new FieldElement(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291"))};
    static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    /**
     * Test method for {@link GroupElement#p2(FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP2() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#p3(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP3() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#p1p1(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP1p1() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#cached(FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testCached() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#GroupElement(GroupElement.Representation, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testGroupElementRepresentationFieldElementFieldElementFieldElementFieldElement() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#GroupElement(byte[])}.
     */
    @Test
    public void testGroupElementByteArray() {
        GroupElement t;

        t = new GroupElement(BYTES_ZEROZERO);
        assertThat(t.X, is(equalTo(FieldElement.ZERO)));
        assertThat(t.Y, is(equalTo(FieldElement.ZERO)));
        assertThat(t.Z, is(equalTo(FieldElement.ONE)));
        assertThat(t.T, is(equalTo(FieldElement.ZERO)));

        t = new GroupElement(BYTES_ONEONE);
        assertThat(t.X, is(equalTo(FieldElement.ONE)));
        assertThat(t.Y, is(equalTo(FieldElement.ONE)));
        assertThat(t.Z, is(equalTo(FieldElement.ONE)));
        assertThat(t.T, is(equalTo(FieldElement.ONE)));


        t = new GroupElement(BYTES_TENZERO);
        assertThat(t.X, is(equalTo(new FieldElement(BigInteger.TEN))));
        assertThat(t.Y, is(equalTo(FieldElement.ZERO)));
        assertThat(t.Z, is(equalTo(FieldElement.ONE)));
        assertThat(t.T, is(equalTo(FieldElement.ZERO)));

        t = new GroupElement(BYTES_ONETEN);
        assertThat(t.X, is(equalTo(FieldElement.ONE)));
        assertThat(t.Y, is(equalTo(new FieldElement(BigInteger.TEN))));
        assertThat(t.Z, is(equalTo(FieldElement.ONE)));
        assertThat(t.T, is(equalTo(new FieldElement(BigInteger.TEN))));

        t = new GroupElement(BYTES_PKR);
        assertThat(t.X, is(equalTo(PKR[0])));
        assertThat(t.Y, is(equalTo(PKR[1])));
        assertThat(t.Z, is(equalTo(FieldElement.ONE)));
        assertThat(t.T, is(equalTo(PKR[0].multiply(PKR[1]))));
    }

    /**
     * Test method for {@link GroupElement#toByteArray()}.
     */
    @Test
    public void testToByteArray() {
        byte[] zerozero = GroupElement.p2(FieldElement.ZERO, FieldElement.ZERO, FieldElement.ONE).toByteArray();
        assertThat(zerozero.length, is(equalTo(BYTES_ZEROZERO.length)));
        assertThat(zerozero, is(equalTo(BYTES_ZEROZERO)));

        byte[] oneone = GroupElement.p2(FieldElement.ONE, FieldElement.ONE, FieldElement.ONE).toByteArray();
        assertThat(oneone.length, is(equalTo(BYTES_ONEONE.length)));
        assertThat(oneone, is(equalTo(BYTES_ONEONE)));

        byte[] tenzero = GroupElement.p2(new FieldElement(BigInteger.TEN), FieldElement.ZERO, FieldElement.ONE).toByteArray();
        assertThat(tenzero.length, is(equalTo(BYTES_TENZERO.length)));
        assertThat(tenzero, is(equalTo(BYTES_TENZERO)));

        byte[] oneten = GroupElement.p2(FieldElement.ONE, new FieldElement(BigInteger.TEN), FieldElement.ONE).toByteArray();
        assertThat(oneten.length, is(equalTo(BYTES_ONETEN.length)));
        assertThat(oneten, is(equalTo(BYTES_ONETEN)));

        byte[] pkr = GroupElement.p2(PKR[0], PKR[1], FieldElement.ONE).toByteArray();
        assertThat(pkr.length, is(equalTo(BYTES_PKR.length)));
        assertThat(pkr, is(equalTo(BYTES_PKR)));
    }

    /**
     * Test method for {@link GroupElement#toP2()}.
     */
    @Test
    public void testToP2() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#toP3()}.
     */
    @Test
    public void testToP3() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link GroupElement#toP1P1()}.
     */
    @Test
    public void testToP1P1() {
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
     * Test method for {@link GroupElement#dbl()}.
     */
    @Test
    public void testDbl() {
        fail("Not yet implemented");
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
        assertThat(GroupElement.p2(FieldElement.ZERO, FieldElement.ONE, FieldElement.ONE),
                is(equalTo(GroupElement.P2_ZERO)));
    }

    /**
     * Test method for {@link GroupElement#isOnCurve(GroupElement)}.
     */
    @Test
    public void testIsOnCurve() {
        assertThat(GroupElement.isOnCurve(GroupElement.P2_ZERO),
                is(true));
        assertThat(GroupElement.isOnCurve(GroupElement.p2(FieldElement.ZERO, FieldElement.ZERO, FieldElement.ONE)),
                is(false));
    }

}
