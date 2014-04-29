package net.i2p.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class UtilsTest {
    static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_42 = Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_1234567890 = Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000");
    static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    static final byte[] RADIX16_ZERO = Utils.hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_ONE = Utils.hexToBytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_42 = Utils.hexToBytes("FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#equal(int, int)}.
     */
    @Test
    public void testEqual() {
        assertThat(Utils.equal(0, 0),       is(1));
        assertThat(Utils.equal(1, 1),       is(1));
        assertThat(Utils.equal(1, 0),       is(0));
        assertThat(Utils.equal(1, 127),     is(0));
        assertThat(Utils.equal(-127, 127),  is(0));
        assertThat(Utils.equal(-42, -42),   is(1));
        assertThat(Utils.equal(255, 255),   is(1));
        assertThat(Utils.equal(-255, -256), is(0));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#negative(int)}.
     */
    @Test
    public void testNegative() {
        assertThat(Utils.negative(0),    is(0));
        assertThat(Utils.negative(1),    is(0));
        assertThat(Utils.negative(-1),   is(1));
        assertThat(Utils.negative(32),   is(0));
        assertThat(Utils.negative(-100), is(1));
        assertThat(Utils.negative(127),  is(0));
        assertThat(Utils.negative(-255), is(1));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#toRadix16(byte[])}.
     */
    @Test
    public void testToRadix16() {
        assertThat(Utils.toRadix16(BYTES_ZERO), is(RADIX16_ZERO));
        assertThat(Utils.toRadix16(BYTES_ONE), is(RADIX16_ONE));
        assertThat(Utils.toRadix16(BYTES_42), is(RADIX16_42));

        byte[] from1234567890 = Utils.toRadix16(BYTES_1234567890);
        int total = 0;
        for (int i = 0; i < from1234567890.length; i++) {
            assertThat(from1234567890[i], is(greaterThanOrEqualTo((byte)-8)));
            assertThat(from1234567890[i], is(lessThanOrEqualTo((byte)8)));
            total += from1234567890[i] * Math.pow(16, i);
        }
        assertThat(total, is(1234567890));

        byte[] pkrR16 = Utils.toRadix16(BYTES_PKR);
        for (int i = 0; i < pkrR16.length; i++) {
            assertThat(pkrR16[i], is(greaterThanOrEqualTo((byte)-8)));
            assertThat(pkrR16[i], is(lessThanOrEqualTo((byte)8)));
        }
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#bit(byte[], int)}.
     */
    @Test
    public void testBit() {
        assertThat(Utils.bit(new byte[] {0}, 0), is(0));
        assertThat(Utils.bit(new byte[] {8}, 3), is(1));
        assertThat(Utils.bit(new byte[] {1, 2, 3}, 9), is(1));
        assertThat(Utils.bit(new byte[] {1, 2, 3}, 15), is(0));
        assertThat(Utils.bit(new byte[] {1, 2, 3}, 16), is(1));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#Hint(byte[])}.
     */
    @Test
    public void testHint() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#getHex(byte[])}.
     */
    @Test
    public void testGetHex() {
        fail("Not yet implemented");
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#hexToBytes(java.lang.String)}.
     */
    @Test
    public void testHexToBytes() {
        fail("Not yet implemented");
    }

}
