package net.i2p.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class UtilsTest {
    static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

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
}
