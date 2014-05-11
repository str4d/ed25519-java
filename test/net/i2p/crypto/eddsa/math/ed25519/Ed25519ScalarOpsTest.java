/**
 * 
 */
package net.i2p.crypto.eddsa.math.ed25519;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.ScalarOps;
import org.junit.Test;

/**
 * @author str4d
 *
 */
public class Ed25519ScalarOpsTest {
    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#reduce(byte[])}.
     */
    @Test
    public void testReduce() {
        ScalarOps sc = new Ed25519ScalarOps();
        // Example from test case 1
        byte[] r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d");
        assertThat(sc.reduce(r), is(equalTo(Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#multiplyAndAdd(byte[], byte[], byte[])}.
     */
    @Test
    public void testMultiplyAndAdd() {
        fail("Not yet implemented");
    }

}
