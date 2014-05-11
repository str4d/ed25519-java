/**
 * 
 */
package net.i2p.crypto.eddsa.math.bigint;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.ScalarOps;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class BigIntegerScalarOpsTest {

    static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("ed25519-sha-512");
    static final Field ed25519Field = ed25519.getCurve().getField();

    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#reduce(byte[])}.
     */
    @Test
    public void testReduce() {
        ScalarOps sc = new BigIntegerScalarOps(ed25519Field,
                new BigIntegerFieldElement(ed25519Field,
                        new BigInteger("5")));
        assertThat(sc.reduce(new byte[] {7}),
                is(equalTo(Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000"))));

        ScalarOps sc2 = new BigIntegerScalarOps(ed25519Field,
                new BigIntegerFieldElement(ed25519Field,
                        new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")));
        // Example from test case 1
        byte[] r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d");
        assertThat(sc2.reduce(r), is(equalTo(Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#multiplyAndAdd(byte[], byte[], byte[])}.
     */
    @Test
    public void testMultiplyAndAdd() {
        fail("Not yet implemented");
    }

}
