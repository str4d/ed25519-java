package net.i2p.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;

import org.junit.Test;

/**
 * Based on the tests in checkparams.py from the Python Ed25519 implementation.
 * @author str4d
 *
 */
public class ConstantsTest {

    @Test
    public void testb() {
        assertThat(Constants.b, is(greaterThanOrEqualTo(10)));
        assertThat(8 * Ed25519.H("hash input".getBytes()).length, is(equalTo(2 * Constants.b)));
    }

    @Test
    public void testq() {
        assertThat(FieldElement.TWO.modPow(Constants.q.subtract(BigInteger.ONE), Constants.q), is(equalTo(FieldElement.ONE)));
        assertThat(Constants.q.mod(BigInteger.valueOf(4)), is(equalTo(BigInteger.ONE)));
    }

    @Test
    public void testl() {
        assertThat(FieldElement.TWO.modPow(Constants.l.subtract(BigInteger.ONE), Constants.l), is(equalTo(FieldElement.ONE)));
        assertThat(Constants.l, is(greaterThanOrEqualTo(BigInteger.valueOf(2).pow(Constants.b-4))));
        assertThat(Constants.l, is(lessThanOrEqualTo(BigInteger.valueOf(2).pow(Constants.b-3))));
    }

    @Test
    public void testd() {
        assertThat(Constants.d.modPow(Constants.q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), Constants.q), is(equalTo(new FieldElement(Constants.q.subtract(BigInteger.ONE)))));
    }

    @Test
    public void testI() {
        assertThat(Constants.I.modPow(BigInteger.valueOf(2), Constants.q), is(equalTo(new FieldElement(Constants.q.subtract(BigInteger.ONE)))));
    }

    @Test
    public void testB() {
        assertThat(GroupElement.isOnCurve(Constants.B), is(true));
        assertThat(Ed25519.scalarmult(Constants.B, Constants.l), is(equalTo(GroupElement.P3_ZERO)));
    }

}
