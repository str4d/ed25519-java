import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class FieldElementTest {
	static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
	static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
	static final byte[] BYTES_TEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000");

	/**
	 * Test method for {@link FieldElement#FieldElement(java.math.BigInteger)}.
	 */
	@Test
	public void testFieldElementBigInteger() {
		assertThat(new FieldElement(BigInteger.ZERO).bi, is(BigInteger.ZERO));
		assertThat(new FieldElement(BigInteger.ONE).bi, is(BigInteger.ONE));
		assertThat(new FieldElement(BigInteger.valueOf(2)).bi, is(BigInteger.valueOf(2)));
	}

	/**
	 * Test method for {@link FieldElement#FieldElement(byte[])}.
	 */
	@Test
	public void testFieldElementByteArray() {
		assertThat(new FieldElement(BYTES_ZERO).bi, is(equalTo(BigInteger.ZERO)));
		assertThat(new FieldElement(BYTES_ONE).bi, is(equalTo(BigInteger.ONE)));
		assertThat(new FieldElement(BYTES_TEN).bi, is(equalTo(BigInteger.TEN)));
		// XXX: Should these pass or fail?
		assertThat(new FieldElement(Utils.hexToBytes("00")).bi, is(BigInteger.ZERO));
		assertThat(new FieldElement(Utils.hexToBytes("01")).bi, is(BigInteger.ONE));
	}

	/**
	 * Test method for {@link FieldElement#toByteArray()}.
	 */
	@Test
	public void testToByteArray() {
		assertThat(FieldElement.ZERO.toByteArray(), is(equalTo(BYTES_ZERO)));
		assertThat(FieldElement.ONE.toByteArray(), is(equalTo(BYTES_ONE)));
		assertThat(new FieldElement(BigInteger.TEN).toByteArray(), is(equalTo(BYTES_TEN)));
	}

	/**
	 * Test method for {@link FieldElement#isNonZero()}.
	 */
	@Test
	public void testIsNonZero() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#isNegative()}.
	 */
	@Test
	public void testIsNegative() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#add(FieldElement)}.
	 */
	@Test
	public void testAdd() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#subtract(FieldElement)}.
	 */
	@Test
	public void testSubtract() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#negate()}.
	 */
	@Test
	public void testNegate() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#multiply(FieldElement)}.
	 */
	@Test
	public void testMultiply() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#square()}.
	 */
	@Test
	public void testSquare() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#squareAndDouble()}.
	 */
	@Test
	public void testSquareAndDouble() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#invert()}.
	 */
	@Test
	public void testInvert() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#modPow(java.math.BigInteger, java.math.BigInteger)}.
	 */
	@Test
	public void testModPow() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link FieldElement#equals(java.lang.Object)}.
	 */
	@Test
	public void testEqualsObject() {
		assertThat(new FieldElement(BigInteger.ZERO), is(equalTo(FieldElement.ZERO)));
	}

}
