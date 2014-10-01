package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.ed25519.*;

import java.math.BigInteger;
import java.security.SecureRandom;
/**
 * Utility class to help with calculation.
 */
public class MathUtils {
	private static final int[] exponents = {0, 26, 26 + 25, 2*26 + 25, 2*26 + 2*25, 3*26 + 2*25, 3*26 + 3*25, 4*26 + 3*25, 4*26 + 4*25, 5*26 + 4*25};
	private static final SecureRandom random = new SecureRandom();

	/**
	 * Gets q = 2^255 - 19 as BigInteger.
	 */
	public static BigInteger getQ() {
		return new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
	}

	/**
	 * Gets the underlying finite field with q=2^255 - 19 elements.
	 *
	 * @return The finite field.
	 */
	public static Field getField() {
		return new Field(
				256, // b
				Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
				new Ed25519LittleEndianEncoding());
	}

	/**
	 * Converts a 2^25.5 bit representation to a BigInteger.
	 * Value: 2^exponents[0] * t[0] + 2^exponents[1] * t[1] + ... + 2^exponents[9] * t[9]
	 *
	 * @param t The 2^25.5 bit representation.
	 * @return The BigInteger.
	 */
	public static BigInteger toBigInteger(final int[] t) {
		BigInteger b = BigInteger.ZERO;
		for (int i=0; i<10; i++) {
			b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(t[i])).shiftLeft(exponents[i]));
		}

		return b;
	}

	/**
	 * Converts a 32 byte representation to a BigInteger.
	 * Value: bytes[0] + 2^8 * bytes[1] + ... + 2^248 * bytes[31]
	 *
	 * @param bytes The 32 byte representation.
	 * @return The BigInteger.
	 */
	public static BigInteger toBigInteger(final byte[] bytes) {
		BigInteger b = BigInteger.ZERO;
		for (int i=0; i<32; i++) {
			b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(bytes[i] & 0xff)).shiftLeft(i * 8));
		}

		return b;
	}

	/**
	 * Converts a field element to a BigInteger.
	 *
	 * @param f The field element.
	 * @return The BigInteger.
	 */
	public static BigInteger toBigInteger(final FieldElement f) {
		return toBigInteger(f.toByteArray());
	}

	/**
	 * Converts a BigInteger to a little endian 32 byte representation.
	 *
	 * @param b The BigInteger.
	 * @return The 32 byte representation.
	 */
	public static byte[] toByteArray(final BigInteger b) {
		if (b.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0) {
			throw new RuntimeException("only numbers < 2^256 are allowed");
		}
		final byte[] bytes = new byte[32];
		final byte[] original = b.toByteArray();

		// Although b < 2^256, toByteArray can have length > 32 with some bytes set to 0.
		final int offset = original.length > 32? original.length - 32 : 0;
		for (int i=0; i<original.length - offset; i++) {
			bytes[original.length - i - offset - 1] = original[i + offset];
		}

		return bytes;
	}

	public static FieldElement getRandomFieldElement() {
		final int[] t = new int[10];
		for (int j=0; j<10; j++) {
			t[j] = random.nextInt(1 << 25) - (1 << 24);
		}
		return new Ed25519FieldElement(MathUtils.getField(), t);
	}
}
