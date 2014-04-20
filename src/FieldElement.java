import java.math.BigInteger;


public class FieldElement {
	public static final FieldElement ZERO = new FieldElement(BigInteger.ZERO);
	public static final FieldElement ONE = new FieldElement(BigInteger.ONE);
	public static final FieldElement TWO = new FieldElement(BigInteger.valueOf(2));

	final BigInteger x;

	public FieldElement(BigInteger x) {
		this.x = x;
	}

	/**
	 * Translates a byte array containing the two's-complement binary
	 * representation of a FieldElement into a FieldElement. The input array is
	 * assumed to be in little-endian byte-order: the least significant byte is
	 * in the zeroth element.
	 * @param val
	 */
	public FieldElement(byte[] val) {
		byte[] out = new byte[val.length];
		for (int i = 0; i < val.length; i++) {
			out[i] = val[val.length-1-i];
		}
		this.x = new BigInteger(out).and(Constants.un);
	}

	public byte[] toByteArray() {
		byte[] in = x.toByteArray();
		byte[] out = new byte[in.length];
		for (int i = 0; i < in.length; i++) {
			out[i] = in[in.length-1-i];
		}
		return out;
	}

	public boolean isNonZero() {
		return !x.equals(BigInteger.ZERO);
	}

	public boolean isNegative() {
		return x.testBit(0);
	}

	public FieldElement add(FieldElement val) {
		return new FieldElement(x.add(val.x));
	}

	public FieldElement subtract(FieldElement val) {
		return new FieldElement(x.subtract(val.x));
	}

	public FieldElement negate() {
		return new FieldElement(Constants.q.subtract(x));
	}

	public FieldElement multiply(FieldElement val) {
		return new FieldElement(x.multiply(val.x).mod(Constants.q));
	}

	public FieldElement square() {
		return new FieldElement(x.modPow(BigInteger.valueOf(2), Constants.q));
	}

	public FieldElement squareAndDouble() {
		return square().multiply(TWO);
	}

	public FieldElement invert() {
		return modPow(Constants.qm2, Constants.q);
	}

	public FieldElement modPow(BigInteger e, BigInteger m) {
		return new FieldElement(x.modPow(e, m));
	}
}
