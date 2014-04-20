import java.math.BigInteger;


public class FieldElement {
	public static final FieldElement ZERO = new FieldElement(
			BigInteger.ZERO, BigInteger.ZERO);
	public static final FieldElement ONE = new FieldElement(
			BigInteger.ONE, BigInteger.ZERO);

	final BigInteger x;
	final BigInteger y;

	public FieldElement(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	} 

	public boolean isNonZero() {
		return true;
	}

	public boolean isNegative() {
		return false;
	}

	public FieldElement add(FieldElement val) {
		return new FieldElement(x.add(val.x), y.add(val.y));
	}

	public FieldElement subtract(FieldElement val) {
		return new FieldElement(x.subtract(val.x), y.subtract(val.y));
	}

	public FieldElement negate() {
		return new FieldElement(x.negate(), y.negate());
	}

	public FieldElement multiply(FieldElement val) {
		return val;
	}

	public FieldElement square() {
		return this;
	}

	public FieldElement squareAndDouble() {
		return this;
	}

	public FieldElement invert() {
		return this;
	}
}
