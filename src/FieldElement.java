import java.math.BigInteger;


public class FieldElement {
	public static final FieldElement ZERO = new FieldElement(BigInteger.ZERO);
	public static final FieldElement ONE = new FieldElement(BigInteger.ONE);

	final BigInteger x;

	public FieldElement(BigInteger x) {
		this.x = x;
	} 

	public boolean isNonZero() {
		return !x.equals(BigInteger.ZERO);
	}

	public boolean isNegative() {
		return !x.equals(x.abs());
	}

	public FieldElement add(FieldElement val) {
		return new FieldElement(x.add(val.x));
	}

	public FieldElement subtract(FieldElement val) {
		return new FieldElement(x.subtract(val.x));
	}

	public FieldElement negate() {
		return new FieldElement(x.negate());
	}

	public FieldElement multiply(FieldElement val) {
		return new FieldElement(x.multiply(val.x));
	}

	public FieldElement square() {
		return new FieldElement(x.pow(2));
	}

	public FieldElement squareAndDouble() {
		return new FieldElement(x.pow(2).multiply(BigInteger.valueOf(2)));
	}

	public FieldElement invert() {
		return this;
	}
}
