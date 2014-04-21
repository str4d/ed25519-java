import java.math.BigInteger;

/**
 * The set of pairs (x,y) of FieldElements satisfying
 * -x^2 + y^2 = 1 + d x^2y^2 where d = -121665/121666.
 * @author str4d
 *
 */
public class GroupElement {
	public enum Representation {
		P2,      // Projective: (X:Y:Z) satisfying x=X/Z, y=Y/Z
		P3,      // Extended: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
		P1P1,    // Completed: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
		PRECOMP, // Precomputed (Duif): (y+x,y-x,2dxy)
		CACHED   // Cached: (Y+X,Y-X,Z,2dT)
	}

	public static final GroupElement P2_ZERO = p2(
			FieldElement.ZERO, FieldElement.ONE, FieldElement.ONE);
	public static final GroupElement P3_ZERO = p3(
			FieldElement.ZERO, FieldElement.ONE,
			FieldElement.ONE, FieldElement.ZERO);
	public static final GroupElement PRECOMP_ZERO = p2(
			FieldElement.ONE, FieldElement.ONE, FieldElement.ZERO);

	public static GroupElement p2(FieldElement X, FieldElement Y,
			FieldElement Z) {
		return new GroupElement(Representation.P2, X, Y, Z, null);
	}
	public static GroupElement p2(GroupElement p) {
		return p.toRep(Representation.P2);
	}

	public static GroupElement p3(FieldElement X, FieldElement Y,
			FieldElement Z, FieldElement T) {
		return new GroupElement(Representation.P3, X, Y, Z, T);
	}
	public static GroupElement p3(GroupElement p) {
		return p.toRep(Representation.P3);
	}

	public static GroupElement p1p1(FieldElement X, FieldElement Y,
			FieldElement Z, FieldElement T) {
		return new GroupElement(Representation.P1P1, X, Y, Z, T);
	}
	public static GroupElement p1p1(GroupElement p) {
		return p.toRep(Representation.P1P1);
	}

	public static GroupElement cached(FieldElement YpX, FieldElement YmX,
			FieldElement Z, FieldElement T2d) {
		return new GroupElement(Representation.CACHED, YpX, YmX, Z, T2d);
	}
	public static GroupElement cached(GroupElement p) {
		return p.toRep(Representation.CACHED);
	}

	final Representation repr;
	final FieldElement X;
	final FieldElement Y;
	final FieldElement Z;
	final FieldElement T;

	public GroupElement(Representation repr, FieldElement X, FieldElement Y,
			FieldElement Z, FieldElement T) {
		this.repr = repr;
		this.X = X;
		this.Y = Y;
		this.Z = Z;
		this.T = T;
	}

	public GroupElement(byte[] s) {
		FieldElement x, y, u, v, v3, vxx, check;
		y = new FieldElement(s);
		u = y.square();
		v = u.multiply(Constants.d);
		u = u.subtract(FieldElement.ONE);	// u = y^2-1
		v = v.add(FieldElement.ONE);		// v = dy^2+1

		v3 = v.square().multiply(v);				// v3 = v^3
		x = v3.square().multiply(v).multiply(u);	// x = uv^7

		x = x.modPow(Constants.qp5.divide(BigInteger.valueOf(8)), Constants.q); //  x = (uv^7)^((q-5)/8)
		x = x.multiply(v3).multiply(u);		// x = uv^3(uv^7)^((q-5)/8)

		vxx = x.square().multiply(v);
		check = vxx.subtract(u);			// vx^2-u
		if (check.isNonZero()) {
			check = vxx.add(u);				// vx^2+u
			if (check.isNonZero())
				throw new IllegalArgumentException();
			x = x.multiply(Constants.I);
		}

		if ((x.isNegative() ? 1 : 0) == (s[s.length-1] >> 7))
			x = x.negate();

		repr = Representation.P3;
		X = x;
		Y = y;
		Z = FieldElement.ONE;
		T = X.multiply(Y);
	}

	public byte[] toByteArray() {
		switch (repr) {
		case P2:
		case P3:
			FieldElement recip = Z.invert();
			FieldElement x = X.multiply(recip);
			FieldElement y = Y.multiply(recip);
			byte[] s = y.toByteArray();
			s[s.length-1] |= (x.isNegative() ? 0x80 : 0);
			return s;
		default:
			return toRep(Representation.P2).toByteArray();
		}
	}

	/**
	 * Convert a GroupElement from one Representation to another.
	 * r = p
	 * Supported conversions:
	 * - P3 -> P2
	 * - P1P1 -> P2|P3
	 * @param rep The Representation to convert to.
	 * @return A new GroupElement in the given Representation.
	 */
	private GroupElement toRep(Representation repr) {
		switch (this.repr) {
		case P3:
			switch (repr) {
			case P2:
				return p2(X, Y, Z);
			case CACHED:
				return cached(Y.add(X), Y.subtract(X), Z, T.multiply(Constants.d2));
			default:
				throw new IllegalArgumentException();
			}
		case P1P1:
			switch (repr) {
			case P2:
				return p2(X.multiply(T), Y.multiply(Z), Z.multiply(T));
			case P3:
				return p3(X.multiply(T), Y.multiply(Z), Z.multiply(T), X.multiply(Y));
			default:
				throw new IllegalArgumentException();
			}
		default:
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * r = 2 * p
	 * @return The P1P1 representation
	 */
	public GroupElement dbl() {
		switch (repr) {
		case P2:
			FieldElement XX, YY, B, A, AA, Yn, Zn;
			XX = X.square();
			YY = Y.square();
			B = Z.squareAndDouble();
			A = X.add(Y);
			AA = A.square();
			Yn = YY.add(XX);
			Zn = YY.subtract(XX);
			return p1p1(AA.subtract(Yn), Yn, Zn, B.subtract(Zn));
		case P3:
			return toRep(Representation.P2).dbl();
		default:
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * r = p + q
	 * @param q
	 * @return
	 */
	public GroupElement madd(GroupElement q) {
		if (this.repr != Representation.P3)
			throw new UnsupportedOperationException();
		if (q.repr != Representation.PRECOMP)
			throw new IllegalArgumentException();

		FieldElement YpX, YmX, A, B, C, D;
		YpX = Y.add(X);
		YmX = Y.subtract(X);
		A = YpX.multiply(q.X); // q->y+x
		B = YmX.multiply(q.Y); // q->y-x
		C = q.Z.multiply(T); // q->2dxy
		D = Z.add(Z);
		return p1p1(A.subtract(B), A.add(B), D.add(C), D.subtract(C));
	}

	/**
	 * r = p - q
	 * @param q
	 * @return
	 */
	public GroupElement msub(GroupElement q) {
		if (this.repr != Representation.P3)
			throw new UnsupportedOperationException();
		if (q.repr != Representation.PRECOMP)
			throw new IllegalArgumentException();

		FieldElement YpX, YmX, A, B, C, D;
		YpX = Y.add(X);
		YmX = Y.subtract(X);
		A = YpX.multiply(q.Y); // q->y-x
		B = YmX.multiply(q.X); // q->y+x
		C = q.Z.multiply(T); // q->2dxy
		D = Z.add(Z);
		return p1p1(A.subtract(B), A.add(B), D.subtract(C), D.add(C));
	}

	/**
	 * r = p + q
	 * @param q
	 * @return
	 */
	public GroupElement add(GroupElement q) {
		if (this.repr != Representation.P3)
			throw new UnsupportedOperationException();
		if (q.repr != Representation.CACHED)
			throw new IllegalArgumentException();

		FieldElement YpX, YmX, A, B, C, ZZ, D;
		YpX = Y.add(X);
		YmX = Y.subtract(X);
		A = YpX.multiply(q.X); // q->Y+X
		B = YmX.multiply(q.Y); // q->Y-X
		C = q.T.multiply(T); // q->2dT
		ZZ = Z.multiply(q.Z);
		D = ZZ.add(ZZ);
		return p1p1(A.subtract(B), A.add(B), D.add(C), D.subtract(C));
	}

	/**
	 * r = p - q
	 * @param q
	 * @return
	 */
	public GroupElement sub(GroupElement q) {
		if (this.repr != Representation.P3)
			throw new UnsupportedOperationException();
		if (q.repr != Representation.CACHED)
			throw new IllegalArgumentException();

		FieldElement YpX, YmX, A, B, C, ZZ, D;
		YpX = Y.add(X);
		YmX = Y.subtract(X);
		A = YpX.multiply(q.Y); // q->Y-X
		B = YmX.multiply(q.X); // q->Y+X
		C = q.T.multiply(T); // q->2dT
		ZZ = Z.multiply(q.Z);
		D = ZZ.add(ZZ);
		return p1p1(A.subtract(B), A.add(B), D.subtract(C), D.add(C));
	}

	/**
	 * h = a * B
	 * where a = a[0]+256*a[1]+...+256^31 a[31]
	 * B is the Ed25519 base point (x,4/5) with x positive.
	 *
	 * Preconditions: TODO: Check this applies here
	 *   a[31] <= 127
	 * @param a
	 * @return
	 */
	public static GroupElement scalarMultiplyBase(BigInteger a) {
		return null;
	}
}
