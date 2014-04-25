package net.i2p.crypto.eddsa.math;

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

    /*
    public static final GroupElement P2_ZERO = p2(
            FieldElement.ZERO, FieldElement.ONE, FieldElement.ONE);
    public static final GroupElement P3_ZERO = p3(
            FieldElement.ZERO, FieldElement.ONE,
            FieldElement.ONE, FieldElement.ZERO);
    public static final GroupElement PRECOMP_ZERO = p2(
            FieldElement.ONE, FieldElement.ONE, FieldElement.ZERO);
    */

    public static GroupElement p2(Curve curve, FieldElement X,
            FieldElement Y, FieldElement Z) {
        return new GroupElement(curve, Representation.P2, X, Y, Z, null);
    }

    public static GroupElement p3(Curve curve, FieldElement X,
            FieldElement Y, FieldElement Z, FieldElement T) {
        return new GroupElement(curve, Representation.P3, X, Y, Z, T);
    }

    public static GroupElement p1p1(Curve curve, FieldElement X,
            FieldElement Y, FieldElement Z, FieldElement T) {
        return new GroupElement(curve, Representation.P1P1, X, Y, Z, T);
    }

    public static GroupElement cached(Curve curve, FieldElement YpX,
            FieldElement YmX, FieldElement Z, FieldElement T2d) {
        return new GroupElement(curve, Representation.CACHED, YpX, YmX, Z, T2d);
    }

    final Curve curve;
    final Representation repr;
    final FieldElement X;
    final FieldElement Y;
    final FieldElement Z;
    final FieldElement T;

    public GroupElement(Curve curve, Representation repr, FieldElement X, FieldElement Y,
            FieldElement Z, FieldElement T) {
        this.curve = curve;
        this.repr = repr;
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
    }

    public GroupElement(Curve curve, byte[] s) {
        FieldElement x, y, u, v, v3, vxx, check, xx, yy;
        y = curve.fromByteArray(s);
        /*
        u = y.square();
        v = u.multiply(Constants.d);
        u = u.subtract(FieldElement.ONE);	// u = y^2-1
        v = v.add(FieldElement.ONE);		// v = dy^2+1

        v3 = v.square().multiply(v);				// v3 = v^3
        x = v3.square().multiply(v).multiply(u);	// x = uv^7

        x = x.modPow(Constants.qp5.divide(BigInteger.valueOf(8)), Constants.q); //  x = (uv^7)^((q-5)/8)
        x = x.multiply(v3).multiply(u);		// x = uv^3(uv^7)^((q-5)/8)
        */

        // From xrecover
        yy = y.square();
        xx = (yy.subtractOne()).multiply(curve.getD().multiply(yy).addOne().invert());
        x = xx.modPow(curve.getQp3().divide(BigInteger.valueOf(8)), curve.getQ());

        //vxx = x.square().multiply(v);
        //check = vxx.subtract(u);			// vx^2-u
        check = x.square().subtract(xx);
        if (check.isNonZero()) {
            //check = vxx.add(u);				// vx^2+u
            check = x.square().add(xx);
            if (check.isNonZero())
                throw new IllegalArgumentException("not a valid GroupElement");
            x = x.multiply(Constants.I);
        }

        if ((x.isNegative() ? 1 : 0) == (s[s.length-1] >> 7))
            x = x.negate();

        this.curve = curve;
        repr = Representation.P3;
        X = x;
        Y = y;
        Z = curve.fromBigInteger(Constants.ONE);
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
            return toP2().toByteArray();
        }
    }

    public GroupElement toP2() {
        return toRep(Representation.P2);
    }
    public GroupElement toP3() {
        return toRep(Representation.P3);
    }
    public GroupElement toP1P1() {
        return toRep(Representation.P1P1);
    }
    public GroupElement toCached() {
        return toRep(Representation.CACHED);
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
                return p2(curve, X, Y, Z);
            case CACHED:
                return cached(curve, Y.add(X), Y.subtract(X), Z, T.multiply(curve.get2D()));
            default:
                throw new IllegalArgumentException();
            }
        case P1P1:
            switch (repr) {
            case P2:
                return p2(curve, X.multiply(T), Y.multiply(Z), Z.multiply(T));
            case P3:
                return p3(curve, X.multiply(T), Y.multiply(Z), Z.multiply(T), X.multiply(Y));
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
            return p1p1(curve, AA.subtract(Yn), Yn, Zn, B.subtract(Zn));
        case P3:
            return toP2().dbl();
        default:
            throw new UnsupportedOperationException();
        }
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * r = p + q
     * @param q the PRECOMP representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
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
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * r = p - q
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
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
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * r = p + q
     * @param q the CACHED representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
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
        return p1p1(curve, A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * r = p - q
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
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
        return p1p1(curve, A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof GroupElement))
            return false;
        GroupElement ge = (GroupElement) obj;
        if (!this.repr.equals(ge.repr)) {
            try {
                ge = ge.toRep(this.repr);
            } catch (Exception e) {
                return false;
            }
        }
        FieldElement recip1 = Z.invert();
        FieldElement x1 = X.multiply(recip1);
        FieldElement y1 = Y.multiply(recip1);
        FieldElement recip2 = ge.Z.invert();
        FieldElement x2 = ge.X.multiply(recip2);
        FieldElement y2 = ge.Y.multiply(recip2);
        return x1.equals(x2) && y1.equals(y2);
    }

    /**
     * Verify that a point is on the curve.
     * @param P The point to check.
     * @return true if the point lies on the curve.
     */
    public static boolean isOnCurve(GroupElement P) {
        switch (P.repr) {
        case P2:
        case P3:
            FieldElement recip = P.Z.invert();
            FieldElement x = P.X.multiply(recip);
            FieldElement y = P.Y.multiply(recip);
            FieldElement xx = x.square();
            FieldElement yy = y.square();
            FieldElement dxxyy = Constants.d.multiply(xx).multiply(yy);
            return FieldElement.ONE.add(dxxyy).add(xx).subtract(yy).equals(FieldElement.ZERO);

        default:
            return isOnCurve(P.toP2());
        }
    }

    public static GroupElement scalarmult(GroupElement P, BigInteger e) {
        BigInteger[] t = new BigInteger[9999];
        GroupElement Q;     
        t[0] = e;
        int i=1;

        while(true) {           
            t[i] = t[i-1].divide(BigInteger.valueOf(2));;           
            if (t[i].equals(BigInteger.ZERO)) {             
                break;          
            }           
            i++;
        }

        GroupElement Pcached = P.toCached();
        Q = GroupElement.P3_ZERO;
        for (int j = i; j >= 0; j--) {
            Q = Q.add(Q.toCached()).toP3();
            if (t[j].testBit(0)) Q = Q.add(Pcached).toP3();
        }       
        return Q;
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
     *//*
	public static GroupElement scalarMultiplyBase(BigInteger a) {
		GroupElement t;
		int i;

		for (i = 0; i < 63; i++) {
		}

		GroupElement h = P3_ZERO;
		for (i = 1; i < 64; i += 2) {
			t = select(i/2, e[i]);
			h = h.madd(t).toP3();
		}

		h = h.dbl().toP2().dbl().toP2().dbl().toP2().dbl().toP3();

		for (i = 0; i < 64; i += 2) {
			t = select(i/2, e[i]);
			h = h.madd(t).toP3();
		}

		return h;
	}*/
}
