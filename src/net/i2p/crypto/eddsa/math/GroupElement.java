package net.i2p.crypto.eddsa.math;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.Utils;

/**
 * A point (x,y) on an EdDSA curve.
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

    public static GroupElement precomp(Curve curve, FieldElement ypx,
            FieldElement ymx, FieldElement xy2d) {
        return new GroupElement(curve, Representation.PRECOMP, ypx, ymx, xy2d, null);
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

    // Precomputed table for scalarMultiply, filled if necessary
    GroupElement[][] precmp;
    // Precomputed table for doubleScalarMultiplyVariableTime
    GroupElement[] dblPrecmp;

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
        FieldElement x, y, yy, u, v, v3, vxx, check;
        y = curve.fromByteArray(s);
        yy = y.square();

        // u = y^2-1	
        u = yy.subtractOne();

        // v = dy^2+1
        v = yy.multiply(curve.getD()).addOne();

        // v3 = v^3
        v3 = v.square().multiply(v);

        // x = (v3^2)vu, aka x = uv^7
        x = v3.square().multiply(v).multiply(u);	

        //  x = (uv^7)^((q-5)/8)
        x = x.pow(curve.getField().getQm5().divide(BigInteger.valueOf(8))); 

        // x = uv^3(uv^7)^((q-5)/8)
        x = v3.multiply(u).multiply(x);

        vxx = x.square().multiply(v);
        check = vxx.subtract(u);			// vx^2-u
        if (check.isNonZero()) {
            check = vxx.add(u);				// vx^2+u

            if (check.isNonZero())
                throw new IllegalArgumentException("not a valid GroupElement");
            x = x.multiply(curve.getI());
        }

        if ((x.isNegative() ? 1 : 0) != Utils.bit(s, curve.getField().getb()-1)) {
            x = x.negate();
        }

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
            s[s.length-1] |= (x.isNegative() ? (byte) 0x80 : 0);
            return s;
        default:
            return toP2().toByteArray();
        }
    }

    public GroupElement clone() {
        return new GroupElement(curve, repr, X, Y, Z, T);
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
     * Precompute the tables for {@link GroupElement#scalarMultiply(byte[])}
     * and {@link GroupElement#doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])}.
     */
    public void precompute() {
        precmp = new GroupElement[32][8];
        dblPrecmp = new GroupElement[8];

        GroupElement Bi = clone();
        for (int i = 0; i < 32; i++) {
            GroupElement Bij = Bi.clone();
            for (int j = 0; j < 8; j++) {
                FieldElement recip = Bij.Z.invert();
                FieldElement x = Bij.X.multiply(recip);
                FieldElement y = Bij.Y.multiply(recip);
                precmp[i][j] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.get2D()));
                Bij = Bij.add(Bi.toCached()).toP3();
            }
            for (int k = 0; k < 8; k++) {
                Bi = Bi.add(Bi.toCached()).toP3();
            }
        }

        Bi = clone();
        for (int i = 0; i < 8; i++) {
            FieldElement recip = Bi.Z.invert();
            FieldElement x = Bi.X.multiply(recip);
            FieldElement y = Bi.Y.multiply(recip);
            dblPrecmp[i] = precomp(curve, y.add(x), y.subtract(x), x.multiply(y).multiply(curve.get2D()));
            // Bi = edwards(B,edwards(B,Bi))
            Bi = add(add(Bi.toCached()).toP3().toCached()).toP3();
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

    public GroupElement scalarmult(FieldElement e) {
        return scalarmult(e.bi);
    }

    /**
     * Old, slow scalar multiplication.
     * @param e
     * @return
     */
    public GroupElement scalarmult(BigInteger e) {
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

        GroupElement Pcached = toCached();
        Q = curve.getZero(Representation.P3);
        for (int j = i; j >= 0; j--) {
            Q = Q.add(Q.toCached()).toP3();
            if (t[j].testBit(0)) Q = Q.add(Pcached).toP3();
        }       
        return Q;
    }

    /**
     * Replace this with u if b == 1.
     * Replace this with this if b == 0.
     * @param u
     * @param b in {0, 1}
     * @return
     */
    public GroupElement cmov(GroupElement u, int b) {
        return precomp(curve, X.cmov(u.X, b), Y.cmov(u.Y, b), Z.cmov(u.Z, b));
    }

    /**
     * Look up 16^i r_i B in the precomputed table.
     * No secret array indices, no secret branching.
     * @param pos = i/2 for i in {0, 2, 4,..., 62}
     * @param b = r_i
     * @return
     */
    private GroupElement select(int pos, int b) {
        // Is r_i negative?
        int bnegative = Utils.negative(b);
        // |r_i|
        int babs = b - (((-bnegative) & b) << 1);

        // 16^i |r_i| B
        GroupElement t = curve.getZero(Representation.PRECOMP)
                .cmov(precmp[pos][0], Utils.equal(babs, 1))
                .cmov(precmp[pos][1], Utils.equal(babs, 2))
                .cmov(precmp[pos][2], Utils.equal(babs, 3))
                .cmov(precmp[pos][3], Utils.equal(babs, 4))
                .cmov(precmp[pos][4], Utils.equal(babs, 5))
                .cmov(precmp[pos][5], Utils.equal(babs, 6))
                .cmov(precmp[pos][6], Utils.equal(babs, 7))
                .cmov(precmp[pos][7], Utils.equal(babs, 8));
        // -16^i |r_i| B
        GroupElement tminus = precomp(curve, t.Y, t.X, t.Z.negate());
        // 16^i r_i B
        return t.cmov(tminus, bnegative);
    }

    /**
     * h = a * Bb where a = a[0]+256*a[1]+...+256^31 a[31] and
     * B is this point. If its lookup table has not been precomputed, it
     * will be at the start of the method (and cached for later calls). 
     *
     * Preconditions: TODO: Check this applies here
     *   a[31] <= 127
     * @param a = a[0]+256*a[1]+...+256^31 a[31]
     * @return
     */
    public GroupElement scalarMultiply(byte[] a) {
        byte[] e = new byte[64];
        GroupElement t;
        int i;

        // Radix 16 notation
        for (i = 0; i < 32; i++) {
            e[2*i+0] = (byte) ((a[i] >> 0) & 15);
            e[2*i+1] = (byte) ((a[i] >> 4) & 15);
        }
        /* each e[i] is between 0 and 15 */
        /* e[63] is between 0 and 7 */
        int carry = 0;
        for (i = 0; i < 63; i++) {
            e[i] += carry;
            carry = e[i] + 8;
            carry >>= 4;
        e[i] -= carry << 4;
        }
        e[63] += carry;
        /* each e[i] is between -8 and 8 */

        GroupElement h = curve.getZero(Representation.P3);
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
    }

    /**
     * r = a * A + b * B where a = a[0]+256*a[1]+...+256^31 a[31],
     * b = b[0]+256*b[1]+...+256^31 b[31] and B is this point.
     * @param A in P3 representation.
     * @param a = a[0]+256*a[1]+...+256^31 a[31]
     * @param b = b[0]+256*b[1]+...+256^31 b[31]
     * @return
     */
    public GroupElement doubleScalarMultiplyVariableTime(GroupElement A, byte[] a, byte[] b) {
        GroupElement[] Ai = new GroupElement[8]; // A,3A,5A,7A,9A,11A,13A,15A

        byte[] aslide = Utils.slide(a);
        byte[] bslide = Utils.slide(b);

        Ai[0] = A.toCached();
        GroupElement A2 = A.dbl().toP3();
        Ai[1] = A2.add(Ai[0]).toP3().toCached();
        Ai[2] = A2.add(Ai[1]).toP3().toCached();
        Ai[3] = A2.add(Ai[2]).toP3().toCached();
        Ai[4] = A2.add(Ai[3]).toP3().toCached();
        Ai[5] = A2.add(Ai[4]).toP3().toCached();
        Ai[6] = A2.add(Ai[5]).toP3().toCached();
        Ai[7] = A2.add(Ai[6]).toP3().toCached();

        GroupElement r = curve.getZero(Representation.P2);

        int i;
        for (i = 255; i >= 0; --i) {
            if (aslide[i] != 0 || bslide[i] != 0) break;
        }

        for (; i >= 0; --i) {
            GroupElement t = r.dbl();

            if (aslide[i] > 0) {
                t = t.toP3().add(Ai[aslide[i]/2]);
            } else if(aslide[i] < 0) {
                t = t.toP3().sub(Ai[(-aslide[i])/2]);
            }

            if (bslide[i] > 0) {
                t = t.toP3().madd(dblPrecmp[bslide[i]/2]);
            } else if(bslide[i] < 0) {
                t = t.toP3().msub(dblPrecmp[(-bslide[i])/2]);
            }

            r = t.toP2();
        }

        return r;
    }

    @Override
    public String toString() {
        return "[GroupElement\nX="+X+"\nY="+Y+"\nZ="+Z+"\nT="+T+"\n]";
    }
}
