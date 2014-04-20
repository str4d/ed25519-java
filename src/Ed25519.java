import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/* Written by k3d3
 * Released to the public domain
 */

public class Ed25519 {
	/**
	 * Calculate the hash of a message.
	 */
	private static byte[] H(byte[] m) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-512");
			md.reset();
			return md.digest(m);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return null;
	}

	private static BigInteger Hint(byte[] m) {
		byte[] h = H(m);
		BigInteger hsum = BigInteger.ZERO;
		for (int i=0;i<2*Constants.b;i++) {
			hsum = hsum.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
		}
		return hsum;
	}

	private static BigInteger expmod(BigInteger b, BigInteger e, BigInteger m) {
		return b.modPow(e, m);
	}

	private static BigInteger inv(BigInteger x) {
		return expmod(x, Constants.qm2, Constants.q);
	}

	/**
	 * Recover x from element (x,y) given y. The caller must correct the
	 * sign of x based on the stored sign.
	 */
	private static BigInteger xrecover(BigInteger y) {
		BigInteger y2 = y.multiply(y);
		BigInteger xx = (y2.subtract(BigInteger.ONE)).multiply(inv(Constants.d.multiply(y2).add(BigInteger.ONE)));
		BigInteger x = expmod(xx, Constants.qp3.divide(BigInteger.valueOf(8)), Constants.q);
		if (!x.multiply(x).subtract(xx).mod(Constants.q).equals(BigInteger.ZERO)) x = (x.multiply(Constants.I).mod(Constants.q));
		if (!x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) x = Constants.q.subtract(x);
		return x;
	}

	/**
	 * The twisted Edwards addition law.
	 */
	private static BigInteger[] edwards(BigInteger[] P, BigInteger[] Q) {
		BigInteger x1 = P[0];
		BigInteger y1 = P[1];
		BigInteger x2 = Q[0];
		BigInteger y2 = Q[1];
		BigInteger dtemp = Constants.d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
		BigInteger x3 = ((x1.multiply(y2)).add((x2.multiply(y1)))).multiply(inv(BigInteger.ONE.add(dtemp)));
		BigInteger y3 = ((y1.multiply(y2)).add((x1.multiply(x2)))).multiply(inv(BigInteger.ONE.subtract(dtemp)));
		return new BigInteger[]{x3.mod(Constants.q), y3.mod(Constants.q)};
	}

	private static BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
		BigInteger[] t = new BigInteger[9999];
		BigInteger[] Q;		
		t[0] = e;
		int i=1;

		while(true) {			
			t[i] = t[i-1].divide(BigInteger.valueOf(2));;			
			if (t[i].equals(BigInteger.ZERO)) {				
				break;			
			}			
			i++;
		}

		Q = new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};		
		for (int j = i; j >= 0; j--) {
			Q = edwards(Q, Q);
			if (t[j].testBit(0)) Q = edwards(Q, P);		
		}		
		return Q;
	}

	/**
	 * Verify that a point is on the curve.
	 * @param P The point to check.
	 * @return true if the point lies on the curve.
	 */
	private static boolean isoncurve(BigInteger[] P) {
		BigInteger x = P[0];
		BigInteger y = P[1];

		BigInteger xx = x.multiply(x);
		BigInteger yy = y.multiply(y);
		BigInteger dxxyy = Constants.d.multiply(yy).multiply(xx);

		return xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(Constants.q).equals(BigInteger.ZERO);
	}

	private static BigInteger decodeint(byte[] s) {
		byte[] out = new byte[s.length];
		for (int i=0;i<s.length;i++) {
			out[i] = s[s.length-1-i];
		}
		return new BigInteger(out).and(Constants.un);
	}

	private static BigInteger[] decodepoint(byte[] s) throws Exception {
		byte[] ybyte = new byte[s.length];
		for (int i=0;i<s.length;i++) {
			ybyte[i] = s[s.length-1-i];
		}
		BigInteger y = new BigInteger(ybyte).and(Constants.un);
		BigInteger x = xrecover(y);
		if ((x.testBit(0)?1:0) != bit(s, Constants.b-1)) {
			x = Constants.q.subtract(x);
		}
		BigInteger[] P = {x,y};
		if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
		return P;
	}

	public static byte[] encodeint(BigInteger y) {
		byte[] in = y.toByteArray();
		byte[] out = new byte[in.length];
		for (int i=0;i<in.length;i++) {
			out[i] = in[in.length-1-i];
		}
		return out;
	}

	public static byte[] encodepoint(BigInteger[] P) {
		BigInteger x = P[0];
		BigInteger y = P[1];
		byte[] out = encodeint(y);
		out[out.length-1] |= (x.testBit(0) ? 0x80 : 0);
		return out;
	}

	private static int bit(byte[] h, int i) {
		return h[i/8] >> (i%8) & 1;
	}

	/**
	 * Calculate the public key from the given seed.
	 * @param sk The private seed.
	 * @return The 32-byte public key.
	 */
	public static byte[] publickey(byte[] sk) {
		byte[] h = H(sk);

		BigInteger a = BigInteger.valueOf(2).pow(Constants.b-2);
		for (int i=3;i<(Constants.b-2);i++) {
			BigInteger apart = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i)));
			a = a.add(apart);
		}
		BigInteger[] A = scalarmult(Constants.B,a);

		return encodepoint(A);
	}

	/**
	 * Sign a message.
	 * @param m The message to be signed.
	 * @param sk The private seed.
	 * @param pk The public key.
	 * @return The 64-byte signature (R+S).
	 */
	public static byte[] signature(byte[] m, byte[] sk, byte[] pk) {
		// H(k)
		byte[] h = H(sk);

		// a
		BigInteger a = BigInteger.valueOf(2).pow(Constants.b-2);
		for (int i=3;i<(Constants.b-2);i++) {
			a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
		}

		// h_b,...,h_2b-1,M
		ByteBuffer rsub = ByteBuffer.allocate((Constants.b/8)+m.length);
		rsub.put(h, Constants.b/8, Constants.b/4-Constants.b/8).put(m);
		// r = H(h_b,...,h_2b-1,M)
		BigInteger r = Hint(rsub.array());

		// R = rB
		BigInteger[] R = scalarmult(Constants.B,r);

		// Rbar,Abar,M 
		ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
		Stemp.put(encodepoint(R)).put(pk).put(m);
		// S = (r + H(Rbar,Abar,M)*a) mod l
		BigInteger S = r.add(Hint(Stemp.array()).multiply(a)).mod(Constants.l);

		// R+S
		ByteBuffer out = ByteBuffer.allocate(64);
		out.put(encodepoint(R)).put(encodeint(S));
		return out.array();
	}

	/**
	 * Check the validity of a signature.
	 * @param s The signature to validate.
	 * @param m The message.
	 * @param pk The 32-byte public key.
	 * @return true if the signature is valid.
	 */
	public static boolean checkvalid(byte[] s, byte[] m, byte[] pk) throws Exception {
		if (s.length != Constants.b/4) throw new Exception("signature length is wrong");
		if (pk.length != Constants.b/8) throw new Exception("public-key length is wrong");

		byte[] Rbyte = Arrays.copyOfRange(s, 0, Constants.b/8);
		BigInteger[] R = decodepoint(Rbyte);

		BigInteger[] A = decodepoint(pk);

		byte[] Sbyte = Arrays.copyOfRange(s, Constants.b/8, Constants.b/4);
		BigInteger S = decodeint(Sbyte);

		// Rbar,Abar,M
		ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
		Stemp.put(encodepoint(R)).put(pk).put(m);
		// h = H(Rbar,Abar,M)
		BigInteger h = Hint(Stemp.array());
		// SB
		BigInteger[] ra = scalarmult(Constants.B,S);
		// R + H(Rbar,Abar,M)A
		BigInteger[] rb = edwards(R,scalarmult(A,h));

		// SB = R + H(Rbar,Abar,M)A
		if (!ra[0].equals(rb[0]) || !ra[1].equals(rb[1])) // Constant time comparison
			return false;
		return true;
	}
}
