import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/* Written by k3d3
 * Released to the public domain
 */

public class ed25519 {
	static final int b = 256;
	static final BigInteger q = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
	static final BigInteger qm2 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819947");
	static final BigInteger qp3 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819952");
	static final BigInteger l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
	static final BigInteger d = new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
	static final BigInteger I = new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752");
	static final BigInteger By = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
	static final BigInteger Bx = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
	static final BigInteger[] B = {Bx.mod(q),By.mod(q)};
	static final BigInteger un = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967");
	
	static byte[] H(byte[] m) {
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
	
	static BigInteger expmod(BigInteger b, BigInteger e, BigInteger m) {
		//System.out.println("expmod open with b=" + b + " e=" + e + " m=" + m);
		if (e.equals(BigInteger.ZERO)) {
			//System.out.println("expmod close with 1z");
			return BigInteger.ONE;
		}
		BigInteger t = expmod(b, e.divide(BigInteger.valueOf(2)), m).pow(2).mod(m);
		//System.out.println("expmod 1/2 t="+t+" e="+e+" testbit="+(e.testBit(0)?1:0));
		if (e.testBit(0)) {
			t = t.multiply(b).mod(m);
		}
		//System.out.println("expmod close with " + t);
		return t;
	}
	
	static BigInteger inv(BigInteger x) {
		//System.out.println("inv open with " + x);
		//System.out.println("inv close with " + expmod(x, qm2, q));
		return expmod(x, qm2, q);
	}
	
	static BigInteger xrecover(BigInteger y) {
		BigInteger y2 = y.multiply(y);
		BigInteger xx = (y2.subtract(BigInteger.ONE)).multiply(inv(d.multiply(y2).add(BigInteger.ONE)));
		BigInteger x = expmod(xx, qp3.divide(BigInteger.valueOf(8)), q);
		if (!x.multiply(x).subtract(xx).mod(q).equals(BigInteger.ZERO)) x = (x.multiply(I).mod(q));
		if (!x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) x = q.subtract(x);
		return x;
	}
	
	static BigInteger[] edwards(BigInteger[] P, BigInteger[] Q) {
		BigInteger x1 = P[0];
		BigInteger y1 = P[1];
		BigInteger x2 = Q[0];
		BigInteger y2 = Q[1];
		BigInteger dtemp = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
		//System.out.println("edwards open with "+x1+","+x2+" "+y1+","+y2+" d="+d+" dtemp="+dtemp);
		BigInteger x3 = ((x1.multiply(y2)).add((x2.multiply(y1)))).multiply(inv(BigInteger.ONE.add(dtemp)));
		//System.out.println("edwards 1/2 with "+x1+","+x2+" "+y1+","+y2+" d="+d+" dtemp="+dtemp);
		BigInteger y3 = ((y1.multiply(y2)).add((x1.multiply(x2)))).multiply(inv(BigInteger.ONE.subtract(dtemp)));
		//System.out.println("edwards 2/2 with "+x1+","+x2+" "+y1+","+y2+" d="+d+" dtemp="+dtemp);
		//System.out.println("edwards close with "+x3.mod(q)+","+y3.mod(q));
		return new BigInteger[]{x3.mod(q), y3.mod(q)};
	}
	
	static BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
		//System.out.println("scalarmult open with e = " + e);
		if (e.equals(BigInteger.ZERO)) {
			//System.out.println("scalarmult close with Q = 0,1");
			return new BigInteger[]{BigInteger.ZERO, BigInteger.ONE};
		}
		BigInteger[] Q = scalarmult(P, e.divide(BigInteger.valueOf(2)));
		//System.out.println("scalarmult asQ = " + Q[0] + "," + Q[1]);
		Q = edwards(Q, Q);
		//System.out.println("scalarmult aeQ = " + Q[0] + "," + Q[1] + " e="+e+" testbit="+(e.testBit(0)?1:0));
		if (e.testBit(0)) Q = edwards(Q, P);
		//System.out.println("scalarmult close with Q = " + Q[0] + "," + Q[1]);
		return Q;
	}
	
	static byte[] encodeint(BigInteger y) {
		byte[] in = y.toByteArray();
		byte[] out = new byte[in.length];
		for (int i=0;i<in.length;i++) {
			out[i] = in[in.length-1-i];
		}
		return out;
	}
	
	static byte[] encodepoint(BigInteger[] P) {
		BigInteger x = P[0];
		BigInteger y = P[1];
		byte[] out = encodeint(y);
		//System.out.println("encodepoint x="+x+" testbit="+(x.testBit(0) ? 1 : 0));
		out[out.length-1] |= (x.testBit(0) ? 0x80 : 0);
		return out;
	}
	
	static int bit(byte[] h, int i) {
		//System.out.println("bit open with i="+i);
		//System.out.println("bit close with "+(h[i/8] >> (i%8) & 1));
		return h[i/8] >> (i%8) & 1;
	}
	
	static byte[] publickey(byte[] sk) {
		byte[] h = H(sk);
		//System.out.println("publickey open with h=" + test.getHex(h));
		BigInteger a = BigInteger.valueOf(2).pow(b-2);
		for (int i=3;i<(b-2);i++) {
			BigInteger apart = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i)));
			//System.out.println("publickey apart="+apart);
			a = a.add(apart);
		}
		BigInteger[] A = scalarmult(B,a);
		//System.out.println("publickey close with A="+A[0]+","+A[1]+" out="+test.getHex(encodepoint(A)));
		return encodepoint(A);
	}
	
	static BigInteger Hint(byte[] m) {
		byte[] h = H(m);
		BigInteger hsum = BigInteger.ZERO;
		for (int i=0;i<2*b;i++) {
			hsum = hsum.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
		}
		return hsum;
	}
	
	static byte[] signature(byte[] m, byte[] sk, byte[] pk) {
		byte[] h = H(sk);
		//System.out.println("signature open with m="+test.getHex(m)+" h="+test.getHex(h)+" pk="+test.getHex(pk));
		BigInteger a = BigInteger.valueOf(2).pow(b-2);
		for (int i=3;i<(b-2);i++) {
			a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h,i))));
		}
		//System.out.println("signature a="+a);
		ByteBuffer rsub = ByteBuffer.allocate((b/8)+m.length);
		rsub.put(h, b/8, b/4-b/8).put(m);
		//System.out.println("signature rsub="+test.getHex(rsub.array()));
		BigInteger r = Hint(rsub.array());
		//System.out.println("signature r="+r);
		BigInteger[] R = scalarmult(B,r);
		ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
		Stemp.put(encodepoint(R)).put(pk).put(m);
		BigInteger S = r.add(Hint(Stemp.array()).multiply(a)).mod(l);
		ByteBuffer out = ByteBuffer.allocate(64);
		out.put(encodepoint(R)).put(encodeint(S));
		return out.array();
	}
	
	static boolean isoncurve(BigInteger[] P) {
		BigInteger x = P[0];
		BigInteger y = P[1];
		//System.out.println("isoncurve open with P="+x+","+y);
		BigInteger xx = x.multiply(x);
		BigInteger yy = y.multiply(y);
		BigInteger dxxyy = d.multiply(yy).multiply(xx);
		//System.out.println("isoncurve close with "+xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(q));
		return xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(q).equals(BigInteger.ZERO);
	}
	
	static BigInteger decodeint(byte[] s) {
		byte[] out = new byte[s.length];
		for (int i=0;i<s.length;i++) {
			out[i] = s[s.length-1-i];
		}
		return new BigInteger(out).and(un);
	}
	
	static BigInteger[] decodepoint(byte[] s) throws Exception {
		byte[] ybyte = new byte[s.length];
		for (int i=0;i<s.length;i++) {
			ybyte[i] = s[s.length-1-i];
		}
		//System.out.println("decodepoint open with s="+test.getHex(s)+" ybyte="+test.getHex(ybyte));
		BigInteger y = new BigInteger(ybyte).and(un);
		//System.out.println("decodepoint y="+y);
		BigInteger x = xrecover(y);
		//System.out.println("decodepoint x="+x+" testbit="+(x.testBit(0)?1:0)+" bit="+bit(s, b-1));
		if ((x.testBit(0)?1:0) != bit(s, b-1)) {
			x = q.subtract(x);
		}
		BigInteger[] P = {x,y};
		if (!isoncurve(P)) throw new Exception("decoding point that is not on curve");
		return P;
	}
	
	static boolean checkvalid(byte[] s, byte[] m, byte[] pk) throws Exception {
		if (s.length != b/4) throw new Exception("signature length is wrong");
		if (pk.length != b/8) throw new Exception("public-key length is wrong");
		//System.out.println("checkvalid open with s="+test.getHex(s)+" m="+test.getHex(m)+" pk="+test.getHex(pk));
		byte[] Rbyte = Arrays.copyOfRange(s, 0, b/8);
		//System.out.println("checkvalid Rbyte="+test.getHex(Rbyte));
		BigInteger[] R = decodepoint(Rbyte);
		BigInteger[] A = decodepoint(pk);
		//System.out.println("checkvalid R="+R[0]+","+R[1]+" A="+A[0]+","+A[1]);
		byte[] Sbyte = Arrays.copyOfRange(s, b/8, b/4);
		//System.out.println("checkvalid Sbyte="+test.getHex(Sbyte));
		BigInteger S = decodeint(Sbyte);
		//System.out.println("checkvalid S="+S);
		ByteBuffer Stemp = ByteBuffer.allocate(32+pk.length+m.length);
		Stemp.put(encodepoint(R)).put(pk).put(m);
		BigInteger h = Hint(Stemp.array());
		BigInteger[] ra = scalarmult(B,S);
		BigInteger[] rb = edwards(R,scalarmult(A,h));
		//System.out.println("checkvalid ra="+ra[0]+","+ra[1]+" rb="+rb[0]+","+rb[1]);
		if (!ra[0].equals(rb[0]) || !ra[1].equals(rb[1])) // Constant time comparison
			return false;
		return true;
	}
}
