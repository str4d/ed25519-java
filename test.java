import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;

/* Written by k3d3
 * Released to the public domain
 */

public class test {

	static final String HEXES = "0123456789abcdef";
	
	public static String getHex( byte [] raw ) {
		if ( raw == null ) {
			return null;
		}
		final StringBuilder hex = new StringBuilder( 2 * raw.length );
		for ( final byte b : raw ) {
	    	hex.append(HEXES.charAt((b & 0xF0) >> 4))
	    	.append(HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}
	  
	public static void main(String[] args) {
		byte[] sk = new byte[32];
		Arrays.fill(sk, (byte)0);
		byte[] pk = ed25519.publickey(sk);
		System.out.println("publickey for 0 is \"" + getHex(pk) + "\"");
		System.out.println("encodeint 0 = " + getHex(ed25519.encodeint(BigInteger.ZERO)));
		System.out.println("encodeint 1 = " + getHex(ed25519.encodeint(BigInteger.ONE)));
		System.out.println("encodeint 10 = " + getHex(ed25519.encodeint(BigInteger.TEN)));
		BigInteger[] zerozero = new BigInteger[]{BigInteger.ZERO,BigInteger.ZERO};
		BigInteger[] oneone = new BigInteger[]{BigInteger.ONE,BigInteger.ONE};
		BigInteger[] tenzero = new BigInteger[]{BigInteger.TEN,BigInteger.ZERO};
		BigInteger[] oneten = new BigInteger[]{BigInteger.ONE,BigInteger.TEN};
		BigInteger[] pkr = new BigInteger[]{new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616"), new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")};
		System.out.println("encodepoint 0,0 = " + getHex(ed25519.encodepoint(zerozero)));
		System.out.println("encodepoint 1,1 = " + getHex(ed25519.encodepoint(oneone)));
		System.out.println("encodepoint 10,0 = " + getHex(ed25519.encodepoint(tenzero)));
		System.out.println("encodepoint 1,10 = " + getHex(ed25519.encodepoint(oneten)));
		System.out.println("encodepoint 9639205628789703341510410801487549615560488670885798085067615194958049462616,18930617471878267742194159801949745215346600387277955685031939302387136031291 = "+getHex(ed25519.encodepoint(pkr)));
		byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
		byte[] signature = ed25519.signature(message, sk, pk);
		System.out.println("signature(\"This is a secret message\") = "+getHex(signature));
		try {
			System.out.println("check signature result:\n"+ed25519.checkvalid(signature,message,pk));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
