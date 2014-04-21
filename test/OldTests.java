import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;

/* Written by k3d3
 * Released to the public domain
 */

public class OldTests {

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
		byte[] pk = Ed25519.publickey(sk);
		System.out.println("publickey for 0 is \"" + getHex(pk) + "\"");
		System.out.println("encodeint 0 = " + getHex(FieldElement.ZERO.toByteArray()));
		System.out.println("encodeint 1 = " + getHex(FieldElement.ONE.toByteArray()));
		System.out.println("encodeint 10 = " + getHex(new FieldElement(BigInteger.TEN).toByteArray()));
		GroupElement zerozero = GroupElement.p2(FieldElement.ZERO, FieldElement.ZERO, FieldElement.ONE);
		GroupElement oneone = GroupElement.p2(FieldElement.ONE, FieldElement.ONE, FieldElement.ONE);
		GroupElement tenzero = GroupElement.p2(new FieldElement(BigInteger.TEN), FieldElement.ZERO, FieldElement.ONE);
		GroupElement oneten = GroupElement.p2(FieldElement.ONE, new FieldElement(BigInteger.TEN), FieldElement.ONE);
		GroupElement pkr = GroupElement.p2(new FieldElement(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")), new FieldElement(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")), FieldElement.ONE);
		System.out.println("encodepoint 0,0 = " + getHex(zerozero.toByteArray()));
		System.out.println("encodepoint 1,1 = " + getHex(oneone.toByteArray()));
		System.out.println("encodepoint 10,0 = " + getHex(tenzero.toByteArray()));
		System.out.println("encodepoint 1,10 = " + getHex(oneten.toByteArray()));
		System.out.println("encodepoint 9639205628789703341510410801487549615560488670885798085067615194958049462616,18930617471878267742194159801949745215346600387277955685031939302387136031291 = "+getHex(pkr.toByteArray()));
		byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
		byte[] signature = Ed25519.signature(message, sk, pk);
		System.out.println("signature(\"This is a secret message\") = "+getHex(signature));
		try {
			System.out.println("check signature result:\n"+Ed25519.checkvalid(signature,message,pk));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
