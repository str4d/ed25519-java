import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;

/* Written by k3d3
 * Released to the public domain
 */

public class OldTests {
	  
	public static void main(String[] args) {
		byte[] sk = new byte[32];
		Arrays.fill(sk, (byte)0);
		byte[] pk = Ed25519.publickey(sk);
		System.out.println("publickey for 0 is \"" + Utils.getHex(pk) + "\"");
		System.out.println("encodeint 0 = " + Utils.getHex(FieldElement.ZERO.toByteArray()));
		System.out.println("encodeint 1 = " + Utils.getHex(FieldElement.ONE.toByteArray()));
		System.out.println("encodeint 10 = " + Utils.getHex(new FieldElement(BigInteger.TEN).toByteArray()));
		GroupElement zerozero = GroupElement.p2(FieldElement.ZERO, FieldElement.ZERO, FieldElement.ONE);
		GroupElement oneone = GroupElement.p2(FieldElement.ONE, FieldElement.ONE, FieldElement.ONE);
		GroupElement tenzero = GroupElement.p2(new FieldElement(BigInteger.TEN), FieldElement.ZERO, FieldElement.ONE);
		GroupElement oneten = GroupElement.p2(FieldElement.ONE, new FieldElement(BigInteger.TEN), FieldElement.ONE);
		GroupElement pkr = GroupElement.p2(new FieldElement(new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616")), new FieldElement(new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")), FieldElement.ONE);
		System.out.println("encodepoint 0,0 = " + Utils.getHex(zerozero.toByteArray()));
		System.out.println("encodepoint 1,1 = " + Utils.getHex(oneone.toByteArray()));
		System.out.println("encodepoint 10,0 = " + Utils.getHex(tenzero.toByteArray()));
		System.out.println("encodepoint 1,10 = " + Utils.getHex(oneten.toByteArray()));
		System.out.println("encodepoint 9639205628789703341510410801487549615560488670885798085067615194958049462616,18930617471878267742194159801949745215346600387277955685031939302387136031291 = "+Utils.getHex(pkr.toByteArray()));
		byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
		byte[] signature = Ed25519.signature(message, sk, pk);
		System.out.println("signature(\"This is a secret message\") = "+Utils.getHex(signature));
		try {
			System.out.println("check signature result:\n"+Ed25519.checkvalid(signature,message,pk));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
