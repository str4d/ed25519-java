import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.nio.charset.Charset;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * @author str4d
 *
 */
public class Ed25519Test {
	static final byte[] ZERO_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
	static final byte[] ZERO_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
	static final byte[] ZERO_MSG_SIG = Utils.hexToBytes("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");

	@Rule
	public ExpectedException exception = ExpectedException.none();

	/**
	 * Test method for {@link Ed25519#H(byte[])}.
	 */
	@Test
	public void testH() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Ed25519#scalarmult(GroupElement, java.math.BigInteger)}.
	 */
	@Test
	public void testScalarmult() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link Ed25519#publickey(byte[])}.
	 */
	@Test
	public void testPublickey() {
		assertThat(Ed25519.publickey(ZERO_SEED), is(equalTo(ZERO_PK)));
	}

	/**
	 * Test method for {@link Ed25519#signature(byte[], byte[], byte[])}.
	 */
	@Test
	public void testSignature() {
		byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
		assertThat(Ed25519.signature(message, ZERO_SEED, ZERO_PK),
				is(equalTo(ZERO_MSG_SIG)));
	}

	/**
	 * Test method for {@link Ed25519#checkvalid(byte[], byte[], byte[])}.
	 */
	@Test
	public void testCheckvalid() {
		byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
		assertThat(Ed25519.checkvalid(ZERO_MSG_SIG, message, ZERO_PK), is(true));
	}

	/**
	 * Test method for {@link Ed25519#checkvalid(byte[], byte[], byte[])}.
	 * Checks that a wrong-length signature throws an IAE.
	 */
	@Test
	public void testCheckvalidWrongSigLength() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("signature length is wrong");
		Ed25519.checkvalid(new byte[] {0}, new byte[]{0}, ZERO_PK);
	}

	/**
	 * Test method for {@link Ed25519#checkvalid(byte[], byte[], byte[])}.
	 * Checks that a wrong-length public key throws an IAE.
	 */
	@Test
	public void testCheckvalidWrongPKLength() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("public-key length is wrong");
		Ed25519.checkvalid(ZERO_MSG_SIG, new byte[]{0}, new byte[] {0});
	}

}
