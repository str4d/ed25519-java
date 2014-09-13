package net.i2p.crypto.eddsa.math.ed25519;

import org.hamcrest.core.IsEqual;
import org.junit.*;

public class Ed25519LittleEndianEncodingTest {

	@Test
	public void decodeReturnsCorrectResult() {
		// Arange:
		final Ed25519LittleEndianEncoding encoding = new Ed25519LittleEndianEncoding();
		final byte[] byteRep = new byte[32];
		byteRep[31] = (byte)(1 << 6);

		// Act:
		final Ed25519FieldElement element = (Ed25519FieldElement)encoding.decode(byteRep);

		// Assert:
		Assert.assertThat(element.t[9], IsEqual.equalTo(1 << 24));
	}
}
