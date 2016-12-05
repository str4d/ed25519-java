/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.security.spec.PKCS8EncodedKeySpec;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class EdDSAPrivateKeyTest {
    /**
     * The example private key MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
     * from https://tools.ietf.org/html/draft-ietf-curdle-pkix-04#section-10.3
     */
    static final byte[] TEST_PRIVKEY = Utils.hexToBytes("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");

    static final byte[] TEST_PRIVKEY_NULL_PARAMS = Utils.hexToBytes("3030020100300706032b6570050004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
    static final byte[] TEST_PRIVKEY_OLD = Utils.hexToBytes("302f020100300806032b65640a01010420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");

    @Test
    public void testDecodeAndEncode() throws Exception {
        // Decode
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(TEST_PRIVKEY);
        EdDSAPrivateKey keyIn = new EdDSAPrivateKey(encoded);

        // Encode
        EdDSAPrivateKeySpec decoded = new EdDSAPrivateKeySpec(
                keyIn.getSeed(),
                keyIn.getH(),
                keyIn.geta(),
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPrivateKey keyOut = new EdDSAPrivateKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PRIVKEY)));
    }

    @Test
    public void testDecodeWithNullAndEncode() throws Exception {
        // Decode
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(TEST_PRIVKEY_NULL_PARAMS);
        EdDSAPrivateKey keyIn = new EdDSAPrivateKey(encoded);

        // Encode
        EdDSAPrivateKeySpec decoded = new EdDSAPrivateKeySpec(
                keyIn.getSeed(),
                keyIn.getH(),
                keyIn.geta(),
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPrivateKey keyOut = new EdDSAPrivateKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PRIVKEY)));
    }

    @Test
    public void testReEncodeOldEncoding() throws Exception {
        // Decode
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(TEST_PRIVKEY_OLD);
        EdDSAPrivateKey keyIn = new EdDSAPrivateKey(encoded);

        // Encode
        EdDSAPrivateKeySpec decoded = new EdDSAPrivateKeySpec(
                keyIn.getSeed(),
                keyIn.getH(),
                keyIn.geta(),
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPrivateKey keyOut = new EdDSAPrivateKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PRIVKEY)));
    }
}
