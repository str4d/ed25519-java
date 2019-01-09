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

import java.security.spec.X509EncodedKeySpec;

import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.InvalidKeySpecException;

/**
 * @author str4d
 *
 */
public class EdDSAPublicKeyTest {
    /**
     * The example public key MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
     * from https://tools.ietf.org/html/draft-ietf-curdle-pkix-04#section-10.1
     */
    static final byte[] TEST_PUBKEY = Utils.hexToBytes("302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");

    static final byte[] TEST_PUBKEY_NULL_PARAMS = Utils.hexToBytes("302c300706032b6570050003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
    static final byte[] TEST_PUBKEY_OLD = Utils.hexToBytes("302d300806032b65640a010103210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");

    @Test
    public void testDecodeAndEncode() throws Exception {
        // Decode
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(TEST_PUBKEY);
        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);

        // Encode
        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PUBKEY)));
    }

    @Test
    public void testDecodeWithNullAndEncode() throws Exception {
        // Decode
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(TEST_PUBKEY_NULL_PARAMS);
        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);

        // Encode
        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PUBKEY)));
    }

    @Test
    public void testReEncodeOldEncoding() throws Exception {
        // Decode
        X509EncodedKeySpec encoded = new X509EncodedKeySpec(TEST_PUBKEY_OLD);
        EdDSAPublicKey keyIn = new EdDSAPublicKey(encoded);

        // Encode
        EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
                keyIn.getA(),
                keyIn.getParams());
        EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);

        // Check
        assertThat(keyOut.getEncoded(), is(equalTo(TEST_PUBKEY)));
    }

    @Test
    public void testJavaSerialization() throws InvalidKeySpecException {
        final X509EncodedKeySpec encoded = new X509EncodedKeySpec(TEST_PUBKEY_OLD);
        final EdDSAPublicKey keyOut = new EdDSAPublicKey(encoded);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
        try {
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(keyOut);
            oos.flush();
            oos.close();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to serialize object of type: " + keyOut.getClass(), ex);
        }

        try {
            final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
            final EdDSAPublicKey keyIn = (EdDSAPublicKey) ois.readObject();
            assertThat(keyIn, is(keyOut));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to deserialize object", ex);
        }
    }
}
