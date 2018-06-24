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
package jp.co.soramitsu.crypto.ed25519;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * @author str4d
 *
 */
public class EdDSAEngineTest {
    static final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] TEST_PK = Utils.hexToBytes("43eeb17f0bab10dd51ab70983c25200a1742d31b3b7b54c38c34d7b827b26eed");
    static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_MSG_SIG = Utils.hexToBytes("fb95fd5387920d177e9281821ceacca377b9e897aa6ddad6a9224b10827fde9105873e89e5cf067a3f42cfe7b8fb3f9b1fe3d8c185cfbdc850f45e823e038300");

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testSign() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));

        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
            EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(testCase.seed, spec);
            PrivateKey sKey = new EdDSAPrivateKey(privKey);
            sgr.initSign(sKey);

            sgr.update(testCase.message);

            assertThat("Test case " + testCase.caseNum + " failed",
                    sgr.sign(), is(equalTo(testCase.sig)));
        }
    }

    @Test
    public void testVerify() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
            EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(testCase.pk, spec);
            PublicKey vKey = new EdDSAPublicKey(pubKey);
            sgr.initVerify(vKey);

            sgr.update(testCase.message);

            assertThat("Test case " + testCase.caseNum + " failed",
                    sgr.verify(testCase.sig), is(true));
        }
    }

    /**
     * Checks that a wrong-length signature throws an IAE.
     */
    @Test
    public void testVerifyWrongSigLength() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        sgr.update(TEST_MSG);

        exception.expect(SignatureException.class);
        exception.expectMessage("signature length is wrong");
        sgr.verify(new byte[] {0});
    }

    @Test
    public void testSignResetsForReuse() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);

        // First usage
        sgr.update(new byte[] {0});
        sgr.sign();

        // Second usage
        sgr.update(TEST_MSG);
        assertThat("Second sign failed", sgr.sign(), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyResetsForReuse() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        // First usage
        sgr.update(new byte[] {0});
        sgr.verify(TEST_MSG_SIG);

        // Second usage
        sgr.update(TEST_MSG);
        assertThat("Second verify failed", sgr.verify(TEST_MSG_SIG), is(true));
    }

    @Test
    public void testSignOneShotMode() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        assertThat("One-shot mode sign failed", sgr.sign(), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyOneShotMode() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        assertThat("One-shot mode verify failed", sgr.verify(TEST_MSG_SIG), is(true));
    }

    @Test
    public void testSignOneShotModeMultipleUpdates() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        exception.expect(SignatureException.class);
        exception.expectMessage("update() already called");
        sgr.update(TEST_MSG);
    }

    @Test
    public void testVerifyOneShotModeMultipleUpdates() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        exception.expect(SignatureException.class);
        exception.expectMessage("update() already called");
        sgr.update(TEST_MSG);
    }

    @Test
    public void testSignOneShot() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);

        assertThat("signOneShot() failed", sgr.signOneShot(TEST_MSG), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyOneShot() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        assertThat("verifyOneShot() failed", sgr.verifyOneShot(TEST_MSG, TEST_MSG_SIG), is(true));
    }
}
