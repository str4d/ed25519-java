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
package net.i2p.crypto.eddsa.spec;

import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519;
import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519_CURVE_SPEC;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author str4d
 *
 */
public class EdDSANamedCurveTableTest {
    /**
     * Ensure curve names are case-inspecific
     */
    @Test
    public void curveNamesAreCaseInspecific() {
        EdDSANamedCurveSpec mixed = EdDSANamedCurveTable.getByName("Ed25519");
        EdDSANamedCurveSpec lower = EdDSANamedCurveTable.getByName("ed25519");
        EdDSANamedCurveSpec upper = EdDSANamedCurveTable.getByName("ED25519");

        assertThat(lower, is(equalTo(mixed)));
        assertThat(upper, is(equalTo(mixed)));
    }

    @Test
    public void testConstants() {
        EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(ED_25519);
        assertThat("Named curve and constant should match", spec, is(equalTo(ED_25519_CURVE_SPEC)));
    }
}
