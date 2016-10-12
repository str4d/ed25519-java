package net.i2p.crypto.eddsa;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

/**
 * A security {@link Provider} that can be registered via {@link Security#addProvider(Provider)}
 *
 * @author str4d
 */
public class EdDSASecurityProvider extends Provider {
    private static final long serialVersionUID = 1210027906682292307L;
    public static final String PROVIDER_NAME = "EdDSA";

    public EdDSASecurityProvider() {
        super(PROVIDER_NAME, 0.1 /* should match POM major.minor version */, "str4d " + PROVIDER_NAME + " security provider wrapper");

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                setup();
                return null;
            }
        });
    }

    protected void setup() {
        // see https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html
        put("KeyPairGenerator." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyPairGenerator");
        put("KeyFactory." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyFactory");
        put("Signature." + EdDSANamedCurveTable.CURVE_ED25519_SHA512, "net.i2p.crypto.eddsa.EdDSAEngine");
    }
}
