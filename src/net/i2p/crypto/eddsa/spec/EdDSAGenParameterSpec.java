package net.i2p.crypto.eddsa.spec;

import java.security.spec.AlgorithmParameterSpec;

public class EdDSAGenParameterSpec implements AlgorithmParameterSpec {
    private String name;

    public EdDSAGenParameterSpec(String stdName) {
        name = stdName;
    }

    public String getName() {
        return name;
    }
}
