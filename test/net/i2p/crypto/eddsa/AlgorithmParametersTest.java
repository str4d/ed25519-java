package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.Assert.assertTrue;

public class AlgorithmParametersTest {

    @Test
    public void testInitEngineWithEdGen() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
    }

    @Test
    public void testInitEngineEdNameCurve() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519));
    }

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testInitEngineWithNotImplementedParamSpec() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        EdDSANamedCurveSpec nameSpec = EdDSANamedCurveTable.ED_25519_CURVE_SPEC;
        EdDSAParameterSpec paramSpec = new EdDSAParameterSpec(nameSpec.getCurve(),nameSpec.getHashAlgorithm(),nameSpec.getScalarOps(),nameSpec.getB());
        exception.expect(InvalidParameterSpecException.class);
        algorithmParameters.engineInit(paramSpec);
    }

    @Test
    public void testengineGetParameterSpec_A() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519));
        EdDSAGenParameterSpec edDSAGenParameterSpec = algorithmParameters.engineGetParameterSpec(EdDSAGenParameterSpec.class);
        assertTrue(edDSAGenParameterSpec != null);
    }

    @Test
    public void testengineGetParameterSpec_B() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
        EdDSANamedCurveSpec edDSANamedCurveSpec = algorithmParameters.engineGetParameterSpec(EdDSANamedCurveSpec.class);
        assertTrue(edDSANamedCurveSpec != null);
    }

    @Test
    public void testengineGetParameterSpec_C() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
        EdDSAParameterSpec edDSAParameterSpec = algorithmParameters.engineGetParameterSpec(EdDSAParameterSpec.class);
        assertTrue(edDSAParameterSpec != null);
    }

    @Test
    public void testengineGetParameterSpec_Exception() throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters = new AlgorithmParameters();
        algorithmParameters.engineInit(new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
        exception.expect(InvalidParameterSpecException.class);
        ECGenParameterSpec edDSAParameterSpec = algorithmParameters.engineGetParameterSpec(ECGenParameterSpec.class);
    }
}
