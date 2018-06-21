package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class AlgorithmParameters extends AlgorithmParametersSpi{

    private EdDSANamedCurveSpec edDSANamedCurveSpec = null;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {

           if(paramSpec instanceof EdDSAGenParameterSpec){
               edDSANamedCurveSpec = EdDSANamedCurveTable.getByName(((EdDSAGenParameterSpec) paramSpec).getName());
           }
           else if(paramSpec instanceof EdDSANamedCurveSpec){
               this.edDSANamedCurveSpec= (EdDSANamedCurveSpec) paramSpec;
           }
           else throw new InvalidParameterSpecException("Invalid or not yet implemented "+ paramSpec.toString());
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented yet...");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented yet...");
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
       if(EdDSAParameterSpec.class.isAssignableFrom(paramSpec)){
           return (T) this.edDSANamedCurveSpec;
       }
       else if(EdDSAGenParameterSpec.class.isAssignableFrom(paramSpec)){
           return (T) new EdDSAGenParameterSpec(edDSANamedCurveSpec.getName());
       }
       else throw new InvalidParameterSpecException("Invalid or not yet implemented "+ paramSpec.toString());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Not implemented yet...");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Not implemented yet...");
    }

    @Override
    protected String engineToString() {
        return this.getClass().getCanonicalName();
    }
}
