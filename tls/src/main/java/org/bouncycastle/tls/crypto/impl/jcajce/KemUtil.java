package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

class KemUtil
{
    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return null;
//            AlgorithmParameters algParams = AlgorithmParameters.getInstance(kemName, "BC");
//            MLKEMParameterSpec mlkemSpec = MLKEMParameterSpec.fromName(kemName);
//            algParams.init(mlkemSpec);
//            return algParams;
        }
        catch (AssertionError e)
        {
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static Cipher getCipher(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return crypto.getHelper().createCipher(kemName);
        }
        catch (AssertionError e)
        {
        }
        catch (Exception e)
        {
            throw new IllegalStateException("KEM cipher failed: " + kemName, e);
        }

        return null;
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        // TODO[tls-kem] When implemented via provider, need to check for support dynamically
        return kemName != null && getCipher(crypto, kemName) != null;
    }

    static int getEncapsulationLength(String kemName)
    {
        switch (kemName)
        {
        case "ML-KEM-512":
            return 768;
        case "ML-KEM-768":
            return 1088;
        case "ML-KEM-1024":
            return 1568;
        default:
            throw new IllegalArgumentException("unknown kem name " + kemName);
        }
    }
}
