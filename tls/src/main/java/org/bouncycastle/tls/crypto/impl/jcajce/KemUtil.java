package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.AlgorithmParameters;

import javax.crypto.Cipher;

import org.bouncycastle.util.Exceptions;

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
            throw Exceptions.illegalStateException("KEM cipher failed: " + kemName, e);
        }

        return null;
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        // TODO[tls-kem] When implemented via provider, need to check for support dynamically
        return kemName != null && getCipher(crypto, kemName) != null;
    }

    // TODO: not used?
    static int getEncapsulationLength(String kemName)
    {
        if ("ML-KEM-512".equals(kemName))
        {
            return 768;
        }
        else if ("ML-KEM-768".equals(kemName))
        {
            return 1088;
        }
        else if ("ML-KEM-1024".equals(kemName))
        {
            return 1568;
        }
        else
        {
            throw new IllegalArgumentException("unknown kem name " + kemName);
        }
    }
}
