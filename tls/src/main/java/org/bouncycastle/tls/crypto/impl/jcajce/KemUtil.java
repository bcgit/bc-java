package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.AlgorithmParameters;

import javax.crypto.Cipher;

class KemUtil
{
    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            // TODO[tls-kem] Return AlgorithmParameters to check against disabled algorithms?
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
        }

        return null;
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        // TODO[tls-kem] When implemented via provider, need to check for support dynamically
//        return kemName != null && getCipher(crypto, kemName) != null;
        return true;
    }
}
