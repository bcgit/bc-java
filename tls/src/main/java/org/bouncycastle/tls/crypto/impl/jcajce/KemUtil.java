package org.bouncycastle.tls.crypto.impl.jcajce;

import javax.crypto.Cipher;

class KemUtil
{
    static Cipher getCipher(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return crypto.getHelper().createCipher(kemName);
        }
        catch (AssertionError e)
        {
            return null;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
    	return kemName != null && getCipher(crypto, kemName) != null;
    }
}
