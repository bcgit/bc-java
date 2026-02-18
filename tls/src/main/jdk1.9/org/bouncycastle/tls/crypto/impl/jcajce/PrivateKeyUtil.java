package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

abstract class PrivateKeyUtil
{
    static void destroy(PrivateKey privateKey)
    {
        if (privateKey != null)
        {
            try
            {
                privateKey.destroy();
            }
            catch (Exception e)
            {
            }
        }
    }
}
