package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

abstract class PrivateKeyUtil
{
    void destroy(PrivateKey privateKey)
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
