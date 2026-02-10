package org.bouncycastle.tls.crypto.impl.jcajce;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

abstract class SecretKeyUtil
{
    static void destroy(SecretKey secretKey)
    {
        if (secretKey != null)
        {
            try
            {
                ((Destroyable)secretKey).destroy();
            }
            catch (Exception e)
            {
            }
        }
    }
}
