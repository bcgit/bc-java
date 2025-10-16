package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

import javax.security.auth.Destroyable;

abstract class PrivateKeyUtil
{
    static void destroy(PrivateKey privateKey)
    {
        if (privateKey instanceof Destroyable)
        {
            try
            {
                ((Destroyable)privateKey).destroy();
            }
            catch (Exception e)
            {
            }
        }
    }
}
