package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;

abstract class X509KeyManagerUtil
{
    static BCX509ExtendedKeyManager importX509KeyManager(JcaJceHelper helper, X509KeyManager x509KeyManager)
    {
        if (x509KeyManager instanceof BCX509ExtendedKeyManager)
        {
            return (BCX509ExtendedKeyManager)x509KeyManager;
        }

        return new ImportX509KeyManager_5(helper, x509KeyManager);
    }
}
