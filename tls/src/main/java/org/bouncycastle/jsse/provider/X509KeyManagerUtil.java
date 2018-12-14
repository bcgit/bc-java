package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

abstract class X509KeyManagerUtil
{
    static X509ExtendedKeyManager importX509KeyManager(X509KeyManager x509KeyManager)
    {
        if (x509KeyManager instanceof X509ExtendedKeyManager)
        {
            return (X509ExtendedKeyManager)x509KeyManager;
        }

        return new ImportX509KeyManager_5(x509KeyManager);
    }
}
