package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

abstract class X509TrustManagerUtil
{
    static X509TrustManager exportX509TrustManager(BCX509ExtendedTrustManager x509TrustManager)
    {
        if (x509TrustManager instanceof ImportX509TrustManager)
        {
            return ((ImportX509TrustManager)x509TrustManager).unwrap();
        }

        return new ExportX509TrustManager_7(x509TrustManager);
    }

    static BCX509ExtendedTrustManager importX509TrustManager(boolean isInFipsMode, JcaJceHelper helper, X509TrustManager x509TrustManager)
    {
        if (x509TrustManager instanceof BCX509ExtendedTrustManager)
        {
            return (BCX509ExtendedTrustManager)x509TrustManager;
        }

        if (x509TrustManager instanceof ExportX509TrustManager)
        {
            return ((ExportX509TrustManager)x509TrustManager).unwrap();
        }

        if (x509TrustManager instanceof X509ExtendedTrustManager)
        {
            return new ImportX509TrustManager_7((X509ExtendedTrustManager)x509TrustManager);
        }

        return new ImportX509TrustManager_5(isInFipsMode, helper, x509TrustManager);
    }
}
