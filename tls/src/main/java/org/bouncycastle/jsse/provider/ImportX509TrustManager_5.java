package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

class ImportX509TrustManager_5
    extends BCX509ExtendedTrustManager
    implements ImportX509TrustManager
{
    final X509TrustManager x509TrustManager;

    ImportX509TrustManager_5(X509TrustManager x509TrustManager)
    {
        this.x509TrustManager = x509TrustManager;
    }

    public X509TrustManager unwrap()
    {
        return x509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(checkChain(chain), authType);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        ProvX509TrustManager.checkExtendedTrust(chain, authType, socket, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        ProvX509TrustManager.checkExtendedTrust(chain, authType, engine, false);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(checkChain(chain), authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        ProvX509TrustManager.checkExtendedTrust(chain, authType, socket, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        ProvX509TrustManager.checkExtendedTrust(chain, authType, engine, true);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return x509TrustManager.getAcceptedIssuers();
    }

    private static X509Certificate[] checkChain(X509Certificate[] chain)
    {
        if (null == chain || chain.length < 1)
        {
            throw new IllegalArgumentException("'chain' must be a chain of at least one certificate");
        }

        return chain;
    }

    private static X509Certificate[] copyChain(X509Certificate[] chain)
    {
        return checkChain(chain).clone();
    }
}
