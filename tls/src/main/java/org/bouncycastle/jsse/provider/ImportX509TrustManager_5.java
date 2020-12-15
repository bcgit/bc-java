package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

class ImportX509TrustManager_5
    extends BCX509ExtendedTrustManager
    implements ImportX509TrustManager
{
    final boolean isInFipsMode;
    final JcaJceHelper helper;
    final X509TrustManager x509TrustManager;

    ImportX509TrustManager_5(boolean isInFipsMode, JcaJceHelper helper, X509TrustManager x509TrustManager)
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.x509TrustManager = x509TrustManager;
    }

    public X509TrustManager unwrap()
    {
        return x509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, null, false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(socket), false);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(engine), false);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, null, true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(socket), true);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(copyChain(chain), authType);
        checkAdditionalTrust(chain, authType, TransportData.from(engine), true);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return x509TrustManager.getAcceptedIssuers();
    }

    private void checkAdditionalTrust(X509Certificate[] chain, String authType, TransportData transportData,
        boolean checkServerTrusted) throws CertificateException
    {
        checkAlgorithmConstraints(chain, authType, transportData, checkServerTrusted);

        ProvX509TrustManager.checkExtendedTrust(chain, authType, transportData, checkServerTrusted);
    }

    private void checkAlgorithmConstraints(X509Certificate[] chain, String authType, TransportData transportData,
        boolean checkServerTrusted) throws CertificateException
    {
        BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, false);
        Set<X509Certificate> trustedCerts = getTrustedCerts();

        KeyPurposeId ekuOID = ProvX509TrustManager.getRequiredExtendedKeyUsage(checkServerTrusted);
        int kuBit = ProvX509TrustManager.getRequiredKeyUsage(checkServerTrusted, authType); 

        try
        {
            ProvAlgorithmChecker.checkChain(isInFipsMode, helper, algorithmConstraints, trustedCerts, chain, ekuOID, kuBit);
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("Certificates do not conform to algorithm constraints", e);
        }
    }

    private Set<X509Certificate> getTrustedCerts()
    {
        X509Certificate[] issuers = getAcceptedIssuers();
        if (null == issuers || issuers.length < 1)
        {
            return Collections.emptySet();
        }

        Set<X509Certificate> trustedCerts = new HashSet<X509Certificate>();
        for (int i = 0; i < issuers.length; ++i)
        {
            X509Certificate issuer = issuers[i];
            if (null != issuer)
            {
                trustedCerts.add(issuer);
            }
        }
        return Collections.unmodifiableSet(trustedCerts);
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
