package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;

class JsseUtils
{
    protected static X509Certificate[] EMPTY_CHAIN = new X509Certificate[0];

    public static String getAuthType(int keyExchangeAlgorithm) throws IOException
    {
        // TODO[jsse] Support for full range of key exchange algorithms
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_RSA:
            return "DH_RSA";
        case KeyExchangeAlgorithm.DHE_RSA:
            return "DHE_RSA";
        case KeyExchangeAlgorithm.ECDH_ECDSA:
            return "ECDH_ECDSA";
        case KeyExchangeAlgorithm.ECDH_RSA:
            return "ECDH_RSA";
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return "ECDHE_ECDSA";
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return "ECDHE_RSA";
        case KeyExchangeAlgorithm.RSA:
            return "RSA";
        case KeyExchangeAlgorithm.RSA_PSK:
            return "RSA_PSK";
        case KeyExchangeAlgorithm.SRP_RSA:
            return "SRP_RSA";
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public static Certificate getCertificateMessage(TlsCrypto crypto, X509Certificate[] chain) throws IOException
    {
        if (chain == null || chain.length < 1)
        {
            return Certificate.EMPTY_CHAIN;
        }

        TlsCertificate[] certificateList = new TlsCertificate[chain.length];
        try
        {
            for (int i = 0; i < chain.length; ++i)
            {
                // TODO[jsse] Prefer an option that will not re-encode for typical use-cases
                certificateList[i] = crypto.createCertificate(chain[i].getEncoded());
            }
        }
        catch (CertificateEncodingException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        return new Certificate(certificateList);
    }

    public static X509Certificate[] getX509CertificateChain(Certificate certificateMessage) throws IOException
    {
        if (certificateMessage == null || certificateMessage.isEmpty())
        {
            return EMPTY_CHAIN;
        }

        // TODO[jsse] Consider provider-related issues
        JcaJceHelper helper = new DefaultJcaJceHelper();

        X509Certificate[] chain = new X509Certificate[certificateMessage.getLength()];
        for (int i = 0; i < chain.length; ++i)
        {
            chain[i] = JcaTlsCertificate.convert(certificateMessage.getCertificateAt(i), helper).getX509Certificate();
        }
        return chain;
    }
}
