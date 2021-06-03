package org.bouncycastle.jsse.provider;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.TlsUtils;

class ProvX509Key
    implements BCX509Key
{
    static ProvX509Key from(X509KeyManager x509KeyManager, String keyType, String alias)
    {
        if (null == x509KeyManager)
        {
            throw new NullPointerException("'x509KeyManager' cannot be null");
        }

        if (null == keyType || null == alias)
        {
            return null;
        }

        // TODO[jsse] Log the probable misconfigured keystore when returning null below

        PrivateKey privateKey = x509KeyManager.getPrivateKey(alias);
        if (null == privateKey)
        {
            return null;
        }

        X509Certificate[] certificateChain = x509KeyManager.getCertificateChain(alias);
        if (TlsUtils.isNullOrEmpty(certificateChain))
        {
            return null;
        }

        certificateChain = certificateChain.clone();

        if (JsseUtils.containsNull(certificateChain))
        {
            return null;
        }

        // TODO[jsse] Consider taking a 'keyAlgorithm' parameter and validating the key algorithms
//        if ((!keyAlgorithm.equals(JsseUtils.getPrivateKeyAlgorithm(privateKey))
//            || !keyAlgorithm.equals(JsseUtils.getPublicKeyAlgorithm(certificateChain[0].getPublicKey())))
//        {
//            return null;
//        }

        return new ProvX509Key(keyType, privateKey, certificateChain);
    }

    private final String keyType;
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;

    ProvX509Key(String keyType, PrivateKey privateKey, X509Certificate[] certificateChain)
    {
        this.keyType = keyType;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
    }

    public X509Certificate[] getCertificateChain()
    {
        return certificateChain.clone();
    }

    public String getKeyType()
    {
        return keyType;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
}
