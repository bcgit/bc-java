package org.bouncycastle.jsse.provider;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.TlsUtils;

class ProvX509Key
    implements BCX509Key
{
    private static final Logger LOG = Logger.getLogger(ProvX509Key.class.getName());

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

        X509Certificate[] certificateChain = getCertificateChain(x509KeyManager, alias);
        if (null == certificateChain)
        {
            return null;
        }

        PrivateKey privateKey = getPrivateKey(x509KeyManager, alias);
        if (null == privateKey)
        {
            return null;
        }

        return new ProvX509Key(keyType, privateKey, certificateChain);
    }

    static ProvX509Key validate(X509KeyManager x509KeyManager, boolean forServer, String keyType, String alias,
        TransportData transportData)
    {
        if (null == x509KeyManager)
        {
            throw new NullPointerException("'x509KeyManager' cannot be null");
        }
        if (null == keyType || null == alias)
        {
            return null;
        }

        X509Certificate[] certificateChain = getCertificateChain(x509KeyManager, alias);
        if (null == certificateChain)
        {
            return null;
        }

        /*
         * We have several reports of custom key managers that don't properly check the key type, instead just
         * returning a fixed alias. Therefore we perform a sanity check here that should allow such key
         * managers a better chance of working correctly.
         */
        if (!ProvX509KeyManager.isSuitableKeyType(forServer, keyType, certificateChain[0], transportData))
        {
            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer("Rejecting alias '" + alias + "': not suitable for key type '" + keyType + "'");
            }
            return null;
        }

        PrivateKey privateKey = getPrivateKey(x509KeyManager, alias);
        if (null == privateKey)
        {
            return null;
        }

        return new ProvX509Key(keyType, privateKey, certificateChain);
    }

    private static X509Certificate[] getCertificateChain(X509KeyManager x509KeyManager, String alias)
    {
        X509Certificate[] certificateChain = x509KeyManager.getCertificateChain(alias);
        if (TlsUtils.isNullOrEmpty(certificateChain))
        {
            LOG.finer("Rejecting alias '" + alias + "': no certificate chain");
            return null;
        }

        certificateChain = certificateChain.clone();

        if (JsseUtils.containsNull(certificateChain))
        {
            LOG.finer("Rejecting alias '" + alias + "': invalid certificate chain");
            return null;
        }

        return certificateChain;
    }

    private static PrivateKey getPrivateKey(X509KeyManager x509KeyManager, String alias)
    {
        PrivateKey privateKey = x509KeyManager.getPrivateKey(alias);
        if (null == privateKey)
        {
            LOG.finer("Rejecting alias '" + alias + "': no private key");
            return null;
        }
        return privateKey;
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
