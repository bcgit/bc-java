package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvX509KeyManagerSimple
    extends X509ExtendedKeyManager
{
    @SuppressWarnings("unused")
    private final JcaJceHelper helper;
    private final Map<String, Credential> credentials = new HashMap<String, Credential>();

    ProvX509KeyManagerSimple(JcaJceHelper helper, KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        this.helper = helper;

        if (null == ks)
        {
            return;
        }

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if (ks.entryInstanceOf(alias, PrivateKeyEntry.class))
            {
                PrivateKey privateKey = (PrivateKey)ks.getKey(alias, password);
                X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(ks.getCertificateChain(alias));
                if (certificateChain != null && certificateChain.length > 0)
                {
                    credentials.put(alias, new Credential(privateKey, certificateChain));
                }
            }
        }
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseAlias(keyTypes, issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(keyTypes, issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(new String[]{ keyType }, issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseAlias(new String[]{ keyType }, issuers, TransportData.from(socket), true);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        Credential credential = getCredential(alias);
        return credential == null ? null : credential.getCertificateChain().clone();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return getAliases(false, keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        Credential credential = getCredential(alias);
        return credential == null ? null : credential.getPrivateKey();
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return getAliases(true, keyType, issuers);
    }

    // TODO[jsse] TransportData argument currently unused
    private String chooseAlias(String[] keyTypes, Principal[] issuers, TransportData transportData, boolean forServer)
    {
        // TODO[jsse] Need to support the keyTypes that SunJSSE sends here

        Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);

        for (String keyType : keyTypes)
        {
            for (Map.Entry<String, Credential> entry : credentials.entrySet())
            {
                if (isSuitableCredential(forServer, keyType, issuerNames, entry.getValue()))
                {
                    return entry.getKey();
                }
            }
        }
        return null;
    }

    private String[] getAliases(boolean forServer, String keyType, Principal[] issuers)
    {
        Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);

        List<String> aliases = new ArrayList<String>();
        for (Map.Entry<String, Credential> entry : credentials.entrySet())
        {
            if (isSuitableCredential(forServer, keyType, issuerNames, entry.getValue()))
            {
                aliases.add(entry.getKey());
            }
        }
        return aliases.toArray(new String[aliases.size()]);
    }

    private Credential getCredential(String alias)
    {
        return alias == null ? null : credentials.get(alias);
    }

    private boolean hasSuitableIssuer(Set<X500Name> issuerNames, X509Certificate c)
    {
        return issuerNames.contains(JsseUtils.toX500Name(c.getIssuerX500Principal()));
    }

    private boolean isSuitableCredential(boolean forServer, String keyType, Set<X500Name> issuerNames, Credential credential)
    {
        X509Certificate[] certificateChain = credential.getCertificateChain();
        if (null == certificateChain || certificateChain.length < 1
            || !ProvX509KeyManager.isSuitableCertificate(forServer, keyType, certificateChain[0]))
        {
            return false;
        }
        if (issuerNames == null || issuerNames.isEmpty())
        {
            return true;
        }
        int pos = certificateChain.length;
        while (--pos >= 0)
        {
            if (hasSuitableIssuer(issuerNames, certificateChain[pos]))
            {
                return true;
            }
        }
        return false;
    }

    private static class Credential
    {
        private final PrivateKey privateKey;
        private final X509Certificate[] certificateChain;

        Credential(PrivateKey privateKey, X509Certificate[] certificateChain)
        {
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }

        X509Certificate[] getCertificateChain()
        {
            return certificateChain;
        }

        PrivateKey getPrivateKey()
        {
            return privateKey;
        }
    }
}
