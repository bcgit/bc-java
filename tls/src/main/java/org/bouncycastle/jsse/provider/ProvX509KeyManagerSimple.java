package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;

class ProvX509KeyManagerSimple
    extends X509ExtendedKeyManager
{
    private final Map<String, Credential> credentials = new HashMap<String, Credential>();

    ProvX509KeyManagerSimple(KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
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
        // TODO[jsse] Socket argument currently unused
        return chooseAlias(false, keyTypes, issuers);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        // TODO[jsse] SSLEngine argument currently unused
        return chooseAlias(false, keyTypes, issuers);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        // TODO[jsse] SSLEngine argument currently unused
        return chooseAlias(true, new String[]{ keyType }, issuers);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        // TODO[jsse] Socket argument currently unused
        return chooseAlias(true, new String[]{ keyType }, issuers);
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

    private String chooseAlias(boolean forServer, String[] keyTypes, Principal[] issuers)
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
        if (!isSuitableCertificate(forServer, keyType, certificateChain[0]))
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

    private boolean isSuitableCertificate(boolean forServer, String keyType, X509Certificate c)
    {
        if (keyType == null || c == null)
        {
            return false;
        }
        PublicKey pub = c.getPublicKey();
        if (keyType.equalsIgnoreCase("DHE_RSA")
            || keyType.equalsIgnoreCase("ECDHE_RSA")
            || keyType.equalsIgnoreCase("SRP_RSA"))
        {
            return (pub instanceof RSAPublicKey) && isSuitableKeyUsage(KeyUsage.digitalSignature, c);
        }
        else if (keyType.equalsIgnoreCase("DHE_DSS")
            || keyType.equalsIgnoreCase("SRP_DSS"))
        {
            return (pub instanceof DSAPublicKey) && isSuitableKeyUsage(KeyUsage.digitalSignature, c);
        }
        else if (keyType.equalsIgnoreCase("ECDHE_ECDSA"))
        {
            return (pub instanceof ECPublicKey) && isSuitableKeyUsage(KeyUsage.digitalSignature, c);
        }
        else if (keyType.equalsIgnoreCase("RSA"))
        {
            int keyUsage = forServer ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature;
            return (pub instanceof RSAPublicKey) && isSuitableKeyUsage(keyUsage, c);
        }
        else if (keyType.equalsIgnoreCase("DSA"))
        {
            return !forServer && (pub instanceof DSAPublicKey) && isSuitableKeyUsage(KeyUsage.digitalSignature, c);
        }
        else if (keyType.equalsIgnoreCase("EC"))
        {
            // NOTE: SunJSSE server asks for "EC" for ECDHE_ECDSA key exchange
            return (pub instanceof ECPublicKey) && isSuitableKeyUsage(KeyUsage.digitalSignature, c);
        }
        // TODO[jsse] Support other key exchanges (and client certificate types)
        return false;
    }

    static boolean isSuitableKeyUsage(int keyUsageBits, X509Certificate c)
    {
        try
        {
            boolean[] keyUsage = c.getKeyUsage();
            if (null == keyUsage)
            {
                return true;
            }

            int bits = 0, count = Math.min(32, keyUsage.length);
            for (int i = 0; i < count; ++i)
            {
                if (keyUsage[i])
                {
                    int u = i & 7, v = i - u;
                    bits |= (0x80 >>> u) << v;
                }
            }

            return (bits & keyUsageBits) == keyUsageBits;
        }
        catch (Exception e)
        {
            return false;
        }
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
