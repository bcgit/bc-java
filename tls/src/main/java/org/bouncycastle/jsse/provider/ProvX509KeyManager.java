package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvX509KeyManager
    extends X509ExtendedKeyManager
{
    @SuppressWarnings("unused")
    private final JcaJceHelper helper;
    private final List<KeyStore.Builder> builders;

    // TODO: does this need to be threadsafe? Will leak memory...
    private final Map<String, KeyStore.PrivateKeyEntry> keys = new HashMap<String, KeyStore.PrivateKeyEntry>();

    private final AtomicLong version = new AtomicLong();

    ProvX509KeyManager(JcaJceHelper helper, List<KeyStore.Builder> builders)
    {
        this.helper = helper;

        // the builder list is processed on request so the key manager is dynamic.
        this.builders = builders;
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
        PrivateKeyEntry entry = getPrivateKeyEntry(alias);
        return entry == null ? null : (X509Certificate[])entry.getCertificateChain();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return getAliases(false, keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        PrivateKeyEntry entry = getPrivateKeyEntry(alias);
        return entry == null ? null : entry.getPrivateKey();
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return getAliases(true, keyType, issuers);
    }

    // TODO[jsse] TransportData argument currently unused
    private String chooseAlias(String[] keyTypes, Principal[] issuers, TransportData transportData, boolean forServer)
    {
        try
        {
            Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);

            // TODO[jsse] Need to support the keyTypes that SunJSSE sends here
            for (int i = 0; i != keyTypes.length; i++)
            {
                List<String> aliases = findAliases(forServer, keyTypes[i], issuerNames);
                if (!aliases.isEmpty())
                {
                    return aliases.get(0);
                }
            }
        }
        catch (Exception e)
        {
        }

        return null;
    }

    private List<String> findAliases(boolean forServer, String keyType, Set<X500Name> issuers)
    {
        List<String> aliases = new ArrayList<String>();

        for (int i = 0; i != builders.size(); i++)
        {
            KeyStore.Builder builder = builders.get(i);

            try
            {
                aliases.addAll(findAliases(forServer, i, builder.getKeyStore(), builder, keyType, issuers));
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException("unable to build key store: " + e.getMessage(), e);
            }
        }

        return aliases;
    }

    private List<String> findAliases(boolean forServer, int index, KeyStore keyStore, KeyStore.Builder storeBuilder, String keyType, Set<X500Name> issuers)
        throws GeneralSecurityException
    {
        List<String> aliases = new ArrayList<String>();

        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
        {
            String eName = (String)en.nextElement();

            if (!keyStore.isKeyEntry(eName))      // not a key entry
            {
                continue;
            }

            X509Certificate[] chain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(eName));
            if (chain == null || chain.length == 0)    // not an entry with a certificate
            {
                continue;
            }

            // TODO: manage two key/certs in one store that matches

            if (isSuitableCredential(forServer, keyType, issuers, chain))
            {
                KeyStore.PrivateKeyEntry kEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(eName, storeBuilder.getProtectionParameter(eName));

                String alias = index + "." + eName + "." + version.getAndIncrement();

                keys.put(alias, kEntry);

                aliases.add(alias);
            }
        }

        return aliases;
    }

    private String[] getAliases(boolean forServer, String keyType, Principal[] issuers)
    {
        List<String> aliases = findAliases(forServer, keyType, JsseUtils.toX500Names(issuers));
        return aliases.toArray(new String[aliases.size()]);
    }

    private PrivateKeyEntry getPrivateKeyEntry(String alias)
    {
        return alias == null ? null : keys.get(alias);
    }

    private boolean hasSuitableIssuer(Set<X500Name> issuerNames, X509Certificate c)
    {
        return issuerNames.contains(JsseUtils.toX500Name(c.getIssuerX500Principal()));
    }

    private boolean isSuitableCredential(boolean forServer, String keyType, Set<X500Name> issuerNames,
        X509Certificate[] certificateChain)
    {
        if (null == certificateChain || certificateChain.length < 1
            || !isSuitableCertificate(forServer, keyType, certificateChain[0]))
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

    static boolean isSuitableCertificate(boolean forServer, String keyType, X509Certificate c)
    {
        if (keyType == null || c == null)
        {
            return false;
        }

        PublicKey pub = c.getPublicKey();

        if (keyType.equalsIgnoreCase("RSA"))
        {
            int keyUsage = forServer ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature;
            return (pub instanceof RSAPublicKey) && isSuitableKeyUsage(keyUsage, c);
        }

        if (isSuitableKeyUsage(KeyUsage.digitalSignature, c))
        {
            if ("Ed25519".equalsIgnoreCase(keyType))
            {
                return "Ed25519".equalsIgnoreCase(pub.getAlgorithm());
            }
            if ("Ed448".equalsIgnoreCase(keyType))
            {
                return "Ed448".equalsIgnoreCase(pub.getAlgorithm());
            }

            if (forServer)
            {
                if (keyType.equalsIgnoreCase("ECDHE_ECDSA"))
                {
                    return (pub instanceof ECPublicKey);
                }
                if (keyType.equalsIgnoreCase("ECDHE_RSA")
                    ||  keyType.equalsIgnoreCase("DHE_RSA")
                    ||  keyType.equalsIgnoreCase("SRP_RSA"))
                {
                    return (pub instanceof RSAPublicKey);
                }
                if (keyType.equalsIgnoreCase("DHE_DSS")
                    || keyType.equalsIgnoreCase("SRP_DSS"))
                {
                    return (pub instanceof DSAPublicKey);
                }
            }
            else 
            {
                if (keyType.equalsIgnoreCase("EC"))
                {
                    return (pub instanceof ECPublicKey);
                }
                if (keyType.equalsIgnoreCase("DSA"))
                {
                    return (pub instanceof DSAPublicKey);
                }
            }
        }

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
}
