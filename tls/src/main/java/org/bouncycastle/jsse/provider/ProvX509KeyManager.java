package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

class ProvX509KeyManager
    extends X509ExtendedKeyManager
{
    private static final Map<String, String> ALGORITHM_ALIASES = new HashMap<String, String>();
    static
    {
        ALGORITHM_ALIASES.put("DHE", "DH");
        ALGORITHM_ALIASES.put("ECDH", "EC");
        ALGORITHM_ALIASES.put("ECDHE", "EC");
    }

    private static String resolveAlgorithmAlias(String alias)
    {
        String target = ALGORITHM_ALIASES.get(alias);
        return target == null ? alias : target;
    }

    private final List<KeyStore.Builder> builders;

    private final String RSA = "RSA";
    private final String DSA = "DSA";
    private final String DH = "DH";
    private final String EC = "EC";

    // TODO: does this need to be threadsafe? Will leak memory...
    private final Map<String, KeyStore.PrivateKeyEntry> keys = new HashMap<String, KeyStore.PrivateKeyEntry>();

    private final AtomicLong version = new AtomicLong();

    public ProvX509KeyManager(List<KeyStore.Builder> builders)
    {
        // the builder list is processed on request so the key manager is dynamic.
        this.builders = builders;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        List<String> aliases = findAliases(keyType, principalToIssuers(issuers));

        return aliases.toArray(new String[aliases.size()]);
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        try
        {
            for (int i = 0; i != keyTypes.length; i++)
            {
                List<String> aliases = findAliases(keyTypes[i], principalToIssuers(issuers));
                if (!aliases.isEmpty())
                {
                    return aliases.get(0);
                }
            }

            return null;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        List<String> aliases = findAliases(keyType, principalToIssuers(issuers));

        return aliases.toArray(new String[aliases.size()]);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        try
        {
            List<String> aliases = findAliases(keyType, principalToIssuers(issuers));

            if (aliases.isEmpty())
            {
                return null;
            }

            return aliases.get(0);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        return (X509Certificate[])keys.get(alias).getCertificateChain();
    }

    public PrivateKey getPrivateKey(String alias)
    {
        return keys.get(alias).getPrivateKey();
    }

    private static Set<X500Name> principalToIssuers(Principal[] principals)
    {
        if (principals == null || principals.length == 0)
        {
            return Collections.emptySet();
        }

        Set<X500Name> issuers = new HashSet<X500Name>(principals.length);

        for (int i = 0; i != principals.length; i++)
        {
            Principal p = principals[i];

            if (p instanceof X500Principal)
            {
                issuers.add(X500Name.getInstance(((X500Principal)p).getEncoded()));
            }
            else
            {
                issuers.add(new X500Name(p.getName()));       // hope for the best
            }
        }

        return issuers;
    }

    private List<String> findAliases(String keyType, Set<X500Name> issuers)
    {
        String algType;
        String sigType;
        int dashIndex = keyType.indexOf("_");

        if (dashIndex > 0)
        {
            algType = keyType.substring(0, dashIndex);
            sigType = keyType.substring(dashIndex + 1);
        }
        else
        {
            algType = keyType;
            sigType = null;
        }

        algType = resolveAlgorithmAlias(algType);

        List<String> aliases = new ArrayList<String>();

        for (int i = 0; i != builders.size(); i++)
        {
            KeyStore.Builder builder = builders.get(i);

            try
            {
                aliases.addAll(findAliases(i, builder.getKeyStore(), builder, algType, sigType, issuers));
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException("unable to build key store: " + e.getMessage(), e);
            }
        }

        return aliases;
    }

    private List<String> findAliases(int index, KeyStore keyStore, KeyStore.Builder storeBuilder, String algType, String sigType, Set<X500Name> issuers)
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

            Certificate[] chain = keyStore.getCertificateChain(eName);
            if (chain == null || chain.length == 0)    // not an entry with a certificate
            {
                continue;
            }

            if (!(chain[0] instanceof X509Certificate))
            {
                continue;
            }

            // scan back along the list of certificates
            boolean found = false;
            for (int i = chain.length - 1; i >= 0; i--)
            {
                X509Certificate x509Cert = (X509Certificate)chain[i];

                org.bouncycastle.asn1.x509.Certificate asn1Cert = org.bouncycastle.asn1.x509.Certificate.getInstance(x509Cert.getEncoded());

                if (!issuers.isEmpty() && !issuers.contains(asn1Cert.getIssuer()))   // not the right issuer
                {
                    continue;
                }

                if (!x509Cert.getPublicKey().getAlgorithm().equals(algType))
                {
                    continue;
                }

                found = true;
                break;

            }
            // TODO: manage two key/certs in one store that matches

            if (found)
            {
                KeyStore.PrivateKeyEntry kEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(eName, storeBuilder.getProtectionParameter(eName));

                String alias = index + "." + eName + "." + version.getAndIncrement();

                keys.put(alias, kEntry);

                aliases.add(alias);
            }
        }

        return aliases;
    }
}
