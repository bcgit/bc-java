package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
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
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;

class ProvX509KeyManager
    extends X509ExtendedKeyManager
{
    private final List<KeyStore.Builder> builders;

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
        List<String> aliases = findAliases(false, keyType, JsseUtils.toX500Names(issuers));

        return aliases.toArray(new String[aliases.size()]);
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        try
        {
            Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);

            // TODO[jsse] Need to support the keyTypes that SunJSSE sends here
            for (int i = 0; i != keyTypes.length; i++)
            {
				List<String> aliases = findAliases(false, keyTypes[i], issuerNames);
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
        List<String> aliases = findAliases(true, keyType, JsseUtils.toX500Names(issuers));

        return aliases.toArray(new String[aliases.size()]);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        try
        {
            List<String> aliases = findAliases(true, keyType, JsseUtils.toX500Names(issuers));

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
                if (isSuitableCertificate(forServer, keyType, issuers, x509Cert))
                {
                    // TODO[jsse] Double-check the private key type here?
                    found = true;
                    break;
                }
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

    private boolean isSuitableCertificate(boolean forServer, String keyType, Set<X500Name> issuers, X509Certificate c)
    {
        if (keyType == null || c == null)
        {
            return false;
        }
        if (!isSuitableIssuer(issuers, c))
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
        if (keyType.equalsIgnoreCase("ECDHE_ECDSA"))
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

    private boolean isSuitableIssuer(Set<X500Name> issuers, X509Certificate c)
    {
        try
        {
            org.bouncycastle.asn1.x509.Certificate asn1Cert = org.bouncycastle.asn1.x509.Certificate.getInstance(c.getEncoded());
            return issuers == null || issuers.isEmpty() || issuers.contains(asn1Cert.getIssuer());
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private boolean isSuitableKeyUsage(int keyUsageBits, X509Certificate c)
    {
        try
        {
            Extensions exts = TBSCertificate.getInstance(c.getTBSCertificate()).getExtensions();
            if (exts != null)
            {
                KeyUsage ku = KeyUsage.fromExtensions(exts);
                if (ku != null)
                {
                    int bits = ku.getBytes()[0] & 0xff;
                    if ((bits & keyUsageBits) != keyUsageBits)
                    {
                        return false;
                    }
                }
            }
        }
        catch (Exception e)
        {
            return false;
        }
        return true;
    }
}
