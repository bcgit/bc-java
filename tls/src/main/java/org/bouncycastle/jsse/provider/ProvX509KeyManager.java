package org.bouncycastle.jsse.provider;

import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

class ProvX509KeyManager
    extends X509ExtendedKeyManager
{
    private final JcaJceHelper helper;
    private final List<KeyStore.Builder> builders;

    @SuppressWarnings("serial")
    private final Map<String, SoftReference<KeyStore.PrivateKeyEntry>> cachedEntries = Collections.synchronizedMap(
        new LinkedHashMap<String, SoftReference<KeyStore.PrivateKeyEntry>>(16, 0.75f, true)
        {
            protected boolean removeEldestEntry(Map.Entry<String, SoftReference<KeyStore.PrivateKeyEntry>> eldest)
            {
                return size() > 16;
            }
        });

    private final AtomicLong versions = new AtomicLong();

    ProvX509KeyManager(JcaJceHelper helper, List<KeyStore.Builder> builders)
    {
        this.helper = helper;
        this.builders = builders;
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(socket), true);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry(alias);
        return null == entry ? null : (X509Certificate[])entry.getCertificateChain();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return getAliases(getKeyTypes(keyType), issuers, null, false);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry(alias);
        return null == entry ? null : entry.getPrivateKey();
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return getAliases(getKeyTypes(keyType), issuers, null, true);
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer)
    {
        Match bestMatch = Match.NOTHING;

        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            for (int i = 0, count = builders.size(); i < count; ++i)
            {
                try
                {
                    Match match = chooseAliasFromBuilder(i, keyTypes, issuerNames, algorithmConstraints, forServer,
                        atDate, requestedHostName);

                    if (match.compareTo(bestMatch) < 0)
                    {
                        bestMatch = match;

                        if (Match.Quality.OK == bestMatch.quality)
                        {
                            break;
                        }
                    }
                }
                catch (Exception e)
                {
                }
            }
        }

        return Match.NOTHING == bestMatch ? null : getAlias(bestMatch, getNextVersionSuffix());
    }

    private Match chooseAliasFromBuilder(int builderIndex, List<String> keyTypes, Set<X500Name> issuerNames,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws Exception
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        KeyStore keyStore = builder.getKeyStore();

        Match bestMatch = Match.NOTHING;

        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
        {
            String localAlias = en.nextElement();

            Match match = getPotentialMatch(builderIndex, keyStore, localAlias, bestMatch.quality, keyTypes,
                issuerNames, algorithmConstraints, forServer, atDate, requestedHostName);

            if (null != match)
            {
                bestMatch = match;

                if (Match.Quality.OK == bestMatch.quality)
                {
                    break;
                }
            }
        }

        return bestMatch;
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            Set<X500Name> issuerNames = JsseUtils.toX500Names(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            List<Match> allMatches = null;

            for (int i = 0, count = builders.size(); i < count; ++i)
            {
                try
                {
                    List<Match> matches = getAliasesFromBuilder(i, keyTypes, issuerNames, algorithmConstraints,
                        forServer, atDate, requestedHostName);

                    allMatches = addToAllMatches(allMatches, matches);
                }
                catch (Exception e)
                {
                }
            }

            if (null != allMatches && !allMatches.isEmpty())
            {
                // NOTE: We are relying on this being a stable sort
                Collections.sort(allMatches);

                return getAliases(allMatches, getNextVersionSuffix());
            }
        }

        return null;
    }

    private List<Match> getAliasesFromBuilder(int builderIndex, List<String> keyTypes, Set<X500Name> issuerNames,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws Exception
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        KeyStore keyStore = builder.getKeyStore();

        List<Match> matches = null;

        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
        {
            String localAlias = en.nextElement();

            Match match = getPotentialMatch(builderIndex, keyStore, localAlias, Match.Quality.NONE, keyTypes,
                issuerNames, algorithmConstraints, forServer, atDate, requestedHostName);

            if (null != match)
            {
                matches = addToMatches(matches, match);
            }
        }

        return matches;
    }

    private String getNextVersionSuffix()
    {
        return "." + versions.incrementAndGet();
    }

    private Match getPotentialMatch(int builderIndex, KeyStore keyStore, String localAlias, Match.Quality qualityLimit,
        List<String> keyTypes, Set<X500Name> issuerNames, BCAlgorithmConstraints algorithmConstraints,
        boolean forServer, Date atDate, String requestedHostName) throws Exception
    {
        if (keyStore.isKeyEntry(localAlias))
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(localAlias));
            if (isSuitableChain(chain, keyTypes, issuerNames, algorithmConstraints, forServer))
            {
                Match.Quality quality = getCertificateQuality(chain[0], atDate, requestedHostName);
                if (quality.compareTo(qualityLimit) < 0)
                {
                    return new Match(builderIndex, localAlias, quality);
                }
            }
        }

        return null;
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias)
    {
        if (null != alias)
        {
            SoftReference<KeyStore.PrivateKeyEntry> entryRef = cachedEntries.get(alias);
            if (null != entryRef)
            {
                KeyStore.PrivateKeyEntry cachedEntry = entryRef.get();
                if (null != cachedEntry)
                {
                    return cachedEntry;
                }
            }

            try
            {
                String[] parts = alias.split("\\.");
                if (parts.length == 3)
                {
                    int builderIndex = Integer.parseInt(parts[0]);
                    if (0 <= builderIndex && builderIndex < builders.size())
                    {
                        KeyStore.Builder builder = builders.get(builderIndex);

                        String localAlias = parts[1];
                        KeyStore keyStore = builder.getKeyStore();
                        ProtectionParameter protectionParameter = builder.getProtectionParameter(localAlias);

                        KeyStore.Entry entry = keyStore.getEntry(localAlias, protectionParameter);
                        if (entry instanceof KeyStore.PrivateKeyEntry)
                        {
                            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)entry;
                            cachedEntries.put(alias, new SoftReference<KeyStore.PrivateKeyEntry>(privateKeyEntry));
                            return privateKeyEntry;
                        }
                    }
                }
            }
            catch (Exception e)
            {
            }
        }
        return null;
    }

    private boolean isSuitableChain(X509Certificate[] chain, List<String> keyTypes, Set<X500Name> issuerNames,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer)
    {
        if (null == chain || chain.length < 1
            || !isSuitableChainForIssuers(chain, issuerNames)
            || !isSuitableEECert(chain[0], keyTypes, algorithmConstraints, forServer))
        {
            return false;
        }

        try
        {
            Set<X509Certificate> trustedCerts = Collections.emptySet();
            KeyPurposeId ekuOID = ProvX509TrustManager.getRequiredExtendedKeyUsage(forServer);
            int kuBit = -1; // i.e. no checks; we handle them in isSuitableEECert

            ProvAlgorithmChecker.checkChain(helper, algorithmConstraints, trustedCerts, chain, ekuOID, kuBit);
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }

        return true;
    }

    private static List<Match> addToAllMatches(List<Match> allMatches, List<Match> matches)
    {
        if (null != matches && !matches.isEmpty())
        {
            if (null == allMatches)
            {
                allMatches = matches;
            }
            else
            {
                allMatches.addAll(matches);
            }
        }
        return allMatches;
    }

    private static List<Match> addToMatches(List<Match> matches, Match match)
    {
        if (null == matches)
        {
            matches = new ArrayList<Match>();
        }

        matches.add(match);
        return matches;
    }

    private static String getAlias(Match match, String versionSuffix)
    {
        return match.builderIndex + "." + match.localAlias + versionSuffix;
    }

    private static String[] getAliases(List<Match> matches, String versionSuffix)
    {
        int count = matches.size(), pos = 0;
        String[] result = new String[count];
        for (Match match : matches)
        {
            result[pos++] = getAlias(match, versionSuffix);
        }
        return result;
    }

    private static Match.Quality getCertificateQuality(X509Certificate certificate, Date atDate, String requestedHostName)
    {
        try
        {
            certificate.checkValidity(atDate);
        }
        catch (CertificateException e)
        {
            return Match.Quality.EXPIRED;
        }

        if (null != requestedHostName)
        {
            try
            {
                /*
                 * NOTE: For compatibility with SunJSSE, we also re-use HTTPS endpoint ID checks for
                 * SNI certificate selection.
                 */
                ProvX509TrustManager.checkEndpointID(requestedHostName, certificate, "HTTPS");
            }
            catch (CertificateException e)
            {
                return Match.Quality.MISMATCH_SNI;
            }
        }

        return Match.Quality.OK;
    }

    private static List<String> getKeyTypes(String... keyTypes)
    {
        if (null != keyTypes && keyTypes.length > 0)
        {
            List<String> result = new ArrayList<String>(keyTypes.length);
            for (String keyType : keyTypes)
            {
                if (null != keyType)
                {
                    result.add(keyType);
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    private static String getRequestedHostName(TransportData transportData, boolean forServer)
    {
        if (null != transportData && forServer)
        {
            BCExtendedSSLSession sslSession = transportData.getHandshakeSession();
            if (null != sslSession)
            {
                BCSNIHostName sniHostName = JsseUtils.getSNIHostName(sslSession.getRequestedServerNames());
                if (null != sniHostName)
                {
                    return sniHostName.getAsciiName();
                }
            }
        }
        return null;
    }

    private static boolean hasSuitableIssuer(X509Certificate certificate, Set<X500Name> issuerNames)
    {
        return issuerNames.contains(JsseUtils.toX500Name(certificate.getIssuerX500Principal()));
    }

    private static boolean isSuitableChainForIssuers(X509Certificate[] chain, Set<X500Name> issuerNames)
    {
        if (null == issuerNames || issuerNames.isEmpty())
        {
            return true;
        }
        int pos = chain.length;
        while (--pos >= 0)
        {
            if (hasSuitableIssuer(chain[pos], issuerNames))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean isSuitableEECert(X509Certificate eeCert, List<String> keyTypes,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer)
    {
        for (String keyType : keyTypes)
        {
            if (isSuitableEECert(eeCert, keyType, algorithmConstraints, forServer))
            {
                return true;
            }
        }

        return false;
    }

    private static boolean isSuitableEECert(X509Certificate eeCert, String keyType,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer)
    {
        PublicKey publicKey = eeCert.getPublicKey();
        boolean[] keyUsage = eeCert.getKeyUsage(); 

        if (forServer && keyType.equalsIgnoreCase("RSA"))
        {
            return publicKey instanceof RSAPublicKey
                && ProvAlgorithmChecker.supportsKeyUsage(keyUsage, ProvAlgorithmChecker.KU_KEY_ENCIPHERMENT)
                && algorithmConstraints.permits(JsseUtils.KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC,  publicKey);
        }

        if (ProvAlgorithmChecker.supportsKeyUsage(keyUsage, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE)
            && algorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, publicKey))
        {
            if ("Ed25519".equalsIgnoreCase(keyType))
            {
                return "Ed25519".equalsIgnoreCase(publicKey.getAlgorithm());
            }
            if ("Ed448".equalsIgnoreCase(keyType))
            {
                return "Ed448".equalsIgnoreCase(publicKey.getAlgorithm());
            }

            if (forServer)
            {
                if (keyType.equalsIgnoreCase("ECDHE_ECDSA"))
                {
                    return publicKey instanceof ECPublicKey;
                }
                if (keyType.equalsIgnoreCase("ECDHE_RSA")
                    ||  keyType.equalsIgnoreCase("DHE_RSA")
                    ||  keyType.equalsIgnoreCase("SRP_RSA"))
                {
                    return publicKey instanceof RSAPublicKey;
                }
                if (keyType.equalsIgnoreCase("DHE_DSS")
                    || keyType.equalsIgnoreCase("SRP_DSS"))
                {
                    return publicKey instanceof DSAPublicKey;
                }
            }
            else 
            {
                if (keyType.equalsIgnoreCase("EC"))
                {
                    return publicKey instanceof ECPublicKey;
                }
                if (keyType.equalsIgnoreCase("RSA"))
                {
                    return publicKey instanceof RSAPublicKey;
                }
                if (keyType.equalsIgnoreCase("DSA"))
                {
                    return publicKey instanceof DSAPublicKey;
                }
            }
        }

        return false;
    }

    private static final class Match
        implements Comparable<Match>
    {
        // NOTE: We rely on these being in preference order. 
        static enum Quality
        {
            OK,
            MISMATCH_SNI,
            EXPIRED,
            // TODO[jsse] Consider allowing certificates with invalid ExtendedKeyUsage and/or KeyUsage (as SunJSSE does)
//            MISMATCH_EKU,
//            MISMATCH_KU,
            NONE
        }

        static final Match NOTHING = new Match(-1, null, Quality.NONE);

        final int builderIndex;
        final String localAlias;
        final Quality quality;

        Match(int builderIndex, String localAlias, Quality quality)
        {
            this.builderIndex = builderIndex;
            this.localAlias = localAlias;
            this.quality = quality;
        }

        public int compareTo(Match other)
        {
            return this.quality.compareTo(other.quality);
        }
    }
}
