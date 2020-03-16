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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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

    private static final Map<String, PublicKeyFilter> FILTERS_CLIENT = createFiltersClient();
    private static final Map<String, PublicKeyFilter> FILTERS_SERVER = createFiltersServer();

    private static void addFilter(Map<String, PublicKeyFilter> filters, String keyType)
    {
        String algorithm = keyType;

        addFilter(filters, algorithm, null, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, keyType);
    }

    private static void addFilter(Map<String, PublicKeyFilter> filters, Class<? extends PublicKey> clazz, String... keyTypes)
    {
        addFilter(filters, null, clazz, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, keyTypes);
    }

    private static void addFilter(Map<String, PublicKeyFilter> filters, String algorithm,
        Class<? extends PublicKey> clazz, int keyUsageBit, String... keyTypes)
    {
        PublicKeyFilter filter = new PublicKeyFilter(algorithm, clazz, keyUsageBit);

        for (String keyType : keyTypes)
        {
            if (null != filters.put(keyType.toUpperCase(Locale.ENGLISH), filter))
            {
                throw new IllegalStateException("Duplicate names in filters");
            }
        }
    }

    private static Map<String, PublicKeyFilter> createFiltersClient()
    {
        Map<String, PublicKeyFilter> filters = new HashMap<String, PublicKeyFilter>();

        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");

        addFilter(filters, DSAPublicKey.class, "DSA");
        addFilter(filters, ECPublicKey.class, "EC");
        addFilter(filters, RSAPublicKey.class, "RSA");

        return Collections.unmodifiableMap(filters);
    }

    private static Map<String, PublicKeyFilter> createFiltersServer()
    {
        Map<String, PublicKeyFilter> filters = new HashMap<String, PublicKeyFilter>();

        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");

        addFilter(filters, DSAPublicKey.class, "DHE_DSS", "SRP_DSS");
        addFilter(filters, ECPublicKey.class, "ECDHE_ECDSA");
        addFilter(filters, RSAPublicKey.class, "DHE_RSA", "ECDHE_RSA", "SRP_RSA");

        addFilter(filters, null, RSAPublicKey.class, ProvAlgorithmChecker.KU_KEY_ENCIPHERMENT, "RSA");

        return Collections.unmodifiableMap(filters);
    }

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
                    result.add(keyType.toUpperCase(Locale.ENGLISH));
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
        Map<String, PublicKeyFilter> filters = forServer ? FILTERS_SERVER : FILTERS_CLIENT;

        PublicKey publicKey = eeCert.getPublicKey();
        boolean[] keyUsage = eeCert.getKeyUsage();

        for (String keyType : keyTypes)
        {
            PublicKeyFilter filter = filters.get(keyType);
            if (null != filter && filter.accepts(publicKey, keyUsage, algorithmConstraints))
            {
                return true;
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

    private static final class PublicKeyFilter
    {
        final String algorithm;
        final Class<? extends PublicKey> clazz;
        final int keyUsageBit;

        PublicKeyFilter(String algorithm, Class<? extends PublicKey> clazz, int keyUsageBit)
        {
            this.algorithm = algorithm;
            this.clazz = clazz;
            this.keyUsageBit = keyUsageBit;
        }

        boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints)
        {
            return appliesTo(publicKey)
                && ProvAlgorithmChecker.permitsKeyUsage(publicKey, keyUsage, keyUsageBit, algorithmConstraints);
        }

        private boolean appliesTo(PublicKey publicKey)
        {
            return (null != algorithm && algorithm.equalsIgnoreCase(publicKey.getAlgorithm()))
                || (null != clazz && clazz.isInstance(publicKey));
        }
    }
}
