package org.bouncycastle.jsse.provider;

import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.KeyExchangeAlgorithm;

class ProvX509KeyManager
    extends BCX509ExtendedKeyManager
{
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManager.class.getName());

    private static final boolean provKeyManagerCheckEKU = PropertyUtils
        .getBooleanSystemProperty("org.bouncycastle.jsse.keyManager.checkEKU", true);

    private final AtomicLong versions = new AtomicLong();

    private final boolean isInFipsMode;
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

        addFilter(filters, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, algorithm, null, keyType);
    }

    private static void addFilter(Map<String, PublicKeyFilter> filters, Class<? extends PublicKey> clazz, String... keyTypes)
    {
        addFilter(filters, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, null, clazz, keyTypes);
    }

    private static void addFilter(Map<String, PublicKeyFilter> filters, int keyUsageBit, String algorithm,
        Class<? extends PublicKey> clazz, String... keyTypes)
    {
        PublicKeyFilter filter = new PublicKeyFilter(algorithm, clazz, keyUsageBit);

        for (String keyType : keyTypes)
        {
            if (null != filters.put(keyType.toUpperCase(Locale.ENGLISH), filter))
            {
                throw new IllegalStateException("Duplicate keys in filters");
            }
        }
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> filters, String algorithm,
        int... keyExchangeAlgorithms)
    {
        addFilterLegacyServer(filters, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, algorithm, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> filters, int keyUsageBit, String algorithm,
        int... keyExchangeAlgorithms)
    {
        addFilterLegacyServer(filters, keyUsageBit, algorithm, null, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> filters, Class<? extends PublicKey> clazz,
        int... keyExchangeAlgorithms)
    {
        addFilterLegacyServer(filters, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE, null, clazz, keyExchangeAlgorithms);
    }

    private static void addFilterLegacyServer(Map<String, PublicKeyFilter> filters, int keyUsageBit, String algorithm,
        Class<? extends PublicKey> clazz, int... keyExchangeAlgorithms)
    {
        addFilter(filters, keyUsageBit, algorithm, clazz, getKeyTypesLegacyServer(keyExchangeAlgorithms));
    }

    private static Map<String, PublicKeyFilter> createFiltersClient()
    {
        Map<String, PublicKeyFilter> filters = new HashMap<String, PublicKeyFilter>();

        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");

        // TODO Perhaps check the public key OID explicitly for these
        addFilter(filters, "RSA");
        addFilter(filters, "RSASSA-PSS");

        addFilter(filters, DSAPublicKey.class, "DSA");
        addFilter(filters, ECPublicKey.class, "EC");

        return Collections.unmodifiableMap(filters);
    }

    private static Map<String, PublicKeyFilter> createFiltersServer()
    {
        Map<String, PublicKeyFilter> filters = new HashMap<String, PublicKeyFilter>();

        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");

        // TODO Perhaps check the public key OID explicitly for these
        addFilter(filters, "RSA");
        addFilter(filters, "RSASSA-PSS");

        addFilterLegacyServer(filters, DSAPublicKey.class, KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.SRP_DSS);
        addFilterLegacyServer(filters, ECPublicKey.class, KeyExchangeAlgorithm.ECDHE_ECDSA);
        addFilterLegacyServer(filters, "RSA", KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_RSA,
            KeyExchangeAlgorithm.SRP_RSA);
        addFilterLegacyServer(filters, ProvAlgorithmChecker.KU_KEY_ENCIPHERMENT, "RSA", KeyExchangeAlgorithm.RSA);

        return Collections.unmodifiableMap(filters);
    }

    private static String[] getKeyTypesLegacyServer(int... keyExchangeAlgorithms)
    {
        int count = keyExchangeAlgorithms.length;
        String[] keyTypes = new String[count];
        for (int i = 0; i < count; ++i)
        {
            keyTypes[i] = JsseUtils.getKeyTypeLegacyServer(keyExchangeAlgorithms[i]);
        }
        return keyTypes;
    }

    ProvX509KeyManager(boolean isInFipsMode, JcaJceHelper helper, List<KeyStore.Builder> builders)
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.builders = builders;
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    @Override
    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    @Override
    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(engine), true);
    }

    @Override
    public BCX509Key chooseEngineServerKeyBC(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return chooseKeyBC(getKeyTypes(keyType), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(socket), true);
    }

    @Override
    public BCX509Key chooseServerKeyBC(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseKeyBC(getKeyTypes(keyType), issuers, TransportData.from(socket), true);
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

    @Override
    public BCX509Key getKeyBC(String alias)
    {
        KeyStore.PrivateKeyEntry entry = getPrivateKeyEntry(alias);
        if (null == entry)
        {
            return null;
        }

        PrivateKey privateKey = entry.getPrivateKey();
        if (null == privateKey)
        {
            return null;
        }

        X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(entry.getCertificateChain());
        if (certificateChain == null || certificateChain.length < 1)
        {
            return null;
        }

        return new ProvX509Key(privateKey, certificateChain);
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

    static KeyPurposeId getRequiredExtendedKeyUsage(boolean forServer)
    {
        return !provKeyManagerCheckEKU
            ?   null
            :   forServer
            ?   KeyPurposeId.id_kp_serverAuth
            :   KeyPurposeId.id_kp_clientAuth;
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (Match.NOTHING != bestMatch)
        {
            String alias = getAlias(bestMatch, getNextVersionSuffix());
            LOG.fine("Found matching key, returning alias: " + alias);
            return alias;
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key chooseKeyBC(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (Match.NOTHING != bestMatch)
        {
            try
            {
                BCX509Key keyBC = createKeyBC(bestMatch.builderIndex, bestMatch.localAlias, bestMatch.cachedKeyStore,
                    bestMatch.cachedCertificateChain);
                if (null != keyBC)
                {
                    LOG.fine("Found matching key, from alias: " + bestMatch.builderIndex + "." + bestMatch.localAlias);
                    return keyBC;
                }
            }
            catch (Exception e)
            {
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(int builderIndex, String alias, KeyStore keyStore, X509Certificate[] certificateChain)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        ProtectionParameter protectionParameter = builder.getProtectionParameter(alias);

        if (protectionParameter instanceof KeyStore.PasswordProtection)
        {
            KeyStore.PasswordProtection passwordProtection = (KeyStore.PasswordProtection)protectionParameter;
            if (null == passwordProtection.getProtectionAlgorithm())
            {
                Key key = keyStore.getKey(alias, passwordProtection.getPassword());
                if (key instanceof PrivateKey)
                {
                    return new ProvX509Key((PrivateKey) key, certificateChain);
                }
            }
        }

        return null;
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            List<Match> allMatches = null;

            for (int i = 0, count = builders.size(); i < count; ++i)
            {
                try
                {
                    List<Match> matches = getAliasesFromBuilder(i, keyTypes, uniqueIssuers, algorithmConstraints,
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

    private List<Match> getAliasesFromBuilder(int builderIndex, List<String> keyTypes, Set<Principal> uniqueIssuers,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws Exception
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        KeyStore keyStore = builder.getKeyStore();

        List<Match> matches = null;

        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
        {
            String localAlias = en.nextElement();

            Match match = getPotentialMatch(builderIndex, builder, keyStore, localAlias, Match.Quality.NONE, keyTypes,
                uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);

            if (null != match)
            {
                matches = addToMatches(matches, match);
            }
        }

        return matches;
    }

    private Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = Match.NOTHING;

        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            for (int i = 0, count = builders.size(); i < count; ++i)
            {
                try
                {
                    Match match = getBestMatchFromBuilder(i, keyTypes, uniqueIssuers, algorithmConstraints, forServer,
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

        return bestMatch;
    }

    private Match getBestMatchFromBuilder(int builderIndex, List<String> keyTypes, Set<Principal> uniqueIssuers,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws Exception
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        KeyStore keyStore = builder.getKeyStore();

        Match bestMatch = Match.NOTHING;

        for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
        {
            String localAlias = en.nextElement();

            Match match = getPotentialMatch(builderIndex, builder, keyStore, localAlias, bestMatch.quality, keyTypes,
                uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);

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

    private String getNextVersionSuffix()
    {
        return "." + versions.incrementAndGet();
    }

    private Match getPotentialMatch(int builderIndex, KeyStore.Builder builder, KeyStore keyStore, String localAlias,
        Match.Quality qualityLimit, List<String> keyTypes, Set<Principal> uniqueIssuers,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws Exception
    {
        if (keyStore.isKeyEntry(localAlias))
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(localAlias));
            if (isSuitableChain(chain, keyTypes, uniqueIssuers, algorithmConstraints, forServer))
            {
                Match.Quality quality = getCertificateQuality(chain[0], atDate, requestedHostName);
                if (quality.compareTo(qualityLimit) < 0)
                {
                    return new Match(quality, builderIndex, localAlias, keyStore, chain);
                }
            }
        }

        return null;
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias)
    {
        if (null == alias)
        {
            return null;
        }

        SoftReference<KeyStore.PrivateKeyEntry> entryRef = cachedEntries.get(alias);
        if (null != entryRef)
        {
            KeyStore.PrivateKeyEntry cachedEntry = entryRef.get();
            if (null != cachedEntry)
            {
                return cachedEntry;
            }
        }

        KeyStore.PrivateKeyEntry result = loadPrivateKeyEntry(alias);
        if (null != result)
        {
            cachedEntries.put(alias, new SoftReference<KeyStore.PrivateKeyEntry>(result));
        }
        return result;
    }

    private boolean isSuitableChain(X509Certificate[] chain, List<String> keyTypes, Set<Principal> uniqueIssuers,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer)
    {
        if (null == chain || chain.length < 1
            || !isSuitableChainForIssuers(chain, uniqueIssuers)
            || !isSuitableEECert(chain[0], keyTypes, algorithmConstraints, forServer))
        {
            return false;
        }

        try
        {
            Set<X509Certificate> trustedCerts = Collections.emptySet();
            KeyPurposeId ekuOID = getRequiredExtendedKeyUsage(forServer);
            int kuBit = -1; // i.e. no checks; we handle them in isSuitableEECert

            ProvAlgorithmChecker.checkChain(isInFipsMode, helper, algorithmConstraints, trustedCerts, chain, ekuOID,
                kuBit);
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }

        return true;
    }

    private KeyStore.PrivateKeyEntry loadPrivateKeyEntry(String alias)
    {
        try
        {
            int builderIndexStart = 0;
            int builderIndexEnd = alias.indexOf('.', builderIndexStart);
            if (builderIndexEnd > builderIndexStart)
            {
                int localAliasStart = builderIndexEnd + 1;
                int localAliasEnd = alias.indexOf('.', localAliasStart);
                if (localAliasEnd > localAliasStart)
                {
                    int builderIndex = Integer.parseInt(alias.substring(builderIndexStart, builderIndexEnd));
                    if (0 <= builderIndex && builderIndex < builders.size())
                    {
                        KeyStore.Builder builder = builders.get(builderIndex);

                        String localAlias = alias.substring(localAliasStart, localAliasEnd);
                        KeyStore keyStore = builder.getKeyStore();
                        ProtectionParameter protectionParameter = builder.getProtectionParameter(localAlias);

                        KeyStore.Entry entry = keyStore.getEntry(localAlias, protectionParameter);
                        if (entry instanceof KeyStore.PrivateKeyEntry)
                        {
                            return (KeyStore.PrivateKeyEntry)entry;
                        }
                    }
                }
            }
        }
        catch (Exception e)
        {
            LOG.log(Level.FINER, "Failed to load PrivateKeyEntry: " + alias, e);
        }
        return null;
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

        /*
         * Prefer RSA certificates with more specific KeyUsage over "multi-use" ones.
         */
        if ("RSA".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(certificate.getPublicKey())))
        {
            boolean[] keyUsage = certificate.getKeyUsage();
            if (ProvAlgorithmChecker.supportsKeyUsage(keyUsage, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE) &&
                ProvAlgorithmChecker.supportsKeyUsage(keyUsage, ProvAlgorithmChecker.KU_KEY_ENCIPHERMENT))
            {
                return Match.Quality.RSA_MULTI_USE; 
            }
        }

        return Match.Quality.OK;
    }

    private static List<String> getKeyTypes(String... keyTypes)
    {
        if (null != keyTypes && keyTypes.length > 0)
        {
            ArrayList<String> result = new ArrayList<String>(keyTypes.length);
            for (String keyType : keyTypes)
            {
                if (null != keyType)
                {
                    result.add(keyType.toUpperCase(Locale.ENGLISH));
                }
            }
            if (!result.isEmpty())
            {
                return Collections.unmodifiableList(result);
            }
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

    private static Set<Principal> getUniquePrincipals(Principal[] principals)
    {
        if (null == principals)
        {
            return null;
        }
        if (principals.length > 0)
        {
            Set<Principal> result = new HashSet<Principal>();
            for (int i = 0; i < principals.length; ++i)
            {
                Principal principal = principals[i];
                if (null != principal)
                {
                    result.add(principal);
                }
            }
            if (!result.isEmpty())
            {
                return Collections.unmodifiableSet(result);
            }
        }
        return Collections.emptySet();
    }

    private static boolean isSuitableChainForIssuers(X509Certificate[] chain, Set<Principal> uniqueIssuers)
    {
        // NOTE: Empty issuers means same as absent issuers, per SunJSSE
        if (null == uniqueIssuers || uniqueIssuers.isEmpty())
        {
            return true;
        }
        int pos = chain.length;
        while (--pos >= 0)
        {
            if (uniqueIssuers.contains(chain[pos].getIssuerX500Principal()))
            {
                return true;
            }
        }
        X509Certificate eeCert = chain[0];
        return eeCert.getBasicConstraints() >= 0
            && uniqueIssuers.contains(eeCert.getSubjectX500Principal());
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
            RSA_MULTI_USE,
            MISMATCH_SNI,
            EXPIRED,
            // TODO[jsse] Consider allowing certificates with invalid ExtendedKeyUsage and/or KeyUsage (as SunJSSE does)
//            MISMATCH_EKU,
//            MISMATCH_KU,
            NONE
        }

        static final Match NOTHING = new Match(Quality.NONE, -1, null, null, null);

        final Quality quality;
        final int builderIndex;
        final String localAlias;
        final KeyStore cachedKeyStore;
        final X509Certificate[] cachedCertificateChain;

        Match(Quality quality, int builderIndex, String localAlias, KeyStore cachedKeyStore,
            X509Certificate[] cachedCertificateChain)
        {
            this.quality = quality;
            this.builderIndex = builderIndex;
            this.localAlias = localAlias;
            this.cachedKeyStore = cachedKeyStore;
            this.cachedCertificateChain = cachedCertificateChain;
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
            return (null != algorithm && algorithm.equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey)))
                || (null != clazz && clazz.isInstance(publicKey));
        }
    }
}
