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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;

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

    private static void addECFilter13(Map<String, PublicKeyFilter> filters, int namedGroup13)
    {
        if (!NamedGroup.canBeNegotiated(namedGroup13, ProtocolVersion.TLSv13))
        {
            throw new IllegalStateException("Invalid named group for TLS 1.3 EC filter");
        }

        String curveName = NamedGroup.getCurveName(namedGroup13);
        if (null != curveName)
        {
            ASN1ObjectIdentifier standardOID = ECNamedCurveTable.getOID(curveName);
            if (null != standardOID)
            {
                String keyType = JsseUtils.getKeyType13("EC", namedGroup13);
                PublicKeyFilter filter = new ECPublicKeyFilter13(standardOID);
                addFilterToMap(filters, keyType, filter);
                return;
            }
        }

        LOG.warning("Failed to register public key filter for EC with " + NamedGroup.getText(namedGroup13));
    }

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
        PublicKeyFilter filter = new DefaultPublicKeyFilter(algorithm, clazz, keyUsageBit);

        for (String keyType : keyTypes)
        {
            addFilterToMap(filters, keyType, filter);
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

    private static void addFilterToMap(Map<String, PublicKeyFilter> filters, String keyType, PublicKeyFilter filter)
    {
        if (null != filters.put(keyType, filter))
        {
            throw new IllegalStateException("Duplicate keys in filters");
        }
    }

    private static Map<String, PublicKeyFilter> createFiltersClient()
    {
        Map<String, PublicKeyFilter> filters = new HashMap<String, PublicKeyFilter>();

        addFilter(filters, "Ed25519");
        addFilter(filters, "Ed448");

        addECFilter13(filters, NamedGroup.brainpoolP256r1tls13);
        addECFilter13(filters, NamedGroup.brainpoolP384r1tls13);
        addECFilter13(filters, NamedGroup.brainpoolP512r1tls13);

        addECFilter13(filters, NamedGroup.secp256r1);
        addECFilter13(filters, NamedGroup.secp384r1);
        addECFilter13(filters, NamedGroup.secp521r1);

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

        addECFilter13(filters, NamedGroup.brainpoolP256r1tls13);
        addECFilter13(filters, NamedGroup.brainpoolP384r1tls13);
        addECFilter13(filters, NamedGroup.brainpoolP512r1tls13);

        addECFilter13(filters, NamedGroup.secp256r1);
        addECFilter13(filters, NamedGroup.secp384r1);
        addECFilter13(filters, NamedGroup.secp521r1);

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
    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return chooseAlias(getKeyTypes(keyType), issuers, TransportData.from(socket), true);
    }

    @Override
    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return chooseKeyBC(getKeyTypes(keyTypes), issuers, TransportData.from(socket), true);
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

    @Override
    protected BCX509Key getKeyBC(String keyType, String alias)
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
        if (TlsUtils.isNullOrEmpty(certificateChain))
        {
            return null;
        }

        return new ProvX509Key(keyType, privateKey, certificateChain);
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (bestMatch.compareTo(Match.NOTHING) < 0)
        {
            String keyType = keyTypes.get(bestMatch.keyTypeIndex);
            String alias = getAlias(bestMatch, getNextVersionSuffix());
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("Found matching key of type: " + keyType + ", returning alias: " + alias);
            }
            return alias;
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key chooseKeyBC(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (bestMatch.compareTo(Match.NOTHING) < 0)
        {
            try
            {
                String keyType = keyTypes.get(bestMatch.keyTypeIndex);

                BCX509Key keyBC = createKeyBC(keyType, bestMatch.builderIndex, bestMatch.localAlias,
                    bestMatch.cachedKeyStore, bestMatch.cachedCertificateChain);
                if (null != keyBC)
                {
                    if (LOG.isLoggable(Level.FINE))
                    {
                        LOG.fine("Found matching key of type: " + keyType + ", from alias: " + bestMatch.builderIndex
                            + "." + bestMatch.localAlias);
                    }

                    return keyBC;
                }
            }
            catch (Exception e)
            {
                LOG.log(Level.FINER, "Failed to load private key", e);
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(String keyType, int builderIndex, String localAlias, KeyStore keyStore,
        X509Certificate[] certificateChain)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        KeyStore.Builder builder = builders.get(builderIndex);
        ProtectionParameter protectionParameter = builder.getProtectionParameter(localAlias);

        Key key = KeyStoreUtil.getKey(keyStore, localAlias, protectionParameter);
        if (key instanceof PrivateKey)
        {
            return new ProvX509Key(keyType, (PrivateKey)key, certificateChain);
        }

        return null;
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);
            List<Match> matches = null;

            for (int builderIndex = 0, count = builders.size(); builderIndex < count; ++builderIndex)
            {
                try
                {
                    KeyStore.Builder builder = builders.get(builderIndex);
                    KeyStore keyStore = builder.getKeyStore();

                    for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
                    {
                        String localAlias = en.nextElement();

                        Match match = getPotentialMatch(builderIndex, builder, keyStore, localAlias, keyTypes,
                            keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);

                        if (match.compareTo(Match.NOTHING) < 0)
                        {
                            matches = addToMatches(matches, match);
                        }
                    }
                }
                catch (KeyStoreException e)
                {
                    LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + builderIndex, e);
                }
            }

            if (null != matches && !matches.isEmpty())
            {
                // NOTE: We are relying on this being a stable sort
                Collections.sort(matches);

                return getAliases(matches, getNextVersionSuffix());
            }
        }

        return null;
    }

    private Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatchSoFar = Match.NOTHING;

        if (!builders.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            for (int builderIndex = 0, count = builders.size(); builderIndex < count; ++builderIndex)
            {
                try
                {
                    KeyStore.Builder builder = builders.get(builderIndex);
                    KeyStore keyStore = builder.getKeyStore();

                    for (Enumeration<String> en = keyStore.aliases(); en.hasMoreElements();)
                    {
                        String localAlias = en.nextElement();

                        Match match = getPotentialMatch(builderIndex, builder, keyStore, localAlias, keyTypes,
                            keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);

                        if (match.compareTo(bestMatchSoFar) < 0)
                        {
                            bestMatchSoFar = match;

                            if (bestMatchSoFar.isIdeal())
                            {
                                return bestMatchSoFar;
                            }
                            if (bestMatchSoFar.isValid())
                            {
                                keyTypeLimit = Math.min(keyTypeLimit, bestMatchSoFar.keyTypeIndex + 1);
                            }
                        }
                    }
                }
                catch (KeyStoreException e)
                {
                    LOG.log(Level.WARNING, "Failed to fully process KeyStore.Builder at index " + builderIndex, e);
                }
            }
        }

        return bestMatchSoFar;
    }

    private String getNextVersionSuffix()
    {
        return "." + versions.incrementAndGet();
    }

    private Match getPotentialMatch(int builderIndex, KeyStore.Builder builder, KeyStore keyStore, String localAlias,
        List<String> keyTypes, int keyTypeLimit, Set<Principal> uniqueIssuers,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName)
        throws KeyStoreException
    {
        if (keyStore.isKeyEntry(localAlias))
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(keyStore.getCertificateChain(localAlias));
            if (!TlsUtils.isNullOrEmpty(chain) && isSuitableChainForIssuers(chain, uniqueIssuers))
            {
                int keyTypeIndex = getSuitableKeyTypeForEECert(chain[0], keyTypes, keyTypeLimit, algorithmConstraints,
                    forServer);
                if (keyTypeIndex >= 0 && isSuitableChain(chain, algorithmConstraints, forServer))
                {
                    Match.Quality quality = getCertificateQuality(chain[0], atDate, requestedHostName);

                    return new Match(quality, keyTypeIndex, builderIndex, localAlias, keyStore, chain);
                }
            }
        }

        return Match.NOTHING;
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

    private boolean isSuitableChain(X509Certificate[] chain, BCAlgorithmConstraints algorithmConstraints,
        boolean forServer)
    {
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
                int localAliasEnd = alias.lastIndexOf('.');
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

    static KeyPurposeId getRequiredExtendedKeyUsage(boolean forServer)
    {
        return !provKeyManagerCheckEKU
            ?   null
            :   forServer
            ?   KeyPurposeId.id_kp_serverAuth
            :   KeyPurposeId.id_kp_clientAuth;
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
                if (null == keyType)
                {
                    throw new IllegalArgumentException("Key types cannot be null");
                }
                if (!result.contains(keyType))
                {
                    result.add(keyType);
                }
            }
            return Collections.unmodifiableList(result);
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

    private static int getSuitableKeyTypeForEECert(X509Certificate eeCert, List<String> keyTypes, int keyTypeLimit,
        BCAlgorithmConstraints algorithmConstraints, boolean forServer)
    {
        Map<String, PublicKeyFilter> filters = forServer ? FILTERS_SERVER : FILTERS_CLIENT;

        PublicKey publicKey = eeCert.getPublicKey();
        boolean[] keyUsage = eeCert.getKeyUsage();

        for (int keyTypeIndex = 0; keyTypeIndex < keyTypeLimit; ++keyTypeIndex)
        {
            String keyType = keyTypes.get(keyTypeIndex);
            PublicKeyFilter filter = filters.get(keyType);
            if (null != filter && filter.accepts(publicKey, keyUsage, algorithmConstraints))
            {
                return keyTypeIndex;
            }
        }

        return -1;
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

        static final Quality INVALID = Quality.MISMATCH_SNI;
        static final Match NOTHING = new Match(Quality.NONE, -1, -1, null, null, null);

        final Quality quality;
        final int keyTypeIndex;
        final int builderIndex;
        final String localAlias;
        final KeyStore cachedKeyStore;
        final X509Certificate[] cachedCertificateChain;

        Match(Quality quality, int keyTypeIndex, int builderIndex, String localAlias, KeyStore cachedKeyStore,
            X509Certificate[] cachedCertificateChain)
        {
            this.quality = quality;
            this.keyTypeIndex = keyTypeIndex;
            this.builderIndex = builderIndex;
            this.localAlias = localAlias;
            this.cachedKeyStore = cachedKeyStore;
            this.cachedCertificateChain = cachedCertificateChain;
        }

        public int compareTo(Match that)
        {
            int cmp = Boolean.compare(that.isValid(), this.isValid());
            if (cmp == 0)
            {
                cmp = Integer.compare(this.keyTypeIndex, that.keyTypeIndex);
                if (cmp == 0)
                {
                    cmp = this.quality.compareTo(that.quality);
                }
            }
            return cmp;
        }

        boolean isIdeal()
        {
            return Quality.OK == quality && 0 == keyTypeIndex;
        }

        boolean isValid()
        {
            return quality.compareTo(INVALID) < 0;
        }
    }

    private static interface PublicKeyFilter
    {
        boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints);
    }

    private static final class DefaultPublicKeyFilter
        implements PublicKeyFilter
    {
        final String algorithm;
        final Class<? extends PublicKey> clazz;
        final int keyUsageBit;

        DefaultPublicKeyFilter(String algorithm, Class<? extends PublicKey> clazz, int keyUsageBit)
        {
            this.algorithm = algorithm;
            this.clazz = clazz;
            this.keyUsageBit = keyUsageBit;
        }

        public boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints)
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

    private static final class ECPublicKeyFilter13
        implements PublicKeyFilter
    {
        final ASN1ObjectIdentifier standardOID;

        ECPublicKeyFilter13(ASN1ObjectIdentifier standardOID)
        {
            this.standardOID = standardOID;
        }

        public boolean accepts(PublicKey publicKey, boolean[] keyUsage, BCAlgorithmConstraints algorithmConstraints)
        {
            return appliesTo(publicKey)
                && ProvAlgorithmChecker.permitsKeyUsage(publicKey, keyUsage, ProvAlgorithmChecker.KU_DIGITAL_SIGNATURE,
                    algorithmConstraints);
        }

        private boolean appliesTo(PublicKey publicKey)
        {
            if ("EC".equalsIgnoreCase(JsseUtils.getPublicKeyAlgorithm(publicKey))
                || ECPublicKey.class.isInstance(publicKey))
            {
                ASN1ObjectIdentifier oid = JsseUtils.getNamedCurveOID(publicKey);
                if (standardOID.equals(oid))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
