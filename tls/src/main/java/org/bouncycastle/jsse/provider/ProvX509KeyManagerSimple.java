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
import java.util.List;
import java.util.Map;
import java.util.Set;
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

class ProvX509KeyManagerSimple
    extends BCX509ExtendedKeyManager
{
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManagerSimple.class.getName());

    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final Map<String, Credential> credentials;

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

    private static Map<String, Credential> loadCredentials(KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        Map<String, Credential> credentials = new HashMap<String, Credential>(4);

        if (null != ks)
        {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                if (!ks.entryInstanceOf(alias, PrivateKeyEntry.class))
                {
                    continue;
                }

                PrivateKey privateKey = (PrivateKey)ks.getKey(alias, password);
                if (null == privateKey)
                {
                    continue;
                }

                X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(ks.getCertificateChain(alias));
                if (TlsUtils.isNullOrEmpty(certificateChain))
                {
                    continue;
                }

                credentials.put(alias, new Credential(alias, privateKey, certificateChain));
            }
        }

        return Collections.unmodifiableMap(credentials);
    }

    ProvX509KeyManagerSimple(boolean isInFipsMode, JcaJceHelper helper, KeyStore ks, char[] password)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.credentials = loadCredentials(ks, password);
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
        Credential credential = getCredential(alias);
        return null == credential ? null : credential.certificateChain.clone();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return getAliases(getKeyTypes(keyType), issuers, null, false);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        Credential credential = getCredential(alias);
        return null == credential ? null : credential.privateKey;
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return getAliases(getKeyTypes(keyType), issuers, null, true);
    }

    @Override
    protected BCX509Key getKeyBC(String keyType, String alias)
    {
        Credential credential = getCredential(alias);
        return createKeyBC(keyType, credential);
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatch = getBestMatch(keyTypes, issuers, transportData, forServer);

        if (bestMatch.compareTo(Match.NOTHING) < 0)
        {
            String keyType = keyTypes.get(bestMatch.keyTypeIndex);
            String alias = getAlias(bestMatch);
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
            String keyType = keyTypes.get(bestMatch.keyTypeIndex);

            BCX509Key keyBC = createKeyBC(keyType, bestMatch.credential);
            if (null != keyBC)
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("Found matching key of type: " + keyType + ", from alias: " + getAlias(bestMatch));
                }
                return keyBC;
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(String keyType, Credential credential)
    {
        return null == credential
            ?   null
            :   new ProvX509Key(keyType, credential.privateKey, credential.certificateChain);
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        if (!credentials.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size(); 
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);
            List<Match> matches = null;

            for (Credential credential : credentials.values())
            {
                Match match = getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints,
                    forServer, atDate, requestedHostName);

                if (match.compareTo(Match.NOTHING) < 0)
                {
                    matches = addToMatches(matches, match);
                }
            }

            if (null != matches && !matches.isEmpty())
            {
                // NOTE: We are relying on this being a stable sort
                Collections.sort(matches);

                return getAliases(matches);
            }
        }

        return null;
    }

    private Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData,
        boolean forServer)
    {
        Match bestMatchSoFar = Match.NOTHING;

        if (!credentials.isEmpty() && !keyTypes.isEmpty())
        {
            int keyTypeLimit = keyTypes.size(); 
            Set<Principal> uniqueIssuers = getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = getRequestedHostName(transportData, forServer);

            for (Credential credential : credentials.values())
            {
                Match match = getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers,
                    algorithmConstraints, forServer, atDate, requestedHostName);

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

        return bestMatchSoFar;
    }

    private Match getPotentialMatch(Credential credential, List<String> keyTypes, int keyTypeLimit,
        Set<Principal> uniqueIssuers, BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate,
        String requestedHostName)
    {
        X509Certificate[] chain = credential.certificateChain;
        if (!TlsUtils.isNullOrEmpty(chain) && isSuitableChainForIssuers(chain, uniqueIssuers))
        {
            int keyTypeIndex = getSuitableKeyTypeForEECert(chain[0], keyTypes, keyTypeLimit, algorithmConstraints,
                forServer);
            if (keyTypeIndex >= 0 && isSuitableChain(chain, algorithmConstraints, forServer))
            {
                Match.Quality quality = getCertificateQuality(chain[0], atDate, requestedHostName);

                return new Match(quality, keyTypeIndex, credential);
            }
        }
        return Match.NOTHING;
    }

    private Credential getCredential(String alias)
    {
        return null == alias ? null : credentials.get(alias);
    }

    private boolean isSuitableChain(X509Certificate[] chain, BCAlgorithmConstraints algorithmConstraints,
        boolean forServer)
    {
        try
        {
            Set<X509Certificate> trustedCerts = Collections.emptySet();
            KeyPurposeId ekuOID = ProvX509KeyManager.getRequiredExtendedKeyUsage(forServer);
            int kuBit = -1; // i.e. no checks; we handle them in isSuitableEECert

            ProvAlgorithmChecker.checkChain(isInFipsMode, helper, algorithmConstraints, trustedCerts, chain, ekuOID,
                kuBit);

            return true;
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }
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

    private static String getAlias(Match match)
    {
        return match.credential.alias;
    }

    private static String[] getAliases(List<Match> matches)
    {
        int count = matches.size(), pos = 0;
        String[] result = new String[count];
        for (Match match : matches)
        {
            result[pos++] = getAlias(match);
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

    private static class Credential
    {
        private final String alias;
        private final PrivateKey privateKey;
        private final X509Certificate[] certificateChain;

        Credential(String alias, PrivateKey privateKey, X509Certificate[] certificateChain)
        {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }
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
        static final Match NOTHING = new Match(Quality.NONE, -1, null);

        final Quality quality;
        final int keyTypeIndex;
        final Credential credential;

        Match(Quality quality, int keyTypeIndex, Credential credential)
        {
            this.quality = quality;
            this.keyTypeIndex = keyTypeIndex;
            this.credential = credential;
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
