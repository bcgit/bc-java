package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

class SignatureSchemeInfo
{
    private static final Logger LOG = Logger.getLogger(SignatureSchemeInfo.class.getName());

    static final int historical_dsa_sha1 = 0x0202;
    static final int historical_dsa_sha224 = 0x0302;
    static final int historical_dsa_sha256 = 0x0402;
    static final int historical_ecdsa_sha224 = 0x0303;
    static final int historical_rsa_md5 = 0x0101;
    static final int historical_rsa_sha224 = 0x0301;

    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES = "jdk.tls.client.SignatureSchemes";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES = "jdk.tls.server.SignatureSchemes";

    private static final String PROPERTY_CLIENT_SIGNATURE_SCHEMES_CERT = "org.bouncycastle.jsse.client.SignatureSchemesCert";
    private static final String PROPERTY_SERVER_SIGNATURE_SCHEMES_CERT = "org.bouncycastle.jsse.server.SignatureSchemesCert";

    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private enum All
    {
        ed25519(SignatureScheme.ed25519, "Ed25519", "Ed25519"),
        ed448(SignatureScheme.ed448, "Ed448", "Ed448"),

        ecdsa_secp256r1_sha256(SignatureScheme.ecdsa_secp256r1_sha256, "SHA256withECDSA", "EC"),
        ecdsa_secp384r1_sha384(SignatureScheme.ecdsa_secp384r1_sha384, "SHA384withECDSA", "EC"),
        ecdsa_secp521r1_sha512(SignatureScheme.ecdsa_secp521r1_sha512, "SHA512withECDSA", "EC"),

        ecdsa_brainpoolP256r1tls13_sha256(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256, "SHA256withECDSA", "EC"),
        ecdsa_brainpoolP384r1tls13_sha384(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384, "SHA384withECDSA", "EC"),
        ecdsa_brainpoolP512r1tls13_sha512(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512, "SHA512withECDSA", "EC"),

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
        rsa_pss_pss_sha256(SignatureScheme.rsa_pss_pss_sha256, "SHA256withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha384(SignatureScheme.rsa_pss_pss_sha384, "SHA384withRSAandMGF1", "RSASSA-PSS"),
        rsa_pss_pss_sha512(SignatureScheme.rsa_pss_pss_sha512, "SHA512withRSAandMGF1", "RSASSA-PSS"),

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
        rsa_pss_rsae_sha256(SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha384(SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1", "RSA"),
        rsa_pss_rsae_sha512(SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1", "RSA"),

        // Deprecated: only for certs in 1.3
        rsa_pkcs1_sha256(SignatureScheme.rsa_pkcs1_sha256, "SHA256withRSA", "RSA", true),
        rsa_pkcs1_sha384(SignatureScheme.rsa_pkcs1_sha384, "SHA384withRSA", "RSA", true),
        rsa_pkcs1_sha512(SignatureScheme.rsa_pkcs1_sha512, "SHA512withRSA", "RSA", true),

        sm2sig_sm3(SignatureScheme.sm2sig_sm3, "SM3withSM2", "EC"),

        // TODO[tls] Need mechanism for restricting signature schemes to TLS 1.3+ before adding
        DRAFT_mldsa44(SignatureScheme.DRAFT_mldsa44, "ML-DSA-44", "ML-DSA-44"),
        DRAFT_mldsa65(SignatureScheme.DRAFT_mldsa65, "ML-DSA-65", "ML-DSA-65"),
        DRAFT_mldsa87(SignatureScheme.DRAFT_mldsa87, "ML-DSA-87", "ML-DSA-87"),

        /*
         * Legacy/Historical: mostly not supported in 1.3, except ecdsa_sha1 and rsa_pkcs1_sha1 are
         * still permitted as a last resort for certs.
         */
        dsa_sha256(historical_dsa_sha256, "dsa_sha256", "SHA256withDSA", "DSA"),
        ecdsa_sha224(historical_ecdsa_sha224, "ecdsa_sha224", "SHA224withECDSA", "EC"),
        rsa_sha224(historical_rsa_sha224, "rsa_sha224", "SHA224withRSA", "RSA"),
        dsa_sha224(historical_dsa_sha224, "dsa_sha224", "SHA224withDSA", "DSA"),
        ecdsa_sha1(SignatureScheme.ecdsa_sha1, "SHA1withECDSA", "EC", true),
        rsa_pkcs1_sha1(SignatureScheme.rsa_pkcs1_sha1, "SHA1withRSA", "RSA", true),
        dsa_sha1(historical_dsa_sha1, "dsa_sha1", "SHA1withDSA", "DSA"),
        rsa_md5(historical_rsa_md5, "rsa_md5", "MD5withRSA", "RSA");

        private final int signatureScheme;
        private final String name;
        private final String text;
        private final String jcaSignatureAlgorithm;
        private final String jcaSignatureAlgorithmBC;
        private final String keyAlgorithm;
        private final String keyType13;
        private final boolean supportedPost13;
        private final boolean supportedPre13;
        private final boolean supportedCerts13;
        private final int namedGroup13;

        private All(int signatureScheme, String jcaSignatureAlgorithm, String keyAlgorithm)
        {
            this(signatureScheme, jcaSignatureAlgorithm, keyAlgorithm, true, true,
                SignatureScheme.getNamedGroup(signatureScheme));
        }

        // Deprecated/Legacy
        private All(int signatureScheme, String jcaSignatureAlgorithm, String keyAlgorithm, boolean supportedCerts13)
        {
            this(signatureScheme, jcaSignatureAlgorithm, keyAlgorithm, false, supportedCerts13, -1);
        }

        private All(int signatureScheme, String jcaSignatureAlgorithm, String keyAlgorithm, boolean supportedPost13,
            boolean supportedCerts13, int namedGroup13)
        {
            this(signatureScheme, SignatureScheme.getName(signatureScheme), jcaSignatureAlgorithm, keyAlgorithm,
                supportedPost13, supportedCerts13, namedGroup13);
        }

        // Historical
        private All(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm)
        {
            this(signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm, false, false, -1);
        }

        private All(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm,
            boolean supportedPost13, boolean supportedCerts13, int namedGroup13)
        {
            String keyType13 = JsseUtils.getKeyType13(keyAlgorithm, namedGroup13);
            String jcaSignatureAlgorithmBC = JsseUtils.getJcaSignatureAlgorithmBC(jcaSignatureAlgorithm, keyAlgorithm);


            this.signatureScheme = signatureScheme;
            this.name = name;
            this.text = name + "(0x" + Integer.toHexString(signatureScheme) + ")";
            this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
            this.jcaSignatureAlgorithmBC = jcaSignatureAlgorithmBC;
            this.keyAlgorithm = keyAlgorithm;
            this.keyType13 = keyType13;
            this.supportedPost13 = supportedPost13;
            this.supportedPre13 = (namedGroup13 < 0) || NamedGroup.canBeNegotiated(namedGroup13, ProtocolVersion.TLSv12);
            this.supportedCerts13 = supportedCerts13;
            this.namedGroup13 = namedGroup13;
        }
    }

    private static final int[] CANDIDATES_DEFAULT = createCandidatesDefault();

    static class PerConnection
    {
        private final List<SignatureSchemeInfo> localSigSchemes;
        private final List<SignatureSchemeInfo> localSigSchemesCert;
        private final AtomicReference<List<SignatureSchemeInfo>> peerSigSchemes;
        private final AtomicReference<List<SignatureSchemeInfo>> peerSigSchemesCert;

        PerConnection(List<SignatureSchemeInfo> localSigSchemes, List<SignatureSchemeInfo> localSigSchemesCert)
        {
            this.localSigSchemes = localSigSchemes;
            this.localSigSchemesCert = localSigSchemesCert;
            this.peerSigSchemes = new AtomicReference<List<SignatureSchemeInfo>>();
            this.peerSigSchemesCert = new AtomicReference<List<SignatureSchemeInfo>>();
        }

        String[] getLocalJcaSignatureAlgorithms()
        {
            return getJcaSignatureAlgorithms(getLocalSigSchemesCert());
        }

        String[] getLocalJcaSignatureAlgorithmsBC()
        {
            return getJcaSignatureAlgorithmsBC(getLocalSigSchemesCert());
        }

        Vector<SignatureAndHashAlgorithm> getLocalSignatureAndHashAlgorithms()
        {
            return getSignatureAndHashAlgorithms(localSigSchemes);
        }

        Vector<SignatureAndHashAlgorithm> getLocalSignatureAndHashAlgorithmsCert()
        {
            return getSignatureAndHashAlgorithms(localSigSchemesCert);
        }

        List<SignatureSchemeInfo> getLocalSigSchemes()
        {
            return localSigSchemes;
        }

        List<SignatureSchemeInfo> getLocalSigSchemesCert()
        {
            return localSigSchemesCert != null ? localSigSchemesCert : getLocalSigSchemes();
        }

        String[] getPeerJcaSignatureAlgorithms()
        {
            return getJcaSignatureAlgorithms(getPeerSigSchemesCert());
        }

        String[] getPeerJcaSignatureAlgorithmsBC()
        {
            return getJcaSignatureAlgorithmsBC(getPeerSigSchemesCert());
        }

        List<SignatureSchemeInfo> getPeerSigSchemes()
        {
            return peerSigSchemes.get();
        }

        List<SignatureSchemeInfo> getPeerSigSchemesCert()
        {
            List<SignatureSchemeInfo> sigSchemesCert = peerSigSchemesCert.get();

            return sigSchemesCert != null ? sigSchemesCert : getPeerSigSchemes();
        }

        boolean hasLocalSignatureScheme(SignatureSchemeInfo signatureSchemeInfo)
        {
            return localSigSchemes.contains(signatureSchemeInfo);
        }

        void notifyPeerData(List<SignatureSchemeInfo> sigSchemes, List<SignatureSchemeInfo> sigSchemesCert)
        {
            peerSigSchemes.set(sigSchemes);
            peerSigSchemesCert.set(sigSchemesCert);
        }
    }

    static class PerContext
    {
        private final Map<Integer, SignatureSchemeInfo> index;
        private final int[] candidatesClient, candidatesServer;
        private final int[] candidatesCertClient, candidatesCertServer;

        PerContext(Map<Integer, SignatureSchemeInfo> index, int[] candidatesClient, int[] candidatesServer,
            int[] candidatesCertClient, int[] candidatesCertServer)
        {
            this.index = index;
            this.candidatesClient = candidatesClient;
            this.candidatesServer = candidatesServer;
            this.candidatesCertClient = candidatesCertClient;
            this.candidatesCertServer = candidatesCertServer;
        }
    }

    static PerConnection createPerConnectionClient(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions, NamedGroupInfo.PerConnection namedGroups)
    {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(latest))
        {
            return new PerConnection(null, null);
        }

        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        return createPerConnection(perContext, false, sslParameters, earliest, latest, namedGroups);
    }

    static PerConnection createPerConnectionServer(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion negotiatedVersion, NamedGroupInfo.PerConnection namedGroups)
    {
        if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(negotiatedVersion))
        {
            return new PerConnection(null, null);
        }

        return createPerConnection(perContext, true, sslParameters, negotiatedVersion, negotiatedVersion, namedGroups);
    }

    private static PerConnection createPerConnection(PerContext perContext, boolean isServer, ProvSSLParameters sslParameters,
        ProtocolVersion earliest, ProtocolVersion latest, NamedGroupInfo.PerConnection namedGroups)
    {
        int[] candidates;
        {
            String[] signatureSchemes = sslParameters.getSignatureSchemes();

            if (signatureSchemes == null)
            {
                candidates = isServer ? perContext.candidatesServer : perContext.candidatesClient;

                if (candidates == null)
                {
                    candidates = CANDIDATES_DEFAULT;
                }
            }
            else
            {
                candidates = createCandidates(perContext.index, signatureSchemes, "SSLParameters.signatureSchemes");
            }
        }

        int[] candidatesCert;
        {
            String[] signatureSchemesCert = sslParameters.getSignatureSchemesCert();

            if (signatureSchemesCert == null)
            {
                candidatesCert = isServer ? perContext.candidatesCertServer : perContext.candidatesCertClient;
            }
            else
            {
                candidatesCert = createCandidates(perContext.index, signatureSchemesCert,
                    "SSLParameters.signatureSchemesCert");
            }
        }

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        ArrayList<SignatureSchemeInfo> localSigSchemes;
        {
            int count = candidates.length;
            localSigSchemes = new ArrayList<SignatureSchemeInfo>(count);
            for (int i = 0; i < count; ++i)
            {
                Integer candidate = Integers.valueOf(candidates[i]);
                SignatureSchemeInfo signatureSchemeInfo = perContext.index.get(candidate);

                if (null != signatureSchemeInfo
                    && signatureSchemeInfo.isActiveCerts(algorithmConstraints, post13Active, pre13Active, namedGroups))
                {
                    localSigSchemes.add(signatureSchemeInfo);
                }
            }
            localSigSchemes.trimToSize();
        }

        ArrayList<SignatureSchemeInfo> localSigSchemesCert = null;
        if (candidatesCert != null)
        {
            int count = candidatesCert.length;
            localSigSchemesCert = new ArrayList<SignatureSchemeInfo>(count);
            for (int i = 0; i < count; ++i)
            {
                Integer candidate = Integers.valueOf(candidatesCert[i]);
                SignatureSchemeInfo signatureSchemeInfo = perContext.index.get(candidate);

                if (null != signatureSchemeInfo
                    && signatureSchemeInfo.isActiveCerts(algorithmConstraints, post13Active, pre13Active, namedGroups))
                {
                    localSigSchemesCert.add(signatureSchemeInfo);
                }
            }
            localSigSchemesCert.trimToSize();
        }

        return new PerConnection(localSigSchemes, localSigSchemesCert);
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto,
        NamedGroupInfo.PerContext namedGroups)
    {
        Map<Integer, SignatureSchemeInfo> index = createIndex(isFipsContext, crypto, namedGroups);

        int[] candidatesClient = createCandidatesFromProperty(index, PROPERTY_CLIENT_SIGNATURE_SCHEMES);
        int[] candidatesServer = createCandidatesFromProperty(index, PROPERTY_SERVER_SIGNATURE_SCHEMES);

        int[] candidatesCertClient = createCandidatesFromProperty(index, PROPERTY_CLIENT_SIGNATURE_SCHEMES_CERT);
        int[] candidatesCertServer = createCandidatesFromProperty(index, PROPERTY_SERVER_SIGNATURE_SCHEMES_CERT);

        return new PerContext(index, candidatesClient, candidatesServer, candidatesCertClient, candidatesCertServer);
    }

    private static String[] getJcaSignatureAlgorithms(Collection<SignatureSchemeInfo> infos)
    {
        if (null == infos)
        {
            return TlsUtils.EMPTY_STRINGS;
        }

        String[] result = new String[infos.size()];
        int resultPos = 0;
        for (SignatureSchemeInfo info : infos)
        {
            // TODO The two kinds of PSS signature scheme can give duplicates here
            result[resultPos++] = info.getJcaSignatureAlgorithm();
        }
        return result;
    }

    private static String[] getJcaSignatureAlgorithmsBC(Collection<SignatureSchemeInfo> infos)
    {
        if (null == infos)
        {
            return TlsUtils.EMPTY_STRINGS;
        }

        String[] result = new String[infos.size()];
        int resultPos = 0;
        for (SignatureSchemeInfo info : infos)
        {
            result[resultPos++] = info.getJcaSignatureAlgorithmBC();
        }
        return result;
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }

        return SignatureScheme.getSignatureAndHashAlgorithm(signatureScheme);
    }

    private static Vector<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(
        Collection<SignatureSchemeInfo> signatureSchemeInfos)
    {
        // TODO[tls13] Actually should return empty for empty?
        if (null == signatureSchemeInfos || signatureSchemeInfos.isEmpty())
        {
            return null;
        }

        int count = signatureSchemeInfos.size();
        Vector<SignatureAndHashAlgorithm> result = new Vector<SignatureAndHashAlgorithm>(count);
        for (SignatureSchemeInfo signatureSchemeInfo : signatureSchemeInfos)
        {
            if (null != signatureSchemeInfo)
            {
                SignatureAndHashAlgorithm sigAndHashAlg = signatureSchemeInfo.getSignatureAndHashAlgorithm();

                result.add(sigAndHashAlg);
            }
        }
        if (result.isEmpty())
        {
            // TODO[tls13] Actually should return empty for empty?
            return null;
        }
        result.trimToSize();
        return result;
    }

    static List<SignatureSchemeInfo> getSignatureSchemes(PerContext perContext,
        Vector<SignatureAndHashAlgorithm> sigAndHashAlgs)
    {
        if (null == sigAndHashAlgs || sigAndHashAlgs.isEmpty())
        {
            return null;
        }

        int count = sigAndHashAlgs.size();
        ArrayList<SignatureSchemeInfo> result = new ArrayList<SignatureSchemeInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            SignatureAndHashAlgorithm sigAndHashAlg = sigAndHashAlgs.elementAt(i);
            if (null != sigAndHashAlg)
            {
                int signatureScheme = SignatureScheme.from(sigAndHashAlg);

                SignatureSchemeInfo signatureSchemeInfo = perContext.index.get(signatureScheme);
                if (null != signatureSchemeInfo)
                {
                    result.add(signatureSchemeInfo);
                }
            }
        }
        if (result.isEmpty())
        {
            return null;
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    private static void addSignatureScheme(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext ng,
        Map<Integer, SignatureSchemeInfo> ss, All all)
    {
        final int signatureScheme = all.signatureScheme;

        if (isFipsContext && !FipsUtils.isFipsSignatureScheme(signatureScheme))
        {
            // In FIPS mode, non-FIPS schemes are currently not even entered into the map
            return;
        }

        NamedGroupInfo namedGroupInfo = null;
        boolean disabled13 = false;

        int namedGroup13 = all.namedGroup13;
        if (namedGroup13 >= 0)
        {
            namedGroupInfo = NamedGroupInfo.getNamedGroup(ng, namedGroup13);
            if (null == namedGroupInfo || !namedGroupInfo.isEnabled() || !namedGroupInfo.isSupportedPost13())
            {
                disabled13 = true;
            }
        }

        boolean enabled = crypto.hasSignatureScheme(signatureScheme);

        AlgorithmParameters algorithmParameters = null;
        if (enabled)
        {
            // TODO[jsse] Consider also fetching 'jcaSignatureAlgorithm' and 'keyAlgorithm'
            try
            {
                algorithmParameters = crypto.getSignatureSchemeAlgorithmParameters(signatureScheme);
            }
            catch (Exception e)
            {
                enabled = false;
            }
        }

        SignatureSchemeInfo signatureSchemeInfo = new SignatureSchemeInfo(all, algorithmParameters, namedGroupInfo,
            enabled, disabled13);

        if (null != ss.put(signatureScheme, signatureSchemeInfo))
        {
            throw new IllegalStateException("Duplicate entries for SignatureSchemeInfo");
        }
    }

    private static int[] createCandidatesFromProperty(Map<Integer, SignatureSchemeInfo> index, String propertyName)
    {
        String[] names = PropertyUtils.getStringArraySystemProperty(propertyName);
        if (null == names)
        {
            return null;
        }

        return createCandidates(index, names, propertyName);
    }

    private static int[] createCandidates(Map<Integer, SignatureSchemeInfo> index, String[] names, String description)
    {
        int[] result = new int[names.length];
        int count = 0;
        for (String name : names)
        {
            int signatureScheme = getSignatureSchemeByName(name);
            if (signatureScheme < 0)
            {
                LOG.warning("'" + description + "' contains unrecognised SignatureScheme: " + name);
                continue;
            }

            SignatureSchemeInfo signatureSchemeInfo = index.get(signatureScheme);
            if (null == signatureSchemeInfo)
            {
                LOG.warning("'" + description + "' contains unsupported SignatureScheme: " + name);
                continue;
            }

            if (!signatureSchemeInfo.isEnabled())
            {
                LOG.warning("'" + description + "' contains disabled SignatureScheme: " + name);
                continue;
            }

            result[count++] = signatureScheme;
        }
        if (count < result.length)
        {
            result = Arrays.copyOf(result, count);
        }
        if (result.length < 1)
        {
            LOG.severe("'" + description + "' contained no usable SignatureScheme values");
        }
        return result;
    }

    private static int[] createCandidatesDefault()
    {
        All[] values = All.values();
        int[] result = new int[values.length];
        for (int i = 0; i < values.length; ++i)
        {
            result[i] = values[i].signatureScheme;
        }
        return result;
    }

    private static Map<Integer, SignatureSchemeInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto,
        NamedGroupInfo.PerContext ng)
    {
        Map<Integer, SignatureSchemeInfo> ss = new TreeMap<Integer, SignatureSchemeInfo>();
        for (All all : All.values())
        {
            addSignatureScheme(isFipsContext, crypto, ng, ss, all);
        }
        return ss;
    }

    private static int getSignatureSchemeByName(String name)
    {
        for (All all : All.values())
        {
            if (all.name.equalsIgnoreCase(name))
            {
                return all.signatureScheme;
            }
        }

        return -1;
    }

    private static boolean isECDSA(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
        case SignatureScheme.ecdsa_secp256r1_sha256:
        case SignatureScheme.ecdsa_secp384r1_sha384:
        case SignatureScheme.ecdsa_secp521r1_sha512:
        case SignatureScheme.ecdsa_sha1:
        case historical_ecdsa_sha224:
            return true;

        default:
            return false;
        }
    }

    private final All all;
    private final AlgorithmParameters algorithmParameters;
    private final NamedGroupInfo namedGroupInfo;
    private final boolean enabled;
    private final boolean disabled13;

    SignatureSchemeInfo(All all, AlgorithmParameters algorithmParameters, NamedGroupInfo namedGroupInfo,
        boolean enabled, boolean disabled13)
    {
        this.all = all;
        this.algorithmParameters = algorithmParameters;
        this.namedGroupInfo = namedGroupInfo;
        this.enabled = enabled;
        this.disabled13 = disabled13;
    }

    short getHashAlgorithm()
    {
        return SignatureScheme.getHashAlgorithm(all.signatureScheme);
    }

    String getJcaSignatureAlgorithm()
    {
        return all.jcaSignatureAlgorithm;
    }

    String getJcaSignatureAlgorithmBC()
    {
        return all.jcaSignatureAlgorithmBC;
    }

    String getKeyType()
    {
        return all.keyAlgorithm;
    }

    String getKeyType13()
    {
        return all.keyType13;
    }

    String getName()
    {
        return all.name;
    }

    NamedGroupInfo getNamedGroupInfo()
    {
        return namedGroupInfo;
    }

    short getSignatureAlgorithm()
    {
        return SignatureScheme.getSignatureAlgorithm(all.signatureScheme);
    }

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return getSignatureAndHashAlgorithm(all.signatureScheme);
    }

    int getSignatureScheme()
    {
        return all.signatureScheme;
    }

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isSupportedPost13()
    {
        return !disabled13 && all.supportedPost13;
    }

    boolean isSupportedPre13()
    {
        return all.supportedPre13;
    }

    boolean isSupportedCerts13()
    {
        return !disabled13 && all.supportedCerts13;
    }

    @Override
    public String toString()
    {
        return all.text;
    }

    // TODO Refactor to use this in non-cert contexts (careful for signatureSchemesCert defaulting case)
//    private boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean post13Active, boolean pre13Active,
//        NamedGroupInfo.PerConnection namedGroupInfos)
//    {
//        return enabled
//            && isNamedGroupOK(post13Active && isSupportedPost13(), pre13Active && isSupportedPre13(), namedGroupInfos)
//            && isPermittedBy(algorithmConstraints);
//    }

    private boolean isActiveCerts(BCAlgorithmConstraints algorithmConstraints, boolean post13Active,
        boolean pre13Active, NamedGroupInfo.PerConnection namedGroupInfos)
    {
        return enabled
            && isNamedGroupOK(post13Active && isSupportedCerts13(), pre13Active && isSupportedPre13(), namedGroupInfos)
            && isPermittedBy(algorithmConstraints);
    }

    private boolean isNamedGroupOK(boolean post13Allowed, boolean pre13Allowed, NamedGroupInfo.PerConnection namedGroupInfos)
    {
        if (null != namedGroupInfo)
        {
                   // TODO[tls13] NOTE: a "restricted group" scheme actually supporting TLS 1.3 usage 
            return (post13Allowed && NamedGroupInfo.hasLocal(namedGroupInfos, namedGroupInfo.getNamedGroup()))
                   // TODO[tls13] NOTE: this can result in a "restricted group" scheme being active, but not actually supporting TLS 1.3 
                || (pre13Allowed && NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos));
        }

        return (post13Allowed || pre13Allowed)
            && (!isECDSA(all.signatureScheme) || NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos));
    }

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, all.name, null)
            && algorithmConstraints.permits(primitives, all.keyAlgorithm, null)
            && algorithmConstraints.permits(primitives, all.jcaSignatureAlgorithm, algorithmParameters);
    }
}
