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

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Integers;

class SignatureSchemeInfo
{
//    private static final Logger LOG = Logger.getLogger(SignatureSchemeInfo.class.getName());

    static final int historical_rsa_md5 = 0x0101;
    static final int historical_rsa_sha224 = 0x0301;

    static final int historical_dsa_sha1 = 0x0202;
    static final int historical_dsa_sha224 = 0x0302;
    static final int historical_dsa_sha256 = 0x0402;

    static final int historical_ecdsa_sha224 = 0x0303;

    // TODO Support jdk.tls.signatureSchemes, a mooted feature in SunJSSE (see JDK-8229720)
    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private static final int[] DEFAULT_CANDIDATES = {
        SignatureScheme.ed25519,
        SignatureScheme.ed448,
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ecdsa_secp521r1_sha512,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
        SignatureScheme.rsa_pss_pss_sha256,
        SignatureScheme.rsa_pss_pss_sha384,
        SignatureScheme.rsa_pss_pss_sha512,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.rsa_pkcs1_sha384,
        SignatureScheme.rsa_pkcs1_sha512,
        historical_dsa_sha256,
        historical_ecdsa_sha224,
        historical_rsa_sha224,
        historical_dsa_sha224,
        SignatureScheme.ecdsa_sha1,
        SignatureScheme.rsa_pkcs1_sha1,
        historical_dsa_sha1,
        historical_rsa_md5,
    };

    static class PerContext
    {
        private final Map<Integer, SignatureSchemeInfo> index;
        private final int[] candidates;

        PerContext(Map<Integer, SignatureSchemeInfo> index, int[] candidates)
        {
            this.index = index;
            this.candidates = candidates;
        }
    }

    static PerContext createPerContext(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext namedGroups)
    {
        Map<Integer, SignatureSchemeInfo> index = createIndex(isFipsContext, crypto, namedGroups);
        int[] candidates = createCandidates(index);

        return new PerContext(index, candidates);
    }

    static List<SignatureSchemeInfo> getActiveCertsSignatureSchemes(PerContext perContext, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions, NamedGroupInfo.PerConnection namedGroups)
    {
        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(latest))
        {
            return null;
        }

        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();
        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        int count = perContext.candidates.length;
        ArrayList<SignatureSchemeInfo> result = new ArrayList<SignatureSchemeInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            Integer candidate = Integers.valueOf(perContext.candidates[i]);
            SignatureSchemeInfo signatureSchemeInfo = perContext.index.get(candidate);

            if (null != signatureSchemeInfo
                && signatureSchemeInfo.isActiveCerts(algorithmConstraints, pre13Active, post13Active, namedGroups))
            {
                result.add(signatureSchemeInfo);
            }
        }
        if (result.isEmpty())
        {
            return Collections.emptyList();
        }
        result.trimToSize();
        return Collections.unmodifiableList(result);
    }

    static String[] getJcaSignatureAlgorithms(Collection<SignatureSchemeInfo> infos)
    {
        if (null == infos)
        {
            return new String[0];
        }

        ArrayList<String> result = new ArrayList<String>();
        for (SignatureSchemeInfo info : infos)
        {
            result.add(info.getJcaSignatureAlgorithm());
        }
        return result.toArray(new String[0]);
    }

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }

        short hashAlgorithm = SignatureScheme.getHashAlgorithm(signatureScheme);
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);

        return SignatureAndHashAlgorithm.getInstance(hashAlgorithm, signatureAlgorithm);
    }

    static Vector<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms(List<SignatureSchemeInfo> signatureSchemeInfos)
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

    static int getSignatureScheme(SignatureAndHashAlgorithm sigAndHashAlg)
    {
        if (null == sigAndHashAlg)
        {
            throw new NullPointerException();
        }

        short hashAlgorithm = sigAndHashAlg.getHash(), signatureAlgorithm = sigAndHashAlg.getSignature();

        return ((hashAlgorithm & 0xFF) << 8) | (signatureAlgorithm & 0xFF);
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
                int signatureScheme = SignatureSchemeInfo.getSignatureScheme(sigAndHashAlg);

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
        Map<Integer, SignatureSchemeInfo> ss, int signatureScheme, String name, String jcaSignatureAlgorithm,
        String keyAlgorithm, boolean supported13, boolean supportedCerts13)
    {
        if (isFipsContext && !FipsUtils.isFipsSignatureScheme(signatureScheme))
        {
            // In FIPS mode, non-FIPS schemes are currently not even entered into the map
            return;
        }

        NamedGroupInfo namedGroupInfo = null;

        int namedGroup = SignatureScheme.getNamedGroup(signatureScheme);
        if (namedGroup >= 0)
        {
            namedGroupInfo = NamedGroupInfo.getNamedGroup(ng, namedGroup);
            if (null == namedGroupInfo || !namedGroupInfo.isEnabled())
            {
                supported13 = false;
                supportedCerts13 = false;
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

        SignatureSchemeInfo signatureSchemeInfo = new SignatureSchemeInfo(signatureScheme, name, jcaSignatureAlgorithm,
            keyAlgorithm, algorithmParameters, supported13, supportedCerts13, namedGroupInfo, enabled);

        if (null != ss.put(signatureScheme, signatureSchemeInfo))
        {
            throw new IllegalStateException("Duplicate entries for SignatureSchemeInfo");
        }
    }

    private static void addSignatureScheme(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext ng,
        Map<Integer, SignatureSchemeInfo> ss, int signatureScheme, String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        String name = SignatureScheme.getName(signatureScheme);

        addSignatureScheme(isFipsContext, crypto, ng, ss, signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm,
            true, true);
    }

    private static void addSignatureSchemeDeprecated(boolean isFipsContext, JcaTlsCrypto crypto, NamedGroupInfo.PerContext ng,
        Map<Integer, SignatureSchemeInfo> ss, int signatureScheme, String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        String name = SignatureScheme.getName(signatureScheme);

        addSignatureScheme(isFipsContext, crypto, ng, ss, signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm,
            false, true);
    }

    private static void addSignatureSchemeHistorical(boolean isFipsContext, JcaTlsCrypto crypto,
        NamedGroupInfo.PerContext ng, Map<Integer, SignatureSchemeInfo> ss, int signatureScheme, String name,
        String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        addSignatureScheme(isFipsContext, crypto, ng, ss, signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm,
            false, false);
    }

    private static void addSignatureSchemeLegacy(boolean isFipsContext, JcaTlsCrypto crypto,
        NamedGroupInfo.PerContext ng, Map<Integer, SignatureSchemeInfo> ss, int signatureScheme,
        String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        /*
         * TODO[tls13] Is there more to do around these restrictions?
         * 
         * RFC 8446 4.2.3. Endpoints SHOULD NOT negotiate these algorithms but are permitted to do
         * so solely for backward compatibility. Clients offering these values MUST list them as the
         * lowest priority (listed after all other algorithms in SignatureSchemeList). TLS 1.3
         * servers MUST NOT offer a SHA-1 signed certificate unless no valid certificate chain can
         * be produced without it [..].
         */
        addSignatureSchemeDeprecated(isFipsContext, crypto, ng, ss, signatureScheme, jcaSignatureAlgorithm, keyAlgorithm);
    }

    private static Map<Integer, SignatureSchemeInfo> createIndex(boolean isFipsContext, JcaTlsCrypto crypto,
        NamedGroupInfo.PerContext ng)
    {
        Map<Integer, SignatureSchemeInfo> ss = new TreeMap<Integer, SignatureSchemeInfo>();

        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.ecdsa_secp256r1_sha256, "SHA256withECDSA",
            "EC");
        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.ecdsa_secp384r1_sha384, "SHA384withECDSA",
            "EC");
        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.ecdsa_secp521r1_sha512, "SHA512withECDSA",
            "EC");

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1",
//            "RSA");
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1",
//            "RSA");
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1",
//            "RSA");

        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.ed25519, "Ed25519", "Ed25519");
        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.ed448, "Ed448", "Ed448");

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_pss_sha256, "SHA256withRSAandMGF1",
//            "RSASSA-PSS");
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_pss_sha384, "SHA384withRSAandMGF1",
//            "RSASSA-PSS");
//        addSignatureScheme(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pss_pss_sha512, "SHA512withRSAandMGF1",
//            "RSASSA-PSS");

        addSignatureSchemeDeprecated(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pkcs1_sha256, "SHA256withRSA",
            "RSA");
        addSignatureSchemeDeprecated(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pkcs1_sha384, "SHA384withRSA",
            "RSA");
        addSignatureSchemeDeprecated(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pkcs1_sha512, "SHA512withRSA",
            "RSA");

        /*
         * Legacy algorithms: "These values refer solely to signatures which appear in certificates
         * (see Section 4.4.2.2) and are not defined for use in signed TLS handshake messages,
         * although they MAY appear in "signature_algorithms" and "signature_algorithms_cert" for
         * backward compatibility with TLS 1.2."
         */
        addSignatureSchemeLegacy(isFipsContext, crypto, ng, ss, SignatureScheme.rsa_pkcs1_sha1, "SHA1withRSA", "RSA");
        addSignatureSchemeLegacy(isFipsContext, crypto, ng, ss, SignatureScheme.ecdsa_sha1, "SHA1withECDSA", "EC");

        /*
         * Historical algorithms (for SignatureAndHashAlgorithm values): TLS 1.2 and earlier only.
         */
        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_rsa_md5,
            "rsa_md5", "MD5withRSA", "RSA");
        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_rsa_sha224,
            "rsa_sha224", "SHA224withRSA", "RSA");

        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_dsa_sha1, "dsa_sha1",
            "SHA1withDSA", "DSA");
        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_dsa_sha224,
            "dsa_sha224", "SHA224withDSA", "DSA");
        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_dsa_sha256,
            "dsa_sha256", "SHA256withDSA", "DSA");

        addSignatureSchemeHistorical(isFipsContext, crypto, ng, ss, SignatureSchemeInfo.historical_ecdsa_sha224,
            "ecdsa_sha224", "SHA224withECDSA", "EC");

        return ss;
    }

    private static int[] createCandidates(Map<Integer, SignatureSchemeInfo> index)
    {
        return DEFAULT_CANDIDATES;
    }

    private static boolean isECDSA(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.ecdsa_sha1:
        case historical_ecdsa_sha224:
        case SignatureScheme.ecdsa_secp256r1_sha256:
        case SignatureScheme.ecdsa_secp384r1_sha384:
        case SignatureScheme.ecdsa_secp521r1_sha512:
            return true;

        default:
            return false;
        }
    }

    private final int signatureScheme;
    private final String name;
    private final String jcaSignatureAlgorithm;
    private final String keyAlgorithm;
    private final AlgorithmParameters algorithmParameters;
    private final boolean supported13;
    private final boolean supportedCerts13;
    private final NamedGroupInfo namedGroupInfo;
    private final boolean enabled;

    SignatureSchemeInfo(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm,
        AlgorithmParameters algorithmParameters, boolean supported13, boolean supportedCerts13,
        NamedGroupInfo namedGroupInfo, boolean enabled)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }
        if (!supportedCerts13 && (supported13 || null != namedGroupInfo))
        {
            throw new IllegalArgumentException();
        }

        this.signatureScheme = signatureScheme;
        this.name = name;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.algorithmParameters = algorithmParameters;
        this.supported13 = supported13;
        this.supportedCerts13 = supportedCerts13;
        this.namedGroupInfo = namedGroupInfo;
        this.enabled = enabled;
    }

    short getHashAlgorithm()
    {
        return SignatureScheme.getHashAlgorithm(signatureScheme);
    }

    String getJcaSignatureAlgorithm()
    {
        return jcaSignatureAlgorithm;
    }

    String getKeyAlgorithm()
    {
        return keyAlgorithm;
    }

    String getName()
    {
        return name;
    }

    NamedGroupInfo getNamedGroupInfo()
    {
        return namedGroupInfo;
    }

    short getSignatureAlgorithm()
    {
        return SignatureScheme.getSignatureAlgorithm(signatureScheme);
    }

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return getSignatureAndHashAlgorithm(signatureScheme);
    }

    int getSignatureScheme()
    {
        return signatureScheme;
    }

    boolean isActive(BCAlgorithmConstraints algorithmConstraints, boolean pre13Active, boolean post13Active,
        NamedGroupInfo.PerConnection namedGroupInfos)
    {
        return enabled
            && isNamedGroupOK(pre13Active, post13Active && supported13, namedGroupInfos)
            && isPermittedBy(algorithmConstraints);
    }

    boolean isActiveCerts(BCAlgorithmConstraints algorithmConstraints, boolean pre13Active, boolean post13Active,
        NamedGroupInfo.PerConnection namedGroupInfos)
    {
        return enabled
            && isNamedGroupOK(pre13Active, post13Active && supportedCerts13, namedGroupInfos)
            && isPermittedBy(algorithmConstraints);
    }

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isSupported13()
    {
        return supported13;
    }

    boolean isSupportedCerts13()
    {
        return supportedCerts13;
    }

    @Override
    public String toString()
    {
        return name + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }

    private boolean isNamedGroupOK(boolean pre13Allowed, boolean post13Allowed, NamedGroupInfo.PerConnection namedGroupInfos)
    {
        if (null != namedGroupInfo)
        {
                   // TODO[tls13] NOTE: a "restricted group" scheme actually supporting TLS 1.3 usage 
            return (post13Allowed && NamedGroupInfo.hasLocal(namedGroupInfos, namedGroupInfo.getNamedGroup()))
                   // TODO[tls13] NOTE: this can result in a "restricted group" scheme being active, but not actually supporting TLS 1.3 
                || (pre13Allowed && NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos));
        }

        return (post13Allowed || pre13Allowed)
            && (!isECDSA(signatureScheme) || NamedGroupInfo.hasAnyECDSALocal(namedGroupInfos));
    }

    private boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, keyAlgorithm, null)
            && algorithmConstraints.permits(primitives, jcaSignatureAlgorithm, algorithmParameters);
    }
}
