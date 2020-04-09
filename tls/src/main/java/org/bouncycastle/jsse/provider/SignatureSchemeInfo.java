package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
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

class SignatureSchemeInfo
{
    static final int historical_rsa_md5 = 0x0101;
    static final int historical_rsa_sha224 = 0x0301;

    static final int historical_dsa_sha1 = 0x0202;
    static final int historical_dsa_sha224 = 0x0302;
    static final int historical_dsa_sha256 = 0x0402;

    static final int historical_ecdsa_sha224 = 0x0303;

    // TODO Support jdk.tls.signatureSchemes, a mooted feature in SunJSSE (see JDK-8229720)
    // NOTE: Not all of these are necessarily enabled/supported; it will be checked at runtime
    private static final int[] DEFAULT_ACTIVE = {
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

    static Map<Integer, SignatureSchemeInfo> createSignatureSchemesMap(ProvSSLContextSpi context,
        JcaTlsCrypto crypto)
    {
        Map<Integer, SignatureSchemeInfo> ss = new TreeMap<Integer, SignatureSchemeInfo>();

        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pkcs1_sha256, "SHA256withRSA", "RSA");
        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pkcs1_sha384, "SHA384withRSA", "RSA");
        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pkcs1_sha512, "SHA512withRSA", "RSA");

        // TODO[tls13] Constrain to the specific NamedGroup (only) for TLS 1.3+
        addSignatureScheme(crypto, ss, SignatureScheme.ecdsa_secp256r1_sha256, "SHA256withECDSA", "EC");
        addSignatureScheme(crypto, ss, SignatureScheme.ecdsa_secp384r1_sha384, "SHA384withECDSA", "EC");
        addSignatureScheme(crypto, ss, SignatureScheme.ecdsa_secp521r1_sha512, "SHA512withECDSA", "EC");

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1", "RSA");
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1", "RSA");
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1", "RSA");

        // TODO[jsse] Preferably add FipsUtils.removeNonFipsSignatureSchemes or similar
        if (!context.isFips())
        {
            addSignatureScheme(crypto, ss, SignatureScheme.ed25519, "Ed25519", "Ed25519");
            addSignatureScheme(crypto, ss, SignatureScheme.ed448, "Ed448", "Ed448");
        }

        // NOTE: SunJSSE is using "RSASSA-PSS" as 'jcaSignatureAlgorithm' for all these
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_pss_sha256, "SHA256withRSAandMGF1", "RSASSA-PSS");
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_pss_sha384, "SHA384withRSAandMGF1", "RSASSA-PSS");
//        addSignatureScheme(crypto, ss, SignatureScheme.rsa_pss_pss_sha512, "SHA512withRSAandMGF1", "RSASSA-PSS");

        /*
         * Legacy algorithms: "These values refer solely to signatures which appear in certificates
         * (see Section 4.4.2.2) and are not defined for use in signed TLS handshake messages,
         * although they MAY appear in "signature_algorithms" and "signature_algorithms_cert" for
         * backward compatibility with TLS 1.2."
         */
        addSignatureSchemeLegacy(crypto, ss, SignatureScheme.rsa_pkcs1_sha1, "SHA1withRSA", "RSA");
        addSignatureSchemeLegacy(crypto, ss, SignatureScheme.ecdsa_sha1, "SHA1withECDSA", "EC");

        /*
         * Historical algorithms (for SignatureAndHashAlgorithm values): TLS 1.2 and earlier only.
         */
        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_rsa_md5, "rsa_md5", "MD5withRSA",
            "RSA");
        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_rsa_sha224, "rsa_sha224",
            "SHA224withRSA", "RSA");

        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_dsa_sha1, "dsa_sha1", "SHA1withDSA",
            "DSA");
        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_dsa_sha224, "dsa_sha224",
            "SHA224withDSA", "DSA");
        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_dsa_sha256, "dsa_sha256",
            "SHA256withDSA", "DSA");

        addSignatureSchemeHistorical(crypto, ss, SignatureSchemeInfo.historical_ecdsa_sha224, "ecdsa_sha224",
            "SHA224withECDSA", "EC");

        return Collections.unmodifiableMap(ss);
    }

    static List<SignatureSchemeInfo> getActiveSignatureSchemes(Map<Integer, SignatureSchemeInfo> signatureSchemesMap,
        ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        // TODO[tls13] SignatureSchemeInfo instances need to know their valid versions for sigAlgs/sigAlgsCert
        if (!ProtocolVersion.contains(activeProtocolVersions, ProtocolVersion.TLSv12))
        {
            return null;
        }

        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        int count = DEFAULT_ACTIVE.length;
        ArrayList<SignatureSchemeInfo> result = new ArrayList<SignatureSchemeInfo>(count);
        for (int i = 0; i < count; ++i)
        {
            SignatureSchemeInfo signatureSchemeInfo = signatureSchemesMap.get(DEFAULT_ACTIVE[i]);
            if (null != signatureSchemeInfo
                && signatureSchemeInfo.isActive(algorithmConstraints))
            {
                result.add(signatureSchemeInfo);
            }
        }
        if (result.isEmpty())
        {
            return null;
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

    static List<SignatureSchemeInfo> getSignatureSchemes(Map<Integer, SignatureSchemeInfo> signatureSchemesMap,
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

                SignatureSchemeInfo signatureSchemeInfo = signatureSchemesMap.get(signatureScheme);
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

    private static void addSignatureScheme(JcaTlsCrypto crypto, Map<Integer, SignatureSchemeInfo> ss,
        int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        boolean enabled = crypto.hasSignatureScheme(signatureScheme);

        AlgorithmParameters algorithmParameters = null;
        if (enabled)
        {
            // TODO[jsse] Consider also fetching 'jcaSignatureAlgorithm' and 'keyAlgorithm'
            try
            {
                algorithmParameters = crypto.getSignatureAlgorithmParameters(signatureScheme);
            }
            catch (GeneralSecurityException e)
            {
                enabled = false;
            }
        }

        SignatureSchemeInfo signatureSchemeInfo = new SignatureSchemeInfo(signatureScheme, name, jcaSignatureAlgorithm,
            keyAlgorithm, algorithmParameters, enabled);

        if (null != ss.put(signatureScheme, signatureSchemeInfo))
        {
            throw new IllegalStateException("Duplicate entries for SignatureSchemeInfo");
        }
    }

    private static void addSignatureScheme(JcaTlsCrypto crypto, Map<Integer, SignatureSchemeInfo> ss, int signatureScheme,
        String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        String name = SignatureScheme.getName(signatureScheme);

        addSignatureScheme(crypto, ss, signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm);
    }

    private static void addSignatureSchemeHistorical(JcaTlsCrypto crypto, Map<Integer, SignatureSchemeInfo> ss, int signatureScheme,
        String name, String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        // TODO[tls13] Historical schemes can no longer be used
        addSignatureScheme(crypto, ss, signatureScheme, name, jcaSignatureAlgorithm, keyAlgorithm);
    }

    private static void addSignatureSchemeLegacy(JcaTlsCrypto crypto, Map<Integer, SignatureSchemeInfo> ss, int signatureScheme,
        String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        // TODO[tls13] Legacy schemes can still be used for certificate signatures only
        addSignatureScheme(crypto, ss, signatureScheme, jcaSignatureAlgorithm, keyAlgorithm);
    }

    private final int signatureScheme;
    private final String name;
    private final String jcaSignatureAlgorithm;
    private final String keyAlgorithm;
    private final AlgorithmParameters algorithmParameters;
    private final boolean enabled;

    SignatureSchemeInfo(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm,
        AlgorithmParameters algorithmParameters, boolean enabled)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }

        this.signatureScheme = signatureScheme;
        this.name = name;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.algorithmParameters = algorithmParameters;
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

    int getNamedGroup()
    {
        return SignatureScheme.getNamedGroup(signatureScheme);
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

    boolean isActive(BCAlgorithmConstraints algorithmConstraints)
    {
        /*
         * TODO[tls13] Exclude based on per-instance valid protocol version ranges. Presumably
         * callers of this method want to exclude historical/legacy schemes from TLS 1.3.
         */
        return enabled
            && isPermittedBy(algorithmConstraints);
    }

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, keyAlgorithm, null)
            && algorithmConstraints.permits(primitives, jcaSignatureAlgorithm, algorithmParameters);
            // TODO[tls13] Some schemes have a specific NamedGroup, check permission if TLS 1.3+
    }

    @Override
    public String toString()
    {
        return name + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }
}
