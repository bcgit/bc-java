package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.CipherType;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;

class CipherSuiteInfo
{
    static CipherSuiteInfo forCipherSuite(int cipherSuite, String name)
    {
        if (!name.startsWith("TLS_"))
        {
            throw new IllegalArgumentException();
        }

        int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(cipherSuite);
        int encryptionAlgorithmType = TlsUtils.getEncryptionAlgorithmType(encryptionAlgorithm);
        int cryptoHashAlgorithm = getCryptoHashAlgorithm(cipherSuite);
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        int macAlgorithm = TlsUtils.getMACAlgorithm(cipherSuite);

        Set<String> decompositionX509 = new HashSet<String>();
        decomposeKeyExchangeAlgorithm(decompositionX509, keyExchangeAlgorithm);

        Set<String> decompositionTLS = new HashSet<String>(decompositionX509);
        decomposeKeyExchangeAlgorithmTLS(decompositionTLS, keyExchangeAlgorithm);

        decomposeEncryptionAlgorithm(decompositionTLS, encryptionAlgorithm);
        decomposeHashAlgorithm(decompositionTLS, cryptoHashAlgorithm);
        decomposeMACAlgorithm(decompositionTLS, encryptionAlgorithmType, macAlgorithm);

        boolean isTLSv13 = (KeyExchangeAlgorithm.NULL == keyExchangeAlgorithm);

        return new CipherSuiteInfo(cipherSuite, name, isTLSv13, Collections.unmodifiableSet(decompositionTLS),
            Collections.unmodifiableSet(decompositionX509));
    }

    private final int cipherSuite;
    private final String name;
    private final boolean isTLSv13;
    private final Set<String> decompositionTLS, decompositionX509;

    private CipherSuiteInfo(int cipherSuite, String name, boolean isTLSv13, Set<String> decompositionTLS,
        Set<String> decompositionX509)
    {
        this.cipherSuite = cipherSuite;
        this.name = name;
        this.isTLSv13 = isTLSv13;
        this.decompositionTLS = decompositionTLS;
        this.decompositionX509 = decompositionX509;
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public Set<String> getDecompositionTLS()
    {
        return decompositionTLS;
    }

    public Set<String> getDecompositionX509()
    {
        return decompositionX509;
    }

    public String getName()
    {
        return name;
    }

    boolean isTLSv13()
    {
        return isTLSv13;
    }

    private static void addAll(Set<String> decomposition, String... entries)
    {
        for (String entry : entries)
        {
            decomposition.add(entry);
        }
    }

    private static void decomposeEncryptionAlgorithm(Set<String> decomposition, int encryptionAlgorithm)
    {
        String transformation = getTransformation(encryptionAlgorithm);
        decomposition.addAll(JcaAlgorithmDecomposer.INSTANCE_JCA.decompose(transformation));

        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            decomposition.add("3DES_EDE_CBC");
            break;
        case EncryptionAlgorithm.AES_128_CBC:
            decomposition.add("AES_128_CBC");
            break;
        case EncryptionAlgorithm.AES_128_CCM:
            decomposition.add("AES_128_CCM");
            break;
        case EncryptionAlgorithm.AES_128_CCM_8:
            decomposition.add("AES_128_CCM_8");
            break;
        case EncryptionAlgorithm.AES_128_GCM:
            decomposition.add("AES_128_GCM");
            break;
        case EncryptionAlgorithm.AES_256_CBC:
            decomposition.add("AES_256_CBC");
            break;
        case EncryptionAlgorithm.AES_256_CCM:
            decomposition.add("AES_256_CCM");
            break;
        case EncryptionAlgorithm.AES_256_CCM_8:
            decomposition.add("AES_256_CCM_8");
            break;
        case EncryptionAlgorithm.AES_256_GCM:
            decomposition.add("AES_256_GCM");
            break;
        case EncryptionAlgorithm.ARIA_128_CBC:
            decomposition.add("ARIA_128_CBC");
            break;
        case EncryptionAlgorithm.ARIA_256_CBC:
            decomposition.add("ARIA_256_CBC");
            break;
        case EncryptionAlgorithm.ARIA_128_GCM:
            decomposition.add("ARIA_128_GCM");
            break;
        case EncryptionAlgorithm.ARIA_256_GCM:
            decomposition.add("ARIA_256_GCM");
            break;
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
            decomposition.add("CAMELLIA_128_CBC");
            break;
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            decomposition.add("CAMELLIA_256_CBC");
            break;
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
            decomposition.add("CAMELLIA_128_GCM");
            break;
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            decomposition.add("CAMELLIA_256_GCM");
            break;
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            // NOTE: Following SunJSSE, nothing beyond the transformation added above (i.e "ChaCha20-Poly1305")
            break;
        case EncryptionAlgorithm.NULL:
            decomposition.add("C_NULL");
            break;
        case EncryptionAlgorithm.NULL_HMAC_SHA256:
            decomposition.add("C_NULL_HMAC");
            decomposeHmacSHA256(decomposition);
            break;
        case EncryptionAlgorithm.NULL_HMAC_SHA384:
            decomposition.add("C_NULL_HMAC");
            decomposeHmacSHA384(decomposition);
            break;
        case EncryptionAlgorithm.SM4_CBC:
            decomposition.add("SM4_CBC");
            break;
        case EncryptionAlgorithm.SM4_CCM:
            decomposition.add("SM4_CCM");
            break;
        case EncryptionAlgorithm.SM4_GCM:
            decomposition.add("SM4_GCM");
            break;
        default:
            throw new IllegalArgumentException();
        }
    }

    private static void decomposeHashAlgorithm(Set<String> decomposition, int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.sha256:
            decomposeHmacSHA256(decomposition);
            break;
        case CryptoHashAlgorithm.sha384:
            decomposeHmacSHA384(decomposition);
            break;
        case CryptoHashAlgorithm.sha512:
            decomposeHmacSHA512(decomposition);
            break;
        case CryptoHashAlgorithm.sm3:
            addAll(decomposition, "SM3", "HmacSM3");
            break;
        default:
            throw new IllegalArgumentException();
        }
    }

    private static void decomposeHmacSHA256(Set<String> decomposition)
    {
        addAll(decomposition, "SHA256", "SHA-256", "HmacSHA256");
    }

    private static void decomposeHmacSHA384(Set<String> decomposition)
    {
        addAll(decomposition, "SHA384", "SHA-384", "HmacSHA384");
    }

    private static void decomposeHmacSHA512(Set<String> decomposition)
    {
        addAll(decomposition, "SHA512", "SHA-512", "HmacSHA512");
    }

    private static void decomposeKeyExchangeAlgorithm(Set<String> decomposition, int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
            addAll(decomposition, "DSA", "DSS", "DH", "DHE", "DiffieHellman", "DHE_DSS");
            break;
        case KeyExchangeAlgorithm.DHE_RSA:
            addAll(decomposition, "RSA", "DH", "DHE", "DiffieHellman", "DHE_RSA");
            break;
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            addAll(decomposition, "ECDHE", "ECDSA", "ECDHE_ECDSA");
            break;
        case KeyExchangeAlgorithm.ECDHE_RSA:
            addAll(decomposition, "ECDHE", "RSA", "ECDHE_RSA");
            break;
        case KeyExchangeAlgorithm.RSA:
            addAll(decomposition, "RSA");
            break;

        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.NULL:
            break;

        default:
            throw new IllegalArgumentException();
        }
    }

    private static void decomposeKeyExchangeAlgorithmTLS(Set<String> decompositionTLS, int keyExchangeAlgorithm)
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
            addAll(decompositionTLS, "ANON", "DH", "DiffieHellman", "DH_ANON");
            break;
        case KeyExchangeAlgorithm.ECDH_anon:
            addAll(decompositionTLS, "ANON", "ECDH", "ECDH_ANON");
            break;
        case KeyExchangeAlgorithm.NULL:
            addAll(decompositionTLS, "K_NULL");
            break;

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
            break;

        default:
            throw new IllegalArgumentException();
        }
    }

    private static void decomposeMACAlgorithm(Set<String> decomposition, int cipherType, int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            if (CipherType.aead != cipherType)
            {
                addAll(decomposition, "M_NULL");
            }
            break;
        case MACAlgorithm.hmac_md5:
            addAll(decomposition, "MD5", "HmacMD5");
            break;
        case MACAlgorithm.hmac_sha1:
            addAll(decomposition, "SHA1", "SHA-1", "HmacSHA1");
            break;
        case MACAlgorithm.hmac_sha256:
            decomposeHmacSHA256(decomposition);
            break;
        case MACAlgorithm.hmac_sha384:
            decomposeHmacSHA384(decomposition);
            break;
        case MACAlgorithm.hmac_sha512:
            decomposeHmacSHA512(decomposition);
            break;
        default:
            throw new IllegalArgumentException();
        }
    }

    private static int getCryptoHashAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
            /*
             * TODO[jsse] We follow SunJSSE behaviour here, but it's not quite right; these cipher
             * suites will actually use the legacy PRF based on MD5/SHA1 for TLS 1.1 or earlier.
             */
            return CryptoHashAlgorithm.sha256;

        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        case CipherSuite.TLS_SHA256_SHA256:
            return CryptoHashAlgorithm.sha256;

        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_SHA384_SHA384:
            return CryptoHashAlgorithm.sha384;

        case CipherSuite.TLS_SM4_CCM_SM3:
        case CipherSuite.TLS_SM4_GCM_SM3:
            return CryptoHashAlgorithm.sm3;

        default:
            throw new IllegalArgumentException();
        }
    }

    private static String getTransformation(int encryptionAlgorithm)
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return "DESede/CBC/NoPadding";
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.AES_256_CBC:
            return "AES/CBC/NoPadding";
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
            return "AES/CCM/NoPadding";
        case EncryptionAlgorithm.AES_128_GCM:
        case EncryptionAlgorithm.AES_256_GCM:
            return "AES/GCM/NoPadding";
        case EncryptionAlgorithm.ARIA_128_CBC:
        case EncryptionAlgorithm.ARIA_256_CBC:
            return "ARIA/CBC/NoPadding";
        case EncryptionAlgorithm.ARIA_128_GCM:
        case EncryptionAlgorithm.ARIA_256_GCM:
            return "ARIA/GCM/NoPadding";
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return "Camellia/CBC/NoPadding";
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            return "Camellia/GCM/NoPadding";
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            return "ChaCha20-Poly1305";
        case EncryptionAlgorithm.NULL:
        case EncryptionAlgorithm.NULL_HMAC_SHA256:
        case EncryptionAlgorithm.NULL_HMAC_SHA384:
            return "NULL";
        case EncryptionAlgorithm.SM4_CBC:
            return "SM4/CBC/NoPadding";
        case EncryptionAlgorithm.SM4_CCM:
            return "SM4/CCM/NoPadding";
        case EncryptionAlgorithm.SM4_GCM:
            return "SM4/GCM/NoPadding";
        default:
            throw new IllegalArgumentException();
        }
    }
}
