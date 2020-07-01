package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.CipherType;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.TlsUtils;

class CipherSuiteInfo
{
    static CipherSuiteInfo forCipherSuite(int cipherSuite, String name, boolean isTLSv13)
    {
        if (!name.startsWith("TLS_"))
        {
            throw new IllegalArgumentException();
        }

        int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(cipherSuite);
        int encryptionAlgorithmType = TlsUtils.getEncryptionAlgorithmType(encryptionAlgorithm);
        short hashAlgorithm = getHashAlgorithm(cipherSuite);
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        int macAlgorithm = TlsUtils.getMACAlgorithm(cipherSuite);

        Set<String> decompositionX509 = new HashSet<String>();
        decomposeKeyExchangeAlgorithm(decompositionX509, keyExchangeAlgorithm);

        Set<String> decompositionTLS = new HashSet<String>(decompositionX509);
        decomposeEncryptionAlgorithm(decompositionTLS, encryptionAlgorithm);
        decomposeHashAlgorithm(decompositionTLS, hashAlgorithm);
        decomposeMACAlgorithm(decompositionTLS, encryptionAlgorithmType, macAlgorithm);

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
        default:
            throw new IllegalArgumentException();
        }
    }

    private static void decomposeHashAlgorithm(Set<String> decomposition, short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.none:
            break;
        case HashAlgorithm.sha256:
            addAll(decomposition, "SHA256", "SHA-256", "HmacSHA256");
            break;
        case HashAlgorithm.sha384:
            addAll(decomposition, "SHA384", "SHA-384", "HmacSHA384");
            break;
//        case HashAlgorithm.sha512:
//            addAll(decomposition, "SHA512", "SHA-512", "HmacSHA512");
//            break;
        default:
            throw new IllegalArgumentException();
        }
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
        case KeyExchangeAlgorithm.NULL:
            // NOTE: TLS 1.3 cipher suites
            break;
        case KeyExchangeAlgorithm.RSA:
            addAll(decomposition, "RSA");
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
            addAll(decomposition, "SHA256", "SHA-256", "HmacSHA256");
            break;
        case MACAlgorithm.hmac_sha384:
            addAll(decomposition, "SHA384", "SHA-384", "HmacSHA384");
            break;
//        case MACAlgorithm.hmac_sha512:
//            addAll(decomposition, "SHA512", "SHA-512", "HmacSHA512");
//            break;
        default:
            throw new IllegalArgumentException();
        }
    }

    private static short getHashAlgorithm(int cipherSuite)
    {
        switch (cipherSuite)
        {
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
            return HashAlgorithm.sha256;

        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
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
            return HashAlgorithm.sha256;

        case CipherSuite.TLS_AES_256_GCM_SHA384:
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
            return HashAlgorithm.sha384;

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
            return "NULL";
        default:
            throw new IllegalArgumentException();
        }
    }
}
