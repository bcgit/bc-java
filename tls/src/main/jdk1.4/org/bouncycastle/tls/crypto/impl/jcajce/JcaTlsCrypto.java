package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.CryptoSignatureAlgorithm;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.tls.crypto.impl.TlsNullCipher;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Client;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Server;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6VerifierGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * Class for providing cryptographic services for TLS based on implementations in the JCA/JCE.
 * <p>
 *     This class provides default implementations for everything. If you need to customise it, extend the class
 *     and override the appropriate methods.
 * </p>
 */
public class JcaTlsCrypto
    extends AbstractTlsCrypto
{
    private final JcaJceHelper helper;
    private final SecureRandom entropySource;
    private final SecureRandom nonceEntropySource;

    private final Hashtable supportedEncryptionAlgorithms = new Hashtable();
    private final Hashtable supportedNamedGroups = new Hashtable();
    private final Hashtable supportedOther = new Hashtable();

    /**
     * Base constructor.
     *
     * @param helper a JCA/JCE helper configured for the class's default provider.
     * @param entropySource primary entropy source, used for key generation.
     * @param nonceEntropySource secondary entropy source, used for nonce and IV generation.
     */
    protected JcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)
    {
        this.helper = helper;
        this.entropySource = entropySource;
        this.nonceEntropySource = nonceEntropySource;
    }

    JceTlsSecret adoptLocalSecret(byte[] data)
    {
        return new JceTlsSecret(this, data);
    }

    Cipher createRSAEncryptionCipher() throws GeneralSecurityException
    {
        try
        {
            return getHelper().createCipher("RSA/NONE/PKCS1Padding");
        }
        catch (GeneralSecurityException e)
        {
            return getHelper().createCipher("RSA/ECB/PKCS1Padding");    // try old style
        }
    }

    public TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial)
    {
        return new JcaNonceGenerator(nonceEntropySource, additionalSeedMaterial);
    }

    public SecureRandom getSecureRandom()
    {
        return entropySource;
    }

    public byte[] calculateKeyAgreement(String agreementAlgorithm, PrivateKey privateKey, PublicKey publicKey, String secretAlgorithm)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = helper.createKeyAgreement(agreementAlgorithm);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        try
        {
            return agreement.generateSecret(secretAlgorithm).getEncoded();
        }
        catch (NoSuchAlgorithmException e)
        {
            // Oracle provider currently does not support generateSecret(algorithmName) for these.
            if ("X25519".equals(agreementAlgorithm) || "X448".equals(agreementAlgorithm))
            {
                return agreement.generateSecret();
            }
            throw e;
        }
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return createCertificate(CertificateType.X509, encoding);
    }

    public TlsCertificate createCertificate(short type, byte[] encoding)
        throws IOException
    {
        if (type != CertificateType.X509)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        return new JcaTlsCertificate(this, encoding);
    }

    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        try
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm._3DES_EDE_CBC:
                return createCipher_CBC(cryptoParams, "DESede", 24, macAlgorithm);
            case EncryptionAlgorithm.AES_128_CBC:
                return createCipher_CBC(cryptoParams, "AES", 16, macAlgorithm);
            case EncryptionAlgorithm.AES_128_CCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(cryptoParams, 16, 16);
            case EncryptionAlgorithm.AES_128_CCM_8:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(cryptoParams, 16, 8);
            case EncryptionAlgorithm.AES_128_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_GCM(cryptoParams, 16, 16);
            case EncryptionAlgorithm.AES_256_CBC:
                return createCipher_CBC(cryptoParams, "AES", 32, macAlgorithm);
            case EncryptionAlgorithm.AES_256_CCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(cryptoParams, 32, 16);
            case EncryptionAlgorithm.AES_256_CCM_8:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(cryptoParams, 32, 8);
            case EncryptionAlgorithm.AES_256_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_GCM(cryptoParams, 32, 16);
            case EncryptionAlgorithm.ARIA_128_CBC:
                return createCipher_CBC(cryptoParams, "ARIA", 16, macAlgorithm);
            case EncryptionAlgorithm.ARIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_ARIA_GCM(cryptoParams, 16, 16);
            case EncryptionAlgorithm.ARIA_256_CBC:
                return createCipher_CBC(cryptoParams, "ARIA", 32, macAlgorithm);
            case EncryptionAlgorithm.ARIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_ARIA_GCM(cryptoParams, 32, 16);
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
                return createCipher_CBC(cryptoParams, "Camellia", 16, macAlgorithm);
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_Camellia_GCM(cryptoParams, 16, 16);
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return createCipher_CBC(cryptoParams, "Camellia", 32, macAlgorithm);
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_Camellia_GCM(cryptoParams, 32, 16);
            case EncryptionAlgorithm.CHACHA20_POLY1305:
                // NOTE: Ignores macAlgorithm
                return createChaCha20Poly1305(cryptoParams);
            case EncryptionAlgorithm.NULL:
                return createNullCipher(cryptoParams, macAlgorithm);
            case EncryptionAlgorithm.SEED_CBC:
                return createCipher_CBC(cryptoParams, "SEED", 16, macAlgorithm);
            case EncryptionAlgorithm.SM4_CBC:
                return createCipher_CBC(cryptoParams, "SM4", 16, macAlgorithm);
            case EncryptionAlgorithm.SM4_CCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_SM4_CCM(cryptoParams);
            case EncryptionAlgorithm.SM4_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_SM4_GCM(cryptoParams);

            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    public TlsHMAC createHMAC(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
        case MACAlgorithm.hmac_sha1:
        case MACAlgorithm.hmac_sha256:
        case MACAlgorithm.hmac_sha384:
        case MACAlgorithm.hmac_sha512:
            return createHMACForHash(TlsCryptoUtils.getHashForHMAC(macAlgorithm));

        default:
            throw new IllegalArgumentException("invalid MACAlgorithm: " + macAlgorithm);
        }
    }

    public TlsHMAC createHMACForHash(int cryptoHashAlgorithm)
    {
        String hmacName = getHMACAlgorithmName(cryptoHashAlgorithm);

        try
        {
            return new JceTlsHMAC(cryptoHashAlgorithm, helper.createMac(hmacName), hmacName);
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException("cannot create HMAC: " + hmacName, e);
        }
    }

    protected TlsHMAC createHMAC_SSL(int macAlgorithm)
        throws GeneralSecurityException, IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return new JcaSSL3HMAC(createHash(getDigestName(CryptoHashAlgorithm.md5)), 16, 64);
        case MACAlgorithm.hmac_sha1:
            return new JcaSSL3HMAC(createHash(getDigestName(CryptoHashAlgorithm.sha1)), 20, 64);
        case MACAlgorithm.hmac_sha256:
            return new JcaSSL3HMAC(createHash(getDigestName(CryptoHashAlgorithm.sha256)), 32, 64);
        case MACAlgorithm.hmac_sha384:
            return new JcaSSL3HMAC(createHash(getDigestName(CryptoHashAlgorithm.sha384)), 48, 128);
        case MACAlgorithm.hmac_sha512:
            return new JcaSSL3HMAC(createHash(getDigestName(CryptoHashAlgorithm.sha512)), 64, 128);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsHMAC createMAC(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws GeneralSecurityException, IOException
    {
        if (TlsImplUtils.isSSL(cryptoParams))
        {
            return createHMAC_SSL(macAlgorithm);
        }
        else
        {
            return createHMAC(macAlgorithm);
        }
    }

    public TlsSRP6Client createSRP6Client(TlsSRPConfig srpConfig)
    {
        final SRP6Client srpClient = new SRP6Client();

        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6Group srpGroup= new SRP6Group(ng[0], ng[1]);
        srpClient.init(srpGroup, createHash(CryptoHashAlgorithm.sha1), this.getSecureRandom());

        return new TlsSRP6Client()
        {
            public BigInteger calculateSecret(BigInteger serverB)
                throws TlsFatalAlert
            {
                try
                {
                    return srpClient.calculateSecret(serverB);
                }
                catch (IllegalArgumentException e)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
                }
            }

            public BigInteger generateClientCredentials(byte[] srpSalt, byte[] identity, byte[] password)
            {
                return srpClient.generateClientCredentials(srpSalt, identity, password);
            }
        };
    }

    public TlsSRP6Server createSRP6Server(TlsSRPConfig srpConfig, BigInteger srpVerifier)
    {
        final SRP6Server srpServer = new SRP6Server();
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6Group srpGroup= new SRP6Group(ng[0], ng[1]);
        srpServer.init(srpGroup, srpVerifier, createHash(CryptoHashAlgorithm.sha1), this.getSecureRandom());
        return new TlsSRP6Server()
        {
            public BigInteger generateServerCredentials()
            {
                return srpServer.generateServerCredentials();
            }

            public BigInteger calculateSecret(BigInteger clientA)
                throws IOException
            {
                try
                {
                    return srpServer.calculateSecret(clientA);
                }
                catch (IllegalArgumentException e)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
                }
            }
        };
    }

    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig srpConfig)
    {
        BigInteger[] ng = srpConfig.getExplicitNG();
        final SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();

        verifierGenerator.init(ng[0], ng[1], createHash(CryptoHashAlgorithm.sha1));

        return new TlsSRP6VerifierGenerator()
        {
            public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
            {
                return verifierGenerator.generateVerifier(salt, identity, password);
            }
        };
    }

    String getHMACAlgorithmName(int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
            return "HmacMD5";
        case CryptoHashAlgorithm.sha1:
            return "HmacSHA1";
        case CryptoHashAlgorithm.sha224:
            return "HmacSHA224";
        case CryptoHashAlgorithm.sha256:
            return "HmacSHA256";
        case CryptoHashAlgorithm.sha384:
            return "HmacSHA384";
        case CryptoHashAlgorithm.sha512:
            return "HmacSHA512";
        case CryptoHashAlgorithm.sm3:
            return "HmacSM3";
        default:
            throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    public AlgorithmParameters getNamedGroupAlgorithmParameters(int namedGroup) throws GeneralSecurityException
    {
        if (NamedGroup.refersToAnXDHCurve(namedGroup))
        {
            switch (namedGroup)
            {
            /*
             * TODO Return AlgorithmParameters to check against disabled algorithms
             * 
             * NOTE: The JDK doesn't even support AlgorithmParameters for XDH, so SunJSSE also winds
             * up using null AlgorithmParameters when checking algorithm constraints.
             */
            case NamedGroup.x25519:
            case NamedGroup.x448:
                return null;
            }
        }
        else if (NamedGroup.refersToAnECDSACurve(namedGroup))
        {
            return ECUtil.getAlgorithmParameters(this, NamedGroup.getCurveName(namedGroup));
        }
        else if (NamedGroup.refersToASpecificFiniteField(namedGroup))
        {
            return DHUtil.getAlgorithmParameters(this, TlsDHUtils.getNamedDHGroup(namedGroup));
        }

        throw new IllegalArgumentException("NamedGroup not supported: " + NamedGroup.getText(namedGroup));
    }

    public AlgorithmParameters getSignatureSchemeAlgorithmParameters(int signatureScheme)
        throws GeneralSecurityException
    {
        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            return null;
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        if (cryptoHashAlgorithm < 0)
        {
            return null;
        }

        String digestName = getDigestName(cryptoHashAlgorithm);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, getHelper());

        Signature signer = getHelper().createSignature(sigName);

        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
        signer.setParameter(pssSpec);

        return signer.getParameters();
    }

    public boolean hasAnyStreamVerifiers(Vector signatureAndHashAlgorithms)
    {
        boolean isRSAStreamVerifier = JcaUtils.isSunMSCAPIProviderActive();

        for (int i = 0, count = signatureAndHashAlgorithms.size(); i < count; ++i)
        {
            SignatureAndHashAlgorithm algorithm = (SignatureAndHashAlgorithm)signatureAndHashAlgorithms.elementAt(i);
            switch (algorithm.getSignature())
            {
            case SignatureAlgorithm.rsa:
            {
                if (isRSAStreamVerifier)
                {
                    return true;
                }
                break;
            }
            case SignatureAlgorithm.dsa:
            {
                if (HashAlgorithm.getOutputSize(algorithm.getHash()) != 20)
                {
                    return true;
                }
                break;
            }
            }

            switch (SignatureScheme.from(algorithm))
            {
            case SignatureScheme.ed25519:
            case SignatureScheme.ed448:
            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
            case SignatureScheme.rsa_pss_pss_sha256:
            case SignatureScheme.rsa_pss_pss_sha384:
            case SignatureScheme.rsa_pss_pss_sha512:
                return true;
            }
        }
        return false;
    }

    public boolean hasAnyStreamVerifiersLegacy(short[] clientCertificateTypes)
    {
        return false;
    }

    public boolean hasCryptoHashAlgorithm(int cryptoHashAlgorithm)
    {
        // TODO: expand
        return true;
    }

    public boolean hasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm)
    {
        switch (cryptoSignatureAlgorithm)
        {
        case CryptoSignatureAlgorithm.rsa:
        case CryptoSignatureAlgorithm.dsa:
        case CryptoSignatureAlgorithm.ecdsa:
        case CryptoSignatureAlgorithm.rsa_pss_rsae_sha256:
        case CryptoSignatureAlgorithm.rsa_pss_rsae_sha384:
        case CryptoSignatureAlgorithm.rsa_pss_rsae_sha512:
        case CryptoSignatureAlgorithm.ed25519:
        case CryptoSignatureAlgorithm.ed448:
        case CryptoSignatureAlgorithm.rsa_pss_pss_sha256:
        case CryptoSignatureAlgorithm.rsa_pss_pss_sha384:
        case CryptoSignatureAlgorithm.rsa_pss_pss_sha512:
            return true;

        // TODO[draft-smyshlyaev-tls12-gost-suites-10]
        case CryptoSignatureAlgorithm.gostr34102012_256:
        case CryptoSignatureAlgorithm.gostr34102012_512:

        // TODO[RFC 8998]
        case CryptoSignatureAlgorithm.sm2:

        default:
            return false;
        }
    }

    public boolean hasDHAgreement()
    {
        return true;
    }

    public boolean hasECDHAgreement()
    {
        return true;
    }

    public boolean hasEncryptionAlgorithm(int encryptionAlgorithm)
    {
        final Integer key = Integers.valueOf(encryptionAlgorithm);
        synchronized (supportedEncryptionAlgorithms)
        {
            Boolean cached = (Boolean)supportedEncryptionAlgorithms.get(key);
            if (cached != null)
            {
                return cached.booleanValue();
            }
        }

        Boolean supported = isSupportedEncryptionAlgorithm(encryptionAlgorithm);
        if (null == supported)
        {
            return false;
        }

        synchronized (supportedEncryptionAlgorithms)
        {
            Boolean cached = (Boolean)supportedEncryptionAlgorithms.put(key, supported);

            // Unlikely, but we want a consistent result
            if (null != cached && supported != cached)
            {
                supportedEncryptionAlgorithms.put(key, cached);
                supported = cached;
            }
        }

        return supported.booleanValue();
    }

    public boolean hasHKDFAlgorithm(int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.sha256:
        case CryptoHashAlgorithm.sha384:
        case CryptoHashAlgorithm.sha512:
        case CryptoHashAlgorithm.sm3:
            return true;

        default:
            return false;
        }
    }

    public boolean hasMacAlgorithm(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
        case MACAlgorithm.hmac_sha1:
        case MACAlgorithm.hmac_sha256:
        case MACAlgorithm.hmac_sha384:
        case MACAlgorithm.hmac_sha512:
            return true;

        default:
            return false;
        }
    }

    public boolean hasNamedGroup(int namedGroup)
    {
        final Integer key = Integers.valueOf(namedGroup);
        synchronized (supportedNamedGroups)
        {
            Boolean cached = (Boolean)supportedNamedGroups.get(key);
            if (null != cached)
            {
                return cached.booleanValue();
            }
        }

        Boolean supported = isSupportedNamedGroup(namedGroup);
        if (null == supported)
        {
            return false;
        }

        synchronized (supportedNamedGroups)
        {
            Boolean cached = (Boolean)supportedNamedGroups.put(key, supported);

            // Unlikely, but we want a consistent result
            if (null != cached && supported != cached)
            {
                supportedNamedGroups.put(key, cached);
                supported = cached;
            }
        }

        return supported.booleanValue();
    }

    public boolean hasRSAEncryption()
    {
        final String key = "KE_RSA";
        synchronized (supportedOther)
        {
            Boolean cached = (Boolean)supportedOther.get(key);
            if (cached != null)
            {
                return cached.booleanValue();
            }
        }

        Boolean supported;
        try
        {
            createRSAEncryptionCipher();
            supported = Boolean.TRUE;
        }
        catch (GeneralSecurityException e)
        {
            supported = Boolean.FALSE;
        }

        synchronized (supportedOther)
        {
            Boolean cached = (Boolean)supportedOther.put(key, supported);

            // Unlikely, but we want a consistent result
            if (null != cached && supported != cached)
            {
                supportedOther.put(key, cached);
                supported = cached;
            }
        }

        return supported.booleanValue();
    }

    public boolean hasSignatureAlgorithm(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
        case SignatureAlgorithm.dsa:
        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.ed25519:
        case SignatureAlgorithm.ed448:
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
            return true;

        // TODO[draft-smyshlyaev-tls12-gost-suites-10]
        case SignatureAlgorithm.gostr34102012_256:
        case SignatureAlgorithm.gostr34102012_512:
        // TODO[RFC 8998]
//        case SignatureAlgorithm.sm2:
        default:
            return false;
        }
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        short signature = sigAndHashAlgorithm.getSignature();

        switch (sigAndHashAlgorithm.getHash())
        {
        case HashAlgorithm.md5:
            return SignatureAlgorithm.rsa == signature && hasSignatureAlgorithm(signature);
        case HashAlgorithm.sha224:
            // Somewhat overkill, but simpler for now. It's also consistent with SunJSSE behaviour.
            return !JcaUtils.isSunMSCAPIProviderActive() && hasSignatureAlgorithm(signature);
        default:
            return hasSignatureAlgorithm(signature);
        }
    }

    public boolean hasSignatureScheme(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.sm2sig_sm3:
            return false;
        default:
        {
            short signature = SignatureScheme.getSignatureAlgorithm(signatureScheme);

            switch(SignatureScheme.getCryptoHashAlgorithm(signatureScheme))
            {
            case CryptoHashAlgorithm.md5:
                return SignatureAlgorithm.rsa == signature && hasSignatureAlgorithm(signature);
            case CryptoHashAlgorithm.sha224:
                // Somewhat overkill, but simpler for now. It's also consistent with SunJSSE behaviour.
                return !JcaUtils.isSunMSCAPIProviderActive() && hasSignatureAlgorithm(signature);
            default:
                return hasSignatureAlgorithm(signature);
            }
        }
        }
    }

    public boolean hasSRPAuthentication()
    {
        return true;
    }

    public TlsSecret createSecret(byte[] data)
    {
        try
        {
            return adoptLocalSecret(Arrays.clone(data));
        }
        finally
        {
            // TODO[tls-ops] Add this after checking all callers
//            if (data != null)
//            {
//                Arrays.fill(data, (byte)0);
//            }
        }
    }

    public TlsSecret generateRSAPreMasterSecret(ProtocolVersion version)
    {
        byte[] data = new byte[48];
        getSecureRandom().nextBytes(data);
        TlsUtils.writeVersion(version, data, 0);
        return adoptLocalSecret(data);
    }

    public TlsHash createHash(int cryptoHashAlgorithm)
    {
        try
        {
            return createHash(getDigestName(cryptoHashAlgorithm));
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalArgumentException("unable to create message digest:" + e.getMessage(), e);
        }
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new JceTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        switch (ecConfig.getNamedGroup())
        {
        case NamedGroup.x25519:
            return new JceX25519Domain(this);
        case NamedGroup.x448:
            return new JceX448Domain(this);
        default:
            return new JceTlsECDomain(this, ecConfig);
        }
    }

    public TlsSecret hkdfInit(int cryptoHashAlgorithm)
    {
        return adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm)]);
    }

    /**
     * If you want to create your own versions of the AEAD ciphers required, override this method.
     *
     * @param cipherName   the full name of the cipher (algorithm/mode/padding)
     * @param algorithm    the base algorithm name
     * @param keySize      keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return an AEAD cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsAEADCipherImpl createAEADCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceAEADCipherImpl(this, helper, cipherName, algorithm, keySize, isEncrypting);
    }

    /**
     * If you want to create your own versions of the block ciphers required, override this method.
     *
     * @param cipherName   the full name of the cipher (algorithm/mode/padding)
     * @param algorithm    the base algorithm name
     * @param keySize      keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsBlockCipherImpl createBlockCipher(String cipherName, String algorithm, int keySize,
        boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipherImpl(this, helper.createCipher(cipherName), algorithm, keySize, isEncrypting);
    }

    /**
     * If you want to create your own versions of the block ciphers for &lt; TLS 1.1, override this method.
     *
     * @param cipherName   the full name of the cipher (algorithm/mode/padding)
     * @param algorithm    the base algorithm name
     * @param keySize      keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsBlockCipherImpl createBlockCipherWithCBCImplicitIV(String cipherName, String algorithm, int keySize,
        boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipherWithCBCImplicitIVImpl(this, helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of Hash functions, override this method.
     *
     * @param digestName the name of the Hash function required.
     * @return a hash calculator.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsHash createHash(String digestName)
        throws GeneralSecurityException
    {
        return new JcaTlsHash(helper.createMessageDigest(digestName));
    }

    /**
     * To disable the null cipher suite, override this method with one that throws an IOException.
     *
     * @param macAlgorithm the name of the algorithm supporting the MAC.
     * @return a null cipher suite implementation.
     * @throws IOException in case of failure.
     * @throws GeneralSecurityException in case of a specific failure in the JCA/JCE layer.
     */
    protected TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsNullCipher(cryptoParams, createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm));
    }

    protected TlsStreamSigner createStreamSigner(SignatureAndHashAlgorithm algorithm, PrivateKey privateKey,
        boolean needsRandom) throws IOException
    {
        String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);

        return createStreamSigner(algorithmName, null, privateKey, needsRandom);
    }

    protected TlsStreamSigner createStreamSigner(String algorithmName, AlgorithmParameterSpec parameter,
        PrivateKey privateKey, boolean needsRandom) throws IOException
    {
        try
        {
            SecureRandom random = needsRandom ? getSecureRandom() : null;

            JcaJceHelper helper = getHelper();
            if (null != parameter)
            {
                Signature dummySigner = helper.createSignature(algorithmName);
                dummySigner.initSign(privateKey, random);
                helper = new ProviderJcaJceHelper(dummySigner.getProvider());
            }

            Signature signer = helper.createSignature(algorithmName);
            if (null != parameter)
            {
                signer.setParameter(parameter);
            }
            signer.initSign(privateKey, random);
            return new JcaTlsStreamSigner(signer);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected TlsStreamVerifier createStreamVerifier(DigitallySigned digitallySigned, PublicKey publicKey) throws IOException
    {
        String algorithmName = JcaUtils.getJcaAlgorithmName(digitallySigned.getAlgorithm());

        return createStreamVerifier(algorithmName, null, digitallySigned.getSignature(), publicKey);
    }

    protected TlsStreamVerifier createStreamVerifier(String algorithmName, AlgorithmParameterSpec parameter,
        byte[] signature, PublicKey publicKey) throws IOException
    {
        try
        {
            JcaJceHelper helper = getHelper();
            if (null != parameter)
            {
                Signature dummyVerifier = helper.createSignature(algorithmName);
                dummyVerifier.initVerify(publicKey);
                helper = new ProviderJcaJceHelper(dummyVerifier.getProvider());
            }

            Signature verifier = helper.createSignature(algorithmName);
            if (null != parameter)
            {
                verifier.setParameter(parameter);
            }
            verifier.initVerify(publicKey);
            return new JcaTlsStreamVerifier(verifier, signature);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected Tls13Verifier createTls13Verifier(String algorithmName, AlgorithmParameterSpec parameter,
        PublicKey publicKey) throws IOException
    {
        try
        {
            JcaJceHelper helper = getHelper();
            if (null != parameter)
            {
                Signature dummyVerifier = helper.createSignature(algorithmName);
                dummyVerifier.initVerify(publicKey);
                helper = new ProviderJcaJceHelper(dummyVerifier.getProvider());
            }

            Signature verifier = helper.createSignature(algorithmName);
            if (null != parameter)
            {
                verifier.setParameter(parameter);
            }
            verifier.initVerify(publicKey);
            return new JcaTls13Verifier(verifier);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected TlsStreamSigner createVerifyingStreamSigner(SignatureAndHashAlgorithm algorithm, PrivateKey privateKey,
        boolean needsRandom, PublicKey publicKey) throws IOException
    {
        String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);

        return createVerifyingStreamSigner(algorithmName, null, privateKey, needsRandom, publicKey);
    }

    protected TlsStreamSigner createVerifyingStreamSigner(String algorithmName, AlgorithmParameterSpec parameter,
        PrivateKey privateKey, boolean needsRandom, PublicKey publicKey) throws IOException
    {
        try
        {
            Signature signer = getHelper().createSignature(algorithmName);
            Signature verifier = getHelper().createSignature(algorithmName);

            if (null != parameter)
            {
                signer.setParameter(parameter);
                verifier.setParameter(parameter);
            }

            signer.initSign(privateKey, needsRandom ? getSecureRandom() : null);
            verifier.initVerify(publicKey);

            return new JcaVerifyingStreamSigner(signer, verifier);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected Boolean isSupportedEncryptionAlgorithm(int encryptionAlgorithm)
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return Boolean.valueOf(isUsableCipher("DESede/CBC/NoPadding", 192));
        case EncryptionAlgorithm.AES_128_CBC:
            return Boolean.valueOf(isUsableCipher("AES/CBC/NoPadding", 128));
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
            return Boolean.valueOf(isUsableCipher("AES/CCM/NoPadding", 128));
        case EncryptionAlgorithm.AES_128_GCM:
            return Boolean.valueOf(isUsableCipher("AES/GCM/NoPadding", 128));
        case EncryptionAlgorithm.AES_256_CBC:
            return Boolean.valueOf(isUsableCipher("AES/CBC/NoPadding", 256));
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
            return Boolean.valueOf(isUsableCipher("AES/CCM/NoPadding", 256));
        case EncryptionAlgorithm.AES_256_GCM:
            return Boolean.valueOf(isUsableCipher("AES/GCM/NoPadding", 256));
        case EncryptionAlgorithm.ARIA_128_CBC:
            return Boolean.valueOf(isUsableCipher("ARIA/CBC/NoPadding", 128));
        case EncryptionAlgorithm.ARIA_128_GCM:
            return Boolean.valueOf(isUsableCipher("ARIA/GCM/NoPadding", 128));
        case EncryptionAlgorithm.ARIA_256_CBC:
            return Boolean.valueOf(isUsableCipher("ARIA/CBC/NoPadding", 256));
        case EncryptionAlgorithm.ARIA_256_GCM:
            return Boolean.valueOf(isUsableCipher("ARIA/GCM/NoPadding", 256));
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
            return Boolean.valueOf(isUsableCipher("Camellia/CBC/NoPadding", 128));
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
            return Boolean.valueOf(isUsableCipher("Camellia/GCM/NoPadding", 128));
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return Boolean.valueOf(isUsableCipher("Camellia/CBC/NoPadding", 256));
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            return Boolean.valueOf(isUsableCipher("Camellia/GCM/NoPadding", 256));
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            return Boolean.valueOf(isUsableCipher("ChaCha7539", 256) && isUsableMAC("Poly1305"));
        case EncryptionAlgorithm.NULL:
            return Boolean.TRUE;
        case EncryptionAlgorithm.SEED_CBC:
            return Boolean.valueOf(isUsableCipher("SEED/CBC/NoPadding", 128));
        case EncryptionAlgorithm.SM4_CBC:
            return Boolean.valueOf(isUsableCipher("SM4/CBC/NoPadding", 128));
        case EncryptionAlgorithm.SM4_CCM:
            return Boolean.valueOf(isUsableCipher("SM4/CCM/NoPadding", 128));
        case EncryptionAlgorithm.SM4_GCM:
            return Boolean.valueOf(isUsableCipher("SM4/GCM/NoPadding", 128));

        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.RC4_128:
        case EncryptionAlgorithm.RC4_40:
            return Boolean.FALSE;
        }

        return null;
    }

    protected Boolean isSupportedNamedGroup(int namedGroup)
    {
        try
        {
            if (NamedGroup.refersToAnXDHCurve(namedGroup))
            {
                /*
                 * NOTE: We don't check for AlgorithmParameters support because even the SunEC
                 * provider doesn't support them. We skip checking KeyFactory and KeyPairGenerator
                 * for performance reasons (and this is consistent with SunJSSE behaviour).
                 */
                switch (namedGroup)
                {
                case NamedGroup.x25519:
                {
//                    helper.createAlgorithmParameters("X25519");
                    helper.createKeyAgreement("X25519");
//                    helper.createKeyFactory("X25519");
//                    helper.createKeyPairGenerator("X25519");
                    return Boolean.TRUE;
                }
                case NamedGroup.x448:
                {
//                    helper.createAlgorithmParameters("X448");
                    helper.createKeyAgreement("X448");
//                    helper.createKeyFactory("X448");
//                    helper.createKeyPairGenerator("X448");
                    return Boolean.TRUE;
                }
                }
            }
            else if (NamedGroup.refersToAnECDSACurve(namedGroup))
            {
                return Boolean.valueOf(ECUtil.isCurveSupported(this, NamedGroup.getCurveName(namedGroup)));
            }
            else if (NamedGroup.refersToASpecificFiniteField(namedGroup))
            {
                return Boolean.valueOf(DHUtil.isGroupSupported(this, TlsDHUtils.getNamedDHGroup(namedGroup)));
            }
        }
        catch (GeneralSecurityException e)
        {
            return Boolean.FALSE;
        }

        // 'null' means we don't even recognize the NamedGroup
        return null;
    }

    protected boolean isUsableCipher(String cipherAlgorithm, int keySize)
    {
//        try
//        {
//            helper.createCipher(cipherAlgorithm);
//            return Cipher.getMaxAllowedKeyLength(cipherAlgorithm) >= keySize;
//        }
//        catch (GeneralSecurityException e)
//        {
//            return false;
//        }
        // not supported in 1.4
        return true;
    }

    protected boolean isUsableMAC(String macAlgorithm)
    {
        try
        {
            helper.createMac(macAlgorithm);
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
    }

    public JcaJceHelper getHelper()
    {
        return helper;
    }

    protected TlsBlockCipherImpl createCBCBlockCipherImpl(TlsCryptoParameters cryptoParams, String algorithm,
        int cipherKeySize, boolean forEncryption) throws GeneralSecurityException
    {
        String cipherName = algorithm + "/CBC/NoPadding";

        if (TlsImplUtils.isTLSv11(cryptoParams))
        {
            return createBlockCipher(cipherName, algorithm, cipherKeySize, forEncryption);
        }
        else
        {
            return createBlockCipherWithCBCImplicitIV(cipherName, algorithm, cipherKeySize, forEncryption);
        }
    }

    private TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, new JceChaCha20Poly1305(this, helper, true),
            new JceChaCha20Poly1305(this, helper, false), 32, 16, TlsAEADCipher.AEAD_CHACHA20_POLY1305);
    }

    private TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, true),
            createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_CCM);
    }

    private TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, true),
            createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_GCM);
    }

    private TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, true),
            createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_GCM);
    }

    private TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams,
            createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, true),
            createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_GCM);
    }

    protected TlsCipher createCipher_CBC(TlsCryptoParameters cryptoParams, String algorithm, int cipherKeySize,
        int macAlgorithm) throws GeneralSecurityException, IOException
    {
        TlsBlockCipherImpl encrypt = createCBCBlockCipherImpl(cryptoParams, algorithm, cipherKeySize, true);
        TlsBlockCipherImpl decrypt = createCBCBlockCipherImpl(cryptoParams, algorithm, cipherKeySize, false);

        TlsHMAC clientMAC = createMAC(cryptoParams, macAlgorithm);
        TlsHMAC serverMAC = createMAC(cryptoParams, macAlgorithm);

        return new TlsBlockCipher(cryptoParams, encrypt, decrypt, clientMAC, serverMAC, cipherKeySize);
    }

    private TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters cryptoParams)
        throws IOException, GeneralSecurityException
    {
        int cipherKeySize = 16, macSize = 16;
        return new TlsAEADCipher(cryptoParams, createAEADCipher("SM4/CCM/NoPadding", "SM4", cipherKeySize, true),
            createAEADCipher("SM4/CCM/NoPadding", "SM4", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_CCM);
    }

    private TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters cryptoParams)
        throws IOException, GeneralSecurityException
    {
        int cipherKeySize = 16, macSize = 16;
        return new TlsAEADCipher(cryptoParams, createAEADCipher("SM4/GCM/NoPadding", "SM4", cipherKeySize, true),
            createAEADCipher("SM4/GCM/NoPadding", "SM4", cipherKeySize, false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_GCM);
    }

    String getDigestName(int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
            return "MD5";
        case CryptoHashAlgorithm.sha1:
            return "SHA-1";
        case CryptoHashAlgorithm.sha224:
            return "SHA-224";
        case CryptoHashAlgorithm.sha256:
            return "SHA-256";
        case CryptoHashAlgorithm.sha384:
            return "SHA-384";
        case CryptoHashAlgorithm.sha512:
            return "SHA-512";
        case CryptoHashAlgorithm.sm3:
            return "SM3";
        default:
            throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }
}
