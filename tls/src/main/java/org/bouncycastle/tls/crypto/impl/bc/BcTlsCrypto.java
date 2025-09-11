package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.CryptoSignatureAlgorithm;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.Tls13NullCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.tls.crypto.impl.TlsNullCipher;
import org.bouncycastle.util.Arrays;

/**
 * Class for providing cryptographic services for TLS based on implementations in the BC light-weight API.
 * <p>
 *     This class provides default implementations for everything. If you need to customise it, extend the class
 *     and override the appropriate methods.
 * </p>
 */
public class BcTlsCrypto
    extends AbstractTlsCrypto
{
    private final SecureRandom entropySource;

    // TODO[tls] Better default SecureRandom?
    public BcTlsCrypto()
    {
        this(new SecureRandom());
    }

    public BcTlsCrypto(SecureRandom entropySource)
    {
        this.entropySource = entropySource;
    }

    BcTlsSecret adoptLocalSecret(byte[] data)
    {
        return new BcTlsSecret(this, data);
    }

    public SecureRandom getSecureRandom()
    {
        return entropySource;
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return createCertificate(CertificateType.X509, encoding);
    }

    public TlsCertificate createCertificate(short type, byte[] encoding)
        throws IOException
    {
        switch (type)
        {
        case CertificateType.X509:
            return new BcTlsCertificate(this, encoding);
        case CertificateType.RawPublicKey:
            return new BcTlsRawKeyCertificate(this, encoding);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.ARIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.SEED_CBC:
        case EncryptionAlgorithm.SM4_CBC:
            return createCipher_CBC(cryptoParams, encryptionAlgorithm, 16, macAlgorithm);

        case EncryptionAlgorithm._3DES_EDE_CBC:
            return createCipher_CBC(cryptoParams, encryptionAlgorithm, 24, macAlgorithm);

        case EncryptionAlgorithm.AES_256_CBC:
        case EncryptionAlgorithm.ARIA_256_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return createCipher_CBC(cryptoParams, encryptionAlgorithm, 32, macAlgorithm);

        case EncryptionAlgorithm.AES_128_CCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.AES_128_CCM_8:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(cryptoParams, 16, 8);
        case EncryptionAlgorithm.AES_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_GCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.AES_256_CCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.AES_256_CCM_8:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(cryptoParams, 32, 8);
        case EncryptionAlgorithm.AES_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_GCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.ARIA_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_ARIA_GCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.ARIA_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_ARIA_GCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            // NOTE: Ignores macAlgorithm
            return createChaCha20Poly1305(cryptoParams);
        case EncryptionAlgorithm.NULL:
            return createNullCipher(cryptoParams, macAlgorithm);
        case EncryptionAlgorithm.NULL_HMAC_SHA256:
            // NOTE: Ignores macAlgorithm
            return create13NullCipher(cryptoParams, MACAlgorithm.hmac_sha256);
        case EncryptionAlgorithm.NULL_HMAC_SHA384:
            // NOTE: Ignores macAlgorithm
            return create13NullCipher(cryptoParams, MACAlgorithm.hmac_sha384);
        case EncryptionAlgorithm.SM4_CCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_SM4_CCM(cryptoParams);
        case EncryptionAlgorithm.SM4_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_SM4_GCM(cryptoParams);

        case EncryptionAlgorithm._28147_CNT_IMIT:
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.KUZNYECHIK_CTR_OMAC:
        case EncryptionAlgorithm.MAGMA_CTR_OMAC:
        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.RC4_128:
        case EncryptionAlgorithm.RC4_40:
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new BcTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        switch (ecConfig.getNamedGroup())
        {
        case NamedGroup.x25519:
            return new BcX25519Domain(this);
        case NamedGroup.x448:
            return new BcX448Domain(this);
        default:
            return new BcTlsECDomain(this, ecConfig);
        }
    }

    public TlsKemDomain createKemDomain(TlsKemConfig kemConfig)
    {
        return new BcTlsMLKemDomain(this, kemConfig);
    }

    public TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial)
    {
        int cryptoHashAlgorithm = CryptoHashAlgorithm.sha256;
        Digest digest = createDigest(cryptoHashAlgorithm);

        byte[] seed = new byte[TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm)];
        getSecureRandom().nextBytes(seed);

        DigestRandomGenerator nonceGen = new DigestRandomGenerator(digest);
        nonceGen.addSeedMaterial(additionalSeedMaterial);
        nonceGen.addSeedMaterial(seed);

        return new BcTlsNonceGenerator(nonceGen);
    }

    public boolean hasAnyStreamVerifiers(Vector signatureAndHashAlgorithms)
    {
        for (int i = 0, count = signatureAndHashAlgorithms.size(); i < count; ++i)
        {
            SignatureAndHashAlgorithm algorithm = (SignatureAndHashAlgorithm)signatureAndHashAlgorithms.elementAt(i);

            switch (SignatureScheme.from(algorithm))
            {
            case SignatureScheme.ed25519:
            case SignatureScheme.ed448:
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
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
        case CryptoHashAlgorithm.sha1:
        case CryptoHashAlgorithm.sha224:
        case CryptoHashAlgorithm.sha256:
        case CryptoHashAlgorithm.sha384:
        case CryptoHashAlgorithm.sha512:
        case CryptoHashAlgorithm.sm3:
        case CryptoHashAlgorithm.gostr3411_2012_256:
            return true;

        default:
            return false;
        }
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

        // TODO[RFC 9189]
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
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
        case EncryptionAlgorithm.AES_128_GCM:
        case EncryptionAlgorithm.AES_256_CBC:
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
        case EncryptionAlgorithm.AES_256_GCM:
        case EncryptionAlgorithm.ARIA_128_CBC:
        case EncryptionAlgorithm.ARIA_128_GCM:
        case EncryptionAlgorithm.ARIA_256_CBC:
        case EncryptionAlgorithm.ARIA_256_GCM:
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
        case EncryptionAlgorithm.CHACHA20_POLY1305:
        case EncryptionAlgorithm.NULL:
        case EncryptionAlgorithm.SEED_CBC:
        case EncryptionAlgorithm.SM4_CBC:
        case EncryptionAlgorithm.SM4_CCM:
        case EncryptionAlgorithm.SM4_GCM:
            return true;

        case EncryptionAlgorithm.NULL_HMAC_SHA256:
            return hasMacAlgorithm(MACAlgorithm.hmac_sha256);

        case EncryptionAlgorithm.NULL_HMAC_SHA384:
            return hasMacAlgorithm(MACAlgorithm.hmac_sha384);

        case EncryptionAlgorithm._28147_CNT_IMIT:
        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.KUZNYECHIK_CTR_OMAC:
        case EncryptionAlgorithm.MAGMA_CTR_OMAC:
        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.RC4_128:
        case EncryptionAlgorithm.RC4_40:
        default:
            return false;
        }
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

    public boolean hasKemAgreement()
    {
        return true;
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
        return NamedGroup.refersToASpecificCurve(namedGroup)
            || NamedGroup.refersToASpecificFiniteField(namedGroup)
            || NamedGroup.refersToASpecificKem(namedGroup);
    }

    public boolean hasRSAEncryption()
    {
        return true;
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

        // TODO[RFC 9189]
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
        int signatureScheme = SignatureScheme.from(sigAndHashAlgorithm);
        if (SignatureScheme.isMLDSA(signatureScheme))
        {
            return true;
        }

        short signature = sigAndHashAlgorithm.getSignature();

        switch (sigAndHashAlgorithm.getHash())
        {
        case HashAlgorithm.md5:
            return SignatureAlgorithm.rsa == signature && hasSignatureAlgorithm(signature);
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
        case SignatureScheme.mldsa44:
        case SignatureScheme.mldsa65:
        case SignatureScheme.mldsa87:
            return true;
        default:
        {
            short signature = SignatureScheme.getSignatureAlgorithm(signatureScheme);

            switch(SignatureScheme.getCryptoHashAlgorithm(signatureScheme))
            {
            case CryptoHashAlgorithm.md5:
                return SignatureAlgorithm.rsa == signature && hasSignatureAlgorithm(signature);
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

    public TlsSecret createHybridSecret(TlsSecret s1, TlsSecret s2)
    {
        return adoptLocalSecret(Arrays.concatenate(s1.extract(), s2.extract()));
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

    public Digest cloneDigest(int cryptoHashAlgorithm, Digest digest)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
            return new MD5Digest((MD5Digest)digest);
        case CryptoHashAlgorithm.sha1:
            return new SHA1Digest((SHA1Digest)digest);
        case CryptoHashAlgorithm.sha224:
            return new SHA224Digest((SHA224Digest)digest);
        case CryptoHashAlgorithm.sha256:
            return SHA256Digest.newInstance(digest);
        case CryptoHashAlgorithm.sha384:
            return new SHA384Digest((SHA384Digest)digest);
        case CryptoHashAlgorithm.sha512:
            return new SHA512Digest((SHA512Digest)digest);
        case CryptoHashAlgorithm.sm3:
            return new SM3Digest((SM3Digest)digest);
        case CryptoHashAlgorithm.gostr3411_2012_256:
            return new GOST3411_2012_256Digest((GOST3411_2012_256Digest)digest);
        default:
            throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    public Digest createDigest(int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
            return new MD5Digest();
        case CryptoHashAlgorithm.sha1:
            return new SHA1Digest();
        case CryptoHashAlgorithm.sha224:
            return new SHA224Digest();
        case CryptoHashAlgorithm.sha256:
            return new SHA256Digest();
        case CryptoHashAlgorithm.sha384:
            return new SHA384Digest();
        case CryptoHashAlgorithm.sha512:
            return new SHA512Digest();
        case CryptoHashAlgorithm.sm3:
            return new SM3Digest();
        case CryptoHashAlgorithm.gostr3411_2012_256:
            return new GOST3411_2012_256Digest();
        default:
            throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    public TlsHash createHash(int cryptoHashAlgorithm)
    {
        return new BcTlsHash(this, cryptoHashAlgorithm);
    }

    protected BlockCipher createBlockCipher(int encryptionAlgorithm)
        throws IOException
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return createDESedeEngine();
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.AES_256_CBC:
            return createAESEngine();
        case EncryptionAlgorithm.ARIA_128_CBC:
        case EncryptionAlgorithm.ARIA_256_CBC:
            return createARIAEngine();
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return createCamelliaEngine();
        case EncryptionAlgorithm.SEED_CBC:
            return createSEEDEngine();
        case EncryptionAlgorithm.SM4_CBC:
            return createSM4Engine();
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected BlockCipher createCBCBlockCipher(BlockCipher blockCipher)
    {
        return CBCBlockCipher.newInstance(blockCipher);
    }

    protected BlockCipher createCBCBlockCipher(int encryptionAlgorithm)
        throws IOException
    {
        return createCBCBlockCipher(createBlockCipher(encryptionAlgorithm));
    }

    protected TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams) throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new BcChaCha20Poly1305(true), new BcChaCha20Poly1305(false), 32, 16,
            TlsAEADCipher.AEAD_CHACHA20_POLY1305, null);
    }

    protected TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAEADCipher.AEAD_CCM,
            null);
    }

    protected TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAEADCipher.AEAD_GCM, null);
    }

    protected TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAEADCipher.AEAD_GCM, null);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAEADCipher.AEAD_GCM, null);
    }

    protected TlsCipher createCipher_CBC(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int cipherKeySize,
        int macAlgorithm) throws IOException
    {
        BcTlsBlockCipherImpl encrypt = new BcTlsBlockCipherImpl(createCBCBlockCipher(encryptionAlgorithm), true);
        BcTlsBlockCipherImpl decrypt = new BcTlsBlockCipherImpl(createCBCBlockCipher(encryptionAlgorithm), false);

        TlsHMAC clientMAC = createMAC(cryptoParams, macAlgorithm);
        TlsHMAC serverMAC = createMAC(cryptoParams, macAlgorithm);

        return new TlsBlockCipher(cryptoParams, encrypt, decrypt, clientMAC, serverMAC, cipherKeySize);
    }

    protected TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters cryptoParams)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 16, 16, TlsAEADCipher.AEAD_CCM, null);
    }

    protected TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters cryptoParams)
        throws IOException
    {
        BcTlsAEADCipherImpl encrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), true);
        BcTlsAEADCipherImpl decrypt = new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), false);

        return new TlsAEADCipher(cryptoParams, encrypt, decrypt, 16, 16, TlsAEADCipher.AEAD_GCM, null);
    }

    protected Tls13NullCipher create13NullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new Tls13NullCipher(cryptoParams, createHMAC(macAlgorithm), createHMAC(macAlgorithm));
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsNullCipher(cryptoParams, createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm));
    }

    protected BlockCipher createAESEngine()
    {
        return AESEngine.newInstance();
    }

    protected BlockCipher createARIAEngine()
    {
        return new ARIAEngine();
    }

    protected BlockCipher createCamelliaEngine()
    {
        return new CamelliaEngine();
    }

    protected BlockCipher createDESedeEngine()
    {
        return new DESedeEngine();
    }

    protected BlockCipher createSEEDEngine()
    {
        return new SEEDEngine();
    }

    protected BlockCipher createSM4Engine()
    {
        return new SM4Engine();
    }

    protected AEADBlockCipher createCCMMode(BlockCipher engine)
    {
        return CCMBlockCipher.newInstance(engine);
    }

    protected AEADBlockCipher createGCMMode(BlockCipher engine)
    {
        // TODO Consider allowing custom configuration of multiplier
        return GCMBlockCipher.newInstance(engine);
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_CCM()
    {
        return createCCMMode(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_GCM()
    {
        return createGCMMode(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_ARIA_GCM()
    {
        return createGCMMode(createARIAEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_Camellia_GCM()
    {
        return createGCMMode(createCamelliaEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_SM4_CCM()
    {
        return createCCMMode(createSM4Engine());
    }

    protected AEADBlockCipher createAEADBlockCipher_SM4_GCM()
    {
        return createGCMMode(createSM4Engine());
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
        return new BcTlsHMAC(new HMac(createDigest(cryptoHashAlgorithm)));
    }

    protected TlsHMAC createHMAC_SSL(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return new BcSSL3HMAC(createDigest(CryptoHashAlgorithm.md5));
        case MACAlgorithm.hmac_sha1:
            return new BcSSL3HMAC(createDigest(CryptoHashAlgorithm.sha1));
        case MACAlgorithm.hmac_sha256:
            return new BcSSL3HMAC(createDigest(CryptoHashAlgorithm.sha256));
        case MACAlgorithm.hmac_sha384:
            return new BcSSL3HMAC(createDigest(CryptoHashAlgorithm.sha384));
        case MACAlgorithm.hmac_sha512:
            return new BcSSL3HMAC(createDigest(CryptoHashAlgorithm.sha512));
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsHMAC createMAC(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
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
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6GroupParameters srpGroup = new SRP6GroupParameters(ng[0], ng[1]);

        SRP6Client srp6Client = new SRP6Client();
        srp6Client.init(srpGroup, createDigest(CryptoHashAlgorithm.sha1), getSecureRandom());

        return new BcTlsSRP6Client(srp6Client);
    }

    public TlsSRP6Server createSRP6Server(TlsSRPConfig srpConfig, BigInteger srpVerifier)
    {
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6GroupParameters srpGroup = new SRP6GroupParameters(ng[0], ng[1]);

        SRP6Server srp6Server = new SRP6Server();
        srp6Server.init(srpGroup, srpVerifier, createDigest(CryptoHashAlgorithm.sha1), getSecureRandom());

        return new BcTlsSRP6Server(srp6Server);
    }

    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig srpConfig)
    {
        BigInteger[] ng = srpConfig.getExplicitNG();

        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
        srp6VerifierGenerator.init(ng[0], ng[1], createDigest(CryptoHashAlgorithm.sha1));

        return new BcTlsSRP6VerifierGenerator(srp6VerifierGenerator);
    }

    public TlsSecret hkdfInit(int cryptoHashAlgorithm)
    {
        return adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm)]);
    }
}
