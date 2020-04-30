package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
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
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsEncryptor;
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
        return new BcTlsCertificate(this, encoding);
    }

    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return createDESedeCipher(cryptoParams, macAlgorithm);
        case EncryptionAlgorithm.AES_128_CBC:
            return createAESCipher(cryptoParams, 16, macAlgorithm);
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
            return createAESCipher(cryptoParams, 32, macAlgorithm);
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
            return createARIACipher(cryptoParams, 16, macAlgorithm);
        case EncryptionAlgorithm.ARIA_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_ARIA_GCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.ARIA_256_CBC:
            return createARIACipher(cryptoParams, 32, macAlgorithm);
        case EncryptionAlgorithm.ARIA_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_ARIA_GCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
            return createCamelliaCipher(cryptoParams, 16, macAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(cryptoParams, 16, 16);
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return createCamelliaCipher(cryptoParams, 32, macAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(cryptoParams, 32, 16);
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            // NOTE: Ignores macAlgorithm
            return createChaCha20Poly1305(cryptoParams);
        case EncryptionAlgorithm.NULL:
            return createNullCipher(cryptoParams, macAlgorithm);
        case EncryptionAlgorithm.SEED_CBC:
            return createSEEDCipher(cryptoParams, macAlgorithm);
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

    protected TlsEncryptor createEncryptor(TlsCertificate certificate)
        throws IOException
    {
        BcTlsCertificate bcCert = BcTlsCertificate.convert(this, certificate);
        bcCert.validateKeyUsage(KeyUsage.keyEncipherment);

        final RSAKeyParameters pubKeyRSA = bcCert.getPubKeyRSA();

        return new TlsEncryptor()
        {
            public byte[] encrypt(byte[] input, int inOff, int length)
                throws IOException
            {
                try
                {
                    PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
                    encoding.init(true, new ParametersWithRandom(pubKeyRSA, getSecureRandom()));
                    return encoding.processBlock(input, inOff, length);
                }
                catch (InvalidCipherTextException e)
                {
                    /*
                     * This should never happen, only during decryption.
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
        };
    }

    public TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial)
    {
        final DigestRandomGenerator nonceGen = new DigestRandomGenerator(createDigest(HashAlgorithm.sha256));

        if (additionalSeedMaterial != null && additionalSeedMaterial.length > 0)
        {
            nonceGen.addSeedMaterial(additionalSeedMaterial);
        }

        byte[] seed = new byte[createDigest(HashAlgorithm.sha256).getDigestSize()];
        entropySource.nextBytes(seed);

        nonceGen.addSeedMaterial(seed);

        return new TlsNonceGenerator()
        {
            public byte[] generateNonce(int size)
            {
                byte[] nonce = new byte[size];
                nonceGen.nextBytes(nonce);
                return nonce;
            }
        };
    }

    public boolean hasAllRawSignatureAlgorithms()
    {
        // TODO[RFC 8422] Revisit the need to buffer the handshake for "Intrinsic" hash signatures
        return !hasSignatureAlgorithm(SignatureAlgorithm.ed25519)
            && !hasSignatureAlgorithm(SignatureAlgorithm.ed448);
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
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.RC4_128:
        case EncryptionAlgorithm.RC4_40:
            return false;

        default:
            return true;
        }
    }

    public boolean hasHashAlgorithm(short hashAlgorithm)
    {
        return true;
    }

    public boolean hasMacAlgorithm(int macAlgorithm)
    {
        return true;
    }

    public boolean hasNamedGroup(int namedGroup)
    {
        return NamedGroup.refersToASpecificGroup(namedGroup);
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
            return true;
        default:
            return false;
        }
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        return hasSignatureAlgorithm(sigAndHashAlgorithm.getSignature());
    }

    public boolean hasSignatureScheme(int signatureScheme)
    {
        return hasSignatureAlgorithm((short)(signatureScheme & 0xFF));
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
        entropySource.nextBytes(data);
        TlsUtils.writeVersion(version, data, 0);
        return adoptLocalSecret(data);
    }

    public Digest createDigest(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.none:
            return new NullDigest();
        case HashAlgorithm.md5:
            return new MD5Digest();
        case HashAlgorithm.sha1:
            return new SHA1Digest();
        case HashAlgorithm.sha224:
            return new SHA224Digest();
        case HashAlgorithm.sha256:
            return new SHA256Digest();
        case HashAlgorithm.sha384:
            return new SHA384Digest();
        case HashAlgorithm.sha512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("invalid HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    public TlsHash createHash(short algorithm)
    {
        return new BcTlsHash(algorithm, createDigest(algorithm));
    }

    private static class BcTlsHash
        implements TlsHash
    {
        private final short hashAlgorithm;
        private final Digest digest;

        BcTlsHash(short hashAlgorithm, Digest digest)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.digest = digest;
        }

        public void update(byte[] data, int offSet, int length)
        {
            digest.update(data, offSet, length);
        }

        public byte[] calculateHash()
        {
            byte[] rv = new byte[digest.getDigestSize()];
            digest.doFinal(rv, 0);
            return rv;
        }

        public Object clone()
        {
            return new BcTlsHash(hashAlgorithm, cloneDigest(hashAlgorithm, digest));
        }

        public void reset()
        {
            digest.reset();
        }
    }

    public static Digest cloneDigest(short hashAlgorithm, Digest hash)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest((MD5Digest)hash);
        case HashAlgorithm.sha1:
            return new SHA1Digest((SHA1Digest)hash);
        case HashAlgorithm.sha224:
            return new SHA224Digest((SHA224Digest)hash);
        case HashAlgorithm.sha256:
            return new SHA256Digest((SHA256Digest)hash);
        case HashAlgorithm.sha384:
            return new SHA384Digest((SHA384Digest)hash);
        case HashAlgorithm.sha512:
            return new SHA512Digest((SHA512Digest)hash);
        default:
            throw new IllegalArgumentException("invalid HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    protected TlsCipher createAESCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createAESBlockCipher(), true),
            new BlockOperator(createAESBlockCipher(), false), createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createARIACipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createARIABlockCipher(), true),
            new BlockOperator(createARIABlockCipher(), false), createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createCamelliaCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createCamelliaBlockCipher(), true),
            new BlockOperator(createCamelliaBlockCipher(), false), createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams) throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new BcChaCha20Poly1305(true), new BcChaCha20Poly1305(false), 32, 16,
            TlsAEADCipher.AEAD_CHACHA20_POLY1305);
    }

    protected TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_AES_CCM(), true),
            new AeadOperator(createAEADBlockCipher_AES_CCM(), false), cipherKeySize, macSize, TlsAEADCipher.AEAD_CCM);
    }

    protected TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_AES_GCM(), true),
            new AeadOperator(createAEADBlockCipher_AES_GCM(), false), cipherKeySize, macSize, TlsAEADCipher.AEAD_GCM);
    }

    protected TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_ARIA_GCM(), true),
            new AeadOperator(createAEADBlockCipher_ARIA_GCM(), false), cipherKeySize, macSize, TlsAEADCipher.AEAD_GCM);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_Camellia_GCM(), true),
            new AeadOperator(createAEADBlockCipher_Camellia_GCM(), false), cipherKeySize, macSize,
            TlsAEADCipher.AEAD_GCM);
    }

    protected TlsBlockCipher createDESedeCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createDESedeBlockCipher(), true),
            new BlockOperator(createDESedeBlockCipher(), false), createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm), 24);
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsNullCipher(cryptoParams, createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm));
    }

    protected TlsBlockCipher createSEEDCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createSEEDBlockCipher(), true),
            new BlockOperator(createSEEDBlockCipher(), false), createMAC(cryptoParams, macAlgorithm),
            createMAC(cryptoParams, macAlgorithm), 16);
    }

    protected BlockCipher createAESEngine()
    {
        return new AESEngine();
    }

    protected BlockCipher createARIAEngine()
    {
        return new ARIAEngine();
    }

    protected BlockCipher createCamelliaEngine()
    {
        return new CamelliaEngine();
    }

    protected BlockCipher createAESBlockCipher()
    {
        return new CBCBlockCipher(createAESEngine());
    }

    protected BlockCipher createARIABlockCipher()
    {
        return new CBCBlockCipher(createARIAEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_CCM()
    {
        return new CCMBlockCipher(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_GCM()
    {
        // TODO Consider allowing custom configuration of multiplier
        return new GCMBlockCipher(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_ARIA_GCM()
    {
        // TODO Consider allowing custom configuration of multiplier
        return new GCMBlockCipher(createARIAEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_Camellia_GCM()
    {
        // TODO Consider allowing custom configuration of multiplier
        return new GCMBlockCipher(createCamelliaEngine());
    }

    protected BlockCipher createCamelliaBlockCipher()
    {
        return new CBCBlockCipher(createCamelliaEngine());
    }

    protected BlockCipher createDESedeBlockCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }

    protected StreamCipher createRC4StreamCipher()
    {
        return new RC4Engine();
    }

    protected BlockCipher createSEEDBlockCipher()
    {
        return new CBCBlockCipher(new SEEDEngine());
    }

    public TlsHMAC createHMAC(short hashAlgorithm)
    {
        return new HMacOperator(createDigest(hashAlgorithm));
    }

    public TlsHMAC createHMAC(int macAlgorithm)
    {
        return createHMAC(TlsUtils.getHashAlgorithmForHMACAlgorithm(macAlgorithm));
    }

    protected TlsHMAC createHMAC_SSL(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return new BcSSL3HMAC(createDigest(HashAlgorithm.md5));
        case MACAlgorithm.hmac_sha1:
            return new BcSSL3HMAC(createDigest(HashAlgorithm.sha1));
        case MACAlgorithm.hmac_sha256:
            return new BcSSL3HMAC(createDigest(HashAlgorithm.sha256));
        case MACAlgorithm.hmac_sha384:
            return new BcSSL3HMAC(createDigest(HashAlgorithm.sha384));
        case MACAlgorithm.hmac_sha512:
            return new BcSSL3HMAC(createDigest(HashAlgorithm.sha512));
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
        final SRP6Client srpClient = new SRP6Client();

        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6GroupParameters srpGroup= new SRP6GroupParameters(ng[0], ng[1]);
        srpClient.init(srpGroup, new SHA1Digest(), this.getSecureRandom());

        return new TlsSRP6Client()
        {
            public BigInteger calculateSecret(BigInteger serverB)
                throws TlsFatalAlert
            {
                try
                {
                    return srpClient.calculateSecret(serverB);
                }
                catch (CryptoException e)
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
        SRP6GroupParameters srpGroup= new SRP6GroupParameters(ng[0], ng[1]);
        srpServer.init(srpGroup, srpVerifier, new SHA1Digest(), this.getSecureRandom());
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
                catch (CryptoException e)
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

        verifierGenerator.init(ng[0], ng[1], new SHA1Digest());

        return new TlsSRP6VerifierGenerator()
        {
            public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
            {
                return verifierGenerator.generateVerifier(salt, identity, password);
            }
        };
    }

    public TlsSecret hkdfInit(short hashAlgorithm)
    {
        return adoptLocalSecret(new byte[HashAlgorithm.getOutputSize(hashAlgorithm)]);
    }

    private class BlockOperator
        implements TlsBlockCipherImpl
    {
        private final boolean isEncrypting;
        private final BlockCipher cipher;

        private KeyParameter key;

        BlockOperator(BlockCipher cipher, boolean isEncrypting)
        {
            this.cipher = cipher;
            this.isEncrypting = isEncrypting;
        }

        public void setKey(byte[] key, int keyOff, int keyLen)
        {
            this.key = new KeyParameter(key, keyOff, keyLen);
            cipher.init(isEncrypting, new ParametersWithIV(this.key, new byte[cipher.getBlockSize()]));
        }

        public void init(byte[] iv, int ivOff, int ivLen)
        {
            cipher.init(isEncrypting, new ParametersWithIV(null, iv, ivOff, ivLen));
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            int blockSize = cipher.getBlockSize();

            for (int i = 0; i < inputLength; i += blockSize)
            {
                cipher.processBlock(input, inputOffset + i, output, outputOffset + i);
            }

            return inputLength;
        }

        public int getBlockSize()
        {
            return cipher.getBlockSize();
        }
    }

    public class AeadOperator
        implements TlsAEADCipherImpl
    {
        private final boolean isEncrypting;
        private final AEADBlockCipher cipher;

        private KeyParameter key;

        public AeadOperator(AEADBlockCipher cipher, boolean isEncrypting)
        {
            this.cipher = cipher;
            this.isEncrypting = isEncrypting;
        }

        public void setKey(byte[] key, int keyOff, int keyLen)
        {
            this.key = new KeyParameter(key, keyOff, keyLen);
        }

        public void init(byte[] nonce, int macSize, byte[] additionalData)
        {
            cipher.init(isEncrypting, new AEADParameters(key, macSize * 8, nonce, additionalData));
        }

        public int getOutputSize(int inputLength)
        {
            return cipher.getOutputSize(inputLength);
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] extraInput, byte[] output, int outputOffset)
            throws IOException
        {
            int len = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);

            int extraInputLength = extraInput.length;
            if (extraInputLength > 0)
            {
                if (!isEncrypting)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                len += cipher.processBytes(extraInput, 0, extraInputLength, output, outputOffset + len);
            }

            try
            {
                len += cipher.doFinal(output, outputOffset + len);
            }
            catch (InvalidCipherTextException e)
            {
                // TODO:
                throw new RuntimeCryptoException(e.toString());
            }

            return len;
        }
    }

    private class HMacOperator implements TlsHMAC
    {
        private final HMac hmac;

        HMacOperator(Digest digest)
        {
            this.hmac = new HMac(digest);
        }

        public void setKey(byte[] key, int keyOff, int keyLen)
        {
            hmac.init(new KeyParameter(key, keyOff, keyLen));
        }

        public void update(byte[] input, int inOff, int length)
        {
            hmac.update(input, inOff, length);
        }

        public byte[] calculateMAC()
        {
            byte[] rv = new byte[hmac.getMacSize()];

            hmac.doFinal(rv, 0);

            return rv;
        }

        public void calculateMAC(byte[] output, int outOff)
        {
            hmac.doFinal(output, outOff);
        }

        public int getInternalBlockSize()
        {
            return ((ExtendedDigest)hmac.getUnderlyingDigest()).getByteLength();
        }

        public int getMacLength()
        {
            return hmac.getMacSize();
        }

        public void reset()
        {
            hmac.reset();
        }
    }
}
