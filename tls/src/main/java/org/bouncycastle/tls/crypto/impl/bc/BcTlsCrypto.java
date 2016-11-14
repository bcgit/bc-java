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
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CombinedHash;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
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
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.ChaCha20Poly1305Cipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsEncryptor;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.tls.crypto.impl.TlsNullCipher;
import org.bouncycastle.tls.crypto.impl.TlsStreamCipher;
import org.bouncycastle.tls.crypto.impl.TlsStreamCipherImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Times;

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
    private final DigestRandomGenerator nonceGen;
    private final SecureRandom entropySource;

    public BcTlsCrypto(SecureRandom entropySource)
    {
        this.entropySource = entropySource;

        Digest digest = createDigest(HashAlgorithm.sha256);

        nonceGen = new DigestRandomGenerator(digest);

        nonceGen.addSeedMaterial(nextCounterValue());
        nonceGen.addSeedMaterial(Times.nanoTime());

        byte[] seed = new byte[digest.getDigestSize()];
        entropySource.nextBytes(seed);

        nonceGen.addSeedMaterial(seed);
    }

    BcTlsSecret adoptLocalSecret(byte[] data)
    {
        return new BcTlsSecret(this, data);
    }

    public byte[] createNonce(int size)
    {
        byte[] nonce = new byte[size];

        nonceGen.nextBytes(nonce);

        return nonce;
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

    protected TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
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
        case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_OCB(cryptoParams, 16, 12);
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
        case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_OCB(cryptoParams, 32, 12);
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
        case EncryptionAlgorithm.RC4_128:
            return createRC4Cipher(cryptoParams, 16, macAlgorithm);
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
        return new BcTlsECDomain(this, ecConfig);
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

    public boolean hasEncryptionAlgorithm(int encryptionAlgorithm)
    {
        return true;
    }

    public boolean hasHashAlgorithm(short hashAlgorithm)
    {
        return true;
    }

    public boolean hasMacAlgorithm(int macAlgorithm)
    {
        return true;
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        return true;
    }

    public boolean hasRSAEncryption()
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

//    public byte[] calculateKeyBlock(TlsContext context, int length)
//    {
//        SecurityParameters securityParameters = context.getSecurityParameters();
//        byte[] master_secret = securityParameters.getMasterSecret();
//        byte[] seed = concat(securityParameters.getServerRandom(), securityParameters.getClientRandom());
//
//        if (isSSL(context))
//        {
//            return context.getCrypto().createSecret(master_secret).deriveSSLKeyBlock(seed, length).extract();
//        }
//
//        return PRF(context, master_secret, ExporterLabel.key_expansion, seed, length);
//    }

    // TODO[tls-ops] Shouldn't be static, need to pass BcTlsCrypto instance to callers
    static Digest createDigest(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
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
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public TlsHash createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (signatureAndHashAlgorithm == null)
        {
            return new CombinedHash(this);
        }

        return new BcTlsHash(signatureAndHashAlgorithm.getHash(), createDigest(signatureAndHashAlgorithm.getHash()));
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
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public Digest createPRFHash(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.tls_prf_legacy:
            return new CombinedPRF();
        default:
            return createDigest(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
        }
    }

    protected TlsCipher createAESCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createAESBlockCipher(), true), new BlockOperator(createAESBlockCipher(), false),
            createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createCamelliaCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createCamelliaBlockCipher(), true), new BlockOperator(createCamelliaBlockCipher(), false),
            createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        throws IOException
    {
        return new ChaCha20Poly1305Cipher(cryptoParams,
                new StreamOperator(new ChaCha7539Engine(), true), new StreamOperator(new ChaCha7539Engine(), false),
            new MacOperator(new Poly1305()), new MacOperator(new Poly1305()));
    }

    protected TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_AES_CCM(), true), new AeadOperator(createAEADBlockCipher_AES_CCM(), false),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_AES_GCM(), true), new AeadOperator(createAEADBlockCipher_AES_GCM(), false),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_OCB(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_AES_OCB(), true), new AeadOperator(createAEADBlockCipher_AES_OCB(), false),
            cipherKeySize, macSize, TlsAEADCipher.NONCE_RFC7905);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(cryptoParams, new AeadOperator(createAEADBlockCipher_Camellia_GCM(), true), new AeadOperator(createAEADBlockCipher_Camellia_GCM(), false),
            cipherKeySize, macSize);
    }

    protected TlsBlockCipher createDESedeCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createDESedeBlockCipher(), true), new BlockOperator(createDESedeBlockCipher(), false),
            createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm), 24);
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsNullCipher(cryptoParams, createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm));
    }

    protected TlsStreamCipher createRC4Cipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsStreamCipher(cryptoParams, new StreamOperator(createRC4StreamCipher(), true), new StreamOperator(createRC4StreamCipher(), false),
            createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm), cipherKeySize, false);
    }

    protected TlsBlockCipher createSEEDCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(this, cryptoParams, new BlockOperator(createSEEDBlockCipher(), true), new BlockOperator(createSEEDBlockCipher(), false),
            createMac(cryptoParams, macAlgorithm), createMac(cryptoParams, macAlgorithm), 16);
    }

    protected BlockCipher createAESEngine()
    {
        return new AESEngine();
    }

    protected BlockCipher createCamelliaEngine()
    {
        return new CamelliaEngine();
    }

    protected BlockCipher createAESBlockCipher()
    {
        return new CBCBlockCipher(createAESEngine());
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

    protected AEADBlockCipher createAEADBlockCipher_AES_OCB()
    {
        return new OCBBlockCipher(createAESEngine(), createAESEngine());
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

    private TlsHMAC createMac(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException
    {
        if (TlsImplUtils.isSSL(cryptoParams))
        {
            return createSSl3HMAC((short)macAlgorithm);
        }
        else
        {
            return createHMAC((short)macAlgorithm);
        }
    }

    protected Digest createHMACDigest(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return createDigest(HashAlgorithm.md5);
        case MACAlgorithm.hmac_sha1:
            return createDigest(HashAlgorithm.sha1);
        case MACAlgorithm.hmac_sha256:
            return createDigest(HashAlgorithm.sha256);
        case MACAlgorithm.hmac_sha384:
            return createDigest(HashAlgorithm.sha384);
        case MACAlgorithm.hmac_sha512:
            return createDigest(HashAlgorithm.sha512);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsHMAC createHMAC(int hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return new HMacOperator(createDigest(HashAlgorithm.md5));
        case MACAlgorithm.hmac_sha1:
            return new HMacOperator(createDigest(HashAlgorithm.sha1));
        case MACAlgorithm.hmac_sha256:
            return new HMacOperator(createDigest(HashAlgorithm.sha256));
        case MACAlgorithm.hmac_sha384:
            return new HMacOperator(createDigest(HashAlgorithm.sha384));
        case MACAlgorithm.hmac_sha512:
            return new HMacOperator(createDigest(HashAlgorithm.sha512));
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
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

    protected TlsHMAC createSSl3HMAC(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return new SSL3Mac(createDigest(HashAlgorithm.md5));
        case MACAlgorithm.hmac_sha1:
            return new SSL3Mac(createDigest(HashAlgorithm.sha1));
        case MACAlgorithm.hmac_sha256:
            return new SSL3Mac(createDigest(HashAlgorithm.sha256));
        case MACAlgorithm.hmac_sha384:
            return new SSL3Mac(createDigest(HashAlgorithm.sha384));
        case MACAlgorithm.hmac_sha512:
            return new SSL3Mac(createDigest(HashAlgorithm.sha512));
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public class CombinedPRF
        implements Digest
    {
        private final MD5Digest md5;
        private final SHA1Digest sha1;

        CombinedPRF()
        {
            this.md5 = new MD5Digest();
            this.sha1 = new SHA1Digest();
        }

        /**
         * @see org.bouncycastle.crypto.Digest#getAlgorithmName()
         */
        public String getAlgorithmName()
        {
            return md5.getAlgorithmName() + " and " + sha1.getAlgorithmName();
        }

        /**
         * @see org.bouncycastle.crypto.Digest#getDigestSize()
         */
        public int getDigestSize()
        {
            return md5.getDigestSize() + sha1.getDigestSize();
        }

        /**
         * @see org.bouncycastle.crypto.Digest#update(byte)
         */
        public void update(byte input)
        {
            md5.update(input);
            sha1.update(input);
        }

        /**
         * @see org.bouncycastle.crypto.Digest#update(byte[], int, int)
         */
        public void update(byte[] input, int inOff, int len)
        {
            md5.update(input, inOff, len);
            sha1.update(input, inOff, len);
        }

        /**
         * @see org.bouncycastle.crypto.Digest#doFinal(byte[], int)
         */
        public int doFinal(byte[] output, int outOff)
        {
            int i1 = md5.doFinal(output, outOff);
            int i2 = sha1.doFinal(output, outOff + i1);
            return i1 + i2;
        }

        /**
         * @see org.bouncycastle.crypto.Digest#reset()
         */
        public void reset()
        {
            md5.reset();
            sha1.reset();
        }
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

        public void setKey(byte[] key)
        {
            this.key = new KeyParameter(key);
            cipher.init(isEncrypting, new ParametersWithIV(this.key, new byte[cipher.getBlockSize()]));
        }

        public void init(byte[] iv)
        {
            cipher.init(isEncrypting, new ParametersWithIV(null, iv));
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

    private class StreamOperator
        implements TlsStreamCipherImpl
    {
        private final boolean isEncrypting;
        private final StreamCipher cipher;

        private KeyParameter key;

        StreamOperator(StreamCipher cipher, boolean isEncrypting)
        {
            this.cipher = cipher;
            this.isEncrypting = isEncrypting;
        }

        public void setKey(byte[] key)
        {
            this.key = new KeyParameter(key);
        }

        public void init(byte[] iv)
        {
            if (iv != null)
            {
                cipher.init(isEncrypting, new ParametersWithIV(this.key, iv));
            }
            else
            {
                cipher.init(isEncrypting, this.key);
            }
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            return cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);
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

        public void setKey(byte[] key)
        {
            this.key = new KeyParameter(key);
        }

        public void init(byte[] nonce, int macSize, byte[] additionalData)
        {
            cipher.init(isEncrypting, new AEADParameters(key, macSize * 8, nonce, additionalData));
        }

        public int getOutputSize(int inputLength)
        {
            return cipher.getOutputSize(inputLength);
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            int len = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);

            try
            {
                return len + cipher.doFinal(output, outputOffset + len);
            }
            catch (InvalidCipherTextException e)
            {
                // TODO:
                e.printStackTrace(); throw new RuntimeCryptoException(e.toString());
            }
        }
    }

    private class MacOperator implements TlsMAC
    {
        private final Mac mac;

        MacOperator(Mac mac)
        {
            this.mac = mac;
        }

        public void setKey(byte[] key)
        {
            mac.init(new KeyParameter(key));
        }

        public void update(byte[] input, int inOff, int length)
        {
            mac.update(input, inOff, length);
        }

        public byte[] calculateMAC()
        {
            byte[] rv = new byte[mac.getMacSize()];

            mac.doFinal(rv, 0);

            return rv;
        }

        public int getMacLength()
        {
            return mac.getMacSize();
        }

        public void reset()
        {
            mac.reset();
        }
    }

    private class HMacOperator implements TlsHMAC
    {
        private final HMac hmac;

        HMacOperator(Digest digest)
        {
            this.hmac = new HMac(digest);
        }

        public void setKey(byte[] key)
        {
            hmac.init(new KeyParameter(key));
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

    private static long counter = Times.nanoTime();

    private synchronized static long nextCounterValue()
    {
        return ++counter;
    }
}
