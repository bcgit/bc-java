package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CombinedHash;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoException;
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
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Client;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Server;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6VerifierGenerator;
import org.bouncycastle.util.Arrays;

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

    public byte[] createNonce(int size)
    {
        byte[] nonce = new byte[size];

        nonceEntropySource.nextBytes(nonce);

        return nonce;
    }

    public SecureRandom getSecureRandom()
    {
        return entropySource;
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return new JcaTlsCertificate(encoding, helper);
    }

    protected TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        try
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
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    public final TlsHMAC createHMAC(int macAlgorithm)
        throws IOException
    {
        try
        {
            switch (macAlgorithm)
            {
            case MACAlgorithm._null:
                return null;
            case MACAlgorithm.hmac_md5:
                return createHMAC("HmacMD5");
            case MACAlgorithm.hmac_sha1:
                return createHMAC("HmacSHA1");
            case MACAlgorithm.hmac_sha256:
                return createHMAC("HmacSHA256");
            case MACAlgorithm.hmac_sha384:
                return createHMAC("HmacSHA384");
            case MACAlgorithm.hmac_sha512:
                return createHMAC("HmacSHA512");
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot create HMAC: " + e.getMessage(), e);
        }
    }

    public TlsSRP6Client createSRP6Client(TlsSRPConfig srpConfig)
    {
        final SRP6Client srpClient = new SRP6Client();

        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6Group srpGroup= new SRP6Group(ng[0], ng[1]);
        srpClient.init(srpGroup, createHash(HashAlgorithm.sha1), this.getSecureRandom());

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
        srpServer.init(srpGroup, srpVerifier, createHash(HashAlgorithm.sha1), this.getSecureRandom());
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

        verifierGenerator.init(ng[0], ng[1], createHash(HashAlgorithm.sha1));

        return new TlsSRP6VerifierGenerator()
        {
            public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
            {
                return verifierGenerator.generateVerifier(salt, identity, password);
            }
        };
    }

    public boolean hasEncryptionAlgorithm(int encryptionAlgorithm)
    {
        if (encryptionAlgorithm == EncryptionAlgorithm.CHACHA20_POLY1305)
        {
            try
            {
                helper.createCipher("ChaCha7539");
                helper.createMac("Poly1305");
            }
            catch (GeneralSecurityException e)
            {
                return false;
            }
        }

        return true;
    }

    public boolean hasHashAlgorithm(short hashAlgorithm)
    {
        // TODO: expand
        return true;
    }

    public boolean hasMacAlgorithm(int macAlgorithm)
    {
        // TODO: expand
        return true;
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        // TODO: expand
        return true;
    }

    public boolean hasRSAEncryption()
    {
        // TODO: expand
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

    public TlsHash createHash(short algorithm)
    {
        try
        {
            return createHash(getDigestName(algorithm));
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to create message digest:" + e.getMessage(), e);
        }
    }

    public TlsHash createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (signatureAndHashAlgorithm == null)
        {
            return new CombinedHash(this);
        }

        return createHash(signatureAndHashAlgorithm.getHash());
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new JceTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        return new JceTlsECDomain(this, ecConfig);
    }

    public TlsEncryptor createEncryptor(TlsCertificate certificate)
        throws IOException
    {
        JcaTlsCertificate jcaCert = JcaTlsCertificate.convert(certificate, this.getHelper());
        jcaCert.validateKeyUsage(KeyUsage.keyEncipherment);

        final RSAPublicKey pubKeyRSA = jcaCert.getPubKeyRSA();

        return new TlsEncryptor()
        {
            public byte[] encrypt(byte[] input, int inOff, int length)
                throws IOException
            {
                try
                {
                    Cipher encoding = getHelper().createCipher("RSA/NONE/PKCS1Padding");
                    encoding.init(Cipher.WRAP_MODE, pubKeyRSA, getSecureRandom());
                    return encoding.doFinal(input, inOff, length);
                }
                catch (GeneralSecurityException e)
                {
                    /*
                     * This should never happen, only during decryption.
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
        };
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
        return new JceAEADCipherImpl(helper.createCipher(cipherName), algorithm, isEncrypting);
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
    protected TlsBlockCipherImpl createBlockCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipherImpl(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of the block ciphers for < TLS 1.1, override this method.
     *
     * @param cipherName   the full name of the cipher (algorithm/mode/padding)
     * @param algorithm    the base algorithm name
     * @param keySize      keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsBlockCipherImpl createBlockCipherWithCBCImplicitIV(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipherWithCBCImplicitIVImpl(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of stream ciphers, override this method.
     *
     * @param cipherName   the full name of the cipher (algorithm/mode/padding)
     * @param algorithm    the base algorithm name
     * @param keySize      keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsStreamCipherImpl createStreamCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceStreamCipherImpl(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of HMACs, override this method.
     *
     * @param hmacName the name of the HMAC required.
     * @return a HMAC calculator.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsHMAC createHMAC(String hmacName)
        throws GeneralSecurityException
    {
        return new JceTlsHMAC(helper.createMac(hmacName), hmacName);
    }

    /**
     * If you want to create your own versions of MACs, override this method.
     *
     * @param macName the name of the MAC required.
     * @return a MAC calculator.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsMAC createMAC(String macName)
        throws GeneralSecurityException
    {
        return new JceTlsMAC(helper.createMac(macName), macName);
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
        return new JcaTlsHash(helper.createDigest(digestName));
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
        return new TlsNullCipher(cryptoParams, createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm));
    }

    JcaJceHelper getHelper()
    {
        return helper;
    }

    private TlsBlockCipher createAESCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "AES", true, cipherKeySize), createCBCBlockOperator(cryptoParams, "AES", false, cipherKeySize),
            createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipher createCamelliaCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "Camellia", true, cipherKeySize), createCBCBlockOperator(cryptoParams, "Camellia", false, cipherKeySize),
            createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipher createDESedeCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "DESede", true, 24), createCBCBlockOperator(cryptoParams, "DESede", false, 24),
            createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), 24);
    }

    private TlsBlockCipher createSEEDCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "SEED", true, 16), createCBCBlockOperator(cryptoParams, "SEED", false, 16),
            createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), 16);
    }

    private TlsBlockCipherImpl createCBCBlockOperator(TlsCryptoParameters cryptoParams, String algorithm, boolean forEncryption, int keySize)
        throws GeneralSecurityException
    {
        String cipherName = algorithm + "/CBC/NoPadding";

        if (TlsImplUtils.isTLSv11(cryptoParams))
        {
            return createBlockCipher(cipherName, algorithm, keySize, forEncryption);
        }
        else
        {
            return createBlockCipherWithCBCImplicitIV(cipherName, algorithm, keySize, forEncryption);
        }
    }

    private TlsHMAC createMAC(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws GeneralSecurityException, IOException
    {
        if (TlsImplUtils.isSSL(cryptoParams))
        {
            return createSSL3HMAC(macAlgorithm);
        }
        else
        {
            return createHMAC(macAlgorithm);
        }
    }

    private TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        throws IOException, GeneralSecurityException
    {
        return new ChaCha20Poly1305Cipher(cryptoParams,
            createStreamCipher("ChaCha7539", "ChaCha7539", 32, true), createStreamCipher("ChaCha7539", "ChaCha7539", 32, false),
            createMAC("Poly1305"), createMAC("Poly1305"));
    }

    private TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsAEADCipher createCipher_AES_OCB(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("AES/OCB/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/OCB/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize, TlsAEADCipher.NONCE_RFC7905);
    }

    private TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, true), createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsStreamCipher createRC4Cipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsStreamCipher(cryptoParams, createStreamCipher("RC4", "RC4", 128, true), createStreamCipher("RC4", "RC4", 128, false),
            createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), cipherKeySize, false);
    }

    private TlsHMAC createSSL3HMAC(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return new SSL3Mac(createHash(getDigestName(HashAlgorithm.md5)), 16, 64);
        case MACAlgorithm.hmac_sha1:
            return new SSL3Mac(createHash(getDigestName(HashAlgorithm.sha1)), 20, 64);
        case MACAlgorithm.hmac_sha256:
            return new SSL3Mac(createHash(getDigestName(HashAlgorithm.sha256)), 32, 64);
        case MACAlgorithm.hmac_sha384:
            return new SSL3Mac(createHash(getDigestName(HashAlgorithm.sha384)), 48, 128);
        case MACAlgorithm.hmac_sha512:
            return new SSL3Mac(createHash(getDigestName(HashAlgorithm.sha512)), 64, 128);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    String getDigestName(short algorithm)
    {
        String digestName;
        switch (algorithm)
        {
        case HashAlgorithm.md5:
            digestName = "MD5";
            break;
        case HashAlgorithm.sha1:
            digestName = "SHA-1";
            break;
        case HashAlgorithm.sha224:
            digestName = "SHA-224";
            break;
        case HashAlgorithm.sha256:
            digestName = "SHA-256";
            break;
        case HashAlgorithm.sha384:
            digestName = "SHA-384";
            break;
        case HashAlgorithm.sha512:
            digestName = "SHA-512";
            break;
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
        return digestName;
    }

    /**
     * HMAC implementation based on original internet draft for HMAC (RFC 2104)
     * <p/>
     * The difference is that padding is concatenated versus XORed with the key
     * <p/>
     * H(K + opad, H(K + ipad, text))
     */
    private static class SSL3Mac
        implements TlsHMAC
    {
        private static final byte IPAD_BYTE = (byte)0x36;
        private static final byte OPAD_BYTE = (byte)0x5C;

        private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
        private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

        private TlsHash digest;
        private final int digestSize;
        private final int internalBlockSize;
        private int padLength;

        private byte[] secret;

        /**
         * Base constructor for one of the standard digest algorithms that the byteLength of
         * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
         *
         * @param digest            the digest.
         * @param digestSize        the digest size.
         * @param internalBlockSize the digest internal block size.
         */
        public SSL3Mac(TlsHash digest, int digestSize, int internalBlockSize)
        {
            this.digest = digest;
            this.digestSize = digestSize;
            this.internalBlockSize = internalBlockSize;

            if (digestSize == 20)
            {
                this.padLength = 40;
            }
            else
            {
                this.padLength = 48;
            }
        }

        public void setKey(byte[] key)
        {
            this.secret = key;

            reset();
        }

        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        public byte[] calculateMAC()
        {
            byte[] tmp = digest.calculateHash();

            digest.update(secret, 0, secret.length);
            digest.update(OPAD, 0, padLength);
            digest.update(tmp, 0, tmp.length);

            byte[] rv = digest.calculateHash();

            reset();

            return rv;
        }

        public int getInternalBlockSize()
        {
            return internalBlockSize;
        }

        public int getMacLength()
        {
            return digestSize;
        }

        /**
         * Reset the mac generator.
         */
        public void reset()
        {
            digest.reset();
            digest.update(secret, 0, secret.length);
            digest.update(IPAD, 0, padLength);
        }

        private static byte[] genPad(byte b, int count)
        {
            byte[] padding = new byte[count];
            Arrays.fill(padding, b);
            return padding;
        }
    }
}
