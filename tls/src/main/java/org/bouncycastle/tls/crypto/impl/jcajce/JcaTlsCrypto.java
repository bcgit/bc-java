package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Hashtable;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
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

    private final Hashtable supportedGroups = new Hashtable();

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

    public SecretKey calculateKeyAgreement(String agreementAlgorithm, PrivateKey privateKey, PublicKey publicKey, String secretAlgorithm)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = helper.createKeyAgreement(agreementAlgorithm);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret(secretAlgorithm);
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return new JcaTlsCertificate(this, encoding);
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
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    public TlsHMAC createHMAC(int macAlgorithm)
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
            throw new IllegalArgumentException("unknown MACAlgorithm: " + MACAlgorithm.getText(macAlgorithm));
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

    public boolean hasAllRawSignatureAlgorithms()
    {
        return !JcaUtils.isSunMSCAPIProviderActive();
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
        try
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.CHACHA20_POLY1305:
            {
                helper.createCipher("ChaCha7539");
                helper.createMac("Poly1305");
                break;
            }
            case EncryptionAlgorithm.AES_128_CCM:
            case EncryptionAlgorithm.AES_128_CCM_8:
            case EncryptionAlgorithm.AES_256_CCM:
            case EncryptionAlgorithm.AES_256_CCM_8:
            {
                helper.createCipher("AES/CCM/NoPadding");
                break;
            }
            case EncryptionAlgorithm.AES_128_GCM:
            case EncryptionAlgorithm.AES_256_GCM:
            {
                helper.createCipher("AES/GCM/NoPadding");
                break;
            }
            case EncryptionAlgorithm.ARIA_128_GCM:
            case EncryptionAlgorithm.ARIA_256_GCM:
            {
                helper.createCipher("ARIA/GCM/NoPadding");
                break;
            }
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
            {
                helper.createCipher("CAMELLIA/GCM/NoPadding");
                break;
            }

            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
                return false;
            }
        }
        catch (GeneralSecurityException e)
        {
            return false;
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

    public boolean hasNamedGroup(int namedGroup)
    {
        // TODO[tls] Actually check for DH support for the individual groups
        if (NamedGroup.refersToASpecificFiniteField(namedGroup))
        {
            return true;
        }

        if (!NamedGroup.refersToASpecificCurve(namedGroup))
        {
            return false;
        }

        String curveName = NamedGroup.getName(namedGroup);
        if (curveName == null)
        {
            return false;
        }

        int key = Integers.valueOf(namedGroup);

        synchronized (supportedGroups)
        {
            Boolean cached = (Boolean)supportedGroups.get(key);
            if (cached != null)
            {
                return cached.booleanValue();
            }
        }

        boolean result = isCurveSupported(curveName);

        synchronized (supportedGroups)
        {
            supportedGroups.put(key, Boolean.valueOf(result));
        }

        return result;
    }

    public boolean hasRSAEncryption()
    {
        try
        {
            createRSAEncryptionCipher();
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
    }

    public boolean hasSignatureAlgorithm(int signatureAlgorithm)
    {
        // TODO: expand
        return true;
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
    {
        /*
         * This is somewhat overkill, but much simpler for now. It's also consistent with SunJSSE behaviour.
         */
        if (sigAndHashAlgorithm.getHash() == HashAlgorithm.sha224 && JcaUtils.isSunMSCAPIProviderActive())
        {
            return false;
        }

        // TODO: expand
        return true;
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
        JcaTlsCertificate jcaCert = JcaTlsCertificate.convert(this, certificate);
        jcaCert.validateKeyUsage(KeyUsage.keyEncipherment);

        final RSAPublicKey pubKeyRSA = jcaCert.getPubKeyRSA();

        return new TlsEncryptor()
        {
            public byte[] encrypt(byte[] input, int inOff, int length)
                throws IOException
            {
                try
                {
                    Cipher c = createRSAEncryptionCipher();
                    // try wrap mode first - strictly speaking this is the correct one to use.
                    try
                    {
                        c.init(Cipher.WRAP_MODE, pubKeyRSA, getSecureRandom());
                        return c.wrap(new SecretKeySpec(input, inOff, length, "TLS"));
                    }
                    catch (Exception e)
                    {
                        // okay, maybe the provider does not support wrap mode.
                        c.init(Cipher.ENCRYPT_MODE, pubKeyRSA, getSecureRandom());
                        return c.doFinal(input, inOff, length);
                    }
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
     * If you want to create your own versions of the block ciphers for &lt; TLS 1.1, override this method.
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
     * If you want to create your own versions of HMACs, override this method.
     *
     * @param hmacName the name of the HMAC required.
     * @return a HMAC calculator.
     */
    protected TlsHMAC createHMAC(String hmacName)
    {
        try
        {
            return new JceTlsHMAC(helper.createMac(hmacName), hmacName);
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException("cannot create HMAC: " + hmacName, e);
        }
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
        return new TlsNullCipher(cryptoParams, createMAC(macAlgorithm), createMAC(macAlgorithm));
    }

    protected boolean isCurveSupported(String curveName)
    {
        try
        {
            AlgorithmParameters params = getHelper().createAlgorithmParameters("EC");
            params.init(new ECGenParameterSpec(curveName));
            if (params.getParameterSpec(ECParameterSpec.class) != null)
            {
                return true;
            }
        }
        catch (Exception e)
        {
        }

        return false;
    }

    JcaJceHelper getHelper()
    {
        return helper;
    }

    private TlsBlockCipher createAESCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "AES", true, cipherKeySize), createCBCBlockOperator(cryptoParams, "AES", false, cipherKeySize),
            createMAC(macAlgorithm), createMAC(macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipher createARIACipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "ARIA", true, cipherKeySize), createCBCBlockOperator(cryptoParams, "ARIA", false, cipherKeySize),
            createMAC(macAlgorithm), createMAC(macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipher createCamelliaCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "Camellia", true, cipherKeySize), createCBCBlockOperator(cryptoParams, "Camellia", false, cipherKeySize),
            createMAC(macAlgorithm), createMAC(macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipher createDESedeCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "DESede", true, 24), createCBCBlockOperator(cryptoParams, "DESede", false, 24),
            createMAC(macAlgorithm), createMAC(macAlgorithm), 24);
    }

    private TlsBlockCipher createSEEDCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(this, cryptoParams, createCBCBlockOperator(cryptoParams, "SEED", true, 16), createCBCBlockOperator(cryptoParams, "SEED", false, 16),
            createMAC(macAlgorithm), createMAC(macAlgorithm), 16);
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

    private TlsHMAC createMAC(int macAlgorithm) throws IOException
    {
        return createHMAC(macAlgorithm);
    }

    private TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, new JceChaCha20Poly1305(helper, true),
            new JceChaCha20Poly1305(helper, false), 32, 16, TlsAEADCipher.NONCE_RFC7905);
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

    private TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, true), createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(cryptoParams, createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, true), createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    String getDigestName(short hashAlgorithm)
    {
        String digestName;
        switch (hashAlgorithm)
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
            throw new IllegalArgumentException("unknown HashAlgorithm: " + HashAlgorithm.getText(hashAlgorithm));
        }
        return digestName;
    }
}
