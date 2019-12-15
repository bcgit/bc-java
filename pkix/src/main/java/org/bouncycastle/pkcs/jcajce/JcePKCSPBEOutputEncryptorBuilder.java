package org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;

public class JcePKCSPBEOutputEncryptorBuilder
{
    private final PBKDFConfig pbkdf;

    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private ASN1ObjectIdentifier algorithm;
    private ASN1ObjectIdentifier keyEncAlgorithm;
    private SecureRandom random;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;
    private AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();
    private int iterationCount = 1024;
    private PBKDF2Config.Builder pbkdfBuilder = new PBKDF2Config.Builder();

    public JcePKCSPBEOutputEncryptorBuilder(ASN1ObjectIdentifier keyEncryptionAlg)
    {
        this.pbkdf = null;
        if (isPKCS12(keyEncryptionAlg))
        {
            this.algorithm = keyEncryptionAlg;
            this.keyEncAlgorithm = keyEncryptionAlg;
        }
        else
        {
            this.algorithm = PKCSObjectIdentifiers.id_PBES2;
            this.keyEncAlgorithm = keyEncryptionAlg;
        }
    }

    /**
     * Constructor allowing different derivation functions such as PBKDF2 and scrypt.
     *
     * @param pbkdfAlgorithm key derivation algorithm definition to use.
     * @param keyEncryptionAlg encryption algorithm to apply the derived key with.
     */
    public JcePKCSPBEOutputEncryptorBuilder(PBKDFConfig pbkdfAlgorithm, ASN1ObjectIdentifier keyEncryptionAlg)
    {
        this.algorithm = PKCSObjectIdentifiers.id_PBES2;
        this.pbkdf = pbkdfAlgorithm;
        this.keyEncAlgorithm = keyEncryptionAlg;
    }

    public JcePKCSPBEOutputEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCSPBEOutputEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcePKCSPBEOutputEncryptorBuilder setRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
     * handle PKCS5 decryption.
     *
     * @param keySizeProvider a provider of integer secret key sizes.
     * @return the current builder.
     */
    public JcePKCSPBEOutputEncryptorBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
    {
        this.keySizeProvider = keySizeProvider;

        return this;
    }

    /**
     * Set the PRF to use for key generation. By default this is HmacSHA1.
     *
     * @param prf algorithm id for PRF.
     * @return the current builder.
     * @throws IllegalStateException if this builder was intialised with a PBKDFDef
     */
    public JcePKCSPBEOutputEncryptorBuilder setPRF(AlgorithmIdentifier prf)
    {
        if (pbkdf != null)
        {
            throw new IllegalStateException("set PRF count using PBKDFDef");
        }
        this.pbkdfBuilder.withPRF(prf);

        return this;
    }

    /**
     * Set the iteration count for the PBE calculation.
     *
     * @param iterationCount the iteration count to apply to the key creation.
     * @return the current builder.
     * @throws IllegalStateException if this builder was intialised with a PBKDFDef
     */
    public JcePKCSPBEOutputEncryptorBuilder setIterationCount(int iterationCount)
    {
        if (pbkdf != null)
        {
            throw new IllegalStateException("set iteration count using PBKDFDef");
        }
        this.iterationCount = iterationCount;
        this.pbkdfBuilder.withIterationCount(iterationCount);

        return this;
    }

    public OutputEncryptor build(final char[] password)
        throws OperatorCreationException
    {
        final Cipher cipher;
        SecretKey key;

        if (random == null)
        {
            random = new SecureRandom();
        }

        final AlgorithmIdentifier encryptionAlg;

        try
        {
            if (isPKCS12(algorithm))
            {
                byte[] salt = new byte[20];

                random.nextBytes(salt);

                cipher = helper.createCipher(algorithm.getId());

                cipher.init(Cipher.ENCRYPT_MODE, new PKCS12KeyWithParameters(password, salt, iterationCount));

                encryptionAlg = new AlgorithmIdentifier(algorithm, new PKCS12PBEParams(salt, iterationCount));
            }
            else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
            {
                PBKDFConfig pbkDef = (pbkdf == null) ? pbkdfBuilder.build() : pbkdf;

                if (MiscObjectIdentifiers.id_scrypt.equals(pbkDef.getAlgorithm()))
                {
                    ScryptConfig skdf = (ScryptConfig)pbkDef;

                    byte[] salt = new byte[skdf.getSaltLength()];

                    random.nextBytes(salt);

                    ScryptParams params = new ScryptParams(
                                                salt,
                                                skdf.getCostParameter(),
                                                skdf.getBlockSize(),
                                                skdf.getParallelizationParameter());
                    
                    SecretKeyFactory keyFact = helper.createSecretKeyFactory("SCRYPT");

                    key = keyFact.generateSecret(new ScryptKeySpec(password,
                        salt, skdf.getCostParameter(), skdf.getBlockSize(), skdf.getParallelizationParameter(),
                                                 keySizeProvider.getKeySize(new AlgorithmIdentifier(keyEncAlgorithm))));

                    cipher = helper.createCipher(keyEncAlgorithm.getId());

                    cipher.init(Cipher.ENCRYPT_MODE, simplifyPbeKey(key), random);

                    PBES2Parameters algParams = new PBES2Parameters(
                        new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, params),
                        new EncryptionScheme(keyEncAlgorithm, ASN1Primitive.fromByteArray(cipher.getParameters().getEncoded())));

                    encryptionAlg = new AlgorithmIdentifier(algorithm, algParams);
                }
                else
                {
                    PBKDF2Config pkdf = (PBKDF2Config)pbkDef;

                    byte[] salt = new byte[pkdf.getSaltLength()];

                    random.nextBytes(salt);

                    SecretKeyFactory keyFact = helper.createSecretKeyFactory(JceUtils.getAlgorithm(pkdf.getPRF().getAlgorithm()));

                    key = keyFact.generateSecret(new PBEKeySpec(password, salt, pkdf.getIterationCount(),
                                            keySizeProvider.getKeySize(new AlgorithmIdentifier(keyEncAlgorithm))));

                    cipher = helper.createCipher(keyEncAlgorithm.getId());

                    cipher.init(Cipher.ENCRYPT_MODE, simplifyPbeKey(key), random);

                    AlgorithmParameters algP = cipher.getParameters();

                    PBES2Parameters algParams;

                    if (algP != null)
                    {
                        algParams = new PBES2Parameters(
                            new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, pkdf.getIterationCount(), pkdf.getPRF())),
                            new EncryptionScheme(keyEncAlgorithm, ASN1Primitive.fromByteArray(cipher.getParameters().getEncoded())));
                    }
                    else
                    {
                        algParams = new PBES2Parameters(
                            new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, pkdf.getIterationCount(), pkdf.getPRF())),
                            new EncryptionScheme(keyEncAlgorithm));
                    }

                    encryptionAlg = new AlgorithmIdentifier(algorithm, algParams);
                }
            }
            else
            {
                throw new OperatorCreationException("unrecognised algorithm");
            }

            return new OutputEncryptor()
            {
                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return encryptionAlg;
                }

                public OutputStream getOutputStream(OutputStream out)
                {
                    return new CipherOutputStream(out, cipher);
                }

                public GenericKey getKey()
                {
                    if (isPKCS12(encryptionAlg.getAlgorithm()))
                    {
                        return new GenericKey(encryptionAlg, PKCS12PasswordToBytes(password));
                    }
                    else
                    {
                        return new GenericKey(encryptionAlg, PKCS5PasswordToBytes(password));
                    }
                }
            };
        }
        catch (Exception e)
        {
            throw new OperatorCreationException("unable to create OutputEncryptor: " + e.getMessage(), e);
        }
    }

    // some providers struggle with generic algorithm names in keys.
    private SecretKey simplifyPbeKey(SecretKey key)
    {
        if (algorithmNameFinder.hasAlgorithmName(keyEncAlgorithm))
        {
            String algName = algorithmNameFinder.getAlgorithmName(keyEncAlgorithm);

            if (algName.indexOf("AES") >= 0)
            {
                key = new SecretKeySpec(key.getEncoded(), "AES");
            }
        }

        return key;
    }

    private boolean isPKCS12(ASN1ObjectIdentifier algorithm)
    {
        return algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)
            || algorithm.on(BCObjectIdentifiers.bc_pbe_sha1_pkcs12)
            || algorithm.on(BCObjectIdentifiers.bc_pbe_sha256_pkcs12);
    }

    /**
     * converts a password to a byte array according to the scheme in
     * PKCS5 (ascii, no padding)
     *
     * @param password a character array representing the password.
     * @return a byte array representing the password.
     */
    private static byte[] PKCS5PasswordToBytes(
        char[] password)
    {
        if (password != null)
        {
            byte[] bytes = new byte[password.length];

            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)password[i];
            }

            return bytes;
        }
        else
        {
            return new byte[0];
        }
    }

    /**
     * converts a password to a byte array according to the scheme in
     * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
     *
     * @param password a character array representing the password.
     * @return a byte array representing the password.
     */
    private static byte[] PKCS12PasswordToBytes(
        char[] password)
    {
        if (password != null && password.length > 0)
        {
            // +1 for extra 2 pad bytes.
            byte[] bytes = new byte[(password.length + 1) * 2];

            for (int i = 0; i != password.length; i++)
            {
                bytes[i * 2] = (byte)(password[i] >>> 8);
                bytes[i * 2 + 1] = (byte)password[i];
            }

            return bytes;
        }
        else
        {
            return new byte[0];
        }
    }
}
