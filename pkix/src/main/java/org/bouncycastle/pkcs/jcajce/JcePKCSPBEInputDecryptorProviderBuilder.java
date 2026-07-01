package org.bouncycastle.pkcs.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.jcajce.PBKDF1Key;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.operator.SecretKeySizeProvider;

/**
 * JCA-based builder for an {@link InputDecryptorProvider} that handles the password-based
 * decryption schemes encountered in PKCS#12 / PKCS#8: the legacy {@code pkcs-12PbeIds} family
 * (RFC 7292 Appendix C), PBES2 / PBKDF2 and PBES2 / scrypt (RFC 8018, RFC 7914), and the older
 * PBE1 schemes ({@code pbeWithMD5AndDES-CBC}, {@code pbeWithSHA1AndDES-CBC}).
 */
public class JcePKCSPBEInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private boolean      wrongPKCS12Zero = false;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;

    /**
     * Base constructor.
     */
    public JcePKCSPBEInputDecryptorProviderBuilder()
    {
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCSPBEInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Enable a workaround for older PKCS#12 files that derive the encryption key without
     * applying the trailing zero byte that RFC 7292 requires.
     *
     * @param tryWrong {@code true} to enable the workaround.
     * @return this builder.
     */
    public JcePKCSPBEInputDecryptorProviderBuilder setTryWrongPKCS12Zero(boolean tryWrong)
    {
        this.wrongPKCS12Zero = tryWrong;

        return this;
    }

    /**
     * Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
     * handle PKCS5 decryption.
     *
     * @param keySizeProvider  a provider of integer secret key sizes.
     *
     * @return the current builder.
     */
    public JcePKCSPBEInputDecryptorProviderBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
    {
        this.keySizeProvider = keySizeProvider;

        return this;
    }

    /**
     * Bind the builder to a password and return an {@link InputDecryptorProvider} that can
     * produce decryptors for the password-based algorithm identifiers it is asked for.
     *
     * @param password the password used to derive the encryption key.
     * @return a configured decryptor provider.
     */
    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                SecretKey key;
                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                    {
                        PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, wrongPKCS12Zero, pbeParams.getIV(), checkIterationCount(pbeParams.getIterations())));

                        encryptionAlg = algorithmIdentifier;
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                    {
                        PBES2Parameters alg = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());

                        if (MiscObjectIdentifiers.id_scrypt.equals(alg.getKeyDerivationFunc().getAlgorithm()))
                        {
                            ScryptParams params = ScryptParams.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            // The KDF cost travels in the unauthenticated container, so bound it
                            // before deriving the key to cap the memory-exhaustion vector.
                            checkScryptCost(params);

                            SecretKeyFactory keyFact = helper.createSecretKeyFactory("SCRYPT");

                            key = keyFact.generateSecret(new ScryptKeySpec(password,
                                       params.getSalt(), params.getCostParameter().intValue(), params.getBlockSize().intValue(),
                                       params.getParallelizationParameter().intValue(), keySizeProvider.getKeySize(encScheme)));
                        }
                        else
                        {
                            SecretKeyFactory keyFact = helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
                            PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            // Bound the unauthenticated iteration count before deriving the key.
                            int iterationCount = checkIterationCount(func.getIterationCount());

                            if (func.isDefaultPrf())
                            {
                                key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), iterationCount, keySizeProvider.getKeySize(encScheme)));
                            }
                            else
                            {
                                key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), iterationCount, keySizeProvider.getKeySize(encScheme), func.getPrf()));
                            }
                        }

                        cipher = helper.createCipher(alg.getEncryptionScheme().getAlgorithm().getId());

                        encryptionAlg = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                        ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
                        if (encParams instanceof ASN1OctetString)
                        {
                            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                        }
                        else if (encParams instanceof ASN1Sequence && isCCMorGCM(alg.getEncryptionScheme()))
                        {
                            AlgorithmParameters params = helper.createAlgorithmParameters(alg.getEncryptionScheme().getAlgorithm().getId());

                            params.init(((ASN1Sequence)encParams).getEncoded());

                            cipher.init(Cipher.DECRYPT_MODE, key, params);
                        }
                        else if (encParams == null) // absent parameters
                        {
                            cipher.init(Cipher.DECRYPT_MODE, key);
                        }
                        else
                        {
                            // TODO: at the moment it's just GOST, but...
                            GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                            cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                        }
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)
                        || algorithm.equals(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC))
                    {
                        PBEParameter pbeParams = PBEParameter.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PBKDF1Key(password, PasswordConverter.ASCII),
                                new PBEParameterSpec(pbeParams.getSalt(), checkIterationCount(pbeParams.getIterationCount())));
                    }
                    else
                    {
                        throw new OperatorCreationException("unable to create InputDecryptor: algorithm " + algorithm + " unknown.");
                    }
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return encryptionAlg;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, cipher);
                    }
                };
            }
        };
    }

    private boolean isCCMorGCM(ASN1Encodable encParams)
    {
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(encParams);
        ASN1Encodable params = algId.getParameters();

        if (params instanceof ASN1Sequence)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(params);
            if (seq.size() == 2)
            {
                return seq.getObjectAt(1) instanceof ASN1Integer;
            }
        }

        return false;
    }

    // The KDF cost parameters of a PBES2-protected key arrive in an unauthenticated container, so
    // they are bounded before the (memory/CPU intensive) derivation to cap a decryption-time DoS.
    private static final int MAX_SCRYPT_BLOCK_SIZE = 1024;

    private static void checkScryptCost(ScryptParams params)
        throws IOException
    {
        BigInteger n = params.getCostParameter();
        BigInteger r = params.getBlockSize();

        if (n == null || r == null
            || n.signum() <= 0 || r.signum() <= 0
            || n.bitLength() > 31 || r.bitLength() > 31)
        {
            throw new IOException("invalid scrypt parameters");
        }

        long blockSize = r.longValue();
        if (blockSize > MAX_SCRYPT_BLOCK_SIZE)
        {
            throw new IOException("scrypt block size (" + blockSize + ") greater than " + MAX_SCRYPT_BLOCK_SIZE);
        }

        long maxMemory = Properties.asInteger(Properties.PBE_MAX_SCRYPT_MEMORY, 1 << 30);
        if (n.longValue() > maxMemory / (128L * blockSize))
        {
            throw new IOException("scrypt cost parameters require more than " + maxMemory + " bytes");
        }
    }

    private static int checkIterationCount(BigInteger ic)
        throws IOException
    {
        if (ic == null || ic.signum() < 0 || ic.bitLength() > 31)
        {
            throw new IOException("invalid iteration count");
        }

        long max = Properties.asInteger(Properties.PBE_MAX_ITERATION_COUNT, 10000000);
        if (ic.longValue() > max)
        {
            throw new IOException("iteration count (" + ic + ") greater than " + max);
        }

        return ic.intValue();
    }
}
