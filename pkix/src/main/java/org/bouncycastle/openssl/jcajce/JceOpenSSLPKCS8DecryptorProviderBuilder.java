package org.bouncycastle.openssl.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.jcajce.PBKDF1KeyWithParameters;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * DecryptorProviderBuilder for producing DecryptorProvider for use with PKCS8EncryptedPrivateKeyInfo.
 */
public class JceOpenSSLPKCS8DecryptorProviderBuilder
{
    private JcaJceHelper helper;

    public JceOpenSSLPKCS8DecryptorProviderBuilder()
    {
        helper = new DefaultJcaJceHelper();
    }

    public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(String providerName)
    {
        helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(Provider provider)
    {
        helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public InputDecryptorProvider build(final char[] password)
        throws OperatorCreationException
    {
        return new InputDecryptorProvider()
        {
            public InputDecryptor get(final AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                final Cipher cipher;

                try
                {
                    if (PEMUtilities.isPKCS5Scheme2(algorithm.getAlgorithm()))
                    {
                        PBES2Parameters params = PBES2Parameters.getInstance(algorithm.getParameters());
                        KeyDerivationFunc func = params.getKeyDerivationFunc();
                        EncryptionScheme scheme = params.getEncryptionScheme();

                        String oid = scheme.getAlgorithm().getId();
                        SecretKey key;

                        if (MiscObjectIdentifiers.id_scrypt.equals(func.getAlgorithm()))
                        {
                            // RFC 7914 / RFC 8018 scrypt KDF inside PBES2.
                            // OpenSSL 1.1+ "openssl pkcs8 -topk8 -scrypt" produces this form;
                            // the caller-supplied char[] password is fed as UTF-8 bytes,
                            // matching OpenSSL's raw-bytes treatment (github #400). The derivation
                            // is driven through the provider's "SCRYPT" SecretKeyFactory (which
                            // applies the same UTF-8 conversion) so the provider stays overridable
                            // via setProvider(...), rather than calling the lightweight engine.
                            ScryptParams scrypt = ScryptParams.getInstance(func.getParameters());

                            // The KDF cost travels in the unauthenticated container, so bound it
                            // before deriving the key to cap the memory-exhaustion vector.
                            checkScryptCost(scrypt);

                            int keySizeBits = PEMUtilities.getKeySize(oid);
                            SecretKeyFactory scryptFact = helper.createSecretKeyFactory("SCRYPT");
                            SecretKey derived = scryptFact.generateSecret(new ScryptKeySpec(password,
                                scrypt.getSalt(),
                                scrypt.getCostParameter().intValue(),
                                scrypt.getBlockSize().intValue(),
                                scrypt.getParallelizationParameter().intValue(),
                                keySizeBits));
                            key = new SecretKeySpec(derived.getEncoded(), PEMUtilities.getAlgorithmName(oid));
                        }
                        else
                        {
                            PBKDF2Params defParams = (PBKDF2Params)func.getParameters();

                            // Bound the unauthenticated iteration count before deriving the key.
                            int iterationCount = checkIterationCount(defParams.getIterationCount());
                            byte[] salt = defParams.getSalt();

                            if (PEMUtilities.isHmacSHA1(defParams.getPrf()))
                            {
                                key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt, iterationCount);
                            }
                            else
                            {
                                key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt, iterationCount, defParams.getPrf());
                            }
                        }

                        cipher = helper.createCipher(PEMUtilities.getCipherName(scheme.getAlgorithm()));
                        AlgorithmParameters algParams = helper.createAlgorithmParameters(oid);

                        algParams.init(scheme.getParameters().toASN1Primitive().getEncoded());

                        cipher.init(Cipher.DECRYPT_MODE, key, algParams);
                    }
                    else if (PEMUtilities.isPKCS12(algorithm.getAlgorithm()))
                    {
                        PKCS12PBEParams params = PKCS12PBEParams.getInstance(algorithm.getParameters());

                        cipher = helper.createCipher(PEMUtilities.getCipherName(algorithm.getAlgorithm()));

                        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, params.getIV(), checkIterationCount(params.getIterations())));
                    }
                    else if (PEMUtilities.isPKCS5Scheme1(algorithm.getAlgorithm()))
                    {
                        PBEParameter params = PBEParameter.getInstance(algorithm.getParameters());

                        cipher = helper.createCipher(PEMUtilities.getCipherName(algorithm.getAlgorithm()));

                        cipher.init(Cipher.DECRYPT_MODE, new PBKDF1KeyWithParameters(password, new CharToByteConverter()
                        {
                            public String getType()
                            {
                                return "ASCII";
                            }

                            public byte[] convert(char[] password)
                            {
                                return Strings.toByteArray(password);     // just drop hi-order byte.
                            }
                        }, params.getSalt(), checkIterationCount(params.getIterationCount())));
                    }
                    else
                    {
                        throw new PEMException("Unknown algorithm: " + algorithm.getAlgorithm());
                    }

                    return new InputDecryptor()
                    {
                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return algorithm;
                        }

                        public InputStream getInputStream(InputStream encIn)
                        {
                            return new CipherInputStream(encIn, cipher);
                        }
                    };
                }
                catch (IOException e)
                {
                    throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
                }
            };
        };
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
