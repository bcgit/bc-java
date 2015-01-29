package org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;

public class JcePKCSPBEOutputEncryptorBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private ASN1ObjectIdentifier algorithm;
    private ASN1ObjectIdentifier keyEncAlgorithm;
    private SecureRandom random;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;
    private int iterationCount = 1024;

    public JcePKCSPBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm)
    {
        if (isPKCS12(algorithm))
        {
            this.algorithm = algorithm;
            this.keyEncAlgorithm = algorithm;
        }
        else
        {
            this.algorithm = PKCSObjectIdentifiers.id_PBES2;
            this.keyEncAlgorithm = algorithm;
        }
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
    
    public JcePKCSPBEOutputEncryptorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;

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
    public JcePKCSPBEOutputEncryptorBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
    {
        this.keySizeProvider = keySizeProvider;

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
        final byte[] salt = new byte[20];

        random.nextBytes(salt);

        try
        {
            if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
            {
                PBEKeySpec pbeSpec = new PBEKeySpec(password);

                SecretKeyFactory keyFact = helper.createSecretKeyFactory(algorithm.getId());

                PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);

                key = keyFact.generateSecret(pbeSpec);

                cipher = helper.createCipher(algorithm.getId());

                cipher.init(Cipher.ENCRYPT_MODE, key, defParams);

                encryptionAlg = new AlgorithmIdentifier(algorithm, new PKCS12PBEParams(salt, iterationCount));
            }
            else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
            {
                SecretKeyFactory keyFact = helper.createSecretKeyFactory(PKCSObjectIdentifiers.id_PBKDF2.getId());

                key = keyFact.generateSecret(new PBEKeySpec(password, salt, iterationCount, keySizeProvider.getKeySize(new AlgorithmIdentifier(keyEncAlgorithm))));

                cipher = helper.createCipher(keyEncAlgorithm.getId());

                cipher.init(Cipher.ENCRYPT_MODE, key, random);

                PBES2Parameters algParams = new PBES2Parameters(
                                   new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount)),
                                   new EncryptionScheme(keyEncAlgorithm, ASN1Primitive.fromByteArray(cipher.getParameters().getEncoded())));

                encryptionAlg = new AlgorithmIdentifier(algorithm, algParams);
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
                        return new GenericKey(encryptionAlg, PBEParametersGenerator.PKCS5PasswordToBytes(password));
                    }
                    else
                    {
                        return new GenericKey(encryptionAlg, PBEParametersGenerator.PKCS12PasswordToBytes(password));
                    }
                }
            };
        }
        catch (Exception e)
        {
            throw new OperatorCreationException("unable to create OutputEncryptor: " + e.getMessage(), e);
        }
    }

    private boolean isPKCS12(ASN1ObjectIdentifier algorithm)
    {
        return algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds)
            || algorithm.on(BCObjectIdentifiers.bc_pbe_sha1_pkcs12)
            || algorithm.on(BCObjectIdentifiers.bc_pbe_sha256_pkcs12);
    }
}
