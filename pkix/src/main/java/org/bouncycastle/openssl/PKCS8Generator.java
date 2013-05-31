package org.bouncycastle.openssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

public class PKCS8Generator
    implements PemObjectGenerator
{
    public static final ASN1ObjectIdentifier AES_128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
    public static final ASN1ObjectIdentifier AES_192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
    public static final ASN1ObjectIdentifier AES_256_CBC = NISTObjectIdentifiers.id_aes256_CBC;

    public static final ASN1ObjectIdentifier DES3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;

    public static final ASN1ObjectIdentifier PBE_SHA1_RC4_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC4_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4;
    public static final ASN1ObjectIdentifier PBE_SHA1_3DES = PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_2DES = PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC2_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC;
    public static final ASN1ObjectIdentifier PBE_SHA1_RC2_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC;

    private PrivateKeyInfo key;
    private OutputEncryptor outputEncryptor;
    private JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder;

    /**
     * Constructor for an unencrypted private key PEM object.
     *
     * @param key private key to be encoded.
     * @deprecated use JcaPKCS8Generator
     */
    public PKCS8Generator(PrivateKey key)
    {
        this.key = PrivateKeyInfo.getInstance(key.getEncoded());
    }

    /**
     * Constructor for an encrypted private key PEM object.
     *
     * @param key       private key to be encoded
     * @param algorithm encryption algorithm to use
     * @param provider  name of provider to use
     * @throws NoSuchProviderException  if provider cannot be found
     * @throws NoSuchAlgorithmException if algorithm/mode cannot be found
     *  @deprecated  use JcaPKCS8Generator
     */
    public PKCS8Generator(PrivateKey key, ASN1ObjectIdentifier algorithm, String provider)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        Provider prov = Security.getProvider(provider);

        if (prov == null)
        {
            throw new NoSuchProviderException("cannot find provider: " + provider);
        }

        init(key, algorithm, prov);
    }

    /**
     * Constructor for an encrypted private key PEM object.
     *
     * @param key       private key to be encoded
     * @param algorithm encryption algorithm to use
     * @param provider  provider to use
     * @throws NoSuchAlgorithmException if algorithm/mode cannot be found
     * @deprecated  use JcaPKCS8Generator
     */
    public PKCS8Generator(PrivateKey key, ASN1ObjectIdentifier algorithm, Provider provider)
        throws NoSuchAlgorithmException
    {
        init(key, algorithm, provider);
    }

    /**
     * Base constructor.
     */
    public PKCS8Generator(PrivateKeyInfo key, OutputEncryptor outputEncryptor)
    {
        this.key = key;
        this.outputEncryptor = outputEncryptor;
    }

    private void init(PrivateKey key, ASN1ObjectIdentifier algorithm, Provider provider)
        throws NoSuchAlgorithmException
    {
        this.key = PrivateKeyInfo.getInstance(key.getEncoded());
        this.encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(algorithm);

        encryptorBuilder.setProvider(provider);
    }

    /**
     * @deprecated ignored in the updated case.
     */
    public PKCS8Generator setSecureRandom(SecureRandom random)
    {
        encryptorBuilder.setRandom(random);

        return this;
    }

    /**
     * @deprecated ignored in the updated case.
     */
    public PKCS8Generator setPassword(char[] password)
    {
        encryptorBuilder.setPasssword(password);

        return this;
    }

    /**
     * @deprecated ignored in the updated case.
     */
    public PKCS8Generator setIterationCount(int iterationCount)
    {
        encryptorBuilder.setIterationCount(iterationCount);

        return this;
    }

    public PemObject generate()
        throws PemGenerationException
    {
        try
        {
            if (encryptorBuilder != null)
            {
                outputEncryptor = encryptorBuilder.build();
            }
        }
        catch (OperatorCreationException e)
        {
            throw new PemGenerationException("unable to create operator: " + e.getMessage(), e);
        }

        if (outputEncryptor != null)
        {
            return generate(key, outputEncryptor);
        }
        else
        {
            return generate(key, null);
        }
    }

    private PemObject generate(PrivateKeyInfo key, OutputEncryptor encryptor)
        throws PemGenerationException
    {
        try
        {
            byte[] keyData = key.getEncoded();

            if (encryptor == null)
            {
                return new PemObject("PRIVATE KEY", keyData);
            }

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            OutputStream cOut = encryptor.getOutputStream(bOut);

            cOut.write(key.getEncoded());

            cOut.close();

            EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(encryptor.getAlgorithmIdentifier(), bOut.toByteArray());

            return new PemObject("ENCRYPTED PRIVATE KEY", info.getEncoded());
        }
        catch (IOException e)
        {
            throw new PemGenerationException("unable to process encoded key data: " + e.getMessage(), e);
        }
    }
}
