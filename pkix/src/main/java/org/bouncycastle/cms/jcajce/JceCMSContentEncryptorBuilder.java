package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCaptureStream;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;
import org.bouncycastle.operator.jcajce.JceGenericKey;
import org.bouncycastle.util.Strings;

/**
 * Builder for the content encryptor in EnvelopedData - used to encrypt the actual transmitted content.
 */
public class JceCMSContentEncryptorBuilder
{
    private static final SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;
    private static final byte[] hkdfSalt = Strings.toByteArray("The Cryptographic Message Syntax");

    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private SecureRandom random;
    private AlgorithmIdentifier algorithmIdentifier;
    private AlgorithmParameters algorithmParameters;
    private ASN1ObjectIdentifier kdfAlgorithm;

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID));
    }

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;

        int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

        if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC))
        {
            if (keySize != 168 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 168;
        }
        else if (encryptionOID.equals(OIWObjectIdentifiers.desCBC))
        {
            if (keySize != 56 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 56;
        }
        else
        {
            if (fixedSize > 0 && fixedSize != keySize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = keySize;
        }
    }

    /**
     * Constructor for a content encryptor builder based on an algorithm identifier and its contained parameters.
     *
     * @param encryptionAlgId the full algorithm identifier for the encryption.
     */
    public JceCMSContentEncryptorBuilder(AlgorithmIdentifier encryptionAlgId)
    {
        this(encryptionAlgId.getAlgorithm(), KEY_SIZE_PROVIDER.getKeySize(encryptionAlgId.getAlgorithm()));
        this.algorithmIdentifier = encryptionAlgId;
    }

    public JceCMSContentEncryptorBuilder setEnableSha256HKdf(boolean useSha256Hkdf)
    {
        if (useSha256Hkdf)
        {
            // eventually this will be the default.
            this.kdfAlgorithm = CMSObjectIdentifiers.id_alg_cek_hkdf_sha256;
        }
        else
        {
            if (this.kdfAlgorithm != null)
            {
                if (this.kdfAlgorithm.equals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256))
                {
                    this.kdfAlgorithm = null;
                }
                else
                {
                    throw new IllegalStateException("SHA256 HKDF not enabled");
                }
            }
        }

        return this;
    }

    /**
     * Set the provider to use for content encryption.
     *
     * @param provider the provider object to use for cipher and default parameters creation.
     * @return the current builder instance.
     */
    public JceCMSContentEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    /**
     * Set the provider to use for content encryption (by name)
     *
     * @param providerName the name of the provider to use for cipher and default parameters creation.
     * @return the current builder instance.
     */
    public JceCMSContentEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

        return this;
    }

    /**
     * Provide a specified source of randomness to be used for session key and IV/nonce generation.
     *
     * @param random the secure random to use.
     * @return the current builder instance.
     */
    public JceCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Provide a set of algorithm parameters for the content encryption cipher to use.
     *
     * @param algorithmParameters algorithmParameters for content encryption.
     * @return the current builder instance.
     */
    public JceCMSContentEncryptorBuilder setAlgorithmParameters(AlgorithmParameters algorithmParameters)
    {
        this.algorithmParameters = algorithmParameters;

        return this;
    }

    public OutputEncryptor build()
        throws CMSException
    {
        if (algorithmParameters != null)
        {
            if (helper.isAuthEnveloped(encryptionOID))
            {
                return new CMSAuthOutputEncryptor(kdfAlgorithm, encryptionOID, keySize, algorithmParameters, random);
            }
            return new CMSOutputEncryptor(kdfAlgorithm, encryptionOID, keySize, algorithmParameters, random);
        }
        if (algorithmIdentifier != null)
        {
            ASN1Encodable params = algorithmIdentifier.getParameters();
            if (params != null && !params.equals(DERNull.INSTANCE))
            {
                try
                {
                    algorithmParameters = helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());

                    algorithmParameters.init(params.toASN1Primitive().getEncoded());
                }
                catch (Exception e)
                {
                    throw new CMSException("unable to process provided algorithmIdentifier: " + e.toString(), e);
                }
            }
        }

        if (helper.isAuthEnveloped(encryptionOID))
        {
            return new CMSAuthOutputEncryptor(kdfAlgorithm, encryptionOID, keySize, algorithmParameters, random);
        }
        return new CMSOutputEncryptor(kdfAlgorithm, encryptionOID, keySize, algorithmParameters, random);
    }

    private class CMSOutEncryptor
    {
        protected SecretKey encKey;
        protected AlgorithmIdentifier algorithmIdentifier;
        protected Cipher              cipher;

        private void applyKdf(ASN1ObjectIdentifier kdfAlgorithm, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            // TODO: at the moment assumes HKDF with SHA256
            HKDFBytesGenerator kdf = new HKDFBytesGenerator(new SHA256Digest());
            byte[] encKeyEncoded = encKey.getEncoded();
            try
            {
                kdf.init(new HKDFParameters(encKeyEncoded, hkdfSalt, algorithmIdentifier.getEncoded(ASN1Encoding.DER)));
            }
            catch (IOException e)
            {
                throw new CMSException("unable to encode enc algorithm parameters", e);
            }

            kdf.generateBytes(encKeyEncoded, 0, encKeyEncoded.length);

            SecretKeySpec derivedKey = new SecretKeySpec(encKeyEncoded, encKey.getAlgorithm());
            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, derivedKey, params, random);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
            }
            algorithmIdentifier = new AlgorithmIdentifier(kdfAlgorithm, algorithmIdentifier);
        }

        protected void init(ASN1ObjectIdentifier kdfAlgorithm, ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            KeyGenerator keyGen = helper.createKeyGenerator(encryptionOID);

            random = CryptoServicesRegistrar.getSecureRandom(random);

            if (keySize < 0)
            {
                keyGen.init(random);
            }
            else
            {
                keyGen.init(keySize, random);
            }

            cipher = helper.createCipher(encryptionOID);
            encKey = keyGen.generateKey();

            if (params == null)
            {
                params = helper.generateParameters(encryptionOID, encKey, random);
            }
            
            if (params != null)
            {
                algorithmIdentifier = helper.getAlgorithmIdentifier(encryptionOID, params);

                if (kdfAlgorithm != null)
                {
                    applyKdf(kdfAlgorithm, params, random);
                }
                else
                {
                    try
                    {
                        cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
                    }
                    catch (GeneralSecurityException e)
                    {
                        throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
                    }
                }
            }
            else
            {
                //
                // If params are null we try and second guess on them as some providers don't provide
                // algorithm parameter generation explicitly but instead generate them under the hood.
                //
                try
                { 
                    cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
                }

                params = cipher.getParameters();

                algorithmIdentifier = helper.getAlgorithmIdentifier(encryptionOID, params);

                if (kdfAlgorithm != null)
                {
                    applyKdf(kdfAlgorithm, params, random);
                }
            }
        }
    }

    private class CMSOutputEncryptor
        extends CMSOutEncryptor
        implements OutputEncryptor
    {
        CMSOutputEncryptor(ASN1ObjectIdentifier kdfAlgorithm, ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            init(kdfAlgorithm, encryptionOID, keySize, params, random);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return new CipherOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new JceGenericKey(algorithmIdentifier, encKey);
        }
    }

    private class CMSAuthOutputEncryptor
        extends CMSOutEncryptor
        implements OutputAEADEncryptor
    {
        private MacCaptureStream    macOut;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier kdfAlgorithm, ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            init(kdfAlgorithm, encryptionOID, keySize, params, random);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            AlgorithmIdentifier algId;
            if (kdfAlgorithm != null)
            {
                algId = AlgorithmIdentifier.getInstance(algorithmIdentifier.getParameters());
            }
            else
            {
                algId = algorithmIdentifier;
            }
            
            // TODO: works for CCM too, but others will follow.
            GCMParameters p = GCMParameters.getInstance(algId.getParameters());
            macOut = new MacCaptureStream(dOut, p.getIcvLen());
            return new CipherOutputStream(macOut, cipher);
        }

        public GenericKey getKey()
        {
            return new JceGenericKey(algorithmIdentifier, encKey);
        }

        public OutputStream getAADStream()
        {
            if (checkForAEAD())
            {
                return new JceAADStream(cipher);
            }

            return null; // TODO: okay this is awful, we could use AEADParameterSpec for earlier JDKs.
        }

        public byte[] getMAC()
        {
            return macOut.getMac();
        }
    }

    private static boolean checkForAEAD()
    {
        return (Boolean)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    return Cipher.class.getMethod("updateAAD", byte[].class) != null;
                }
                catch (Exception ignore)
                {
                    // TODO[logging] Log the fact that we are falling back to BC-specific class
                    return Boolean.FALSE;
                }
            }
        });
    }
}
