package org.bouncycastle.openssl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceGenericKey;

public class JceOpenSSLPKCS8EncryptorBuilder
{
    public static final String AES_128_CBC = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String AES_192_CBC = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String AES_256_CBC = NISTObjectIdentifiers.id_aes256_CBC.getId();

    public static final String DES3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC.getId();

    public static final String PBE_SHA1_RC4_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4.getId();
    public static final String PBE_SHA1_RC4_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4.getId();
    public static final String PBE_SHA1_3DES = PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId();
    public static final String PBE_SHA1_2DES = PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC.getId();
    public static final String PBE_SHA1_RC2_128 = PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC.getId();
    public static final String PBE_SHA1_RC2_40 = PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC.getId();

    private JcaJceHelper helper = new DefaultJcaJceHelper();

    private AlgorithmParameters params;
    private ASN1ObjectIdentifier algOID;
    byte[] salt;
    int iterationCount;
    private Cipher cipher;
    private SecureRandom random;
    private AlgorithmParameterGenerator paramGen;
    private char[] password;

    private SecretKey key;
    private AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    public JceOpenSSLPKCS8EncryptorBuilder(ASN1ObjectIdentifier algorithm)
    {
        algOID = algorithm;

        this.iterationCount = 2048;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setPasssword(char[] password)
    {
        this.password = password;

        return this;
    }

    /**
     * Set the PRF to use for key generation. By default this is HmacSHA1.
     *
     * @param prf algorithm id for PRF.
     *
     * @return the current builder.
     */
    public JceOpenSSLPKCS8EncryptorBuilder setPRF(AlgorithmIdentifier prf)
    {
        this.prf = prf;

        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;

        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setProvider(String providerName)
    {
        helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JceOpenSSLPKCS8EncryptorBuilder setProvider(Provider provider)
    {
        helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public OutputEncryptor build()
        throws OperatorCreationException
    {
        final AlgorithmIdentifier algID;

        if (random == null)
        {
            random = new SecureRandom();
        }

        try
        {
            this.cipher = helper.createCipher(algOID.getId());

            if (PEMUtilities.isPKCS5Scheme2(algOID))
            {
                this.paramGen = helper.createAlgorithmParameterGenerator(algOID.getId());
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException(algOID + " not available: " + e.getMessage(), e);
        }

        if (PEMUtilities.isPKCS5Scheme2(algOID))
        {
            salt = new byte[PEMUtilities.getSaltSize(prf.getAlgorithm())];

            random.nextBytes(salt);

            params = paramGen.generateParameters();

            try
            {
                EncryptionScheme scheme = new EncryptionScheme(algOID, ASN1Primitive.fromByteArray(params.getEncoded()));
                KeyDerivationFunc func = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount, prf));

                ASN1EncodableVector v = new ASN1EncodableVector();

                v.add(func);
                v.add(scheme);

                algID = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, PBES2Parameters.getInstance(new DERSequence(v)));
            }
            catch (IOException e)
            {
                throw new OperatorCreationException(e.getMessage(), e);
            }

            try
            {
                if (PEMUtilities.isHmacSHA1(prf))
                {
                    key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, algOID.getId(), password, salt, iterationCount);
                }
                else
                {
                    key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, algOID.getId(), password, salt, iterationCount, prf);
                }

                cipher.init(Cipher.ENCRYPT_MODE, key, params);
            }
            catch (GeneralSecurityException e)
            {
                throw new OperatorCreationException(e.getMessage(), e);
            }
        }
        else if (PEMUtilities.isPKCS12(algOID))
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            salt = new byte[20];

            random.nextBytes(salt);

            v.add(new DEROctetString(salt));
            v.add(new ASN1Integer(iterationCount));

            algID = new AlgorithmIdentifier(algOID, PKCS12PBEParams.getInstance(new DERSequence(v)));

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, new PKCS12KeyWithParameters(password, salt, iterationCount));
            }
            catch (GeneralSecurityException e)
            {
                throw new OperatorCreationException(e.getMessage(), e);
            }
        }
        else
        {
            throw new OperatorCreationException("unknown algorithm: " + algOID, null);
        }

        return new OutputEncryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return algID;
            }

            public OutputStream getOutputStream(OutputStream encOut)
            {
                return new CipherOutputStream(encOut, cipher);
            }

            public GenericKey getKey()
            {
                return new JceGenericKey(algID, key);
            }
        };
    }
}
