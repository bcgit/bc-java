package org.bouncycastle.operator.jcajce;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyWrapper;

public class JceSymmetricKeyWrapper
    extends SymmetricKeyWrapper
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private SecretKey wrappingKey;

    public JceSymmetricKeyWrapper(SecretKey wrappingKey)
    {
        super(determineKeyEncAlg(wrappingKey));

        this.wrappingKey = wrappingKey;
    }

    public JceSymmetricKeyWrapper setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceSymmetricKeyWrapper setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JceSymmetricKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        Key contentEncryptionKeySpec = OperatorUtils.getJceKey(encryptionKey);

        Cipher keyEncryptionCipher = helper.createSymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm());

        try
        {
            keyEncryptionCipher.init(Cipher.WRAP_MODE, wrappingKey, random);

            return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
        }
        catch (Exception e)
        {
            throw new OperatorException("cannot wrap key: " + e.getMessage(), e);
        }
    }

    private static AlgorithmIdentifier determineKeyEncAlg(SecretKey key)
    {
        return determineKeyEncAlg(key.getAlgorithm(), key.getEncoded().length * 8);
    }

    static AlgorithmIdentifier determineKeyEncAlg(String algorithm, int keySizeInBits)
    {
        if (algorithm.startsWith("DES") || algorithm.startsWith("TripleDES"))
        {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, DERNull.INSTANCE);
        }
        else if (algorithm.startsWith("RC2"))
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(
                    "1.2.840.113549.1.9.16.3.7"), new ASN1Integer(58));
        }
        else if (algorithm.startsWith("AES"))
        {
            ASN1ObjectIdentifier wrapOid;

            if (keySizeInBits == 128)
            {
                wrapOid = NISTObjectIdentifiers.id_aes128_wrap;
            }
            else if (keySizeInBits == 192)
            {
                wrapOid = NISTObjectIdentifiers.id_aes192_wrap;
            }
            else if (keySizeInBits == 256)
            {
                wrapOid = NISTObjectIdentifiers.id_aes256_wrap;
            }
            else
            {
                throw new IllegalArgumentException("illegal keysize in AES");
            }

            return new AlgorithmIdentifier(wrapOid); // parameters absent
        }
        else if (algorithm.startsWith("SEED"))
        {
            // parameters absent
            return new AlgorithmIdentifier(
                    KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
        }
        else if (algorithm.startsWith("Camellia"))
        {
            ASN1ObjectIdentifier wrapOid;

            if (keySizeInBits == 128)
            {
                wrapOid = NTTObjectIdentifiers.id_camellia128_wrap;
            }
            else if (keySizeInBits == 192)
            {
                wrapOid = NTTObjectIdentifiers.id_camellia192_wrap;
            }
            else if (keySizeInBits == 256)
            {
                wrapOid = NTTObjectIdentifiers.id_camellia256_wrap;
            }
            else
            {
                throw new IllegalArgumentException(
                        "illegal keysize in Camellia");
            }

            return new AlgorithmIdentifier(wrapOid); // parameters must be
                                                     // absent
        }
        else
        {
            throw new IllegalArgumentException("unknown algorithm");
        }
    }
}
