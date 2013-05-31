package org.bouncycastle.openpgp.operator.jcajce;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;

import javax.crypto.Cipher;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

public class JcePublicKeyDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private OperatorHelper contentHelper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JcePublicKeyDataDecryptorFactoryBuilder()
    {
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public JcePublicKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public JcePublicKeyDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);
        this.contentHelper = helper;

        return this;
    }

    public JcePublicKeyDataDecryptorFactoryBuilder setContentProvider(Provider provider)
    {
        this.contentHelper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePublicKeyDataDecryptorFactoryBuilder setContentProvider(String providerName)
    {
        this.contentHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public PublicKeyDataDecryptorFactory build(final PrivateKey privKey)
    {
         return new PublicKeyDataDecryptorFactory()
         {
             public byte[] recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)
                 throws PGPException
             {
                 return decryptSessionData(keyAlgorithm, privKey, secKeyData);
             }

             public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                 throws PGPException
             {
                 return contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
             }
         };
    }


    public PublicKeyDataDecryptorFactory build(final PGPPrivateKey privKey)
    {
         return new PublicKeyDataDecryptorFactory()
         {
             public byte[] recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)
                 throws PGPException
             {
                 return decryptSessionData(keyAlgorithm, keyConverter.getPrivateKey(privKey), secKeyData);
             }

             public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                 throws PGPException
             {
                 return contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
             }
         };
    }

    private byte[] decryptSessionData(int keyAlgorithm, PrivateKey privKey, BigInteger[] secKeyData)
        throws PGPException
    {
        Cipher c1 = helper.createPublicKeyCipher(keyAlgorithm);

        try
        {
            c1.init(Cipher.DECRYPT_MODE, privKey);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }

        if (keyAlgorithm == PGPPublicKey.RSA_ENCRYPT
            || keyAlgorithm == PGPPublicKey.RSA_GENERAL)
        {
            byte[] bi = secKeyData[0].toByteArray();

            if (bi[0] == 0)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                c1.update(bi);
            }
        }
        else
        {
            ElGamalKey k = (ElGamalKey)privKey;
            int size = (k.getParameters().getP().bitLength() + 7) / 8;
            byte[] tmp = new byte[size];

            byte[] bi = secKeyData[0].toByteArray();
            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }

            bi = secKeyData[1].toByteArray();
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = 0;
            }

            if (bi.length > size)
            {
                c1.update(bi, 1, bi.length - 1);
            }
            else
            {
                System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                c1.update(tmp);
            }
        }

        byte[] plain;
        try
        {
            plain = c1.doFinal();
        }
        catch (Exception e)
        {
            throw new PGPException("exception decrypting session data", e);
        }

        return plain;
    }
}
