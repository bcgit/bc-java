package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637KDFCalculator;

public class JcePublicKeyDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private OperatorHelper contentHelper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private JcaKeyFingerprintCalculator fingerprintCalculator = new JcaKeyFingerprintCalculator();

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
             public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
                 throws PGPException
             {
                 if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
                 {
                     throw new PGPException("ECDH requires use of PGPPrivateKey for decryption");
                 }
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
             public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
                 throws PGPException
             {
                 if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
                 {
                     return decryptSessionData(privKey.getPrivateKeyDataPacket(), privKey.getPublicKeyPacket(), secKeyData);
                 }

                 return decryptSessionData(keyAlgorithm, keyConverter.getPrivateKey(privKey), secKeyData);
             }

             public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                 throws PGPException
             {
                 return contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
             }
         };
    }

    private byte[] decryptSessionData(BCPGKey privateKeyPacket, PublicKeyPacket pubKeyData, byte[][] secKeyData)
        throws PGPException
    {
        ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();
        X9ECParameters x9Params = NISTNamedCurves.getByOID(ecKey.getCurveOID());
        ECDomainParameters ecParams = new ECDomainParameters(x9Params.getCurve(), x9Params.getG(), x9Params.getN());

        byte[] enc = secKeyData[0];

        int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
        byte[] pEnc = new byte[pLen];

        System.arraycopy(enc, 2, pEnc, 0, pLen);

        byte[] keyEnc = new byte[enc[pLen + 2]];

        System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.length);

        Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

        ECPoint S = x9Params.getCurve().decodePoint(pEnc).multiply(((ECSecretBCPGKey)privateKeyPacket).getX()).normalize();

        RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(digestCalculatorProviderBuilder.build().get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());

        Key key = new SecretKeySpec(rfc6637KDFCalculator.createKey(ecKey.getCurveOID(), S, fingerprintCalculator.calculateFingerprint(pubKeyData)), "AESWrap");

        try
        {
            c.init(Cipher.UNWRAP_MODE, key);

            Key paddedSessionKey = c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY);

            return PGPUtil.unpadSessionData(paddedSessionKey.getEncoded());
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
    }

    private byte[] decryptSessionData(int keyAlgorithm, PrivateKey privKey, byte[][] secKeyData)
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
            byte[] bi = secKeyData[0];  // encoded MPI

            c1.update(bi, 2, bi.length - 2);
        }
        else
        {
            ElGamalKey k = (ElGamalKey)privKey;
            int size = (k.getParameters().getP().bitLength() + 7) / 8;
            byte[] tmp = new byte[size];

            byte[] bi = secKeyData[0]; // encoded MPI
            if (bi.length - 2 > size)  // leading Zero? Shouldn't happen but...
            {
                c1.update(bi, 3, bi.length - 3);
            }
            else
            {
                System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                c1.update(tmp);
            }

            bi = secKeyData[1];  // encoded MPI
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = 0;
            }

            if (bi.length - 2 > size) // leading Zero? Shouldn't happen but...
            {
                c1.update(bi, 3, bi.length - 3);
            }
            else
            {
                System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                c1.update(tmp);
            }
        }

        try
        {
            return c1.doFinal();
        }
        catch (Exception e)
        {
            throw new PGPException("exception decrypting session data", e);
        }
    }
}
