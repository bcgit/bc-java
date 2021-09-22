package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHKey;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;

public class JcePublicKeyDataDecryptorFactoryBuilder
{
    private static final int X25519_KEY_SIZE = 32;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private OperatorHelper contentHelper = new OperatorHelper(new DefaultJcaJceHelper());
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
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

    private int getExpectedPayloadSize(PrivateKey key)
    {
        if (key instanceof DHKey)
        {
            DHKey k = (DHKey)key;

            return (k.getParams().getP().bitLength() + 7) / 8;
        }
        else if (key instanceof RSAKey)
        {
            RSAKey k = (RSAKey)key;

            return (k.getModulus().bitLength() + 7) / 8;
        }
        else
        {
            return -1;
        }
    }

    public PublicKeyDataDecryptorFactory build(final PrivateKey privKey)
    {
         return new PublicKeyDataDecryptorFactory()
         {
             final int expectedPayLoadSize = getExpectedPayloadSize(privKey);

             public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
                 throws PGPException
             {
                 if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
                 {
                     throw new PGPException("ECDH requires use of PGPPrivateKey for decryption");
                 }
                 return decryptSessionData(keyAlgorithm, privKey, expectedPayLoadSize, secKeyData);
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
         return new JcePublicKeyDataDecryptorFactory(keyConverter, privKey);
    }


    /**
     * Create an instance of the {@link JcePublicKeyDataDecryptorFactory} which is based on the provided session key.
     * This factory will not source the session key from decrypting a public key encrypted session key packet (PKESK)
     * with a private key, but instead use the provided session key directly to decrypt the data.
     *
     * @param sessionKeyAlgorithm session key algorithm
     * @param sessionKey session key
     * @return decryptor factory
     */
    public PublicKeyDataDecryptorFactory createFactoryFromSessionKey(int sessionKeyAlgorithm, byte[] sessionKey)
    {
        return new JcePublicKeyDataDecryptorFactory(keyConverter, null)
        {
            @Override
            public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
            {
                byte[] sessionData = new byte[sessionKey.length + 3];
                sessionData[0] = (byte) sessionKeyAlgorithm;
                System.arraycopy(sessionKey, 0, sessionData, 1, sessionKey.length);
                writeChecksum(sessionData);
                return sessionData;
            }

            private void writeChecksum(byte[] sessionData)
            {
                int    check = 0;
                for (int i = 1; i != sessionData.length - 2; i++)
                {
                    check += sessionData[i] & 0xff;
                }

                sessionData[sessionData.length - 2] = (byte) (check >> 8);
                sessionData[sessionData.length - 1] = (byte) (check);
            }
        };
    }

    private class JcePublicKeyDataDecryptorFactory implements PublicKeyDataDecryptorFactory
    {

        private final JcaPGPKeyConverter keyConverter;
        private final PGPPrivateKey privKey;

        public JcePublicKeyDataDecryptorFactory(JcaPGPKeyConverter keyConverter, PGPPrivateKey privKey)
        {
            this.keyConverter = keyConverter;
            this.privKey = privKey;
        }

        public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
                throws PGPException
        {
            if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
            {
                return decryptSessionData(keyConverter, privKey, secKeyData);
            }
            PrivateKey jcePrivKey = keyConverter.getPrivateKey(privKey);
            int expectedPayLoadSize = getExpectedPayloadSize(jcePrivKey);

            return decryptSessionData(keyAlgorithm, jcePrivKey, expectedPayLoadSize, secKeyData);
        }

        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                throws PGPException
        {
            return contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }

    }

    private byte[] decryptSessionData(JcaPGPKeyConverter converter, PGPPrivateKey privKey, byte[][] secKeyData)
        throws PGPException
    {
        PublicKeyPacket pubKeyData = privKey.getPublicKeyPacket();
        ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();

        byte[] enc = secKeyData[0];

        int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
        if ((2 + pLen + 1) > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }

        byte[] pEnc = new byte[pLen];
        System.arraycopy(enc, 2, pEnc, 0, pLen);

        int keyLen = enc[pLen + 2] & 0xff;
        if ((2 + pLen + 1 + keyLen) > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }

        byte[] keyEnc = new byte[keyLen];
        System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

        try
        {
            KeyAgreement agreement;
            PublicKey publicKey;

            // XDH
            if (ecKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
            {
                agreement = helper.createKeyAgreement(RFC6637Utils.getXDHAlgorithm(pubKeyData));

                KeyFactory keyFact = helper.createKeyFactory("XDH");

                // skip the 0x40 header byte.
                if (pEnc.length != (1 + X25519_KEY_SIZE) || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Curve25519 public key");
                }

                publicKey = keyFact.generatePublic(
                    new X509EncodedKeySpec(
                              new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                                  Arrays.copyOfRange(pEnc, 1, pEnc.length)).getEncoded()));
            }
            else
            {
                X9ECParameters x9Params = ECNamedCurveTable.getByOID(ecKey.getCurveOID());
                ECPoint publicPoint = x9Params.getCurve().decodePoint(pEnc);

                agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKeyData));

                publicKey = converter.getPublicKey(new PGPPublicKey(new PublicKeyPacket(PublicKeyAlgorithmTags.ECDH, new Date(),
                    new ECDHPublicBCPGKey(ecKey.getCurveOID(), publicPoint, ecKey.getHashAlgorithm(), ecKey.getSymmetricKeyAlgorithm())), fingerprintCalculator));
            }

            byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyData, fingerprintCalculator);

            PrivateKey privateKey = converter.getPrivateKey(privKey);

            agreement.init(privateKey, new UserKeyingMaterialSpec(userKeyingMaterial));

            agreement.doPhase(publicKey, true);

            Key key = agreement.generateSecret(RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId());

            Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

            c.init(Cipher.UNWRAP_MODE, key);

            Key paddedSessionKey = c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY);

            return PGPPad.unpadSessionData(paddedSessionKey.getEncoded());
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
        catch (IOException e)
        {
            throw new PGPException("error setting asymmetric cipher", e);
        }
    }

    private void updateWithMPI(Cipher c, int expectedPayloadSize, byte[] encMPI)
    {
        if (expectedPayloadSize > 0)
        {
            if (encMPI.length - 2 > expectedPayloadSize)  // leading Zero? Shouldn't happen but...
            {
                c.update(encMPI, 3, encMPI.length - 3);
            }
            else
            {
                if (expectedPayloadSize > (encMPI.length - 2))
                {
                    c.update(new byte[expectedPayloadSize - (encMPI.length - 2)]);
                }
                c.update(encMPI, 2, encMPI.length - 2);
            }
        }
        else
        {
            c.update(encMPI, 2, encMPI.length - 2);
        }
    }

    private byte[] decryptSessionData(int keyAlgorithm, PrivateKey privKey, int expectedPayloadSize, byte[][] secKeyData)
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
            updateWithMPI(c1, expectedPayloadSize, secKeyData[0]);
        }
        else
        {
            // Elgamal Encryption
            updateWithMPI(c1, expectedPayloadSize, secKeyData[0]);
            updateWithMPI(c1, expectedPayloadSize, secKeyData[1]);
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
