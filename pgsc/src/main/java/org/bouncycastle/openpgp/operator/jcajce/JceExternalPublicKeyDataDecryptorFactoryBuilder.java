package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.openpgp.operator.bc.RFC6637KDFCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory.unwrapSessionData;

public abstract class JceExternalPublicKeyDataDecryptorFactoryBuilder
{
    private final JcePublicKeyDataDecryptorFactoryBuilder softwareDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder();

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private OperatorHelper contentHelper = new OperatorHelper(new DefaultJcaJceHelper());
    private JceAEADUtil aeadHelper = new JceAEADUtil(contentHelper);
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
    private JcaKeyFingerprintCalculator fingerprintCalculator = new JcaKeyFingerprintCalculator();

    public JceExternalPublicKeyDataDecryptorFactoryBuilder()
    {
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider provider object for cryptographic primitives.
     * @return the current builder.
     */
    public JceExternalPublicKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        softwareDecryptorFactory.setProvider(provider);
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        keyConverter.setProvider(provider);
        this.contentHelper = helper;
        this.aeadHelper = new JceAEADUtil(contentHelper);

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName the name of the provider to reference for cryptographic primitives.
     * @return the current builder.
     */
    public JceExternalPublicKeyDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        softwareDecryptorFactory.setProvider(providerName);
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        keyConverter.setProvider(providerName);
        this.contentHelper = helper;
        this.aeadHelper = new JceAEADUtil(contentHelper);

        return this;
    }

    public JceExternalPublicKeyDataDecryptorFactoryBuilder setContentProvider(Provider provider)
    {
        softwareDecryptorFactory.setContentProvider(provider);
        this.contentHelper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadHelper = new JceAEADUtil(contentHelper);

        return this;
    }

    public JceExternalPublicKeyDataDecryptorFactoryBuilder setContentProvider(String providerName)
    {
        softwareDecryptorFactory.setContentProvider(providerName);
        this.contentHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        this.aeadHelper = new JceAEADUtil(contentHelper);

        return this;
    }

    public abstract PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey) throws PGPException;

    protected PublicKeyDataDecryptorFactory build(final PGPKeyPair keyPair, PublicKeyCryptoCallback cryptoCallback)
    {
        final PGPPrivateKey privKey = keyPair.getPrivateKey();
        final PGPPublicKey pubKey = keyPair.getPublicKey();

        if (privKey != null)
        {
            return softwareDecryptorFactory.build(privKey);
        }

        return new AbstractPublicKeyDataDecryptorFactory()
        {
            @Override
            public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
                    throws PGPException
            {
                boolean containsSKAlg = containsSKAlg(pkeskVersion);
                if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
                {
                    return decryptSessionData(keyConverter, pubKey, secKeyData, cryptoCallback);
                }
                else if (keyAlgorithm == PublicKeyAlgorithmTags.X25519) {
                    try {
                        byte[] enc = secKeyData[0];
                        int pLen = X25519PublicBCPGKey.LENGTH;
                        byte[] ephemeralKey = Arrays.copyOf(enc, pLen);

                        // size of following fields
                        int size = enc[pLen] & 0xff;
                        checkRange(pLen + 1 + size, enc);

                        // encrypted session key
                        boolean includesSesKeyAlg = containsSKAlg(pkeskVersion);
                        int sesKeyLen = size - (includesSesKeyAlg ? 1 : 0);
                        int sesKeyOff = pLen + 1 + (includesSesKeyAlg ? 1 : 0);
                        byte[] keyEnc = Arrays.copyOfRange(enc, sesKeyOff, sesKeyOff + sesKeyLen);

                        byte[] secret = cryptoCallback.decryptX25519(getPublicKey(ephemeralKey, EdECObjectIdentifiers.id_X25519, 0));

                        byte[] hkdfOut = RFC6637KDFCalculator.createKey(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128,
                                Arrays.concatenate(ephemeralKey, pubKey.getPublicKeyPacket().getKey().getEncoded(), secret),
                                "OpenPGP X25519");
                        return unwrapSessionData(keyEnc, SymmetricKeyAlgorithmTags.AES_128, new KeyParameter(hkdfOut));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                else if (keyAlgorithm == PublicKeyAlgorithmTags.X448)
                {
                    throw new PGPException("X448 is not supported.");
                }

                return decryptSessionData(keyAlgorithm, secKeyData, cryptoCallback);
            }

            // OpenPGP v4
            @Override
            public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                    throws PGPException
            {
                return contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
            }

            // OpenPGP v5
            @Override
            public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
                    throws PGPException
            {
                return aeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
            }

            // OpenPGP v6
            @Override
            public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
                    throws PGPException
            {
                return aeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
            }
        };
    }

    /**
     * Decrypt ECDH encrypted session keys.
     * @param converter key converter
     * @param pubKey our public key
     * @param secKeyData encrypted session key
     * @return decrypted session key
     * @throws PGPException
     */
    private byte[] decryptSessionData(JcaPGPKeyConverter converter,
                                      PGPPublicKey pubKey,
                                      byte[][] secKeyData,
                                      PublicKeyCryptoCallback cryptoCallback)
            throws PGPException
    {
        PublicKeyPacket pubKeyData = pubKey.getPublicKeyPacket();

        byte[] enc = secKeyData[0];

        byte[] pEnc;
        byte[] keyEnc;
        int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
        checkRange(2 + pLen + 1, enc);

        pEnc = new byte[pLen];
        System.arraycopy(enc, 2, pEnc, 0, pLen);
        System.out.println("JCYK: pEnc: " + Hex.toHexString(pEnc));

        int keyLen = enc[pLen + 2] & 0xff;
        checkRange(2 + pLen + 1 + keyLen, enc);

        keyEnc = new byte[keyLen];
        System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

        try
        {
            PublicKey publicKey;
            byte[] decSessionKey;
            ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();
            // XDH
            if (JcaJcePGPUtil.isX25519(ecKey.getCurveOID()))
            {
                if (pEnc.length != (1 + X25519PublicBCPGKey.LENGTH) || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Curve25519 public key");
                }
                publicKey = getPublicKey(pEnc, EdECObjectIdentifiers.id_X25519, 1);
                decSessionKey = cryptoCallback.decryptX25519(publicKey);
            }
            else if (ecKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
            {
                if (pEnc.length != (1 + X448PublicBCPGKey.LENGTH) || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Curve25519 public key");
                }
                publicKey = getPublicKey(pEnc, EdECObjectIdentifiers.id_X448, 1);
                decSessionKey = cryptoCallback.decryptX448(publicKey);
            }
            else
            {
                X9ECParametersHolder x9Params = ECNamedCurveTable.getByOIDLazy(ecKey.getCurveOID());
                ECPoint publicPoint = x9Params.getCurve().decodePoint(pEnc);

                publicKey = converter.getPublicKey(
                        new PGPPublicKey(new PublicKeyPacket(
                                pubKeyData.getVersion(),
                                PublicKeyAlgorithmTags.ECDH,
                                new Date(),
                                new ECDHPublicBCPGKey(
                                        ecKey.getCurveOID(),
                                        publicPoint,
                                        ecKey.getHashAlgorithm(),
                                        ecKey.getSymmetricKeyAlgorithm()
                                )
                        ), fingerprintCalculator));
                decSessionKey = cryptoCallback.decryptECDH(ecKey, publicKey);
            }

            int hashAlgorithm = ecKey.getHashAlgorithm();
            int symmetricKeyAlgorithm = ecKey.getSymmetricKeyAlgorithm();
            byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyData, fingerprintCalculator);
            RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
                    new JcaPGPDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build().get(hashAlgorithm),
                    symmetricKeyAlgorithm);
            KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(decSessionKey, userKeyingMaterial));

            byte[] unwrapped = unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key);
            return PGPPad.unpadSessionData(unwrapped);
        }
        catch (Exception e)
        {
            throw new PGPException("error decrypting session data: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt X25519 / X448 encrypted session keys.
     * @param converter key converter
     * @param privKey our private key
     * @param enc encrypted session key
     * @param pLen Key length
     * @param agreementAlgorithm agreement algorithm
     * @param symmetricKeyAlgorithm wrapping algorithm
     * @param algorithmIdentifier ephemeral key algorithm identifier
     * @param algorithmName public key algorithm name
     * @param containsSKAlg whether the PKESK packet is version 3
     * @return decrypted session data
     * @throws PGPException
     */
    private byte[] decryptSessionData(JcaPGPKeyConverter converter, PGPPrivateKey privKey, byte[] enc, int pLen, String agreementAlgorithm,
                                      int symmetricKeyAlgorithm, ASN1ObjectIdentifier algorithmIdentifier, String algorithmName, boolean containsSKAlg)
            throws PGPException
    {
        try
        {
            // ephemeral key (32 / 56 octets)
            byte[] ephemeralKey = Arrays.copyOf(enc, pLen);

            int size = enc[pLen] & 0xff;

            checkRange(pLen + 1 + size, enc);

            // encrypted session key
            int sesKeyLen = size - (containsSKAlg ? 1 : 0);
            int sesKeyOff = pLen + 1 + (containsSKAlg ? 1 : 0);
            byte[] keyEnc = Arrays.copyOfRange(enc, sesKeyOff, sesKeyOff + sesKeyLen);

            PublicKey ephemeralPubKey = getPublicKey(ephemeralKey, algorithmIdentifier, 0);
            Key paddedSessionKey = getSessionKey(converter, privKey, agreementAlgorithm, ephemeralPubKey, symmetricKeyAlgorithm, keyEnc,
                    JcaJcePGPUtil.getHybridValueParameterSpecWithPrepend(ephemeralKey, privKey.getPublicKeyPacket(), algorithmName));
            return paddedSessionKey.getEncoded();
        }
        catch (Exception e)
        {
            throw new PGPException("error decrypting session data: " + e.getMessage(), e);
        }
    }

    private Key getSessionKey(JcaPGPKeyConverter converter, PGPPrivateKey privKey, String agreementName,
                              PublicKey publicKey, int symmetricKeyAlgorithm, byte[] keyEnc, AlgorithmParameterSpec ukms)
            throws PGPException, GeneralSecurityException
    {
        Key key = JcaJcePGPUtil.getSecret(helper, publicKey, RFC6637Utils.getKeyEncryptionOID(symmetricKeyAlgorithm).getId(), agreementName, ukms, null);
        Cipher c = helper.createKeyWrapper(symmetricKeyAlgorithm);
        c.init(Cipher.UNWRAP_MODE, key);
        return c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY);
    }

    private PublicKey getPublicKey(byte[] pEnc, ASN1ObjectIdentifier algprithmIdentifier, int pEncOff)
            throws PGPException, GeneralSecurityException, IOException
    {
        KeyFactory keyFact = helper.createKeyFactory("XDH");

        return keyFact.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(algprithmIdentifier), Arrays.copyOfRange(pEnc, pEncOff, pEnc.length)).getEncoded()));
    }

    /**
     * Decrypt RSA / Elgamal encrypted session keys.
     * @param keyAlgorithm public key algorithm
     * @param secKeyData ESK data
     * @return session data
     * @throws PGPException
     */
    private byte[] decryptSessionData(int keyAlgorithm,
                                      byte[][] secKeyData,
                                      PublicKeyCryptoCallback cryptoCallback)
            throws PGPException
    {
        if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL || keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT)
        {
            byte[] sessionKey = Arrays.copyOfRange(secKeyData[0], 2, secKeyData[0].length);
            return cryptoCallback.decryptRSA(keyAlgorithm, sessionKey);
        }
        else if (keyAlgorithm == PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT || keyAlgorithm == PublicKeyAlgorithmTags.ELGAMAL_GENERAL)
        {
            return cryptoCallback.decryptElGamal(keyAlgorithm, secKeyData);
        }
        else throw new PGPException("Unexpected public key algorithm: " + keyAlgorithm);
    }

    private static void checkRange(int pLen, byte[] enc)
            throws PGPException
    {
        if (pLen > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }
    }

    public static abstract class PublicKeyCryptoCallback
    {
        public abstract byte[] decryptRSA(int keyAlgorithm,
                                          byte[] pEnc)
                throws PGPException;

        public abstract byte[] decryptElGamal(int keyAlgorithm,
                                              byte[][] secKeyData)
                throws PGPException;

        public abstract byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                           PublicKey ephemeralKeyBytes)
                throws PGPException;

        public abstract byte[] decryptX25519(PublicKey ephemeralKey)
                throws PGPException;

        public abstract byte[] decryptX448(PublicKey ephemeralKey)
                throws PGPException;
    }
}
