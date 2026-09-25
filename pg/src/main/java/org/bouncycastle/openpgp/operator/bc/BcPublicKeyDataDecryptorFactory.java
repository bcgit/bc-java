package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.ECDHRawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;

/**
 * A decryptor factory for handling public key decryption operations.
 */
public class BcPublicKeyDataDecryptorFactory
    extends AbstractPublicKeyDataDecryptorFactory
{
    private static final BcPGPKeyConverter KEY_CONVERTER = new BcPGPKeyConverter();

    private final PGPPrivateKey pgpPrivKey;
    private final PGPPublicKey pgpPubKey;

    /**
     * Deprecated constructor.
     * @deprecated in favor of constructor taking {@link PGPKeyPair}.
     * @param pgpPrivKey
     */
    @Deprecated
    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey pgpPrivKey)
    {
        this.pgpPrivKey = pgpPrivKey;
        this.pgpPubKey = null;
    }

    public BcPublicKeyDataDecryptorFactory(PGPKeyPair pgpKeyPair)
    {
        this.pgpPrivKey = pgpKeyPair.getPrivateKey();
        this.pgpPubKey = pgpKeyPair.getPublicKey();
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter privKey = null; // null for external keys
            if (pgpPrivKey != null)
            {
                privKey = KEY_CONVERTER.getPrivateKey(pgpPrivKey);
            }

            if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
            {
                return recoverX25519SessionData(secKeyData, pkeskVersion, privKey);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.X448)
            {
                return recoverX448SessionData(secKeyData, pkeskVersion, privKey);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.ECDH)
            {
                return recoverECDHSessionData(secKeyData, privKey);
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT ||
                    keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
            {
                return recoverRSASessionData(keyAlgorithm, secKeyData, privKey);
            }
            else
            {
                return recoverElgamalSessionData(keyAlgorithm, secKeyData, privKey);
            }
        }
        catch (IOException e)
        {
            throw new PGPException("exception creating user keying material: " + e.getMessage(), e);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception decrypting session info: " + e.getMessage(), e);
        }
    }

    private byte[] recoverElgamalSessionData(int keyAlgorithm,
                                             byte[][] secKeyData,
                                             AsymmetricKeyParameter privKey)
            throws PGPException, InvalidCipherTextException
    {
        return getCryptoCallback(privKey).decrypt(keyAlgorithm, secKeyData);
    }

    private byte[] recoverRSASessionData(int keyAlgorithm,
                                         byte[][] secKeyData,
                                         AsymmetricKeyParameter privKey)
        throws PGPException, InvalidCipherTextException
    {
        byte[] sessionKey = Arrays.copyOfRange(secKeyData[0], 2, secKeyData[0].length);
        return getCryptoCallback(privKey).decrypt(keyAlgorithm, new byte[][]{sessionKey});
    }

    private static BufferedAsymmetricBlockCipher getBufferedAsymmetricBlockCipher(int keyAlgorithm, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(BcImplProvider.createPublicKeyCipher(keyAlgorithm));
        c1.init(false, privKey);
        return c1;
    }

    private static void processEncodedMpi(BufferedAsymmetricBlockCipher c1, int size, byte[] tmp, byte[] bi)
    {
        if (bi.length - 2 > size)  // leading Zero? Shouldn't happen but...
        {
            c1.processBytes(bi, 3, bi.length - 3);
        }
        else
        {
            System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
            c1.processBytes(tmp, 0, tmp.length);
        }
    }

    /**
     * Return the public key packet of the key this factory decrypts for.
     * <p>
     * An externally-backed factory is constructed from a {@link PGPKeyPair} carrying only the public half
     * (there is no private key packet to unlock), so the packet has to be taken from the public key when
     * one is available and only then from the private key.
     *
     * @return public key packet
     */
    private PublicKeyPacket getPublicKeyPacket()
    {
        if (pgpPubKey != null)
        {
            return pgpPubKey.getPublicKeyPacket();
        }
        return pgpPrivKey.getPublicKeyPacket();
    }

    private byte[] recoverECDHSessionData(byte[][] secKeyData,
                                          AsymmetricKeyParameter privKey)
            throws PGPException, IOException, InvalidCipherTextException
    {
        byte[][] pEncAndKeyEnc = parseECDHEncSessionKey(secKeyData[0]);
        byte[] pEnc = pEncAndKeyEnc[0];
        byte[] keyEnc = pEncAndKeyEnc[1];

        byte[] secret;
        RFC6637KDFCalculator rfc6637KDFCalculator;
        byte[] userKeyingMaterial;
        int symmetricKeyAlgorithm, hashAlgorithm;

        PublicKeyPacket pubKeyPacket = getPublicKeyPacket();
        ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

        // XDH
        if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
        {
            if (pEnc.length != 1 + X25519PublicKeyParameters.KEY_SIZE || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve25519 public key");
            }
            // skip the 0x40 header byte.
            X25519PublicKeyParameters peerKey = new X25519PublicKeyParameters(pEnc, 1);
            secret = getCryptoCallback(privKey).decrypt(PublicKeyAlgorithmTags.X25519, peerKey);
        }
        else if (ecPubKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
        {
            if (pEnc.length != 1 + X448PublicKeyParameters.KEY_SIZE || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve448 public key");
            }
            // skip the 0x40 header byte.
            X448PublicKeyParameters peerKey = new X448PublicKeyParameters(pEnc, 1);
            secret = getCryptoCallback(privKey).decrypt(PublicKeyAlgorithmTags.X448, peerKey);
        }
        else
        {
            ECPublicKeyParameters peerKey = decodePeerKey(ecPubKey, pEnc);
            secret = getCryptoCallback(privKey).decrypt(PublicKeyAlgorithmTags.ECDH, peerKey);
        }
        hashAlgorithm = ecPubKey.getHashAlgorithm();
        symmetricKeyAlgorithm = ecPubKey.getSymmetricKeyAlgorithm();
        userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, new BcKeyFingerprintCalculator());
        rfc6637KDFCalculator = new RFC6637KDFCalculator(new BcPGPDigestCalculatorProvider().get(hashAlgorithm), symmetricKeyAlgorithm);
        KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

        byte[] unwrapped = unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key);
        return PGPPad.unpadSessionData(unwrapped);
    }

    static ECPublicKeyParameters decodePeerKey(ECPublicBCPGKey publicKey, byte[] peerKey)
    {
        ASN1ObjectIdentifier curveOID = publicKey.getCurveOID();
        org.bouncycastle.asn1.x9.X9ECParameters x9 = BcUtil.getX9Parameters(curveOID);
        ECNamedDomainParameters parameters = new ECNamedDomainParameters(curveOID, x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
        ECPoint pubPoint = BcUtil.decodePoint(new BigInteger(peerKey), parameters.getCurve());
        return new ECPublicKeyParameters(pubPoint, parameters);
    }

    private byte[] recoverX448SessionData(byte[][] secKeyData,
                                          int pkeskVersion,
                                          AsymmetricKeyParameter privKey)
            throws PGPException, InvalidCipherTextException
    {
        byte[][] ephemeralKeyAndKeyEnc = parseXDHEncSessionKey(secKeyData[0], X448PublicBCPGKey.LENGTH,
                containsSKAlg(pkeskVersion));
        byte[] ephemeralKey = ephemeralKeyAndKeyEnc[0];
        byte[] keyEnc = ephemeralKeyAndKeyEnc[1];

        byte[] secret = getCryptoCallback(privKey).decrypt(PublicKeyAlgorithmTags.X448, new X448PublicKeyParameters(ephemeralKey));

        byte[] hkdfOut = RFC6637KDFCalculator.createKey(HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256,
                Arrays.concatenate(ephemeralKey, getPublicKeyPacket().getKey().getEncoded(), secret),
                "OpenPGP X448");

        return unwrapSessionData(keyEnc, SymmetricKeyAlgorithmTags.AES_128, new KeyParameter(hkdfOut));
    }

    private byte[] recoverX25519SessionData(byte[][] secKeyData,
                                            int pkeskVersion,
                                            AsymmetricKeyParameter privKey)
            throws PGPException, InvalidCipherTextException
    {
        byte[][] ephemeralKeyAndKeyEnc = parseXDHEncSessionKey(secKeyData[0], X25519PublicBCPGKey.LENGTH,
                containsSKAlg(pkeskVersion));
        byte[] ephemeralKey = ephemeralKeyAndKeyEnc[0];
        byte[] keyEnc = ephemeralKeyAndKeyEnc[1];

        byte[] secret = getCryptoCallback(privKey)
                .decrypt(PublicKeyAlgorithmTags.X25519, new X25519PublicKeyParameters(ephemeralKey));

        byte[] hkdfOut = RFC6637KDFCalculator.createKey(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128,
                Arrays.concatenate(ephemeralKey, getPublicKeyPacket().getKey().getEncoded(), secret),
                "OpenPGP X25519");

        return unwrapSessionData(keyEnc, SymmetricKeyAlgorithmTags.AES_128, new KeyParameter(hkdfOut));
    }

    // OpenPGP v4
    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    // OpenPGP v5
    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }

    /**
     * Return the callback used for the raw private-key operations. Subclasses backing the key with a
     * hardware device override this to route those operations to the device.
     *
     * @deprecated use {@link #getCryptoCallback(AsymmetricKeyParameter)} instead
     * @return crypto callback
     * @throws PGPException if the crypto callback cannot be instantiated
     */
    @Deprecated
    protected BcPublicKeyCryptoCallback getCryptoCallback()
            throws PGPException
    {
        if (pgpPrivKey == null)
        {
            throw new PGPException("External private key material. Overwrite this method to delegate public-key crypto operation.");
        }
        return new DefaultBcPublicKeyCryptoCallback(KEY_CONVERTER.getPrivateKey(pgpPrivKey));
    }

    /**
     * Return the callback used for the raw private-key operations. Subclasses backing the key with a
     * hardware device override this to route those operations to the device.
     *
     * @return crypto callback
     */
    protected BcPublicKeyCryptoCallback getCryptoCallback(AsymmetricKeyParameter privKey)
    {
        return new DefaultBcPublicKeyCryptoCallback(privKey);
    }

    private static class DefaultBcPublicKeyCryptoCallback
        extends BcPublicKeyCryptoCallback
    {
        private final AsymmetricKeyParameter privKey;

        public DefaultBcPublicKeyCryptoCallback(AsymmetricKeyParameter privKey)
        {
            this.privKey = privKey;
        }

        @Override
        public byte[] decrypt(int keyAlgorithm, byte[][] pEnc)
                throws PGPException, InvalidCipherTextException
        {
            switch (keyAlgorithm)
            {
                case PublicKeyAlgorithmTags.RSA_GENERAL:
                case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                    return decryptRSA(keyAlgorithm, pEnc[0]);

                case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                    return decryptElGamal(keyAlgorithm, pEnc);
            }
            throw new PGPException("Unsupported key algorithm: " + keyAlgorithm);
        }

        @Override
        public byte[] decrypt(int keyAlgorithm, AsymmetricKeyParameter peerKey)
                throws PGPException, InvalidCipherTextException
        {
            switch (keyAlgorithm)
            {
                case PublicKeyAlgorithmTags.ECDH:
                    return BcUtil.getSecret(new ECDHRawAgreement(), privKey, peerKey);

                case PublicKeyAlgorithmTags.X25519:
                    return BcUtil.getSecret(new X25519Agreement(), privKey, peerKey);

                case PublicKeyAlgorithmTags.X448:
                    return BcUtil.getSecret(new X448Agreement(), privKey, peerKey);
            }
            throw new PGPException("Unsupported key algorithm: " + keyAlgorithm);
        }

        private byte[] decryptRSA(int keyAlgorithm, byte[] sessionKey)
                throws PGPException, InvalidCipherTextException
        {
            BufferedAsymmetricBlockCipher c1 = getBufferedAsymmetricBlockCipher(keyAlgorithm, privKey);
            c1.processBytes(sessionKey, 0, sessionKey.length);
            return c1.doFinal();
        }

        private byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
                throws InvalidCipherTextException, PGPException
        {
            BufferedAsymmetricBlockCipher c1 = getBufferedAsymmetricBlockCipher(keyAlgorithm, privKey);

            ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters) privKey;
            int size = (parms.getParameters().getP().bitLength() + 7) / 8;
            byte[] tmp = new byte[size];

            byte[] bi = secKeyData[0]; // encoded MPI
            processEncodedMpi(c1, size, tmp, bi);

            bi = secKeyData[1];  // encoded MPI
            Arrays.fill(tmp, (byte)0);

            processEncodedMpi(c1, size, tmp, bi);

            return c1.doFinal();
        }
    }

    public static byte[] unwrapSessionData(byte[] keyEnc, int symmetricKeyAlgorithm, KeyParameter key)
        throws PGPException, InvalidCipherTextException
    {
        Wrapper c = BcImplProvider.createWrapper(symmetricKeyAlgorithm);
        c.init(false, key);
        return c.unwrap(keyEnc, 0, keyEnc.length);
    }
}