package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.BasicRawAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;

/**
 * A decryptor factory for handling public key decryption operations.
 */
public class BcPublicKeyDataDecryptorFactory
    extends AbstractPublicKeyDataDecryptorFactory
{
    private static final BcPGPKeyConverter KEY_CONVERTER = new BcPGPKeyConverter();

    private final PGPPrivateKey pgpPrivKey;

    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey pgpPrivKey)
    {
        this.pgpPrivKey = pgpPrivKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter privKey = KEY_CONVERTER.getPrivateKey(pgpPrivKey);

            if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
            {
                return getSessionData(secKeyData[0], privKey, X25519PublicBCPGKey.LENGTH, HashAlgorithmTags.SHA256,
                    SymmetricKeyAlgorithmTags.AES_128, new X25519Agreement(), "X25519", containsSKAlg(pkeskVersion), new PublicKeyParametersOperation()
                    {
                        @Override
                        public AsymmetricKeyParameter getPublicKeyParameters(byte[] pEnc, int pEncOff)
                        {
                            return new X25519PublicKeyParameters(pEnc, 0);
                        }
                    });
            }
            else if (keyAlgorithm == PublicKeyAlgorithmTags.X448)
            {
                return getSessionData(secKeyData[0], privKey, X448PublicBCPGKey.LENGTH, HashAlgorithmTags.SHA512,
                    SymmetricKeyAlgorithmTags.AES_256, new X448Agreement(), "X448", containsSKAlg(pkeskVersion), new PublicKeyParametersOperation()
                    {
                        @Override
                        public AsymmetricKeyParameter getPublicKeyParameters(byte[] pEnc, int pEncOff)
                        {
                            return new X448PublicKeyParameters(pEnc, 0);
                        }
                    });
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

    private byte[] recoverRSASessionData(int keyAlgorithm,
                                         byte[][] secKeyData,
                                         AsymmetricKeyParameter privKey)
        throws PGPException, InvalidCipherTextException
    {
        BufferedAsymmetricBlockCipher c1 = getBufferedAsymmetricBlockCipher(keyAlgorithm, privKey);
        byte[] bi = secKeyData[0];
        c1.processBytes(bi, 2, bi.length - 2);
        return c1.doFinal();
    }

    private static BufferedAsymmetricBlockCipher getBufferedAsymmetricBlockCipher(int keyAlgorithm, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(BcImplProvider.createPublicKeyCipher(keyAlgorithm));
        c1.init(false, privKey);
        return c1;
    }

    private void processEncodedMpi(BufferedAsymmetricBlockCipher c1, int size, byte[] tmp, byte[] bi)
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

    private byte[] recoverECDHSessionData(byte[][] secKeyData,
                                          AsymmetricKeyParameter privKey)
            throws PGPException, IOException, InvalidCipherTextException
    {
        byte[] enc = secKeyData[0];
        byte[] pEnc;
        byte[] keyEnc;
        int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
        checkRange(2 + pLen + 1, enc);

        pEnc = new byte[pLen];
        System.arraycopy(enc, 2, pEnc, 0, pLen);

        int keyLen = enc[pLen + 2] & 0xff;
        checkRange(2 + pLen + 1 + keyLen, enc);

        keyEnc = new byte[keyLen];
        System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

        byte[] secret;
        RFC6637KDFCalculator rfc6637KDFCalculator;
        byte[] userKeyingMaterial;
        int symmetricKeyAlgorithm, hashAlgorithm;

        ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pgpPrivKey.getPublicKeyPacket().getKey();
        // XDH
        if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
        {
            if (pEnc.length != 1 + X25519PublicKeyParameters.KEY_SIZE || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve25519 public key");
            }
            // skip the 0x40 header byte.
            secret = BcUtil.getSecret(new X25519Agreement(), privKey, new X25519PublicKeyParameters(pEnc, 1));
        }
        else if (ecPubKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
        {
            if (pEnc.length != 1 + X448PublicKeyParameters.KEY_SIZE || 0x40 != pEnc[0])
            {
                throw new IllegalArgumentException("Invalid Curve448 public key");
            }
            // skip the 0x40 header byte.
            secret = BcUtil.getSecret(new X448Agreement(), privKey, new X448PublicKeyParameters(pEnc, 1));
        }
        else
        {
            ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey).getParameters();
            ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.getCurve().decodePoint(pEnc),
                ecParameters);

            secret = BcUtil.getSecret(new BasicRawAgreement(new ECDHBasicAgreement()), privKey, ephPub);
        }
        hashAlgorithm = ecPubKey.getHashAlgorithm();
        symmetricKeyAlgorithm = ecPubKey.getSymmetricKeyAlgorithm();
        userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pgpPrivKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator());
        rfc6637KDFCalculator = new RFC6637KDFCalculator(new BcPGPDigestCalculatorProvider().get(hashAlgorithm), symmetricKeyAlgorithm);
        KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

        return PGPPad.unpadSessionData(unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key));
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

    @FunctionalInterface
    private interface PublicKeyParametersOperation
    {
        AsymmetricKeyParameter getPublicKeyParameters(byte[] pEnc, int pEncOff);
    }

    private byte[] getSessionData(byte[] enc, AsymmetricKeyParameter privKey, int pLen, int hashAlgorithm, int symmetricKeyAlgorithm,
                                  RawAgreement agreement, String algorithmName, boolean includesSesKeyAlg, PublicKeyParametersOperation pkp)
        throws PGPException, InvalidCipherTextException
    {
        byte[] ephemeralKey = Arrays.copyOf(enc, pLen);

        // size of following fields
        int size = enc[pLen] & 0xff;
        checkRange(pLen + 1 + size, enc);

        // encrypted session key
        int sesKeyLen = size - (includesSesKeyAlg ? 1 : 0);
        int sesKeyOff = pLen + 1 + (includesSesKeyAlg ? 1 : 0);
        byte[] keyEnc = Arrays.copyOfRange(enc, sesKeyOff, sesKeyOff + sesKeyLen);

        byte[] secret = BcUtil.getSecret(agreement, privKey, pkp.getPublicKeyParameters(ephemeralKey, 0));

        byte[] hkdfOut = RFC6637KDFCalculator.createKey(hashAlgorithm, symmetricKeyAlgorithm,
            Arrays.concatenate(ephemeralKey, pgpPrivKey.getPublicKeyPacket().getKey().getEncoded(), secret),
            "OpenPGP " + algorithmName);

        return unwrapSessionData(keyEnc, SymmetricKeyAlgorithmTags.AES_128, new KeyParameter(hkdfOut));
    }

    private static byte[] unwrapSessionData(byte[] keyEnc, int symmetricKeyAlgorithm, KeyParameter key)
        throws PGPException, InvalidCipherTextException
    {
        Wrapper c = BcImplProvider.createWrapper(symmetricKeyAlgorithm);
        c.init(false, key);
        return c.unwrap(keyEnc, 0, keyEnc.length);
    }
}