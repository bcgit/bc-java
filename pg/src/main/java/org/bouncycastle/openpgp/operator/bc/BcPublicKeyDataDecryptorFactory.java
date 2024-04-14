package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X448PublicBCPGKey;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.Wrapper;
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
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * A decryptor factory for handling public key decryption operations.
 */
public class BcPublicKeyDataDecryptorFactory
    implements PublicKeyDataDecryptorFactory
{
    private static final BcPGPKeyConverter KEY_CONVERTER = new BcPGPKeyConverter();

    private final PGPPrivateKey pgpPrivKey;

    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey pgpPrivKey)
    {
        this.pgpPrivKey = pgpPrivKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter privKey = KEY_CONVERTER.getPrivateKey(pgpPrivKey);

            if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
            {
                return getSessionData(secKeyData[0], privKey, X25519PublicBCPGKey.LENGTH, HashAlgorithmTags.SHA256,
                    SymmetricKeyAlgorithmTags.AES_128, new X25519Agreement(), "X25519", new PublicKeyParametersOperation()
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
                    SymmetricKeyAlgorithmTags.AES_256, new X448Agreement(), "X448", new PublicKeyParametersOperation()
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
                byte[] enc = secKeyData[0];
                byte[] pEnc;
                byte[] keyEnc;
                int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
                assertOutOfRange(2 + pLen + 1, enc);

                pEnc = new byte[pLen];
                System.arraycopy(enc, 2, pEnc, 0, pLen);

                int keyLen = enc[pLen + 2] & 0xff;
                assertOutOfRange(2 + pLen + 1 + keyLen, enc);

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
                else
                {
                    ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey).getParameters();

                    ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.getCurve().decodePoint(pEnc),
                        ecParameters);

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(privKey);
                    BigInteger S = agreement.calculateAgreement(ephPub);
                    secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);
                }
                hashAlgorithm = ecPubKey.getHashAlgorithm();
                symmetricKeyAlgorithm = ecPubKey.getSymmetricKeyAlgorithm();
                userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pgpPrivKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator());
                rfc6637KDFCalculator = new RFC6637KDFCalculator(new BcPGPDigestCalculatorProvider().get(hashAlgorithm), symmetricKeyAlgorithm);
                KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

                return PGPPad.unpadSessionData(unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key));
            }
            else
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

                BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

                c1.init(false, privKey);

                if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
                    || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
                {
                    byte[] bi = secKeyData[0];

                    c1.processBytes(bi, 2, bi.length - 2);
                }
                else
                {
                    ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters)privKey;
                    int size = (parms.getParameters().getP().bitLength() + 7) / 8;
                    byte[] tmp = new byte[size];

                    byte[] bi = secKeyData[0]; // encoded MPI
                    if (bi.length - 2 > size)  // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }

                    bi = secKeyData[1];  // encoded MPI
                    Arrays.fill(tmp, (byte)0);

                    if (bi.length - 2 > size) // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }
                }

                return c1.doFinal();
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
                                  RawAgreement agreement, String algorithmName, PublicKeyParametersOperation pkp)
        throws PGPException, InvalidCipherTextException
    {
        byte[] pEnc = new byte[pLen];
        byte[] keyEnc;
        System.arraycopy(enc, 0, pEnc, 0, pLen);
        int keyLen = enc[pLen] & 0xff;
        assertOutOfRange(pLen + 1 + keyLen, enc);
        keyEnc = new byte[keyLen - 1];
        System.arraycopy(enc, pLen + 2, keyEnc, 0, keyEnc.length);
        byte[] secret = BcUtil.getSecret(agreement, privKey, pkp.getPublicKeyParameters(pEnc, 0));
        KeyParameter key = new KeyParameter(RFC6637KDFCalculator.createKey(hashAlgorithm, symmetricKeyAlgorithm,
            Arrays.concatenate(pEnc, pgpPrivKey.getPublicKeyPacket().getKey().getEncoded(), secret), "OpenPGP " + algorithmName));

        return Arrays.concatenate(new byte[]{enc[pLen + 1]}, unwrapSessionData(keyEnc, symmetricKeyAlgorithm, key));
    }

    private static byte[] unwrapSessionData(byte[] keyEnc, int symmetricKeyAlgorithm, KeyParameter key)
        throws PGPException, InvalidCipherTextException
    {
        Wrapper c = BcImplProvider.createWrapper(symmetricKeyAlgorithm);
        c.init(false, key);
        return c.unwrap(keyEnc, 0, keyEnc.length);
    }

    private static void assertOutOfRange(int pLen, byte[] enc)
        throws PGPException
    {
        if (pLen > enc.length)
        {
            throw new PGPException("encoded length out of range");
        }
    }
}