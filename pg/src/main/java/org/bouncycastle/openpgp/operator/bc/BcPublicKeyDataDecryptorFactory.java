package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
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
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
    private PGPPrivateKey privKey;

    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey privKey)
    {
        this.privKey = privKey;
    }

    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        try
        {
            if (keyAlgorithm != PGPPublicKey.ECDH)
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

                AsymmetricKeyParameter key = keyConverter.getPrivateKey(privKey);

                BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

                c1.init(false, key);

                if (keyAlgorithm == PGPPublicKey.RSA_ENCRYPT
                    || keyAlgorithm == PGPPublicKey.RSA_GENERAL)
                {
                    byte[] bi = secKeyData[0];

                    c1.processBytes(bi, 2, bi.length - 2);
                }
                else
                {
                    BcPGPKeyConverter converter = new BcPGPKeyConverter();
                    ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters)converter.getPrivateKey(privKey);
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
                    for (int i = 0; i != tmp.length; i++)
                    {
                        tmp[i] = 0;
                    }

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
            else
            {
                ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)privKey.getPublicKeyPacket().getKey();
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

                Wrapper c = BcImplProvider.createWrapper(ecKey.getSymmetricKeyAlgorithm());
                KeyParameter key;

                // XDH
                if (ecKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    // skip the 0x40 header byte.
                    if (pEnc.length != (1 + X25519PublicKeyParameters.KEY_SIZE) || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    X25519Agreement agreement = new X25519Agreement();

                    agreement.init(new X25519PrivateKeyParameters(Arrays.reverse(BigIntegers.asUnsignedByteArray(((ECSecretBCPGKey)privKey.getPrivateKeyDataPacket()).getX())), 0));

                    byte[] secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(new X25519PublicKeyParameters(pEnc, 1), secret, 0);

                    RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(new BcPGPDigestCalculatorProvider().get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());
                    key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, RFC6637Utils.createUserKeyingMaterial(privKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator())));
                }
                else
                {
                    X9ECParameters x9Params = ECNamedCurveTable.getByOID(ecKey.getCurveOID());
                 
                    ECPoint S = x9Params.getCurve().decodePoint(pEnc).multiply(((ECSecretBCPGKey)privKey.getPrivateKeyDataPacket()).getX()).normalize();

                    RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(new BcPGPDigestCalculatorProvider().get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());
                    key = new KeyParameter(rfc6637KDFCalculator.createKey(S, RFC6637Utils.createUserKeyingMaterial(privKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator())));
                }

                c.init(false, key);

                              return PGPPad.unpadSessionData(c.unwrap(keyEnc, 0, keyEnc.length));
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

    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }
}
