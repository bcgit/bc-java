package org.bouncycastle.openpgp.operator.bc;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

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

    public byte[] recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)
        throws PGPException
    {
        try
        {
            AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

            AsymmetricKeyParameter key = keyConverter.getPrivateKey(privKey);

            BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

            c1.init(false, key);

            if (keyAlgorithm == PGPPublicKey.RSA_ENCRYPT
                || keyAlgorithm == PGPPublicKey.RSA_GENERAL)
            {
                byte[] bi = secKeyData[0].toByteArray();

                if (bi[0] == 0)
                {
                    c1.processBytes(bi, 1, bi.length - 1);
                }
                else
                {
                    c1.processBytes(bi, 0, bi.length);
                }
            }
            else
            {
                BcPGPKeyConverter converter = new BcPGPKeyConverter();
                ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters) converter.getPrivateKey(privKey);
                int size = (parms.getParameters().getP().bitLength() + 7) / 8;
                byte[] tmp = new byte[size];

                byte[] bi = secKeyData[0].toByteArray();
                if (bi.length > size)
                {
                    c1.processBytes(bi, 1, bi.length - 1);
                }
                else
                {
                    System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                    c1.processBytes(tmp, 0, tmp.length);
                }

                bi = secKeyData[1].toByteArray();
                for (int i = 0; i != tmp.length; i++)
                {
                    tmp[i] = 0;
                }

                if (bi.length > size)
                {
                    c1.processBytes(bi, 1, bi.length - 1);
                }
                else
                {
                    System.arraycopy(bi, 0, tmp, tmp.length - bi.length, bi.length);
                    c1.processBytes(tmp, 0, tmp.length);
                }
            }

            return c1.doFinal();
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }

    }

    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }
}
