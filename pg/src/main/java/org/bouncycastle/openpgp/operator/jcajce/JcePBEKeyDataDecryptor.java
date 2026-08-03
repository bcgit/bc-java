package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;

class JcePBEKeyDataDecryptor
{
    static byte[] decryptKeyData(OperatorHelper helper, int encAlgorithm, String mode, byte[] key,
                                 AlgorithmParameterSpec parameters, byte[] keyData, int keyOff, int keyLen)
        throws PGPException
    {
        try
        {
            Cipher cipher = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/" + mode + "/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), parameters);

            return cipher.doFinal(keyData, keyOff, keyLen);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new PGPException("invalid parameter: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("invalid key: " + e.getMessage(), e);
        }
    }
}
