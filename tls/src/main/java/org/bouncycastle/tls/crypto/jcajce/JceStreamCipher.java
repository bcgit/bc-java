package org.bouncycastle.tls.crypto.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.TlsStreamCipher;

public class JceStreamCipher
    implements TlsStreamCipher
{
    private final int cipherMode;
    private final Cipher cipher;
    private final String baseAlgorithm;

    private SecretKey key;
    private boolean hasNoIv;

    public JceStreamCipher(Cipher cipher, String algorithm, boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.cipher = cipher;
        this.baseAlgorithm = algorithm;
        this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    public void setKey(byte[] key)
    {
        this.key = new SecretKeySpec(key, baseAlgorithm);
    }

    public void init(byte[] iv)
    {
        try
        {
            if (iv != null)
            {
                hasNoIv = false;
                cipher.init(cipherMode, key, new IvParameterSpec(iv));
            }
            else
            {
                hasNoIv = true;
                cipher.init(cipherMode, key);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            if (hasNoIv)
            {
                // note: this assumes no internal buffering will take place - fine for BC but with others not so sure..
                int len = cipher.update(input, inputOffset, inputLength, output, outputOffset);

                return len;
            }
            else
            {
                int len = cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);

                return len;
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }
}
