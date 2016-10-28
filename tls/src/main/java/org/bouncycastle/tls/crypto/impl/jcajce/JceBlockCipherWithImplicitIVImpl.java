package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;
import org.bouncycastle.util.Arrays;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed block cipher functionality for TLS where the
 * cipher-suite requires the IV to be continued between calls.
 */
public class JceBlockCipherWithImplicitIVImpl
    implements TlsBlockCipherImpl
{
    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;

    private SecretKey key;
    private byte[] nextIV;

    public JceBlockCipherWithImplicitIVImpl(Cipher cipher, String algorithm, boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.cipher = cipher;
        this.algorithm = algorithm;
        this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    public void setKey(byte[] key)
    {
        this.key = new SecretKeySpec(key, algorithm);
    }

    public void init(byte[] iv)
    {
        nextIV = iv;
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            cipher.init(cipherMode, key, new IvParameterSpec(nextIV));

            if (cipherMode == Cipher.DECRYPT_MODE)
            {
                nextIV = Arrays.copyOfRange(input, inputOffset + inputLength - cipher.getBlockSize(), inputOffset + inputLength);
            }

            int len = cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);

            if (cipherMode == Cipher.ENCRYPT_MODE)
            {
                nextIV = Arrays.copyOfRange(output, outputOffset + inputLength - cipher.getBlockSize(), outputOffset + inputLength);
            }

            init(nextIV);

            return len;
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }
}
