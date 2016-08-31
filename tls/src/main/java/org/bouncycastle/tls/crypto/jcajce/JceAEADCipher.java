package org.bouncycastle.tls.crypto.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.tls.crypto.TlsAEADCipher;

public class JceAEADCipher
    implements TlsAEADCipher
{
    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;

    private SecretKey key;

    public JceAEADCipher(Cipher cipher, String algorithm, boolean isEncrypting)
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

    public void init(byte[] nonce, int macSize, byte[] additionalData)
    {
        try
        {
            cipher.init(cipherMode, key, new AEADParameterSpec(nonce, macSize * 8, additionalData));
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public int getOutputSize(int inputLength)
    {
        return cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            return cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }
}
