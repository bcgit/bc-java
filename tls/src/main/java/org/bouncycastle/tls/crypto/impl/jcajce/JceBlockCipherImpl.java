package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed block cipher functionality for TLS.
 */
public class JceBlockCipherImpl
    implements TlsBlockCipherImpl
{
    private static final int BUF_SIZE = 32 * 1024;

    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;
    private final int keySize;

    private SecretKey key;

    public JceBlockCipherImpl(Cipher cipher, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.cipher = cipher;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        if (keySize != keyLen)
        {
            throw new IllegalStateException();
        }

        this.key = new SecretKeySpec(key, keyOff, keyLen, algorithm);
    }

    public void init(byte[] iv, int ivOff, int ivLen)
    {
        try
        {
            cipher.init(cipherMode, key, new IvParameterSpec(iv, ivOff, ivLen));
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            // to avoid performance issue in FIPS jar  1.0.0-1.0.2
            int totLen = 0;
            while (inputLength > BUF_SIZE)
            {
                totLen += cipher.update(input, inputOffset, BUF_SIZE, output, outputOffset + totLen);

                inputOffset += BUF_SIZE;
                inputLength -= BUF_SIZE;
            }

            totLen += cipher.update(input, inputOffset, inputLength, output, outputOffset + totLen);
            totLen += cipher.doFinal(output, outputOffset + totLen);

            return totLen;
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }
}
