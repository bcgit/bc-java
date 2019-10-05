package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed block cipher functionality for TLS where the
 * cipher requires the IV to be continued between calls.
 */
public class JceBlockCipherWithCBCImplicitIVImpl
    implements TlsBlockCipherImpl
{
    private static final int BUF_SIZE = 32 * 1024;

    private final Cipher cipher;
    private final String algorithm;
    private final boolean isEncrypting;

    private SecretKey key;
    private byte[] nextIV;

    public JceBlockCipherWithCBCImplicitIVImpl(Cipher cipher, String algorithm, boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.cipher = cipher;
        this.algorithm = algorithm;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.key = new SecretKeySpec(key, keyOff, keyLen, algorithm);
    }

    public void init(byte[] iv, int ivOff, int ivLen)
    {
        if (nextIV != null)
        {
            throw new IllegalStateException("unexpected reinitialization of an implicit-IV cipher");
        }

        nextIV = TlsUtils.copyOfRangeExact(iv, ivOff, ivOff + ivLen);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        try
        {
            cipher.init(isEncrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, new IvParameterSpec(nextIV));

            nextIV = null;

            if (!isEncrypting)
            {
                nextIV = TlsUtils.copyOfRangeExact(input, inputOffset + inputLength - cipher.getBlockSize(), inputOffset + inputLength);
            }

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

            if (isEncrypting)
            {
                nextIV = TlsUtils.copyOfRangeExact(output, outputOffset + totLen - cipher.getBlockSize(), outputOffset + totLen);
            }

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
