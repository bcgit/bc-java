package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed block cipher functionality for TLS.
 */
public class JceBlockCipherImpl
    implements TlsBlockCipherImpl
{
    private static Logger LOG = Logger.getLogger(JceBlockCipherImpl.class.getName());
    
    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;

    private SecretKey key;

    public JceBlockCipherImpl(Cipher cipher, String algorithm, boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.cipher = cipher;
        this.algorithm = algorithm;
        this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
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
            throw new IllegalStateException(e);
        }
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
        finally 
        {
            if (this.key != null) 
            {
                try 
                {
                    this.key.destroy();
                } 
                catch (final DestroyFailedException e) 
                {
                    LOG.log(Level.FINE, "Could not destroy calculate SecretKey", e);
                }

            }
        }
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }
}
