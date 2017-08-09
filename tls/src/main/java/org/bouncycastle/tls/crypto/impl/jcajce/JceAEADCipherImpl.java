package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed AEAD cipher functionality for TLS.
 */
public class JceAEADCipherImpl
    implements TlsAEADCipherImpl
{
    private static Constructor<AlgorithmParameterSpec> initSpecConstructor()
    {
        try
        {
            Class<AlgorithmParameterSpec> clazz = AccessController.doPrivileged(new PrivilegedAction<Class<AlgorithmParameterSpec>>()
            {
                public Class<AlgorithmParameterSpec> run()
                {
                    try
                    {
                        return (Class<AlgorithmParameterSpec>)
                            Class.forName("javax.crypto.spec.GCMParameterSpec", true, IvParameterSpec.class.getClassLoader());
                    }
                    catch (Exception e)
                    {
                        return null;
                    }
                }
            });
            return clazz.getConstructor(int.class, byte[].class);
        }
        catch (Exception ignore)
        {
            // TODO[logging] Log the fact that we are falling back to BC-specific class
            return null;
        }
    }

    private static final Constructor<AlgorithmParameterSpec> specConstructor = initSpecConstructor();

    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;

    private SecretKey key;

    public JceAEADCipherImpl(Cipher cipher, String algorithm, boolean isEncrypting)
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

    public void init(byte[] nonce, int macSize, byte[] additionalData)
    {

        try
        {
            // Try to use GCMParameterSpec (introduced in JDK 7)
            if (specConstructor != null)
            {
                try
                {
                    AlgorithmParameterSpec spec = specConstructor.newInstance(macSize * 8, nonce);
                    cipher.init(cipherMode, key, spec);
                    if (additionalData != null && additionalData.length > 0)
                    {
                        cipher.updateAAD(additionalData);
                    }
                    return;
                }
                catch (GeneralSecurityException e)
                {
                    // no point in falling back if it's one of these
                    throw e;
                }
                catch (Exception e)
                {
                    // we don't have the spec class, ignore.
                }
            }

            // Otherwise fall back to the BC-specific AEADParameterSpec
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
