package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;

/**
 * A basic wrapper for a JCE Cipher class to provide the needed AEAD cipher functionality for TLS.
 */
public class JceAEADCipherImpl
    implements TlsAEADCipherImpl
{
    private static String getAlgParamsName(JcaJceHelper helper, String cipherName)
    {
        try
        {
            String algName = cipherName.indexOf("CCM") >= 0 ? "CCM" : "GCM";
            helper.createAlgorithmParameters(algName);
            return algName;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private final JcaTlsCrypto crypto;
    private final JcaJceHelper helper;
    private final int cipherMode;
    private final Cipher cipher;
    private final String algorithm;
    private final int keySize;
    private final String algorithmParamsName;

    private SecretKey key;

    // TODO[tls] These two are only needed while the baseline is pre-Java7
    private byte[] noncePre7;
    private int macSizePre7;

    public JceAEADCipherImpl(JcaTlsCrypto crypto, JcaJceHelper helper, String cipherName, String algorithm, int keySize,
        boolean isEncrypting)
        throws GeneralSecurityException
    {
        this.crypto = crypto;
        this.helper = helper;
        this.cipher = helper.createCipher(cipherName);
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.cipherMode = isEncrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        this.algorithmParamsName = getAlgParamsName(helper, cipherName);
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        if (keySize != keyLen)
        {
            throw new IllegalStateException();
        }

        this.key = new SecretKeySpec(key, keyOff, keyLen, algorithm);
    }

    public void init(byte[] nonce, int macSize)
    {
        // NOTE: Shouldn't need a SecureRandom, but this is cheaper if the provider would auto-create one
        SecureRandom random = crypto.getSecureRandom();

        try
        {
            {
                /*
                 * Otherwise fall back to the BC-specific AEADParameterSpec. Since updateAAD is not available, we
                 * need to use init to pass the associated data (in doFinal), but in order to call getOutputSize we
                 * technically need to init the cipher first. So we init with a dummy nonce to avoid duplicate nonce
                 * error from the init in doFinal.
                 */

                if (this.noncePre7 == null || this.noncePre7.length != nonce.length)
                {
                    this.noncePre7 = new byte[nonce.length];
                }

                System.arraycopy(nonce, 0, this.noncePre7, 0, nonce.length);
                this.macSizePre7 = macSize;

                this.noncePre7[0] ^= 0x80;

                AlgorithmParameterSpec params = new AEADParameterSpec(noncePre7, macSizePre7 * 8, null);
                cipher.init(cipherMode, key, params, random);

                this.noncePre7[0] ^= 0x80;
            }
        }
        catch (Exception e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    public int getOutputSize(int inputLength)
    {
        return cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] additionalData, byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        throws IOException
    {
        if (!Arrays.isNullOrEmpty(additionalData))
        {
            {
                try
                {
                    // NOTE: Shouldn't need a SecureRandom, but this is cheaper if the provider would auto-create one
                    SecureRandom random = crypto.getSecureRandom();

                    AlgorithmParameterSpec params = new AEADParameterSpec(noncePre7, macSizePre7 * 8, additionalData);
                    cipher.init(cipherMode, key, params, random);
                }
                catch (Exception e)
                {
                    throw Exceptions.ioException(e.getMessage(), e);
                }
            }
        }

        /*
         * NOTE: Some providers don't allow cipher update methods with AEAD decryption,
         * since they may return partial data that has not yet been authenticated. So we
         * make sure to use a single call for the whole record.
         */
        try
        {
            return cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("", e);
        }
    }
}
