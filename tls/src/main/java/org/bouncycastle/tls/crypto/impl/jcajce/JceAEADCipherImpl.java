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
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static boolean checkForAEAD()
    {
        return (Boolean)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    return Cipher.class.getMethod("updateAAD", byte[].class) != null;
                }
                catch (Exception ignore)
                {
                    // TODO[logging] Log the fact that we are falling back to BC-specific class
                    return Boolean.FALSE;
                }
            }
        });
    }

    // TODO[tls] Once Java 7 or higher is the baseline, this will always be true
    private static final boolean canDoAEAD = checkForAEAD();

    private static String getAlgParamsName(JcaJceHelper helper, String cipherName)
    {
        try
        {
            String algName = cipherName.contains("CCM") ? "CCM" : "GCM";
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
            if (canDoAEAD && algorithmParamsName != null)
            {
                AlgorithmParameters algParams = helper.createAlgorithmParameters(algorithmParamsName);

                // believe it or not but there are things out there that do not support the ASN.1 encoding...
                if (GCMUtil.isGCMParameterSpecAvailable())
                {
                    algParams.init(GCMUtil.createGCMParameterSpec(macSize * 8, nonce));
                }
                else
                {
                    // fortunately CCM and GCM parameters have the same ASN.1 structure
                    algParams.init(new GCMParameters(nonce, macSize).getEncoded());
                }

                cipher.init(cipherMode, key, algParams, random);
            }
            else
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
            if (canDoAEAD)
            {
                cipher.updateAAD(additionalData);
            }
            else
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
