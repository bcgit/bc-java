package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

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
//    private static boolean checkForAEAD()
//    {
//        return (Boolean)AccessController.doPrivileged(new PrivilegedAction()
//        {
//            public Object run()
//            {
//                try
//                {
//                    return Cipher.class.getMethod("updateAAD", byte[].class) != null;
//                }
//                catch (Exception ignore)
//                {
//                    // TODO[logging] Log the fact that we are falling back to BC-specific class
//                    return Boolean.FALSE;
//                }
//            }
//        });
//    }

    //  private static final boolean canDoAEAD = checkForAEAD();

    private static String getAlgParamsName(JcaJceHelper helper, String cipherName)
    {
        try
        {
            String algName = cipherName.indexOf("CCM") > -1 ? "CCM" : "GCM";
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

    private byte[] nonce;
    private int macSize;

    public void init(byte[] nonce, int macSize)
    {
        // NOTE: Shouldn't need a SecureRandom, but this is cheaper if the provider would auto-create one
        SecureRandom random = crypto.getSecureRandom();

        try
        {
//            if (canDoAEAD && algorithmParamsName != null)
//            {
//                AlgorithmParameters algParams = helper.createAlgorithmParameters(algorithmParamsName);
//
//                // fortunately CCM and GCM parameters have the same ASN.1 structure
//                algParams.init(new GCMParameters(nonce, macSize).getEncoded());
//
//                cipher.init(cipherMode, key, algParams);
//
//                if (additionalData != null && additionalData.length > 0)
//                {
//                    cipher.updateAAD(additionalData);
//                }
//            }
//            else
//            {
            // Otherwise fall back to the BC-specific AEADParameterSpec
                 this.nonce = Arrays.clone(nonce);
                 this.macSize = macSize;
            // }
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
        try
        {
            if (!Arrays.isNullOrEmpty(additionalData))
            {
                cipher.init(cipherMode, key, new AEADParameterSpec(nonce, macSize * 8, additionalData));
            }
            else
            {
                cipher.init(cipherMode, key, new AEADParameterSpec(nonce, macSize * 8, null));
            }
        }
        catch (Exception e)
        {
            throw new IOException(e.toString());
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
