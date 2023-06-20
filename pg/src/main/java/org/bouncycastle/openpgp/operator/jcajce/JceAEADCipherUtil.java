package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

public class JceAEADCipherUtil
{
    static void setUpAeadCipher(Cipher aead, SecretKey secretKey, int mode, byte[] nonce, int aeadMacLen, byte[] aad)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (GcmSpecUtil.gcmSpecExtractable())
        {
            AlgorithmParameterSpec parameters;
            try
            {
                parameters = GcmSpecUtil.extractGcmSpec(new GCMParameters(nonce, (aeadMacLen + 7) / 8).toASN1Primitive());
            }
            catch (InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException(e.getMessage());
            }
            aead.init(mode, secretKey, parameters);
            aead.updateAAD(aad);
        }
        else
        {
            AEADParameterSpec parameters = new AEADParameterSpec(nonce, aeadMacLen, aad);
            aead.init(mode, secretKey, parameters);
        }
    }
}
