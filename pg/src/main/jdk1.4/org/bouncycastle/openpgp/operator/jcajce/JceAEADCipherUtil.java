package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;

public class JceAEADCipherUtil
{
    static void setUpAeadCipher(Cipher aead, SecretKey secretKey, int mode, byte[] nonce, int aeadMacLen, byte[] aad)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AEADParameterSpec parameters = new AEADParameterSpec(nonce, aeadMacLen, aad);
        aead.init(mode, secretKey, parameters);
    }
}
