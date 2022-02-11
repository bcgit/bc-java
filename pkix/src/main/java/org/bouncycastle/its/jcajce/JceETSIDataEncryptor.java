package org.bouncycastle.its.jcajce;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.its.operator.ETSIDataEncryptor;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

public class JceETSIDataEncryptor
    implements ETSIDataEncryptor
{

    private JcaJceHelper helper;

    public JceETSIDataEncryptor()
    {
        this.helper = new DefaultJcaJceHelper();
    }


    public byte[] encrypt(byte[] key, byte[] nonce, byte[] content)
    {
        try
        {
            SecretKey k = new SecretKeySpec(key, "AES");
            Cipher ccm = helper.createCipher("CCM");
            ccm.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, nonce));
            return ccm.doFinal(content);

        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}
