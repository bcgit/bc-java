package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsRecordNumberMask;

/**
 * RFC 9147 4.2.3: Mask = AES-ECB(sn_key, Ciphertext[0..15]), via a JCA "AES/ECB/NoPadding" cipher.
 */
public class JceAESRecordNumberMask
    implements TlsRecordNumberMask
{
    private final Cipher cipher;

    public JceAESRecordNumberMask(JcaJceHelper helper) throws GeneralSecurityException
    {
        this.cipher = helper.createCipher("AES/ECB/NoPadding");
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyOff, keyLen, "AES"));
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public void generateMask(byte[] ciphertext, int ciphertextOff, byte[] mask, int maskOff) throws IOException
    {
        try
        {
            int len = cipher.doFinal(ciphertext, ciphertextOff, 16, mask, maskOff);
            if (16 != len)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
