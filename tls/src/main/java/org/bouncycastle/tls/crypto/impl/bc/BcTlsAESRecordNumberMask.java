package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsRecordNumberMask;

/**
 * RFC 9147 4.2.3: Mask = AES-ECB(sn_key, Ciphertext[0..15]).
 */
public class BcTlsAESRecordNumberMask
    implements TlsRecordNumberMask
{
    private final BlockCipher cipher;

    public BcTlsAESRecordNumberMask(BlockCipher cipher)
    {
        this.cipher = cipher;
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        try
        {
            cipher.init(true, new KeyParameter(key, keyOff, keyLen));
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public void generateMask(byte[] ciphertext, int ciphertextOff, byte[] mask, int maskOff) throws IOException
    {
        try
        {
            cipher.processBlock(ciphertext, ciphertextOff, mask, maskOff);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
