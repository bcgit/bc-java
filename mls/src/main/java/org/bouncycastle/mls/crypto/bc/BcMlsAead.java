package org.bouncycastle.mls.crypto.bc;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.mls.crypto.MlsAead;
import org.bouncycastle.util.Arrays;

public class BcMlsAead
    implements MlsAead
{
    private final short aeadId;
    private final AEADCipher cipher;

    public BcMlsAead(short aeadId)
    {
        this.aeadId = aeadId;

        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
            cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
            break;
        case HPKE.aead_CHACHA20_POLY1305:
            cipher = new ChaCha20Poly1305();
            break;
        case HPKE.aead_EXPORT_ONLY:
        default:
            cipher = null;
            break;
        }
    }

    public int getKeySize()
    {
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
            return 16;
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            return 32;
        }
        return -1;
    }

    public int getNonceSize()
    {
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            return 12;
        }
        return -1;
    }

    public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return crypt(false, key, nonce, aad, ct);
    }

    public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt)
        throws InvalidCipherTextException
    {
        return crypt(true, key, nonce, aad, pt);
    }

    private byte[] crypt(boolean forEncryption, byte[] key, byte[] nonce, byte[] aad, byte[] input)
        throws InvalidCipherTextException
    {
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), nonce));

        if (aad != null)
        {
            cipher.processAADBytes(aad, 0, aad.length);
        }

        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);
        len += cipher.doFinal(output, len);

        if (len < output.length)
        {
            return Arrays.copyOf(output, len);
        }

        return output;
    }
}
