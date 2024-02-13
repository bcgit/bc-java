package org.bouncycastle.mls.crypto.bc;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.mls.crypto.MlsAead;

public class BcMlsAead
    implements MlsAead
{
    AEADCipher cipher;
    private final short aeadId;

    public BcMlsAead(short aeadId)
    {
        this.aeadId = aeadId;

        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
            cipher = new GCMBlockCipher(new AESEngine());
            break;
        case HPKE.aead_CHACHA20_POLY1305:
            cipher = new ChaCha20Poly1305();
            break;
        case HPKE.aead_EXPORT_ONLY:
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

    private int getTagSize()
    {
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            return 16;
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
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.init(false, params);
        if (aad != null)
        {
            cipher.processAADBytes(aad, 0, aad.length);
        }

        byte[] pt = new byte[cipher.getOutputSize(ct.length)];

        int len = cipher.processBytes(ct, 0, ct.length, pt, 0);
        len += cipher.doFinal(pt, len);
        return pt;
    }

    public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt)
        throws InvalidCipherTextException
    {
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.init(true, params);
        cipher.processAADBytes(aad, 0, aad.length);

        byte[] ct = new byte[cipher.getOutputSize(pt.length)];
        int len = cipher.processBytes(pt, 0, pt.length, ct, 0);
        cipher.doFinal(ct, len);
        return ct;
    }
}
