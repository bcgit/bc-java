package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

public class AEAD
{
    private final short aeadId;
    private final byte[] key;
    private final byte[] baseNonce;
    private long seq = 0; // todo throw exception if overflow

    private AEADCipher cipher;

    public AEAD(short aeadId, byte[] key, byte[] baseNonce)
    {
        this.key = key;
        this.baseNonce = baseNonce;
        this.aeadId = aeadId;
        seq = 0;

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
            break;
        }
    }

    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt)
        throws InvalidCipherTextException
    {
        return process(true, aad, pt, 0, pt.length);
    }

    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        throws InvalidCipherTextException
    {
        Arrays.validateSegment(pt, ptOffset, ptLength);

        return process(true, aad, pt, ptOffset, ptLength);
    }

    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return process(false, aad, ct, 0, ct.length);
    }

    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        throws InvalidCipherTextException
    {
        Arrays.validateSegment(ct, ctOffset, ctLength);

        return process(false, aad, ct, ctOffset, ctLength);
    }

    private byte[] computeNonce()
    {
        byte[] seq_bytes = Pack.longToBigEndian(seq++);
        byte[] nonce = Arrays.clone(baseNonce);
        Bytes.xorTo(8, seq_bytes, 0, nonce, nonce.length - 8);
        return nonce;
    }

    private byte[] process(boolean forEncryption, byte[] aad, byte[] buf, int off, int len)
        throws InvalidCipherTextException
    {
        CipherParameters params;
        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
        case HPKE.aead_CHACHA20_POLY1305:
            params = new ParametersWithIV(new KeyParameter(key), computeNonce());
            break;
        case HPKE.aead_EXPORT_ONLY:
        default:
            throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }

        cipher.init(forEncryption, params);
        cipher.processAADBytes(aad, 0, aad.length);

        byte[] output = new byte[cipher.getOutputSize(len)];
        int pos = cipher.processBytes(buf, off, len, output, 0);
        pos += cipher.doFinal(output, pos);
        if (pos != output.length)
        {
            // Existing AEAD modes should return exact value for getOutputSize.
            throw new IllegalStateException();
        }
        return output;
    }
}
