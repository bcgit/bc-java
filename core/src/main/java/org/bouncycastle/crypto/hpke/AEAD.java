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
import org.bouncycastle.util.Pack;

public class AEAD
{

    private final short aeadId;
    private final byte[] key;
    private final byte[] baseNonce;
    private long seq = 0; // todo throw exception if overflow

    private AEADCipher cipher;
    protected static final short AEAD_AESGCM128 = 0x0001;
    private static final short AEAD_AESGCM256 = 0x0002;
    private static final short AEAD_CHACHA20POLY1305 = 0x0003;
    private static final short AEAD_EXPORT_ONLY = (short) 0xFFFF;

    public AEAD(short aeadId, byte[] key, byte[] baseNonce)
    {
        this.key = key;
        this.baseNonce = baseNonce;
        this.aeadId = aeadId;
        seq = 0;

        switch (aeadId)
        {
            case AEAD_AESGCM128:
            case AEAD_AESGCM256:
                cipher = new GCMBlockCipher(new AESEngine());
                break;
            case AEAD_CHACHA20POLY1305:
                cipher = new ChaCha20Poly1305();
                break;
            case AEAD_EXPORT_ONLY:
                break;
        }
    }


    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt)
            throws InvalidCipherTextException
    {
        CipherParameters params;
        switch (aeadId)
        {
            case AEAD_AESGCM128:
            case AEAD_AESGCM256:
            case AEAD_CHACHA20POLY1305:
                params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
                break;
            case AEAD_EXPORT_ONLY:
            default:
                throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }
        cipher.init(true, params);
        //todo process aad here or in init?
        cipher.processAADBytes(aad, 0, aad.length);
        byte[] ct = new byte[cipher.getOutputSize(pt.length)];
        int len = cipher.processBytes(pt, 0, pt.length, ct, 0);
        cipher.doFinal(ct, len);

        seq++;
        return ct;
    }


    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        CipherParameters params;
        switch (aeadId)
        {
            case AEAD_AESGCM128:
            case AEAD_AESGCM256:
            case AEAD_CHACHA20POLY1305:
                params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
//                params = new AEADParameters(new KeyParameter(key), 128, ComputeNonce(), aad);
                break;
            case AEAD_EXPORT_ONLY:
            default:
                throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }
        ////System.out.println("aad: " + Hex.toHexString(aad));
        ////System.out.println("ct: " + Hex.toHexString(ct));
//        CipherParameters params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());

        cipher.init(false, params);
        cipher.processAADBytes(aad, 0, aad.length);

        byte[] pt = new byte[cipher.getOutputSize(ct.length)];
        int len = cipher.processBytes(ct, 0, ct.length, pt, 0);
        len += cipher.doFinal(pt, len);

        seq++;
        return pt;
    }

    private byte[] ComputeNonce()
    {
        byte[] seq_bytes = Pack.longToBigEndian(seq);
        ////System.out.println("base_nonce: " + Hex.toHexString(baseNonce));
        ////System.out.println("seq: " + seq);

        int Nn = baseNonce.length;
        byte[] nonce = Arrays.clone(baseNonce);
        //xor
        for (int i = 0; i < 8; i++)
        {
            nonce[Nn-8+i] ^= seq_bytes[i];
        }
        ////System.out.println("nonce: " + Hex.toHexString(nonce));
        return nonce;
    }


}

