package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsRecordNumberMask;
import org.bouncycastle.util.Pack;

/**
 * RFC 9147 4.2.3: Mask = ChaCha20(sn_key, Ciphertext[0..3], Ciphertext[4..15]).
 * <p>
 * The JCA has no ChaCha20 cipher able to position the block counter on the Java versions this module targets
 * (the base sources compile for Java 8 and below; {@code ChaCha20ParameterSpec}, which carries a counter, only
 * arrived in Java 11), so the lightweight engine is used here, as {@link JcaNonceGenerator} does for its DRBG.
 * </p>
 */
public class JceChaCha20RecordNumberMask
    implements TlsRecordNumberMask
{
    private static final byte[] ZEROES = new byte[16];

    private final ChaCha7539Engine cipher = new ChaCha7539Engine();

    private KeyParameter key;

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void generateMask(byte[] ciphertext, int ciphertextOff, byte[] mask, int maskOff) throws IOException
    {
        if (null == key)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
            long counter = Pack.littleEndianToInt(ciphertext, ciphertextOff) & 0xFFFFFFFFL;

            byte[] nonce = new byte[12];
            System.arraycopy(ciphertext, ciphertextOff + 4, nonce, 0, 12);

            cipher.init(true, new ParametersWithIV(key, nonce));
            cipher.skip(counter * 64L);
            cipher.processBytes(ZEROES, 0, 16, mask, maskOff);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
