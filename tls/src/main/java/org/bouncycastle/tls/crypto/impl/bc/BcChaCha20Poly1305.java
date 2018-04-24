package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class BcChaCha20Poly1305 implements TlsAEADCipherImpl
{
    private static final byte[] ZEROES = new byte[15];

    protected final ChaCha7539Engine cipher = new ChaCha7539Engine();
    protected final Poly1305 mac = new Poly1305();

    protected final boolean isEncrypting;

    protected int additionalDataLength;

    public BcChaCha20Poly1305(boolean isEncrypting)
    {
        this.isEncrypting = isEncrypting;
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        throws IOException
    {
        if (isEncrypting)
        {
            int ciphertextLength = inputLength;

            if (ciphertextLength != cipher.processBytes(input, inputOffset, ciphertextLength, output, outputOffset))
            {
                throw new IllegalStateException();
            }

            updateMAC(output, outputOffset, ciphertextLength);

            byte[] lengths = new byte[16];
            Pack.longToLittleEndian(additionalDataLength & 0xFFFFFFFFL, lengths, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, lengths, 8);
            mac.update(lengths, 0, 16);

            mac.doFinal(output, outputOffset + ciphertextLength);

            return ciphertextLength + 16;
        }
        else
        {
            int ciphertextLength = inputLength - 16;

            updateMAC(input, inputOffset, ciphertextLength);

            byte[] calculatedMAC = new byte[16];
            Pack.longToLittleEndian(additionalDataLength & 0xFFFFFFFFL, calculatedMAC, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, calculatedMAC, 8);
            mac.update(calculatedMAC, 0, 16);
            mac.doFinal(calculatedMAC, 0);

            byte[] receivedMAC = Arrays.copyOfRange(input, inputOffset + ciphertextLength, inputOffset + inputLength);

            if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC))
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }

            if (ciphertextLength != cipher.processBytes(input, inputOffset, ciphertextLength, output, outputOffset))
            {
                throw new IllegalStateException();
            }

            return ciphertextLength;
        }
    }

    public int getOutputSize(int inputLength)
    {
        return isEncrypting ? inputLength + 16 : inputLength - 16;
    }

    public void init(byte[] nonce, int macSize, byte[] additionalData) throws IOException
    {
        if (nonce == null || nonce.length != 12 || macSize != 16)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        cipher.init(isEncrypting, new ParametersWithIV(null, nonce));
        initMAC();
        if (additionalData == null)
        {
            this.additionalDataLength = 0;
        }
        else
        {
            this.additionalDataLength = additionalData.length;
            updateMAC(additionalData, 0, additionalData.length);
        }
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        KeyParameter cipherKey = new KeyParameter(key, keyOff, keyLen);
        cipher.init(isEncrypting, new ParametersWithIV(cipherKey, ZEROES, 0, 12));
    }

    protected void initMAC()
    {
        byte[] firstBlock = new byte[64];
        cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        mac.init(new KeyParameter(firstBlock, 0, 32));
        Arrays.fill(firstBlock, (byte)0);
    }

    protected void updateMAC(byte[] buf, int off, int len)
    {
        mac.update(buf, off, len);

        int partial = len % 16;
        if (partial != 0)
        {
            mac.update(ZEROES, 0, 16 - partial);
        }
    }
}
