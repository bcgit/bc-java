package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Pack;

public class JceChaCha20Poly1305 implements TlsAEADCipherImpl
{
    private static final int BUF_SIZE = 32 * 1024;
    private static final byte[] ZEROES = new byte[15];

    protected final Cipher cipher;
    protected final Mac mac;
    protected final int cipherMode;

    protected SecretKey cipherKey;
    protected byte[] additionalData;

    public JceChaCha20Poly1305(JcaJceHelper helper, boolean isEncrypting) throws GeneralSecurityException
    {
        this.cipher = helper.createCipher("ChaCha7539");
        this.mac = helper.createMac("Poly1305");
        this.cipherMode = isEncrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] extraInput, byte[] output,
        int outputOffset) throws IOException
    {
        /*
         * NOTE: When using the Cipher class, output may be buffered prior to calling doFinal, so
         * getting the MAC key from the first block of cipher output reliably is awkward. We are
         * forced to use a temp buffer and extra copies to make it work. In the case of decryption
         * it has the additional downside that full decryption is performed before we are able to
         * check the MAC.
         */
        try
        {
            int extraInputLength = extraInput.length;

            if (cipherMode == Cipher.ENCRYPT_MODE)
            {
                int ciphertextLength = inputLength + extraInputLength;

                byte[] tmp = new byte[64 + ciphertextLength];
                System.arraycopy(input, inputOffset, tmp, 64, inputLength);
                System.arraycopy(extraInput, 0, tmp, 64 + inputLength, extraInputLength);

                runCipher(tmp);

                System.arraycopy(tmp, 64, output, outputOffset, ciphertextLength);

                initMAC(tmp);
                updateMAC(additionalData, 0, additionalData.length);
                updateMAC(tmp, 64, ciphertextLength);

                byte[] lengths = new byte[16];
                Pack.longToLittleEndian(additionalData.length & 0xFFFFFFFFL, lengths, 0);
                Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, lengths, 8);
                mac.update(lengths, 0, 16);

                mac.doFinal(output, outputOffset + ciphertextLength);

                return ciphertextLength + 16;
            }
            else
            {
                if (extraInputLength > 0)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                int ciphertextLength = inputLength - 16;

                byte[] tmp = new byte[64 + ciphertextLength];
                System.arraycopy(input, inputOffset, tmp, 64, ciphertextLength);

                runCipher(tmp);

                initMAC(tmp);
                updateMAC(additionalData, 0, additionalData.length);
                updateMAC(input, inputOffset, ciphertextLength);

                byte[] expectedMac = new byte[16];
                Pack.longToLittleEndian(additionalData.length & 0xFFFFFFFFL, expectedMac, 0);
                Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, expectedMac, 8);
                mac.update(expectedMac, 0, 16);
                mac.doFinal(expectedMac, 0);

                boolean badMac = !TlsUtils.constantTimeAreEqual(16, expectedMac, 0, input,
                    inputOffset + ciphertextLength);
                if (badMac)
                {
                    throw new TlsFatalAlert(AlertDescription.bad_record_mac);
                }

                System.arraycopy(tmp, 64, output, outputOffset, ciphertextLength);

                return ciphertextLength;
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException(e);
        }
    }

    public int getOutputSize(int inputLength)
    {
        return cipherMode == Cipher.ENCRYPT_MODE ? inputLength + 16 : inputLength - 16;
    }

    public void init(byte[] nonce, int macSize, byte[] additionalData) throws IOException
    {
        if (nonce == null || nonce.length != 12 || macSize != 16)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
            cipher.init(cipherMode, cipherKey, new IvParameterSpec(nonce));
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException(e);
        }

        this.additionalData = additionalData;
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        this.cipherKey = new SecretKeySpec(key, keyOff, keyLen, "ChaCha7539");
    }

    protected void initMAC(byte[] firstBlock) throws InvalidKeyException
    {
        mac.init(new SecretKeySpec(firstBlock, 0, 32, "Poly1305"));

        for (int i = 0; i < 64; ++i)
        {
            firstBlock[i] = 0;
        }
    }

    protected void runCipher(byte[] buf) throws GeneralSecurityException
    {
        // to avoid performance issue in FIPS jar 1.0.0-1.0.2, process in chunks
        int readOff = 0, writeOff = 0;
        while (readOff < buf.length)
        {
            int updateSize = Math.min(BUF_SIZE, buf.length - readOff);
            writeOff += cipher.update(buf, readOff, updateSize, buf, writeOff);
            readOff += updateSize;
        }

        writeOff += cipher.doFinal(buf, writeOff);

        if (buf.length != writeOff)
        {
            throw new IllegalStateException();
        }
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
