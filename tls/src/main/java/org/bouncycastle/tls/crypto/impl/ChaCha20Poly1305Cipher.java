package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Cipher suite specified in RFC 7905 using ChaCha20 and Poly1305.
 */
public class ChaCha20Poly1305Cipher
    implements TlsCipher
{
    private static final byte[] ZEROES = new byte[15];

    protected TlsCryptoParameters context;

    protected TlsMAC writeMac;
    protected TlsMAC readMac;

    protected TlsStreamCipherImpl encryptCipher;
    protected TlsStreamCipherImpl decryptCipher;

    protected byte[] encryptIV, decryptIV;

    public ChaCha20Poly1305Cipher(TlsCryptoParameters context, TlsStreamCipherImpl encryptCipher, TlsStreamCipherImpl decryptCipher,
                                       TlsMAC writeMac, TlsMAC readMac)
        throws IOException
    {
        if (!TlsImplUtils.isTLSv12(context))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.context = context;

        int cipherKeySize = 32;
        // TODO SecurityParameters.fixed_iv_length
        int fixed_iv_length = 12;
        // TODO SecurityParameters.record_iv_length = 0

        int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

        byte[] key_block = TlsImplUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        byte[] client_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] server_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] client_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;
        byte[] server_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.writeMac = writeMac;
        this.readMac = readMac;
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        byte[] encryptKey, decryptKey;
        if (context.isServer())
        {
            encryptKey = server_write_key;
            decryptKey = client_write_key;
            this.encryptIV = server_write_IV;
            this.decryptIV = client_write_IV;
        }
        else
        {
            encryptKey = client_write_key;
            decryptKey = server_write_key;
            this.encryptIV = client_write_IV;
            this.decryptIV = server_write_IV;
        }

        this.encryptCipher.setKey(encryptKey);
        this.encryptCipher.init(encryptIV);
        this.decryptCipher.setKey(decryptKey);
        this.decryptCipher.init(decryptIV);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - 16;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len) throws IOException
    {
        initRecord(encryptCipher, seqNo, encryptIV);

        // MAC key is from the zeros at the front.
        byte[] cipherOut = new byte[64 + len];
        System.arraycopy(plaintext, offset, cipherOut, 64, len);

        encryptCipher.doFinal(cipherOut, 0, cipherOut.length, cipherOut, 0);

        byte[] output = new byte[len + 16];
        byte[] macKey = Arrays.copyOfRange(cipherOut, 0, 32);
        System.arraycopy(cipherOut, 64, output, 0, len);

        Arrays.fill(cipherOut, (byte)0);

        writeMac.setKey(macKey);

        byte[] additionalData = getAdditionalData(seqNo, type, len);
        byte[] mac = calculateRecordMAC(writeMac, additionalData, output, 0, len);
        System.arraycopy(mac, 0, output, len, mac.length);

        return output;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len) throws IOException
    {
        if (getPlaintextLimit(len) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        initRecord(decryptCipher, seqNo, decryptIV);
        int plaintextLength = len - 16;

        // MAC key is from the zeros at the front.
        byte[] cipherOut = new byte[64 + plaintextLength];
        System.arraycopy(ciphertext, offset, cipherOut, 64, plaintextLength);

        decryptCipher.doFinal(cipherOut, 0, cipherOut.length, cipherOut, 0);

        byte[] macKey = Arrays.copyOfRange(cipherOut, 0, 32);
        readMac.setKey(macKey);

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
        byte[] calculatedMAC = calculateRecordMAC(readMac, additionalData, ciphertext, offset, plaintextLength);
        byte[] receivedMAC = Arrays.copyOfRange(ciphertext, offset + plaintextLength, offset + len);
        byte[] output = new byte[plaintextLength];

        System.arraycopy(cipherOut, 64, output, 0, plaintextLength);

        Arrays.fill(cipherOut, (byte)0);

        if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return output;
    }

    protected void initRecord(TlsStreamCipherImpl cipher, long seqNo, byte[] iv)
        throws IOException
    {
        byte[] nonce = calculateNonce(seqNo, iv);
        cipher.init(nonce);
    }

    protected byte[] calculateNonce(long seqNo, byte[] iv)
    {
        byte[] nonce = new byte[12];
        TlsUtils.writeUint64(seqNo, nonce, 4);

        for (int i = 0; i < 12; ++i)
        {
            nonce[i] ^= iv[i];
        }

        return nonce;
    }

    protected byte[] calculateRecordMAC(TlsMAC mac, byte[] additionalData, byte[] buf, int off, int len)
    {
        updateRecordMACText(mac, additionalData, 0, additionalData.length);
        updateRecordMACText(mac, buf, off, len);
        updateRecordMACLength(mac, additionalData.length);
        updateRecordMACLength(mac, len);

        return mac.calculateMAC();
    }

    protected void updateRecordMACLength(TlsMAC mac, int len)
    {
        byte[] longLen = Pack.longToLittleEndian(len & 0xFFFFFFFFL);
        mac.update(longLen, 0, longLen.length);
    }

    protected void updateRecordMACText(TlsMAC mac, byte[] buf, int off, int len)
    {
        mac.update(buf, off, len);

        int partial = len % 16;
        if (partial != 0)
        {
            mac.update(ZEROES, 0, 16 - partial);
        }
    }

    protected byte[] getAdditionalData(long seqNo, short type, int len) throws IOException
    {
        /*
         * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
         * TLSCompressed.length
         */
        byte[] additional_data = new byte[13];
        TlsUtils.writeUint64(seqNo, additional_data, 0);
        TlsUtils.writeUint8(type, additional_data, 8);
        TlsUtils.writeVersion(context.getServerVersion(), additional_data, 9);
        TlsUtils.writeUint16(len, additional_data, 11);

        return additional_data;
    }
}
