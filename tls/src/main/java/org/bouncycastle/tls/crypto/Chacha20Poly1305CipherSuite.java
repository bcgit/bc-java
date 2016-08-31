package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * RFC 7905
 */
public class Chacha20Poly1305CipherSuite
    implements TlsCipherSuite
{
    private static final byte[] ZEROES = new byte[15];

    protected TlsContext context;

    protected TlsMAC writeMac;
    protected TlsMAC readMac;

    protected TlsStreamCipher encryptCipher, decryptCipher;
    protected byte[] encryptIV, decryptIV;

    public Chacha20Poly1305CipherSuite(TlsContext context, TlsStreamCipher encryptCipher, TlsStreamCipher decryptCipher,
                                       TlsMAC writeMac, TlsMAC readMac)
        throws IOException
    {
        if (!TlsUtils.isTLSv12(context))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.context = context;

        int cipherKeySize = 32;
        // TODO SecurityParameters.fixed_iv_length
        int fixed_iv_length = 12;
        // TODO SecurityParameters.record_iv_length = 0

        int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

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
        this.encryptCipher.setKey(decryptKey);
        this.decryptCipher.init(decryptIV);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - 16;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len) throws IOException
    {
        byte[] macKey = initRecord(encryptCipher, seqNo, encryptIV);

        writeMac.setKey(macKey);

        byte[] output = new byte[len + 16];
        encryptCipher.doFinal(plaintext, offset, len, output, 0);

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

        byte[] macKey = initRecord(decryptCipher, seqNo, decryptIV);

        readMac.setKey(macKey);

        int plaintextLength = len - 16;

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
        byte[] calculatedMAC = calculateRecordMAC(readMac, additionalData, ciphertext, offset, plaintextLength);
        byte[] receivedMAC = Arrays.copyOfRange(ciphertext, offset + plaintextLength, offset + len);

        if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        byte[] output = new byte[plaintextLength];
        decryptCipher.doFinal(ciphertext, offset, plaintextLength, output, 0);
        return output;
    }

    protected byte[] initRecord(TlsStreamCipher cipher, long seqNo, byte[] iv)
        throws IOException
    {
        byte[] nonce = calculateNonce(seqNo, iv);
        cipher.init(nonce);
        return generateRecordMACKey(cipher);
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

    protected byte[] generateRecordMACKey(TlsStreamCipher cipher)
        throws IOException
    {
        byte[] firstBlock = new byte[64];
        cipher.doFinal(firstBlock, 0, firstBlock.length, firstBlock, 0);

        byte[] macKey = Arrays.copyOfRange(firstBlock, 0, 32);
        Arrays.fill(firstBlock, (byte)0);
        return macKey;
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
