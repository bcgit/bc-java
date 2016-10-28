package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.0-1.2 / SSLv3 block cipher. This can be used for AES or 3DES for example.
 */
public class TlsBlockCipher
    implements TlsCipher
{
    protected TlsCryptoParameters cryptoParams;
    private final TlsCrypto crypto;
    protected byte[] randomData;
    protected boolean useExplicitIV;
    protected boolean encryptThenMAC;

    protected TlsBlockCipherImpl encryptCipher;
    protected TlsBlockCipherImpl decryptCipher;

    protected TlsSuiteMac writeMac;
    protected TlsSuiteMac readMac;

    public TlsBlockCipher(TlsCrypto crypto, TlsCryptoParameters cryptoParams, TlsBlockCipherImpl encryptCipher, TlsBlockCipherImpl decryptCipher,
                               TlsHMAC writeMac, TlsHMAC readMac, int cipherKeySize)
        throws IOException
    {
        this.cryptoParams = cryptoParams;
        this.crypto = crypto;
        this.randomData = crypto.createNonce(256);

        this.useExplicitIV = TlsImplUtils.isTLSv11(cryptoParams);
        this.encryptThenMAC = cryptoParams.getSecurityParameters().isEncryptThenMAC();

        int key_block_size = (2 * cipherKeySize) + writeMac.getMacLength() + readMac.getMacLength();

        // From TLS 1.1 onwards, block ciphers don't need client_write_IV
        if (!useExplicitIV)
        {
            key_block_size += encryptCipher.getBlockSize() + decryptCipher.getBlockSize();
        }

        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        byte[] clientMacKey = Arrays.copyOfRange(key_block, offset, offset + writeMac.getMacLength());
        offset += clientMacKey.length;
        byte[] serverMacKey = Arrays.copyOfRange(key_block, offset, offset + writeMac.getMacLength());
        offset += serverMacKey.length;

        byte[] client_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] server_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;

        byte[] server_IV, client_IV;

        if (useExplicitIV)
        {
            client_IV = new byte[encryptCipher.getBlockSize()];
            server_IV = new byte[encryptCipher.getBlockSize()];
        }
        else
        {
            client_IV = Arrays.copyOfRange(key_block, offset, offset + encryptCipher.getBlockSize());
            offset += encryptCipher.getBlockSize();
            server_IV = Arrays.copyOfRange(key_block, offset, offset + encryptCipher.getBlockSize());
            offset += encryptCipher.getBlockSize();
        }

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.readMac = new TlsSuiteHMac(cryptoParams, readMac);
        this.writeMac = new TlsSuiteHMac(cryptoParams, writeMac);
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        if (cryptoParams.isServer())
        {
            this.writeMac.setKey(serverMacKey);
            this.readMac.setKey(clientMacKey);

            this.encryptCipher.setKey(server_write_key);
            this.decryptCipher.setKey(client_write_key);
            this.encryptCipher.init(server_IV);
            this.decryptCipher.init(client_IV);
        }
        else
        {
            this.writeMac.setKey(clientMacKey);
            this.readMac.setKey(serverMacKey);

            this.encryptCipher.setKey(client_write_key);
            this.decryptCipher.setKey(server_write_key);
            this.encryptCipher.init(client_IV);
            this.decryptCipher.init(server_IV);
        }
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        int plaintextLimit = ciphertextLimit;

        // An explicit IV consumes 1 block
        if (useExplicitIV)
        {
            plaintextLimit -= blockSize;
        }

        // Leave room for the MAC, and require block-alignment
        if (encryptThenMAC)
        {
            plaintextLimit -= macSize;
            plaintextLimit -= plaintextLimit % blockSize;
        }
        else
        {
            plaintextLimit -= plaintextLimit % blockSize;
            plaintextLimit -= macSize;
        }

        // Minimum 1 byte of padding
        --plaintextLimit;

        return plaintextLimit;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        ProtocolVersion version = cryptoParams.getServerVersion();

        int enc_input_length = len;
        if (!encryptThenMAC)
        {
            enc_input_length += macSize;
        }

        int padding_length = blockSize - 1 - (enc_input_length % blockSize);

        // TODO[DTLS] Consider supporting in DTLS (without exceeding send limit though)
        if (!version.isDTLS() && !version.isSSL())
        {
            // Add a random number of extra blocks worth of padding
            int maxExtraPadBlocks = (255 - padding_length) / blockSize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(crypto.getSecureRandom(), maxExtraPadBlocks);
            padding_length += actualExtraPadBlocks * blockSize;
        }

        int totalSize = len + macSize + padding_length + 1;
        if (useExplicitIV)
        {
            totalSize += blockSize;
        }

        byte[] outBuf = new byte[totalSize];
        int outOff = 0;

        if (useExplicitIV)
        {
            byte[] explicitIV = crypto.createNonce(blockSize);

            encryptCipher.init(explicitIV);

            System.arraycopy(explicitIV, 0, outBuf, outOff, blockSize);
            outOff += blockSize;
        }

        int blocks_start = outOff;

        System.arraycopy(plaintext, offset, outBuf, outOff, len);
        outOff += len;

        if (!encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        for (int i = 0; i <= padding_length; i++)
        {
            outBuf[outOff++] = (byte)padding_length;
        }

        encryptCipher.doFinal(outBuf, blocks_start, outOff - blocks_start, outBuf, blocks_start);

        if (encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, type, outBuf, 0, outOff);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

//        assert outBuf.length == outOff;
        return outBuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int blockSize = decryptCipher.getBlockSize();
        int macSize = readMac.getSize();

        int minLen = blockSize;
        if (encryptThenMAC)
        {
            minLen += macSize;
        }
        else
        {
            minLen = Math.max(minLen, macSize + 1);
        }

        if (useExplicitIV)
        {
            minLen += blockSize;
        }

        if (len < minLen)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int blocks_length = len;
        if (encryptThenMAC)
        {
            blocks_length -= macSize;
        }

        if (blocks_length % blockSize != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decryption_failed);
        }

        if (encryptThenMAC)
        {
            int end = offset + len;
            byte[] receivedMac = Arrays.copyOfRange(ciphertext, end - macSize, end);
            byte[] calculatedMac = readMac.calculateMac(seqNo, type, ciphertext, offset, len - macSize);

            boolean badMac = !Arrays.constantTimeAreEqual(calculatedMac, receivedMac);
            if (badMac)
            {
                /*
                 * RFC 7366 3. The MAC SHALL be evaluated before any further processing such as
                 * decryption is performed, and if the MAC verification fails, then processing SHALL
                 * terminate immediately. For TLS, a fatal bad_record_mac MUST be generated [2]. For
                 * DTLS, the record MUST be discarded, and a fatal bad_record_mac MAY be generated
                 * [4]. This immediate response to a bad MAC eliminates any timing channels that may
                 * be available through the use of manipulated packet data.
                 */
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }
        }

        if (useExplicitIV)
        {
            decryptCipher.init(Arrays.copyOfRange(ciphertext, offset, offset + blockSize));

            offset += blockSize;
            blocks_length -= blockSize;
        }

        decryptCipher.doFinal(ciphertext, offset, blocks_length, ciphertext, offset);

        // If there's anything wrong with the padding, this will return zero
        int totalPad = checkPaddingConstantTime(ciphertext, offset, blocks_length, blockSize, encryptThenMAC ? 0 : macSize);
        boolean badMac = (totalPad == 0);

        int dec_output_length = blocks_length - totalPad;

        if (!encryptThenMAC)
        {
            dec_output_length -= macSize;
            int macInputLen = dec_output_length;
            int macOff = offset + macInputLen;
            byte[] receivedMac = Arrays.copyOfRange(ciphertext, macOff, macOff + macSize);
            byte[] calculatedMac = readMac.calculateMacConstantTime(seqNo, type, ciphertext, offset, macInputLen,
                blocks_length - macSize, randomData);

            badMac |= !Arrays.constantTimeAreEqual(calculatedMac, receivedMac);
        }

        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return Arrays.copyOfRange(ciphertext, offset, offset + dec_output_length);
    }

    protected int checkPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize)
    {
        int end = off + len;
        byte lastByte = buf[end - 1];
        int padlen = lastByte & 0xff;
        int totalPad = padlen + 1;

        int dummyIndex = 0;
        byte padDiff = 0;

        if ((TlsImplUtils.isSSL(cryptoParams) && totalPad > blockSize) || (macSize + totalPad > len))
        {
            totalPad = 0;
        }
        else
        {
            int padPos = end - totalPad;
            do
            {
                padDiff |= (buf[padPos++] ^ lastByte);
            }
            while (padPos < end);

            dummyIndex = totalPad;

            if (padDiff != 0)
            {
                totalPad = 0;
            }
        }

        // Run some extra dummy checks so the number of checks is always constant
        {
            byte[] dummyPad = randomData;
            while (dummyIndex < 256)
            {
                padDiff |= (dummyPad[dummyIndex++] ^ lastByte);
            }
            // Ensure the above loop is not eliminated
            dummyPad[0] ^= padDiff;
        }

        return totalPad;
    }

    protected int chooseExtraPadBlocks(SecureRandom r, int max)
    {
        // return r.nextInt(max + 1);

        int x = r.nextInt();
        int n = lowestBitSet(x);
        return Math.min(n, max);
    }

    protected int lowestBitSet(int x)
    {
        if (x == 0)
        {
            return 32;
        }

        int n = 0;
        while ((x & 1) == 0)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }
}
