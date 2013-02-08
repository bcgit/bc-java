package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.0 / SSLv3 block cipher.
 * This can be used for AES or 3DES for example.
 */
public class TlsBlockCipher implements TlsCipher
{
    protected TlsClientContext context;
    protected byte[] randomData;

    protected BlockCipher encryptCipher;
    protected BlockCipher decryptCipher;

    protected TlsMac writeMac;
    protected TlsMac readMac;

    public TlsMac getWriteMac()
    {
        return writeMac;
    }

    public TlsMac getReadMac()
    {
        return readMac;
    }

    public TlsBlockCipher(TlsClientContext context, BlockCipher encryptCipher,
        BlockCipher decryptCipher, Digest writeDigest, Digest readDigest, int cipherKeySize)
    {
        this.context = context;

        this.randomData = new byte[256];
        context.getSecureRandom().nextBytes(randomData);

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        int key_block_size = (2 * cipherKeySize) + writeDigest.getDigestSize()
            + readDigest.getDigestSize() + encryptCipher.getBlockSize()
            + decryptCipher.getBlockSize();

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        // Init MACs
        writeMac = new TlsMac(context, writeDigest, key_block, offset, writeDigest.getDigestSize());
        offset += writeDigest.getDigestSize();
        readMac = new TlsMac(context, readDigest, key_block, offset, readDigest.getDigestSize());
        offset += readDigest.getDigestSize();

        // Init Ciphers
        this.initCipher(true, encryptCipher, key_block, cipherKeySize, offset, offset
            + (cipherKeySize * 2));
        offset += cipherKeySize;
        this.initCipher(false, decryptCipher, key_block, cipherKeySize, offset, offset
            + cipherKeySize + encryptCipher.getBlockSize());
    }

    protected void initCipher(boolean forEncryption, BlockCipher cipher, byte[] key_block,
        int key_size, int key_offset, int iv_offset)
    {
        KeyParameter key_parameter = new KeyParameter(key_block, key_offset, key_size);
        ParametersWithIV parameters_with_iv = new ParametersWithIV(key_parameter, key_block,
            iv_offset, cipher.getBlockSize());
        cipher.init(forEncryption, parameters_with_iv);
    }

    public byte[] encodePlaintext(short type, byte[] plaintext, int offset, int len)
    {
        int blocksize = encryptCipher.getBlockSize();
        int padding_length = blocksize - 1 - ((len + writeMac.getSize()) % blocksize);

        boolean isTls = context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();

        if (isTls)
        {
            // Add a random number of extra blocks worth of padding
            int maxExtraPadBlocks = (255 - padding_length) / blocksize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(context.getSecureRandom(), maxExtraPadBlocks);
            padding_length += actualExtraPadBlocks * blocksize;
        }

        int totalsize = len + writeMac.getSize() + padding_length + 1;
        byte[] outbuf = new byte[totalsize];
        System.arraycopy(plaintext, offset, outbuf, 0, len);
        byte[] mac = writeMac.calculateMac(type, plaintext, offset, len);
        System.arraycopy(mac, 0, outbuf, len, mac.length);
        int paddoffset = len + mac.length;
        for (int i = 0; i <= padding_length; i++)
        {
            outbuf[i + paddoffset] = (byte)padding_length;
        }
        for (int i = 0; i < totalsize; i += blocksize)
        {
            encryptCipher.processBlock(outbuf, i, outbuf, i);
        }
        return outbuf;
    }

    public byte[] decodeCiphertext(short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int blockSize = decryptCipher.getBlockSize();
        int macSize = readMac.getSize();

        /*
         *  TODO[TLS 1.1] Explicit IV implies minLen = blockSize + max(blockSize, macSize + 1),
         *  and will need further changes to offset and plen variables below.
         */

        int minLen = Math.max(blockSize, macSize + 1);
        if (len < minLen)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        if (len % blockSize != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decryption_failed);
        }

        for (int i = 0; i < len; i += blockSize)
        {
            decryptCipher.processBlock(ciphertext, offset + i, ciphertext, offset + i);
        }

        int plen = len;

        // If there's anything wrong with the padding, this will return zero
        int totalPad = checkPaddingConstantTime(ciphertext, offset, plen, blockSize, macSize);

        int macInputLen = plen - totalPad - macSize;

        byte[] decryptedMac = Arrays.copyOfRange(ciphertext, offset + macInputLen, offset + macInputLen + macSize);
        byte[] calculatedMac = readMac.calculateMacConstantTime(type, ciphertext, offset, macInputLen, plen - macSize, randomData);

        boolean badMac = !Arrays.constantTimeAreEqual(calculatedMac, decryptedMac);

        if (badMac || totalPad == 0)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return Arrays.copyOfRange(ciphertext, offset, offset + macInputLen);
    }

    protected int checkPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize)
    {
        int end = off + len;
        byte lastByte = buf[end - 1];
        int padlen = lastByte & 0xff;
        int totalPad = padlen + 1;

        int dummyIndex = 0;
        byte padDiff = 0;

        boolean isTls = context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();

        if ((!isTls && totalPad > blockSize) || (macSize + totalPad > len))
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
//        return r.nextInt(max + 1);

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