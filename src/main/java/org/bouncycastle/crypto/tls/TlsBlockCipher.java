package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.0-1.1 / SSLv3 block cipher.
 * This can be used for AES or 3DES for example.
 */
public class TlsBlockCipher implements TlsCipher
{
    protected TlsContext context;
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

    public TlsBlockCipher(TlsContext context, BlockCipher encryptCipher,
        BlockCipher decryptCipher, Digest writeDigest, Digest readDigest, int cipherKeySize)
    {
        boolean isServer = context.isServer();

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
        TlsMac clientWriteMac = new TlsMac(context, writeDigest, key_block, offset, writeDigest.getDigestSize());
        offset += writeDigest.getDigestSize();
        TlsMac serverWriteMac = new TlsMac(context, readDigest, key_block, offset, readDigest.getDigestSize());
        offset += readDigest.getDigestSize();

        BlockCipher clientWriteCipher, serverWriteCipher;
        if (isServer)
        {
            writeMac = serverWriteMac;
            readMac = clientWriteMac;
            clientWriteCipher = decryptCipher;
            serverWriteCipher = encryptCipher;
        }
        else
        {
            writeMac = clientWriteMac;
            readMac = serverWriteMac;
            clientWriteCipher = encryptCipher;
            serverWriteCipher = decryptCipher;
        }

        // Init Ciphers
        int key_offset = offset;
        int iv_offset = key_offset + (cipherKeySize * 2);
        this.initCipher(!isServer, clientWriteCipher, key_block, cipherKeySize, key_offset, iv_offset);
        key_offset += cipherKeySize;
        iv_offset += clientWriteCipher.getBlockSize();
        this.initCipher(isServer, serverWriteCipher, key_block, cipherKeySize, key_offset, iv_offset);
    }

    protected void initCipher(boolean forEncryption, BlockCipher cipher, byte[] key_block,
        int key_size, int key_offset, int iv_offset)
    {
        KeyParameter key_parameter = new KeyParameter(key_block, key_offset, key_size);
        ParametersWithIV parameters_with_iv = new ParametersWithIV(key_parameter, key_block,
            iv_offset, cipher.getBlockSize());
        cipher.init(forEncryption, parameters_with_iv);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        ProtocolVersion version = context.getServerVersion();
        boolean useExplicitIV = !version.isSSL() && !version.equals(ProtocolVersion.TLSv10);

        int result = ciphertextLimit - (ciphertextLimit % blockSize) - macSize - 1;
        if (useExplicitIV)
        {
            result -= blockSize;
        }
        
        return result;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        ProtocolVersion version = context.getServerVersion();

        int padding_length = blockSize - 1 - ((len + macSize) % blockSize);

        // TODO[DTLS] Consider supporting in DTLS (without exceeding send limit though)
        if (version.isTLS())
        {
            // Add a random number of extra blocks worth of padding
            int maxExtraPadBlocks = (255 - padding_length) / blockSize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(context.getSecureRandom(), maxExtraPadBlocks);
            padding_length += actualExtraPadBlocks * blockSize;
        }

        boolean useExplicitIV = !version.isSSL() && !version.equals(ProtocolVersion.TLSv10);

        int totalSize = len + macSize + padding_length + 1;
        if (useExplicitIV)
        {
            totalSize += blockSize;
        }

        byte[] outbuf = new byte[totalSize];
        int outOff = 0;

        if (useExplicitIV)
        {
	    byte[] explicitIV = new byte[blockSize];
	    context.getSecureRandom().nextBytes(explicitIV);

	    encryptCipher.init(true, new ParametersWithIV(null, explicitIV));

	    System.arraycopy(explicitIV, 0, outbuf, outOff, blockSize);
	    outOff += blockSize;
        }

        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);

        System.arraycopy(plaintext, offset, outbuf, outOff, len);
        System.arraycopy(mac, 0, outbuf, outOff + len, mac.length);

        int padOffset = outOff + len + mac.length;
        for (int i = 0; i <= padding_length; i++)
        {
            outbuf[i + padOffset] = (byte)padding_length;
        }
        for (int i = outOff; i < totalSize; i += blockSize)
        {
            encryptCipher.processBlock(outbuf, i, outbuf, i);
        }
        return outbuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int blockSize = decryptCipher.getBlockSize();
        int macSize = readMac.getSize();

        ProtocolVersion version = context.getServerVersion();
        boolean expectExplicitIV = !version.isSSL() && !version.equals(ProtocolVersion.TLSv10);

        int minLen = Math.max(blockSize, macSize + 1);
        if (expectExplicitIV)
        {
            minLen += blockSize;
        }

        if (len < minLen)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        if (len % blockSize != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decryption_failed);
        }

        if (expectExplicitIV)
        {
            decryptCipher.init(false, new ParametersWithIV(null, ciphertext, offset, blockSize));

            offset += blockSize;
            len -= blockSize;
        }

        for (int i = 0; i < len; i += blockSize)
        {
            decryptCipher.processBlock(ciphertext, offset + i, ciphertext, offset + i);
        }

        // If there's anything wrong with the padding, this will return zero
        int totalPad = checkPaddingConstantTime(ciphertext, offset, len, blockSize, macSize);

        int macInputLen = len - totalPad - macSize;

        byte[] decryptedMac = Arrays.copyOfRange(ciphertext, offset + macInputLen, offset + macInputLen + macSize);
        byte[] calculatedMac = readMac.calculateMacConstantTime(seqNo, type, ciphertext, offset, macInputLen, len - macSize, randomData);

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

        if ((context.getServerVersion().isSSL() && totalPad > blockSize) || (macSize + totalPad > len))
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