package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Pack;

/**
 * A generic TLS 1.0-1.2 block cipher. This can be used for AES or 3DES for example.
 */
public class TlsBlockCipher
    implements TlsCipher
{
    protected final TlsCryptoParameters cryptoParams;
    protected final byte[] randomData;
    protected final boolean encryptThenMAC;
    protected final boolean useExplicitIV;
    protected final boolean acceptExtraPadding;
    protected final boolean useExtraPadding;

    protected final TlsBlockCipherImpl decryptCipher, encryptCipher;
    protected final TlsSuiteMac readMac, writeMac;

    public TlsBlockCipher(TlsCryptoParameters cryptoParams, TlsBlockCipherImpl encryptCipher,
        TlsBlockCipherImpl decryptCipher, TlsHMAC clientMac, TlsHMAC serverMac, int cipherKeySize) throws IOException
    {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (TlsImplUtils.isTLSv13(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.cryptoParams = cryptoParams;
        this.randomData = cryptoParams.getNonceGenerator().generateNonce(256);

        this.encryptThenMAC = securityParameters.isEncryptThenMAC();
        this.useExplicitIV = TlsImplUtils.isTLSv11(negotiatedVersion);

        this.acceptExtraPadding = !negotiatedVersion.isSSL();

        /*
         * Don't use variable-length padding with truncated MACs.
         * 
         * See "Tag Size Does Matter: Attacks and Proofs for the TLS Record Protocol", Paterson,
         * Ristenpart, Shrimpton.
         *
         * TODO[DTLS] Consider supporting in DTLS (without exceeding send limit though)
         */
        this.useExtraPadding = securityParameters.isExtendedPadding()
            && ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(negotiatedVersion)
            && (encryptThenMAC || !securityParameters.isTruncatedHMac());

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        TlsBlockCipherImpl clientCipher, serverCipher;
        if (cryptoParams.isServer())
        {
            clientCipher = decryptCipher;
            serverCipher = encryptCipher;
        }
        else
        {
            clientCipher = encryptCipher;
            serverCipher = decryptCipher;
        }

        int key_block_size = (2 * cipherKeySize) + clientMac.getMacLength() + serverMac.getMacLength();

        // From TLS 1.1 onwards, block ciphers don't need IVs from the key_block
        if (!useExplicitIV)
        {
            key_block_size += clientCipher.getBlockSize() + serverCipher.getBlockSize();
        }

        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        clientMac.setKey(key_block, offset, clientMac.getMacLength());
        offset += clientMac.getMacLength();
        serverMac.setKey(key_block, offset, serverMac.getMacLength());
        offset += serverMac.getMacLength();

        clientCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        serverCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        int clientIVLength = clientCipher.getBlockSize();
        int serverIVLength = serverCipher.getBlockSize();

        if (useExplicitIV)
        {
            clientCipher.init(new byte[clientIVLength], 0, clientIVLength);
            serverCipher.init(new byte[serverIVLength], 0, serverIVLength);
        }
        else
        {
            clientCipher.init(key_block, offset, clientIVLength);
            offset += clientIVLength;
            serverCipher.init(key_block, offset, serverIVLength);
            offset += serverIVLength;
        }

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (cryptoParams.isServer())
        {
            this.writeMac = new TlsSuiteHMac(cryptoParams, serverMac);
            this.readMac = new TlsSuiteHMac(cryptoParams, clientMac);
        }
        else
        {
            this.writeMac = new TlsSuiteHMac(cryptoParams, clientMac);
            this.readMac = new TlsSuiteHMac(cryptoParams, serverMac);
        }
    }

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        int blockSize = decryptCipher.getBlockSize();
        int macSize = readMac.getSize();
        int maxPadding = 256;

        return getCiphertextLength(blockSize, macSize, maxPadding, plaintextLimit);
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();
        int maxPadding = useExtraPadding ? 256 : blockSize;

        return getCiphertextLength(blockSize, macSize, maxPadding, plaintextLength);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        int plaintextLimit = ciphertextLimit;

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

        // An explicit IV consumes 1 block
        if (useExplicitIV)
        {
            plaintextLimit -= blockSize;
        }

        return plaintextLimit;
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int offset, int len) throws IOException
    {
        int blockSize = encryptCipher.getBlockSize();
        int macSize = writeMac.getSize();

        int enc_input_length = len;
        if (!encryptThenMAC)
        {
            enc_input_length += macSize;
        }

        int padding_length = blockSize - (enc_input_length % blockSize);
        if (useExtraPadding)
        {
            // Add a random number of extra blocks worth of padding
            int maxExtraPadBlocks = (256 - padding_length) / blockSize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(maxExtraPadBlocks);
            padding_length += actualExtraPadBlocks * blockSize;
        }

        int totalSize = len + macSize + padding_length;
        if (useExplicitIV)
        {
            totalSize += blockSize;
        }

        byte[] outBuf = new byte[headerAllocation + totalSize];
        int outOff = headerAllocation;

        if (useExplicitIV)
        {
            // Technically the explicit IV will be the encryption of this nonce
            byte[] explicitIV = cryptoParams.getNonceGenerator().generateNonce(blockSize);
            System.arraycopy(explicitIV, 0, outBuf, outOff, blockSize);
            outOff += blockSize;
        }

        System.arraycopy(plaintext, offset, outBuf, outOff, len);
        outOff += len;

        if (!encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, contentType, plaintext, offset, len);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        byte padByte = (byte)(padding_length - 1);
        for (int i = 0; i < padding_length; ++i)
        {
            outBuf[outOff++] = padByte;
        }

        encryptCipher.doFinal(outBuf, headerAllocation, outOff - headerAllocation, outBuf, headerAllocation);

        if (encryptThenMAC)
        {
            byte[] mac = writeMac.calculateMac(seqNo, contentType, outBuf, headerAllocation, outOff - headerAllocation);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        if (outOff != outBuf.length)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return new TlsEncodeResult(outBuf, 0, outBuf.length, contentType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
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
            byte[] expectedMac = readMac.calculateMac(seqNo, recordType, ciphertext, offset, len - macSize);

            boolean badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext,
                offset + len - macSize);
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

        decryptCipher.doFinal(ciphertext, offset, blocks_length, ciphertext, offset);

        if (useExplicitIV)
        {
            offset += blockSize;
            blocks_length -= blockSize;
        }

        // If there's anything wrong with the padding, this will return zero
        int totalPad = checkPaddingConstantTime(ciphertext, offset, blocks_length, blockSize, encryptThenMAC ? 0 : macSize);
        boolean badMac = (totalPad == 0);

        int dec_output_length = blocks_length - totalPad;

        if (!encryptThenMAC)
        {
            dec_output_length -= macSize;

            byte[] expectedMac = readMac.calculateMacConstantTime(seqNo, recordType, ciphertext, offset,
                dec_output_length, blocks_length - macSize, randomData);

            badMac |= !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + dec_output_length);
        }

        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return new TlsDecodeResult(ciphertext, offset, dec_output_length, recordType);
    }

    public void rekeyDecoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
    
    public void rekeyEncoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean usesOpaqueRecordType()
    {
        return false;
    }

    protected int checkPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize)
    {
        int end = off + len;
        byte lastByte = buf[end - 1];
        int padlen = lastByte & 0xff;
        int totalPad = padlen + 1;

        int dummyIndex = 0;
        byte padDiff = 0;

        int totalPadLimit = Math.min(acceptExtraPadding ? 256 : blockSize, len - macSize);

        if (totalPad > totalPadLimit)
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

    protected int chooseExtraPadBlocks(int max)
    {
        byte[] random = cryptoParams.getNonceGenerator().generateNonce(4);
        int x = Pack.littleEndianToInt(random, 0);
        int n = lowestBitSet(x);
        return Math.min(n, max);
    }

    protected int getCiphertextLength(int blockSize, int macSize, int maxPadding, int plaintextLength)
    {
        int ciphertextLength = plaintextLength;

        // An explicit IV consumes 1 block
        if (useExplicitIV)
        {
            ciphertextLength += blockSize;
        }

        // Leave room for the MAC and (block-aligning) padding

        ciphertextLength += maxPadding;

        if (encryptThenMAC)
        {
            ciphertextLength -= (ciphertextLength % blockSize);
            ciphertextLength += macSize;
        }
        else
        {
            ciphertextLength += macSize;
            ciphertextLength -= (ciphertextLength % blockSize);
        }

        return ciphertextLength;
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
