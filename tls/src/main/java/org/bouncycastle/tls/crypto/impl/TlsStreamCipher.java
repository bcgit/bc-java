package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.0-1.2 / SSLv3 stream cipher.
 */
public class TlsStreamCipher
    implements TlsCipher
{
    protected TlsCryptoParameters cryptoParams;

    protected TlsStreamCipherImpl encryptCipher;
    protected TlsStreamCipherImpl decryptCipher;

    protected TlsSuiteMac writeMac;
    protected TlsSuiteMac readMac;

    protected boolean usesNonce;

    public TlsStreamCipher(TlsCryptoParameters cryptoParams, TlsStreamCipherImpl encryptCipher,
                                TlsStreamCipherImpl decryptCipher, TlsHMAC clientWriteDigest, TlsHMAC serverWriteDigest,
                                int cipherKeySize, boolean usesNonce) throws IOException
    {
        boolean isServer = cryptoParams.isServer();

        this.cryptoParams = cryptoParams;
        this.usesNonce = usesNonce;

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        int key_block_size = (2 * cipherKeySize) + clientWriteDigest.getMacLength()
            + serverWriteDigest.getMacLength();

        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        // Init MACs
        TlsSuiteMac clientWriteMac = new TlsSuiteHMac(cryptoParams, clientWriteDigest);
        clientWriteMac.setKey(Arrays.copyOfRange(key_block, offset, offset + clientWriteDigest.getMacLength()));
        offset += clientWriteDigest.getMacLength();
        TlsSuiteMac serverWriteMac = new TlsSuiteHMac(cryptoParams, serverWriteDigest);
        serverWriteMac.setKey(Arrays.copyOfRange(key_block, offset, offset + serverWriteDigest.getMacLength()));
        offset += serverWriteDigest.getMacLength();

        // Build keys
        byte[] clientWriteKey = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] serverWriteKey = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] encryptParams, decryptParams;
        if (isServer)
        {
            this.writeMac = serverWriteMac;
            this.readMac = clientWriteMac;
            encryptParams = serverWriteKey;
            decryptParams = clientWriteKey;
        }
        else
        {
            this.writeMac = clientWriteMac;
            this.readMac = serverWriteMac;
            encryptParams = clientWriteKey;
            decryptParams = serverWriteKey;
        }

        this.encryptCipher.setKey(encryptParams);
        this.decryptCipher.setKey(decryptParams);
        if (usesNonce)
        {
            byte[] dummyNonce = new byte[8];
            this.encryptCipher.init(dummyNonce);
            this.decryptCipher.init(dummyNonce);
        }
        else
        {
            this.encryptCipher.init(null);
            this.decryptCipher.init(null);
        }
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
    {
        if (usesNonce)
        {
            updateIV(encryptCipher, true, seqNo);
        }

        byte[] outBuf = new byte[len + writeMac.getSize()];
        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);

        System.arraycopy(plaintext, offset, outBuf, 0, len);
        System.arraycopy(mac, 0, outBuf, len, mac.length);

        encryptCipher.doFinal(outBuf, 0, outBuf.length, outBuf, 0);

        return outBuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        if (usesNonce)
        {
            updateIV(decryptCipher, false, seqNo);
        }

        int macSize = readMac.getSize();
        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int plaintextLength = len - macSize;

        byte[] deciphered = new byte[len];
        decryptCipher.doFinal(ciphertext, offset, len, deciphered, 0);
        checkMAC(seqNo, type, deciphered, plaintextLength, len, deciphered, 0, plaintextLength);
        return Arrays.copyOfRange(deciphered, 0, plaintextLength);
    }

    protected void checkMAC(long seqNo, short type, byte[] recBuf, int recStart, int recEnd, byte[] calcBuf, int calcOff, int calcLen)
        throws IOException
    {
        byte[] receivedMac = Arrays.copyOfRange(recBuf, recStart, recEnd);
        byte[] computedMac = readMac.calculateMac(seqNo, type, calcBuf, calcOff, calcLen);

        if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }
    }

    protected void updateIV(org.bouncycastle.tls.crypto.impl.TlsStreamCipherImpl cipher, boolean forEncryption, long seqNo)
        throws IOException
    {
        byte[] nonce = new byte[8];
        TlsUtils.writeUint64(seqNo, nonce, 0);
        cipher.init(nonce);
    }
}