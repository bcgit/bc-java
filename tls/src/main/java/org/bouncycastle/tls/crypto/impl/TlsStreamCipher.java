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
 * A generic TLS 1.0-1.2 stream cipher.
 */
public class TlsStreamCipher
    implements TlsCipher
{
    protected final TlsCryptoParameters cryptoParams;
    protected final TlsStreamCipherImpl decryptCipher, encryptCipher;
    protected final TlsSuiteMac readMac, writeMac;
    protected final boolean usesNonce;

    public TlsStreamCipher(TlsCryptoParameters cryptoParams, TlsStreamCipherImpl encryptCipher,
        TlsStreamCipherImpl decryptCipher, TlsHMAC clientMac, TlsHMAC serverMac, int cipherKeySize, boolean usesNonce)
        throws IOException
    {
        boolean isServer = cryptoParams.isServer();

        this.cryptoParams = cryptoParams;
        this.usesNonce = usesNonce;

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        TlsStreamCipherImpl clientCipher, serverCipher;
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

        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        // Init MACs
        clientMac.setKey(key_block, offset, clientMac.getMacLength());
        offset += clientMac.getMacLength();
        serverMac.setKey(key_block, offset, serverMac.getMacLength());
        offset += serverMac.getMacLength();

        // Build keys
        clientCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        serverCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] initialNonce = usesNonce ? new byte[8] : null;

        clientCipher.init(initialNonce);
        serverCipher.init(initialNonce);

        if (isServer)
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