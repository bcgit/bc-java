package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

public class TlsStreamCipher
    implements TlsCipher
{
    protected TlsStreamOperator encryptCipher;
    protected TlsStreamOperator decryptCipher;

    protected TlsMac writeMac;
    protected TlsMac readMac;

    protected boolean usesNonce;

    public TlsStreamCipher(TlsContext context,
                           TlsStreamOperator encryptCipher, TlsStreamOperator decryptCipher,
                           TlsMac clientWriteMac, TlsMac serverWriteMac,
                           int cipherKeySize, int macKeySize, boolean usesNonce)
        throws IOException
    {
        boolean isServer = context.isServer();

        this.usesNonce = usesNonce;

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        int key_block_size = (2 * cipherKeySize) + macKeySize
            + macKeySize;

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        // Init MACs
        byte[] clientMacKey = Arrays.copyOfRange(key_block, offset, offset + macKeySize);
        offset += macKeySize;
        byte[] serverMacKey = Arrays.copyOfRange(key_block, offset, offset + macKeySize);
        offset += macKeySize;

        clientWriteMac.setKey(clientMacKey);
        serverWriteMac.setKey(serverMacKey);

        // Build keys
        byte[] clientWriteKey = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] serverWriteKey = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (isServer)
        {
            this.writeMac = serverWriteMac;
            this.readMac = clientWriteMac;
            this.encryptCipher.setKey(serverWriteKey);
            this.decryptCipher.setKey(clientWriteKey);
        }
        else
        {
            this.writeMac = clientWriteMac;
            this.readMac = serverWriteMac;
            this.encryptCipher.setKey(clientWriteKey);
            this.decryptCipher.setKey(serverWriteKey);
        }

        if (usesNonce)
        {
            byte[] dummyNonce = new byte[8];
            this.encryptCipher.init(dummyNonce);
            this.encryptCipher.init(dummyNonce);
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
            updateIV(encryptCipher, seqNo);
        }

        byte[] outBuf = new byte[len + writeMac.getSize()];
        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);

        System.arraycopy(plaintext, offset, outBuf, 0, len);
        System.arraycopy(mac, 0, outBuf, len, mac.length);

        encryptCipher.doFinal(outBuf, 0, len, outBuf, 0);

        return outBuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        if (usesNonce)
        {
            updateIV(decryptCipher, seqNo);
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

    protected void updateIV(TlsStreamOperator cipher, long seqNo)
        throws IOException
    {
        byte[] nonce = new byte[8];
        TlsUtils.writeUint64(seqNo, nonce, 0);
        cipher.init(nonce);
    }
}
