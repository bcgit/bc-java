package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.util.Arrays;

public class JceTlsStreamCipher
    implements TlsCipher
{
    protected TlsContext context;

    protected StreamCipher encryptCipher;
    protected StreamCipher decryptCipher;

    protected JceTlsMac writeMac;
    protected JceTlsMac readMac;

    protected boolean usesNonce;

    public JceTlsStreamCipher(TlsContext context, StreamCipher clientWriteCipher,
                              StreamCipher serverWriteCipher, MessageDigest clientWriteDigest, MessageDigest serverWriteDigest,
                              int cipherKeySize, int macKeySize, boolean usesNonce)
        throws IOException, GeneralSecurityException
    {
        boolean isServer = context.isServer();

        this.context = context;
        this.usesNonce = usesNonce;

        this.encryptCipher = clientWriteCipher;
        this.decryptCipher = serverWriteCipher;

        int key_block_size = (2 * cipherKeySize) + clientWriteDigest.getDigestLength()
            + serverWriteDigest.getDigestLength();

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        // Init MACs
        byte[] clientMacKey = Arrays.copyOfRange(key_block, offset, offset + macKeySize);
        offset += macKeySize;
        byte[] serverMacKey = Arrays.copyOfRange(key_block, offset, offset + macKeySize);
        offset += macKeySize;

        JceTlsMac clientWriteMac = new JceTlsMac(context, clientWriteDigest);
        clientWriteMac.setKey(clientMacKey);
        JceTlsMac serverWriteMac = new JceTlsMac(context, serverWriteDigest);
        serverWriteMac.setKey(serverMacKey);

        // Build keys
        KeyParameter clientWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        KeyParameter serverWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        CipherParameters encryptParams, decryptParams;
        if (isServer)
        {
            this.writeMac = serverWriteMac;
            this.readMac = clientWriteMac;
            this.encryptCipher = serverWriteCipher;
            this.decryptCipher = clientWriteCipher;
            encryptParams = serverWriteKey;
            decryptParams = clientWriteKey;
        }
        else
        {
            this.writeMac = clientWriteMac;
            this.readMac = serverWriteMac;
            this.encryptCipher = clientWriteCipher;
            this.decryptCipher = serverWriteCipher;
            encryptParams = clientWriteKey;
            decryptParams = serverWriteKey;
        }

        if (usesNonce)
        {
            byte[] dummyNonce = new byte[8];
            encryptParams = new ParametersWithIV(encryptParams, dummyNonce);
            decryptParams = new ParametersWithIV(decryptParams, dummyNonce);
        }

        this.encryptCipher.init(true, encryptParams);
        this.decryptCipher.init(false, decryptParams);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
    {
        if (usesNonce)
        {
            updateIV(encryptCipher, true, seqNo);
        }

        byte[] outBuf = new byte[len + writeMac.getSize()];

        encryptCipher.processBytes(plaintext, offset, len, outBuf, 0);

        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
        encryptCipher.processBytes(mac, 0, mac.length, outBuf, len);

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
        decryptCipher.processBytes(ciphertext, offset, len, deciphered, 0);
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

    protected void updateIV(StreamCipher cipher, boolean forEncryption, long seqNo)
    {
        byte[] nonce = new byte[8];
        TlsUtils.writeUint64(seqNo, nonce, 0);
        cipher.init(forEncryption, new ParametersWithIV(null, nonce));
    }
}
