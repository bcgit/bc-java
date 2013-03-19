package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class TlsStreamCipher implements TlsCipher
{
    protected TlsContext context;

    protected StreamCipher encryptCipher;
    protected StreamCipher decryptCipher;

    protected TlsMac writeMac;
    protected TlsMac readMac;

    public TlsStreamCipher(TlsContext context, StreamCipher encryptCipher,
        StreamCipher decryptCipher, Digest writeDigest, Digest readDigest, int cipherKeySize)
        throws IOException
    {
        boolean isServer = context.isServer();

        this.context = context;

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        int key_block_size = (2 * cipherKeySize) + writeDigest.getDigestSize()
            + readDigest.getDigestSize();

        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        // Init MACs
        TlsMac clientWriteMac = new TlsMac(context, writeDigest, key_block, offset, writeDigest.getDigestSize());
        offset += writeDigest.getDigestSize();
        TlsMac serverWriteMac = new TlsMac(context, readDigest, key_block, offset, readDigest.getDigestSize());
        offset += readDigest.getDigestSize();

        // Build keys
        KeyParameter clientWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        KeyParameter serverWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        KeyParameter encryptKey, decryptKey;
        if (isServer)
        {
            writeMac = serverWriteMac;
            readMac = clientWriteMac;
            encryptKey = serverWriteKey;
            decryptKey = clientWriteKey;
        }
        else
        {
            writeMac = clientWriteMac;
            readMac = serverWriteMac;
            encryptKey = clientWriteKey;
            decryptKey = serverWriteKey;
        }

        encryptCipher.init(true, encryptKey);
        decryptCipher.init(false, decryptKey);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
    {
        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);

        byte[] outbuf = new byte[len + mac.length];

        encryptCipher.processBytes(plaintext, offset, len, outbuf, 0);
        encryptCipher.processBytes(mac, 0, mac.length, outbuf, len);

        return outbuf;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int macSize = readMac.getSize();
        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] deciphered = new byte[len];
        decryptCipher.processBytes(ciphertext, offset, len, deciphered, 0);

        int macInputLen = len - macSize;

        byte[] receivedMac = Arrays.copyOfRange(deciphered, macInputLen, len);
        byte[] computedMac = readMac.calculateMac(seqNo, type, deciphered, 0, macInputLen);

        if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return Arrays.copyOfRange(deciphered, 0, macInputLen);
    }
}
