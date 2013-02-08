package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class TlsStreamCipher implements TlsCipher
{
    protected TlsClientContext context;

    protected StreamCipher encryptCipher;
    protected StreamCipher decryptCipher;

    protected TlsMac writeMac;
    protected TlsMac readMac;

    public TlsStreamCipher(TlsClientContext context, StreamCipher encryptCipher,
        StreamCipher decryptCipher, Digest writeDigest, Digest readDigest, int cipherKeySize)
        throws IOException
    {
        this.context = context;
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        int prfSize = (2 * cipherKeySize) + writeDigest.getDigestSize()
            + readDigest.getDigestSize();

        SecurityParameters securityParameters = context.getSecurityParameters();

        byte[] keyBlock = TlsUtils.PRF(securityParameters.masterSecret, "key expansion",
            TlsUtils.concat(securityParameters.serverRandom, securityParameters.clientRandom),
            prfSize);

        int offset = 0;

        // Init MACs
        writeMac = new TlsMac(context, writeDigest, keyBlock, offset, writeDigest.getDigestSize());
        offset += writeDigest.getDigestSize();
        readMac = new TlsMac(context, readDigest, keyBlock, offset, readDigest.getDigestSize());
        offset += readDigest.getDigestSize();

        // Build keys
        KeyParameter encryptKey = new KeyParameter(keyBlock, offset, cipherKeySize);
        offset += cipherKeySize;
        KeyParameter decryptKey = new KeyParameter(keyBlock, offset, cipherKeySize);
        offset += cipherKeySize;

        if (offset != prfSize)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        encryptCipher.init(true, encryptKey);
        decryptCipher.init(true, decryptKey);
    }

    public byte[] encodePlaintext(short type, byte[] plaintext, int offset, int len)
    {
        byte[] mac = writeMac.calculateMac(type, plaintext, offset, len);

        byte[] outbuf = new byte[len + mac.length];

        encryptCipher.processBytes(plaintext, offset, len, outbuf, 0);
        encryptCipher.processBytes(mac, 0, mac.length, outbuf, len);

        return outbuf;
    }

    public byte[] decodeCiphertext(short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        byte[] deciphered = new byte[len];
        decryptCipher.processBytes(ciphertext, offset, len, deciphered, 0);

        int plaintextSize = deciphered.length - readMac.getSize();
        byte[] plainText = copyData(deciphered, 0, plaintextSize);

        byte[] receivedMac = copyData(deciphered, plaintextSize, readMac.getSize());
        byte[] computedMac = readMac.calculateMac(type, plainText, 0, plainText.length);

        if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return plainText;
    }

    protected byte[] copyData(byte[] text, int offset, int len)
    {
        byte[] result = new byte[len];
        System.arraycopy(text, offset, result, 0, len);
        return result;
    }
}
