package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.util.Arrays;

public class JceTlsNullCipher
    implements TlsCipher
{
    protected TlsContext context;

    protected JceTlsMac writeMac;
    protected JceTlsMac readMac;

    public JceTlsNullCipher(TlsContext context, MessageDigest clientWriteDigest, MessageDigest serverWriteDigest)
        throws IOException, GeneralSecurityException
    {
        this.context = context;

        JceTlsMac clientWriteMac = null, serverWriteMac = null;

        int key_block_size = clientWriteDigest.getDigestLength()
            + serverWriteDigest.getDigestLength();
        byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        clientWriteMac = new JceTlsMac(context, clientWriteDigest, key_block, offset,
            clientWriteDigest.getDigestLength());
        offset += clientWriteDigest.getDigestLength();

        serverWriteMac = new JceTlsMac(context, serverWriteDigest, key_block, offset,
            serverWriteDigest.getDigestLength());
        offset += serverWriteDigest.getDigestLength();

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (context.isServer())
        {
            writeMac = serverWriteMac;
            readMac = clientWriteMac;
        }
        else
        {
            writeMac = clientWriteMac;
            readMac = serverWriteMac;
        }
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
    {
        byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
        byte[] ciphertext = new byte[len + mac.length];
        System.arraycopy(plaintext, offset, ciphertext, 0, len);
        System.arraycopy(mac, 0, ciphertext, len, mac.length);
        return ciphertext;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int macSize = readMac.getSize();
        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int macInputLen = len - macSize;

        byte[] receivedMac = Arrays.copyOfRange(ciphertext, offset + macInputLen, offset + len);
        byte[] computedMac = readMac.calculateMac(seqNo, type, ciphertext, offset, macInputLen);

        if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return Arrays.copyOfRange(ciphertext, offset, offset + macInputLen);
    }
}
