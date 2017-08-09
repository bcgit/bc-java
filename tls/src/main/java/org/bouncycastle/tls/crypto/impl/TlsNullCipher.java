package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * The NULL cipher.
 */
public class TlsNullCipher
    implements TlsCipher
{
    protected final TlsCryptoParameters cryptoParameters;
    protected final TlsSuiteHMac readMac, writeMac;

    public TlsNullCipher(TlsCryptoParameters cryptoParameters, TlsHMAC clientMac, TlsHMAC serverMac)
        throws IOException
    {
        this.cryptoParameters = cryptoParameters;

        int key_block_size = clientMac.getMacLength() + serverMac.getMacLength();
        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParameters, key_block_size);

        int offset = 0;

        clientMac.setKey(key_block, offset, clientMac.getMacLength());
        offset += clientMac.getMacLength();
        serverMac.setKey(key_block, offset, serverMac.getMacLength());
        offset += serverMac.getMacLength();

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (cryptoParameters.isServer())
        {
            writeMac = new TlsSuiteHMac(cryptoParameters, serverMac);
            readMac = new TlsSuiteHMac(cryptoParameters, clientMac);
        }
        else
        {
            writeMac = new TlsSuiteHMac(cryptoParameters, clientMac);
            readMac = new TlsSuiteHMac(cryptoParameters, serverMac);
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
