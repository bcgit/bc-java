package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;

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

    public int getCiphertextLimit(int plaintextLimit)
    {
        return plaintextLimit + writeMac.getSize();
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public byte[] encodePlaintext(long seqNo, short contentType, int headerAllocation, byte[] plaintext, int offset,
        int len) throws IOException
    {
        byte[] mac = writeMac.calculateMac(seqNo, contentType, plaintext, offset, len);
        byte[] ciphertext = new byte[headerAllocation + len + mac.length];
        System.arraycopy(plaintext, offset, ciphertext, headerAllocation, len);
        System.arraycopy(mac, 0, ciphertext, headerAllocation + len, mac.length);
        return ciphertext;
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short contentType, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        int macSize = readMac.getSize();
        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int macInputLen = len - macSize;

        byte[] expectedMac = readMac.calculateMac(seqNo, contentType, ciphertext, offset, macInputLen);

        boolean badMac = !TlsImplUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + macInputLen);
        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return new TlsDecodeResult(ciphertext, offset, macInputLen, contentType);
    }
}
