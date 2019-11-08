package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;

/**
 * The NULL cipher.
 */
public class TlsNullCipher
    implements TlsCipher
{
    protected final TlsCryptoParameters cryptoParams;
    protected final TlsSuiteHMac readMac, writeMac;

    public TlsNullCipher(TlsCryptoParameters cryptoParams, TlsHMAC clientMac, TlsHMAC serverMac)
        throws IOException
    {
        if (TlsImplUtils.isTLSv13(cryptoParams))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.cryptoParams = cryptoParams;

        int key_block_size = clientMac.getMacLength() + serverMac.getMacLength();
        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        clientMac.setKey(key_block, offset, clientMac.getMacLength());
        offset += clientMac.getMacLength();
        serverMac.setKey(key_block, offset, serverMac.getMacLength());
        offset += serverMac.getMacLength();

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (cryptoParams.isServer())
        {
            writeMac = new TlsSuiteHMac(cryptoParams, serverMac);
            readMac = new TlsSuiteHMac(cryptoParams, clientMac);
        }
        else
        {
            writeMac = new TlsSuiteHMac(cryptoParams, clientMac);
            readMac = new TlsSuiteHMac(cryptoParams, serverMac);
        }
    }

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        return plaintextLimit + writeMac.getSize();
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
    {
        return plaintextLength + writeMac.getSize();
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeMac.getSize();
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation,
        byte[] plaintext, int offset, int len) throws IOException
    {
        byte[] mac = writeMac.calculateMac(seqNo, contentType, plaintext, offset, len);
        byte[] ciphertext = new byte[headerAllocation + len + mac.length];
        System.arraycopy(plaintext, offset, ciphertext, headerAllocation, len);
        System.arraycopy(mac, 0, ciphertext, headerAllocation + len, mac.length);
        return new TlsEncodeResult(ciphertext, 0, ciphertext.length, contentType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
    {
        int macSize = readMac.getSize();
        if (len < macSize)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int macInputLen = len - macSize;

        byte[] expectedMac = readMac.calculateMac(seqNo, recordType, ciphertext, offset, macInputLen);

        boolean badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + macInputLen);
        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        return new TlsDecodeResult(ciphertext, offset, macInputLen, recordType);
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
}
