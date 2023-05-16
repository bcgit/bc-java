package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.util.Arrays;

/**
 * The NULL cipher.
 */
public final class TlsNullCipher
    implements TlsCipher
{
    private final TlsSuiteHMac readMac, writeMac;
    private final byte[] decryptConnectionID, encryptConnectionID;
    private final boolean decryptUseInnerPlaintext, encryptUseInnerPlaintext;

    public TlsNullCipher(TlsCryptoParameters cryptoParams, TlsHMAC clientMac, TlsHMAC serverMac)
        throws IOException
    {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (TlsImplUtils.isTLSv13(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.decryptConnectionID = securityParameters.getConnectionIDPeer();
        this.encryptConnectionID = securityParameters.getConnectionIDLocal();

        this.decryptUseInnerPlaintext = !Arrays.isNullOrEmpty(decryptConnectionID);
        this.encryptUseInnerPlaintext = !Arrays.isNullOrEmpty(encryptConnectionID);

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
        int innerPlaintextLimit = plaintextLimit + (decryptUseInnerPlaintext ? 1 : 0);

        return innerPlaintextLimit + readMac.getSize();        
    }

    public int getCiphertextEncodeLimit(int plaintextLimit)
    {
        int innerPlaintextLimit = plaintextLimit + (encryptUseInnerPlaintext ? 1 : 0);

        return innerPlaintextLimit + writeMac.getSize();        
    }

    public int getPlaintextDecodeLimit(int ciphertextLimit)
    {
        int innerPlaintextLimit = ciphertextLimit - readMac.getSize();

        return innerPlaintextLimit - (decryptUseInnerPlaintext ? 1 : 0);        
    }

    public int getPlaintextEncodeLimit(int ciphertextLimit)
    {
        int innerPlaintextLimit = ciphertextLimit - writeMac.getSize();

        return innerPlaintextLimit - (encryptUseInnerPlaintext ? 1 : 0);        
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation,
        byte[] plaintext, int offset, int len) throws IOException
    {
        int macSize = writeMac.getSize();

        // TODO[cid] If we support adding padding to DTLSInnerPlaintext, this will need review
        int innerPlaintextLength = len + (encryptUseInnerPlaintext ? 1 : 0);

        byte[] ciphertext = new byte[headerAllocation + innerPlaintextLength + macSize];
        System.arraycopy(plaintext, offset, ciphertext, headerAllocation, len);

        short recordType = contentType;
        if (encryptUseInnerPlaintext)
        {
            ciphertext[headerAllocation + len] = (byte)contentType;
            recordType = ContentType.tls12_cid;
        }

        byte[] mac = writeMac.calculateMac(seqNo, recordType, encryptConnectionID, ciphertext, headerAllocation,
            innerPlaintextLength);
        System.arraycopy(mac, 0, ciphertext, headerAllocation + innerPlaintextLength, mac.length);

        return new TlsEncodeResult(ciphertext, 0, ciphertext.length, recordType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len) throws IOException
    {
        int macSize = readMac.getSize();

        int innerPlaintextLength = len - macSize;

        if (innerPlaintextLength < (decryptUseInnerPlaintext ? 1 : 0))
            throw new TlsFatalAlert(AlertDescription.decode_error);

        byte[] expectedMac = readMac.calculateMac(seqNo, recordType, decryptConnectionID, ciphertext, offset,
            innerPlaintextLength);

        boolean badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext,
            offset + innerPlaintextLength);
        if (badMac)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);
        }

        short contentType = recordType;
        int plaintextLength = innerPlaintextLength;

        if (decryptUseInnerPlaintext)
        {
            // Strip padding and read true content type from DTLSInnerPlaintext
            for (;;)
            {
                if (--plaintextLength < 0)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                byte octet = ciphertext[offset + plaintextLength];
                if (0 != octet)
                {
                    contentType = (short)(octet & 0xFF);
                    break;
                }
            }
        }

        return new TlsDecodeResult(ciphertext, offset, plaintextLength, contentType);
    }

    public void rekeyDecoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void rekeyEncoder() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean usesOpaqueRecordTypeDecode()
    {
        return decryptUseInnerPlaintext;
    }

    public boolean usesOpaqueRecordTypeEncode()
    {
        return encryptUseInnerPlaintext;
    }
}
