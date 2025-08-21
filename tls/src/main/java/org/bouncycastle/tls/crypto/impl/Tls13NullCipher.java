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
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * A generic TLS 1.3 "integrity-only" cipher.
 */
public final class Tls13NullCipher
    implements TlsCipher
{
    private final TlsCryptoParameters cryptoParams;

    private final TlsHMAC readHMAC, writeHMAC;
    private final byte[] readNonce, writeNonce;

    public Tls13NullCipher(TlsCryptoParameters cryptoParams, TlsHMAC readHMAC, TlsHMAC writeHMAC)
        throws IOException
    {
        final SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        
        if (!TlsImplUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.cryptoParams = cryptoParams;
        this.readHMAC = readHMAC;
        this.writeHMAC = writeHMAC;

        this.readNonce = new byte[readHMAC.getMacLength()];
        this.writeNonce = new byte[writeHMAC.getMacLength()];

        final boolean isServer = cryptoParams.isServer();
        rekeyHmac(securityParameters, readHMAC, readNonce, !isServer);
        rekeyHmac(securityParameters, writeHMAC, writeNonce, isServer);
    }

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        return plaintextLimit + 1 + readHMAC.getMacLength();
    }

    public int getCiphertextEncodeLimit(int plaintextLimit)
    {
        return plaintextLimit + 1 + writeHMAC.getMacLength();
    }

    public int getPlaintextDecodeLimit(int ciphertextLimit)
    {
        return ciphertextLimit - readHMAC.getMacLength() - 1;
    }

    public int getPlaintextEncodeLimit(int ciphertextLimit)
    {
        return ciphertextLimit - writeHMAC.getMacLength() - 1;
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException
    {
        int macLength = writeHMAC.getMacLength();

        // TODO Possibly redundant if we reset after any failures (i.e. DTLS)
        writeHMAC.reset();

        byte[] nonce = createRecordNonce(writeNonce, seqNo);
        writeHMAC.update(nonce, 0, nonce.length);

        // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
        int innerPlaintextLength = plaintextLength + 1;
        int ciphertextLength = innerPlaintextLength + macLength;
        byte[] output = new byte[headerAllocation + ciphertextLength];
        int outputPos = headerAllocation;

        short recordType = ContentType.application_data;

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength);

        try
        {
            System.arraycopy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
            output[outputPos + plaintextLength] = (byte)contentType;

            writeHMAC.update(additionalData, 0, additionalData.length);
            writeHMAC.update(output, outputPos, innerPlaintextLength);
            writeHMAC.calculateMAC(output, outputPos + innerPlaintextLength);
            outputPos += innerPlaintextLength + macLength;
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        if (outputPos != output.length)
        {
            // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return new TlsEncodeResult(output, 0, output.length, recordType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int ciphertextOffset, int ciphertextLength) throws IOException
    {
        int macLength = readHMAC.getMacLength();

        int innerPlaintextLength = ciphertextLength - macLength;
        if (innerPlaintextLength < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        // TODO Possibly redundant if we reset after any failures (i.e. DTLS)
        readHMAC.reset();

        byte[] nonce = createRecordNonce(readNonce, seqNo);
        readHMAC.update(nonce, 0, nonce.length);

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength);

        try
        {
            readHMAC.update(additionalData, 0, additionalData.length);
            readHMAC.update(ciphertext, ciphertextOffset, innerPlaintextLength);
            byte[] calculated = readHMAC.calculateMAC();
            if (!Arrays.constantTimeAreEqual(macLength, calculated, 0, ciphertext, ciphertextOffset + innerPlaintextLength))
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        short contentType = recordType;
        int plaintextLength = innerPlaintextLength;

        // Strip padding and read true content type from TLSInnerPlaintext
        for (;;)
        {
            if (--plaintextLength < 0)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            byte octet = ciphertext[ciphertextOffset + plaintextLength];
            if (0 != octet)
            {
                contentType = (short)(octet & 0xFF);
                break;
            }
        }

        return new TlsDecodeResult(ciphertext, ciphertextOffset, plaintextLength, contentType);
    }

    public void rekeyDecoder() throws IOException
    {
        rekeyHmac(cryptoParams.getSecurityParametersConnection(), readHMAC, readNonce, !cryptoParams.isServer());
    }

    public void rekeyEncoder() throws IOException
    {
        rekeyHmac(cryptoParams.getSecurityParametersConnection(), writeHMAC, writeNonce, cryptoParams.isServer());
    }

    public boolean usesOpaqueRecordTypeDecode()
    {
        return true;
    }

    public boolean usesOpaqueRecordTypeEncode()
    {
        return true;
    }

    private void rekeyHmac(SecurityParameters securityParameters, TlsHMAC hmac, byte[] nonce, boolean serverSecret)
        throws IOException
    {
        TlsSecret secret = serverSecret
            ?   securityParameters.getTrafficSecretServer()
            :   securityParameters.getTrafficSecretClient();

        // TODO[tls13] For early data, have to disable server->client
        if (null == secret)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        setupHmac(hmac, nonce, secret, securityParameters.getPRFCryptoHashAlgorithm());
    }

    private void setupHmac(TlsHMAC hmac, byte[] nonce, TlsSecret secret, int cryptoHashAlgorithm)
        throws IOException
    {
        int length = hmac.getMacLength();
        byte[] key = hkdfExpandLabel(secret, cryptoHashAlgorithm, "key", length).extract();
        byte[] iv = hkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", length).extract();

        hmac.setKey(key, 0, length);
        System.arraycopy(iv, 0, nonce, 0, length);
    }

    private static byte[] createRecordNonce(byte[] fixedNonce, long seqNo)
    {
        int nonceLength = fixedNonce.length;
        byte[] nonce = new byte[nonceLength];
        TlsUtils.writeUint64(seqNo, nonce, nonceLength - 8);
        Bytes.xorTo(nonceLength, fixedNonce, nonce);
        return nonce;
    }

    private static byte[] getAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
        int ciphertextLength) throws IOException
    {
        /*
         * TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
         */
        byte[] additional_data = new byte[5];
        TlsUtils.writeUint8(recordType, additional_data, 0);
        TlsUtils.writeVersion(recordVersion, additional_data, 1);
        TlsUtils.writeUint16(ciphertextLength, additional_data, 3);
        return additional_data;
    }

    private static TlsSecret hkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, String label, int length)
        throws IOException
    {
        return TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, label, TlsUtils.EMPTY_BYTES, length);
    }
}
