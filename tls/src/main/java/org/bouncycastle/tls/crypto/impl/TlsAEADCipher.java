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
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * A generic AEAD cipher, covering TLS 1.2, TLS 1.3 and DTLS 1.3 record protection.
 */
public final class TlsAEADCipher
    implements TlsCipher, TlsDTLS13Cipher
{
    public static final int AEAD_CCM = 1;
    public static final int AEAD_CHACHA20_POLY1305 = 2;
    public static final int AEAD_GCM = 3;

    private static final int NONCE_RFC5288 = 1;
    private static final int NONCE_RFC7905 = 2;
    private static final long SEQUENCE_NUMBER_PLACEHOLDER = -1L;

    private static final byte[] EPOCH_1 = { 0x00, 0x01 };

    private static final int DTLS13_FIXED_BITS = 0x20;
    private static final int DTLS13_FIXED_BITS_MASK = 0xE0;
    private static final int DTLS13_FLAG_CID = 0x10;
    private static final int DTLS13_FLAG_SEQ16 = 0x08;
    private static final int DTLS13_FLAG_LENGTH = 0x04;
    private static final int DTLS13_MIN_CIPHERTEXT_LENGTH = 16;

    private final TlsCryptoParameters cryptoParams;
    private final int keySize;
    private final int macSize;
    private final int fixed_iv_length;
    private final int record_iv_length;

    private final TlsAEADCipherImpl decryptCipher, encryptCipher;
    private final byte[] decryptNonce, encryptNonce;
    private final byte[] decryptConnectionID, encryptConnectionID;
    private final boolean decryptUseInnerPlaintext, encryptUseInnerPlaintext;

    private final boolean isTLSv13;
    private final int nonceMode;
    private final AEADNonceGenerator nonceGenerator;

    private final boolean isDTLSv13;
    private final TlsRecordNumberMask decryptMask, encryptMask;

    /** @deprecated Use version with extra 'nonceGeneratorFactory' parameter */
    @Deprecated
    @SuppressWarnings("InlineMeSuggester")
    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher,
        TlsAEADCipherImpl decryptCipher, int keySize, int macSize, int aeadType) throws IOException
    {
        this(cryptoParams, encryptCipher, decryptCipher, keySize, macSize, aeadType, null);
    }

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher,
        TlsAEADCipherImpl decryptCipher, int keySize, int macSize, int aeadType,
        AEADNonceGeneratorFactory nonceGeneratorFactory) throws IOException
    {
        this(cryptoParams, encryptCipher, decryptCipher, keySize, macSize, aeadType, nonceGeneratorFactory, null,
            null);
    }

    /**
     * @param encryptMask record number encryption mask for the sending direction (DTLS 1.3 only, may be null
     *        when DTLS 1.3 will not be negotiated).
     * @param decryptMask record number encryption mask for the receiving direction (DTLS 1.3 only).
     */
    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher,
        TlsAEADCipherImpl decryptCipher, int keySize, int macSize, int aeadType,
        AEADNonceGeneratorFactory nonceGeneratorFactory, TlsRecordNumberMask encryptMask,
        TlsRecordNumberMask decryptMask) throws IOException
    {
        final SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        final ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!TlsImplUtils.isTLSv12(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.isTLSv13 = TlsImplUtils.isTLSv13(negotiatedVersion);
        this.isDTLSv13 = isTLSv13 && negotiatedVersion.isDTLS();
        this.nonceMode = getNonceMode(isTLSv13, aeadType);

        this.encryptMask = encryptMask;
        this.decryptMask = decryptMask;

        decryptConnectionID = securityParameters.getConnectionIDPeer();
        encryptConnectionID = securityParameters.getConnectionIDLocal();

        decryptUseInnerPlaintext = isTLSv13 || !Arrays.isNullOrEmpty(decryptConnectionID);
        encryptUseInnerPlaintext = isTLSv13 || !Arrays.isNullOrEmpty(encryptConnectionID);

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            this.fixed_iv_length = 4;
            this.record_iv_length = 8;
            break;
        case NONCE_RFC7905:
            this.fixed_iv_length = 12;
            this.record_iv_length = 0;
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.cryptoParams = cryptoParams;
        this.keySize = keySize;
        this.macSize = macSize;

        this.decryptCipher = decryptCipher;
        this.encryptCipher = encryptCipher;

        this.decryptNonce = new byte[fixed_iv_length];
        this.encryptNonce = new byte[fixed_iv_length];

        final boolean isServer = cryptoParams.isServer();
        if (isTLSv13)
        {
            nonceGenerator = null;
            rekeyCipher(securityParameters, decryptCipher, decryptNonce, decryptMask, !isServer);
            rekeyCipher(securityParameters, encryptCipher, encryptNonce, encryptMask, isServer);
            return;
        }

        int keyBlockSize = (2 * keySize) + (2 * fixed_iv_length);
        byte[] keyBlock = TlsImplUtils.calculateKeyBlock(cryptoParams, keyBlockSize);
        int pos = 0;

        if (isServer)
        {
            decryptCipher.setKey(keyBlock, pos, keySize); pos += keySize;
            encryptCipher.setKey(keyBlock, pos, keySize); pos += keySize;

            System.arraycopy(keyBlock, pos, decryptNonce, 0, fixed_iv_length); pos += fixed_iv_length;
            System.arraycopy(keyBlock, pos, encryptNonce, 0, fixed_iv_length); pos += fixed_iv_length;
        }
        else
        {
            encryptCipher.setKey(keyBlock, pos, keySize); pos += keySize;
            decryptCipher.setKey(keyBlock, pos, keySize); pos += keySize;

            System.arraycopy(keyBlock, pos, encryptNonce, 0, fixed_iv_length); pos += fixed_iv_length;
            System.arraycopy(keyBlock, pos, decryptNonce, 0, fixed_iv_length); pos += fixed_iv_length;
        }

        if (keyBlockSize != pos)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (AEAD_GCM == aeadType && nonceGeneratorFactory != null)
        {
            int nonceLength = fixed_iv_length + record_iv_length;
            byte[] baseNonce = Arrays.copyOf(encryptNonce, nonceLength);
            int counterSizeInBits;
            if (negotiatedVersion.isDTLS())
            {
                counterSizeInBits = (record_iv_length - 2) * 8; // 48
                baseNonce[baseNonce.length - 8] ^= EPOCH_1[0];
                baseNonce[baseNonce.length - 7] ^= EPOCH_1[1];
            }
            else
            {
                counterSizeInBits = record_iv_length * 8; // 64
            }
            nonceGenerator = nonceGeneratorFactory.create(baseNonce, counterSizeInBits);
        }
        else
        {
            nonceGenerator = null;
        }
    }

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        int innerPlaintextLimit = plaintextLimit + (decryptUseInnerPlaintext ? 1 : 0);

        return innerPlaintextLimit + macSize + record_iv_length;
    }

    public int getCiphertextEncodeLimit(int plaintextLimit)
    {
        int innerPlaintextLimit = plaintextLimit + (encryptUseInnerPlaintext ? 1 : 0);

        return innerPlaintextLimit + macSize + record_iv_length;
    }

    public int getPlaintextDecodeLimit(int ciphertextLimit)
    {
        int innerPlaintextLimit = ciphertextLimit - macSize - record_iv_length;

        return innerPlaintextLimit - (decryptUseInnerPlaintext ? 1 : 0);
    }

    public int getPlaintextEncodeLimit(int ciphertextLimit)
    {
        int innerPlaintextLimit = ciphertextLimit - macSize - record_iv_length;

        return innerPlaintextLimit - (encryptUseInnerPlaintext ? 1 : 0);
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException
    {
        byte[] nonce = new byte[encryptNonce.length + record_iv_length];

        if (null != nonceGenerator)
        {
            nonceGenerator.generateNonce(nonce);
        }
        else
        {
            switch (nonceMode)
            {
            case NONCE_RFC5288:
                System.arraycopy(encryptNonce, 0, nonce, 0, encryptNonce.length);
                // RFC 5288/6655: The nonce_explicit MAY be the 64-bit sequence number.
                TlsUtils.writeUint64(seqNo, nonce, encryptNonce.length);
                break;
            case NONCE_RFC7905:
                TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
                for (int i = 0; i < encryptNonce.length; ++i)
                {
                    nonce[i] ^= encryptNonce[i];
                }
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
        int innerPlaintextLength = plaintextLength + (encryptUseInnerPlaintext ? 1 : 0);

        encryptCipher.init(nonce, macSize);

        int encryptionLength = encryptCipher.getOutputSize(innerPlaintextLength);
        int ciphertextLength = record_iv_length + encryptionLength;

        byte[] output = new byte[headerAllocation + ciphertextLength];
        int outputPos = headerAllocation;

        if (record_iv_length != 0)
        {
            System.arraycopy(nonce, nonce.length - record_iv_length, output, outputPos, record_iv_length);
            outputPos += record_iv_length;
        }

        short recordType = contentType;
        if (encryptUseInnerPlaintext)
        {
            recordType = isTLSv13 ? ContentType.application_data : ContentType.tls12_cid;
        }

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength,
            innerPlaintextLength, encryptConnectionID);

        try
        {
            System.arraycopy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
            if (encryptUseInnerPlaintext)
            {
                output[outputPos + plaintextLength] = (byte)contentType;
            }

            outputPos += encryptCipher.doFinal(additionalData, output, outputPos, innerPlaintextLength, output,
                outputPos);
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
        if (getPlaintextDecodeLimit(ciphertextLength) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] nonce = new byte[decryptNonce.length + record_iv_length];

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            System.arraycopy(decryptNonce, 0, nonce, 0, decryptNonce.length);
            System.arraycopy(ciphertext, ciphertextOffset, nonce, nonce.length - record_iv_length, record_iv_length);
            break;
        case NONCE_RFC7905:
            TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
            for (int i = 0; i < decryptNonce.length; ++i)
            {
                nonce[i] ^= decryptNonce[i];
            }
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        decryptCipher.init(nonce, macSize);

        int encryptionOffset = ciphertextOffset + record_iv_length;
        int encryptionLength = ciphertextLength - record_iv_length;
        int innerPlaintextLength = decryptCipher.getOutputSize(encryptionLength);

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength,
            innerPlaintextLength, decryptConnectionID);

        int outputPos;
        try
        {
            outputPos = decryptCipher.doFinal(additionalData, ciphertext, encryptionOffset, encryptionLength,
                ciphertext, encryptionOffset);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        if (outputPos != innerPlaintextLength)
        {
            // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        short contentType = recordType;
        int plaintextLength = innerPlaintextLength;

        if (decryptUseInnerPlaintext)
        {
            // Strip padding and read true content type from TLSInnerPlaintext
            for (;;)
            {
                if (--plaintextLength < 0)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                byte octet = ciphertext[encryptionOffset + plaintextLength];
                if (0 != octet)
                {
                    contentType = (short)(octet & 0xFF);
                    break;
                }
            }
        }

        return new TlsDecodeResult(ciphertext, encryptionOffset, plaintextLength, contentType);
    }

    public TlsEncodeResult encodeDTLS13Plaintext(long seqNo, short contentType, byte[] header, int headerOff,
        int headerLen, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException
    {
        if (!isDTLSv13)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int firstByte = header[headerOff] & 0xFF;
        int cidLength = getDTLS13HeaderConnectionIDLength(firstByte, encryptConnectionID);
        int seqNumOff = 1 + cidLength;
        int seqNumLen = getDTLS13SequenceNumberLength(firstByte);
        boolean hasLength = (firstByte & DTLS13_FLAG_LENGTH) != 0;
        int expectedHeaderLen = seqNumOff + seqNumLen + (hasLength ? 2 : 0);
        if (headerLen != expectedHeaderLen)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /*
         * RFC 9147 4.2.3. Senders MUST pad short plaintexts out [...] in order to make a suitable-length
         * ciphertext (at least 16 bytes, for record number encryption).
         */
        int innerPlaintextLength = plaintextLength + 1;
        int minInnerPlaintextLength = DTLS13_MIN_CIPHERTEXT_LENGTH - macSize;
        if (innerPlaintextLength < minInnerPlaintextLength)
        {
            innerPlaintextLength = minInnerPlaintextLength;
        }

        byte[] nonce = createDTLS13Nonce(encryptNonce, seqNo);

        encryptCipher.init(nonce, macSize);

        int ciphertextLength = encryptCipher.getOutputSize(innerPlaintextLength);
        TlsUtils.checkUint16(ciphertextLength);

        byte[] output = new byte[headerLen + ciphertextLength];
        System.arraycopy(header, headerOff, output, 0, headerLen);
        if (hasLength)
        {
            TlsUtils.writeUint16(ciphertextLength, output, headerLen - 2);
        }

        // RFC 9147 4. The entire header (prior to record number encryption) is the additional data.
        byte[] additionalData = Arrays.copyOfRange(output, 0, headerLen);

        int outputPos = headerLen;
        try
        {
            System.arraycopy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
            output[outputPos + plaintextLength] = (byte)contentType;
            // NOTE: Any padding bytes after the content type are already zero

            outputPos += encryptCipher.doFinal(additionalData, output, outputPos, innerPlaintextLength, output,
                outputPos);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        if (outputPos != output.length)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        applyDTLS13RecordNumberMask(encryptMask, output, seqNumOff, seqNumLen, headerLen);

        return new TlsEncodeResult(output, 0, output.length, (short)firstByte);
    }

    public void decryptDTLS13RecordNumber(byte[] record, int recordOff, int recordLen) throws IOException
    {
        if (!isDTLSv13)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (recordLen < 1 || (record[recordOff] & DTLS13_FIXED_BITS_MASK) != DTLS13_FIXED_BITS)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        int firstByte = record[recordOff] & 0xFF;
        int cidLength = getDTLS13HeaderConnectionIDLength(firstByte, decryptConnectionID);
        int seqNumOff = 1 + cidLength;
        int seqNumLen = getDTLS13SequenceNumberLength(firstByte);
        int headerLen = seqNumOff + seqNumLen + ((firstByte & DTLS13_FLAG_LENGTH) != 0 ? 2 : 0);

        if (recordLen < headerLen + DTLS13_MIN_CIPHERTEXT_LENGTH)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        applyDTLS13RecordNumberMask(decryptMask, record, recordOff + seqNumOff, seqNumLen, recordOff + headerLen);
    }

    public TlsDecodeResult decodeDTLS13Ciphertext(long seqNo, byte[] record, int recordOff, int headerLen,
        int ciphertextLen) throws IOException
    {
        if (!isDTLSv13)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (ciphertextLen < DTLS13_MIN_CIPHERTEXT_LENGTH || getPlaintextDecodeLimit(ciphertextLen) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] nonce = createDTLS13Nonce(decryptNonce, seqNo);

        decryptCipher.init(nonce, macSize);

        int encryptionOffset = recordOff + headerLen;
        int innerPlaintextLength = decryptCipher.getOutputSize(ciphertextLen);

        byte[] additionalData = Arrays.copyOfRange(record, recordOff, recordOff + headerLen);

        int outputPos;
        try
        {
            outputPos = decryptCipher.doFinal(additionalData, record, encryptionOffset, ciphertextLen, record,
                encryptionOffset);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        if (outputPos != innerPlaintextLength)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // Strip padding and read true content type from DTLSInnerPlaintext
        short contentType;
        int plaintextLength = innerPlaintextLength;
        for (;;)
        {
            if (--plaintextLength < 0)
            {
                // NOTE: The DTLS record layer deliberately converts this alert into a silent discard
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            byte octet = record[encryptionOffset + plaintextLength];
            if (0 != octet)
            {
                contentType = (short)(octet & 0xFF);
                break;
            }
        }

        return new TlsDecodeResult(record, encryptionOffset, plaintextLength, contentType);
    }

    private static void applyDTLS13RecordNumberMask(TlsRecordNumberMask mask, byte[] record, int seqNumOff,
        int seqNumLen, int ciphertextOff) throws IOException
    {
        if (null == mask)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] maskBytes = new byte[16];
        mask.generateMask(record, ciphertextOff, maskBytes, 0);

        for (int i = 0; i < seqNumLen; ++i)
        {
            record[seqNumOff + i] ^= maskBytes[i];
        }
    }

    private byte[] createDTLS13Nonce(byte[] fixedNonce, long seqNo)
    {
        /*
         * RFC 9147 4. In DTLS 1.3 the 64-bit sequence_number is used as the sequence number for the AEAD
         * computation; unlike DTLS 1.2, the epoch is not included.
         */
        byte[] nonce = new byte[fixedNonce.length];
        TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
        for (int i = 0; i < fixedNonce.length; ++i)
        {
            nonce[i] ^= fixedNonce[i];
        }
        return nonce;
    }

    private static int getDTLS13HeaderConnectionIDLength(int firstByte, byte[] connectionID) throws IOException
    {
        int cidLength = Arrays.isNullOrEmpty(connectionID) ? 0 : connectionID.length;
        boolean hasCID = (firstByte & DTLS13_FLAG_CID) != 0;
        if (hasCID != (cidLength > 0))
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return cidLength;
    }

    private static int getDTLS13SequenceNumberLength(int firstByte)
    {
        return (firstByte & DTLS13_FLAG_SEQ16) != 0 ? 2 : 1;
    }

    public void rekeyDecoder() throws IOException
    {
        rekeyCipher(cryptoParams.getSecurityParametersConnection(), decryptCipher, decryptNonce, decryptMask,
            !cryptoParams.isServer());
    }

    public void rekeyEncoder() throws IOException
    {
        rekeyCipher(cryptoParams.getSecurityParametersConnection(), encryptCipher, encryptNonce, encryptMask,
            cryptoParams.isServer());
    }

    public boolean usesOpaqueRecordTypeDecode()
    {
        return decryptUseInnerPlaintext;
    }

    public boolean usesOpaqueRecordTypeEncode()
    {
        return encryptUseInnerPlaintext;
    }

    private byte[] getAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
        int ciphertextLength, int plaintextLength, byte[] connectionID) throws IOException
    {
        if (!Arrays.isNullOrEmpty(connectionID))
        {
            /*
             * seq_num_placeholder + tls12_cid + cid_length + tls12_cid + DTLSCiphertext.version + epoch
             *     + sequence_number + cid + length_of_DTLSInnerPlaintext
             */
            int cidLength = connectionID.length;
            byte[] additional_data = new byte[23 + cidLength];
            TlsUtils.writeUint64(SEQUENCE_NUMBER_PLACEHOLDER, additional_data, 0);
            TlsUtils.writeUint8(ContentType.tls12_cid, additional_data, 8);
            TlsUtils.writeUint8(cidLength, additional_data, 9);
            TlsUtils.writeUint8(ContentType.tls12_cid, additional_data, 10);
            TlsUtils.writeVersion(recordVersion, additional_data, 11);
            TlsUtils.writeUint64(seqNo, additional_data, 13);
            System.arraycopy(connectionID, 0, additional_data, 21, cidLength);
            TlsUtils.writeUint16(plaintextLength, additional_data, 21 + cidLength);
            return additional_data;
        }
        else if (isTLSv13)
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
        else
        {
            /*
             * seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length
             */
            byte[] additional_data = new byte[13];
            TlsUtils.writeUint64(seqNo, additional_data, 0);
            TlsUtils.writeUint8(recordType, additional_data, 8);
            TlsUtils.writeVersion(recordVersion, additional_data, 9);
            TlsUtils.writeUint16(plaintextLength, additional_data, 11);
            return additional_data;
        }
    }

    private void rekeyCipher(SecurityParameters securityParameters, TlsAEADCipherImpl cipher, byte[] nonce,
        TlsRecordNumberMask mask, boolean serverSecret) throws IOException
    {
        if (!isTLSv13)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsSecret secret = serverSecret
            ?   securityParameters.getTrafficSecretServer()
            :   securityParameters.getTrafficSecretClient();

        // TODO[tls13] For early data, have to disable server->client
        if (null == secret)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        setup13Cipher(cipher, nonce, mask, secret, securityParameters.getPRFCryptoHashAlgorithm());
    }

    private void setup13Cipher(TlsAEADCipherImpl cipher, byte[] nonce, TlsRecordNumberMask mask, TlsSecret secret,
        int cryptoHashAlgorithm) throws IOException
    {
        byte[] key = hkdfExpandLabel(secret, cryptoHashAlgorithm, "key", keySize).extract();
        byte[] iv = hkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", fixed_iv_length).extract();

        cipher.setKey(key, 0, keySize);
        System.arraycopy(iv, 0, nonce, 0, fixed_iv_length);

        if (isDTLSv13)
        {
            /*
             * RFC 9147 4.2.3. [sender]_sn_key = HKDF-Expand-Label(Secret, "sn", "", key_length)
             */
            if (null == mask)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, "No record number mask for DTLS 1.3");
            }

            byte[] snKey = hkdfExpandLabel(secret, cryptoHashAlgorithm, "sn", keySize).extract();
            mask.setKey(snKey, 0, keySize);
        }
    }

    private static int getNonceMode(boolean isTLSv13, int aeadType) throws IOException
    {
        switch (aeadType)
        {
        case AEAD_CCM:
        case AEAD_GCM:
            return isTLSv13 ? NONCE_RFC7905 : NONCE_RFC5288;

        case AEAD_CHACHA20_POLY1305:
            return NONCE_RFC7905;

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    private static TlsSecret hkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, String label, int length)
        throws IOException
    {
        return TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, label, TlsUtils.EMPTY_BYTES, length);
    }
}
