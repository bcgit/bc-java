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
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.2 AEAD cipher.
 */
public final class TlsAEADCipher
    implements TlsCipher
{
    public static final int AEAD_CCM = 1;
    public static final int AEAD_CHACHA20_POLY1305 = 2;
    public static final int AEAD_GCM = 3;

    private static final int NONCE_RFC5288 = 1;
    private static final int NONCE_RFC7905 = 2;
    private static final long SEQUENCE_NUMBER_PLACEHOLDER = -1L;

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

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher, TlsAEADCipherImpl decryptCipher,
        int keySize, int macSize, int aeadType) throws IOException
    {
        final SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        final ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        if (!TlsImplUtils.isTLSv12(negotiatedVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.isTLSv13 = TlsImplUtils.isTLSv13(negotiatedVersion);
        this.nonceMode = getNonceMode(isTLSv13, aeadType);

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
            rekeyCipher(securityParameters, decryptCipher, decryptNonce, !isServer);
            rekeyCipher(securityParameters, encryptCipher, encryptNonce, isServer);
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

    public void rekeyDecoder() throws IOException
    {
        rekeyCipher(cryptoParams.getSecurityParametersConnection(), decryptCipher, decryptNonce, !cryptoParams.isServer());
    }

    public void rekeyEncoder() throws IOException
    {
        rekeyCipher(cryptoParams.getSecurityParametersConnection(), encryptCipher, encryptNonce, cryptoParams.isServer());
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
        boolean serverSecret) throws IOException
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

        setup13Cipher(cipher, nonce, secret, securityParameters.getPRFCryptoHashAlgorithm());
    }

    private void setup13Cipher(TlsAEADCipherImpl cipher, byte[] nonce, TlsSecret secret, int cryptoHashAlgorithm)
        throws IOException
    {
        byte[] key = TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, "key", TlsUtils.EMPTY_BYTES, keySize).extract();
        byte[] iv = TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", TlsUtils.EMPTY_BYTES, fixed_iv_length).extract();

        cipher.setKey(key, 0, keySize);
        System.arraycopy(iv, 0, nonce, 0, fixed_iv_length);
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
}
