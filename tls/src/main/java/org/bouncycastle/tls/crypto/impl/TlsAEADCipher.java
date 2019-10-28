package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;

/**
 * A generic TLS 1.2 AEAD cipher.
 */
public class TlsAEADCipher
    implements TlsCipher
{
    public static final int AEAD_CCM = 1;
    public static final int AEAD_CHACHA20_POLY1305 = 2;
    public static final int AEAD_GCM = 3;

    private static final int NONCE_RFC5288 = 1;
    private static final int NONCE_RFC7905 = 2;

    protected final TlsCryptoParameters cryptoParams;
    protected final int macSize;
    // TODO SecurityParameters.record_iv_length
    protected final int record_iv_length;

    protected final TlsAEADCipherImpl decryptCipher, encryptCipher;

    protected final byte[] encryptImplicitNonce, decryptImplicitNonce;

    protected final boolean isTLSv13;
    protected final int nonceMode;

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher, TlsAEADCipherImpl decryptCipher,
        int cipherKeySize, int macSize, int aeadType) throws IOException
    {
        final ProtocolVersion serverVersion = cryptoParams.getServerVersion();

        if (!TlsImplUtils.isTLSv12(serverVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.isTLSv13 = TlsImplUtils.isTLSv13(serverVersion);
        this.nonceMode = getNonceMode(isTLSv13, aeadType);

        // TODO SecurityParameters.fixed_iv_length
        int fixed_iv_length;

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            fixed_iv_length = 4;
            this.record_iv_length = 8;
            break;
        case NONCE_RFC7905:
            fixed_iv_length = 12;
            this.record_iv_length = 0;
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.cryptoParams = cryptoParams;
        this.macSize = macSize;

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;

        TlsAEADCipherImpl clientCipher, serverCipher;
        if (cryptoParams.isServer())
        {
            clientCipher = decryptCipher;
            serverCipher = encryptCipher;
        }
        else
        {
            clientCipher = encryptCipher;
            serverCipher = decryptCipher;
        }

        int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

        byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);

        int offset = 0;

        clientCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;
        serverCipher.setKey(key_block, offset, cipherKeySize);
        offset += cipherKeySize;

        byte[] client_write_IV = TlsUtils.copyOfRangeExact(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;
        byte[] server_write_IV = TlsUtils.copyOfRangeExact(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (cryptoParams.isServer())
        {
            this.encryptImplicitNonce = server_write_IV;
            this.decryptImplicitNonce = client_write_IV;
        }
        else
        {
            this.encryptImplicitNonce = client_write_IV;
            this.decryptImplicitNonce = server_write_IV;
        }

        int nonceLength = fixed_iv_length + record_iv_length;

        // NOTE: Ensure dummy nonce is not part of the generated sequence
        byte[] dummyNonce = new byte[nonceLength];
        dummyNonce[0] = (byte)~encryptImplicitNonce[0];

        this.encryptCipher.init(dummyNonce, macSize, null);
        this.decryptCipher.init(dummyNonce, macSize, null);
    }

    public int getCiphertextDecodeLimit(int plaintextLimit)
    {
        return plaintextLimit + macSize + record_iv_length + (isTLSv13 ? 1 : 0);
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
    {
        int innerPlaintextLimit = plaintextLength;
        if (isTLSv13)
        {
            // TODO[tls13] Add support for padding
            int maxPadding = 0;

            innerPlaintextLimit = 1 + Math.min(plaintextLimit, plaintextLength + maxPadding);
        }

        return innerPlaintextLimit + macSize + record_iv_length;
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        return ciphertextLimit - macSize - record_iv_length - (isTLSv13 ? 1 : 0);
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException
    {
        byte[] nonce = new byte[encryptImplicitNonce.length + record_iv_length];

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            System.arraycopy(encryptImplicitNonce, 0, nonce, 0, encryptImplicitNonce.length);
            // RFC 5288/6655: The nonce_explicit MAY be the 64-bit sequence number.
            TlsUtils.writeUint64(seqNo, nonce, encryptImplicitNonce.length);
            break;
        case NONCE_RFC7905:
            TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
            for (int i = 0; i < encryptImplicitNonce.length; ++i)
            {
                nonce[i] ^= encryptImplicitNonce[i];
            }
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO[tls13] If we support adding padding to TLSInnerPlaintext, this will need review
        int encryptionLength = encryptCipher.getOutputSize(plaintextLength + (isTLSv13 ? 1 : 0));
        int ciphertextLength = record_iv_length + encryptionLength;

        byte[] output = new byte[headerAllocation + ciphertextLength];
        int outputPos = headerAllocation;

        if (record_iv_length != 0)
        {
            System.arraycopy(nonce, nonce.length - record_iv_length, output, outputPos, record_iv_length);
            outputPos += record_iv_length;
        }

        short recordType = isTLSv13 ? ContentType.application_data : contentType;

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength, plaintextLength);

        try
        {
            encryptCipher.init(nonce, macSize, additionalData);

            byte[] extraInput = isTLSv13 ? new byte[] { (byte)contentType } : TlsUtils.EMPTY_BYTES;

            outputPos += encryptCipher.doFinal(plaintext, plaintextOffset, plaintextLength, extraInput, output,
                outputPos);
        }
        catch (Exception e)
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
        if (getPlaintextLimit(ciphertextLength) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] nonce = new byte[decryptImplicitNonce.length + record_iv_length];

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            System.arraycopy(decryptImplicitNonce, 0, nonce, 0, decryptImplicitNonce.length);
            System.arraycopy(ciphertext, ciphertextOffset, nonce, nonce.length - record_iv_length, record_iv_length);
            break;
        case NONCE_RFC7905:
            TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
            for (int i = 0; i < decryptImplicitNonce.length; ++i)
            {
                nonce[i] ^= decryptImplicitNonce[i];
            }
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int encryptionOffset = ciphertextOffset + record_iv_length;
        int encryptionLength = ciphertextLength - record_iv_length;
        int plaintextLength = decryptCipher.getOutputSize(encryptionLength);

        byte[] additionalData = getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength, plaintextLength);

        int outputPos;
        try
        {
            decryptCipher.init(nonce, macSize, additionalData);
            outputPos = decryptCipher.doFinal(ciphertext, encryptionOffset, encryptionLength, TlsUtils.EMPTY_BYTES,
                ciphertext, encryptionOffset);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        if (outputPos != plaintextLength)
        {
            // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        short contentType = recordType;
        if (isTLSv13)
        {
            // Strip padding and read true content type from TLSInnerPlaintext
            int pos = plaintextLength;
            for (;;)
            {
                if (--pos < 0)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                byte octet = ciphertext[encryptionOffset + pos];
                if (0 != octet)
                {
                    contentType = (short)(octet & 0xFF);
                    plaintextLength = pos;
                    break;
                }
            }
        }

        return new TlsDecodeResult(ciphertext, encryptionOffset, plaintextLength, contentType);
    }

    protected byte[] getAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
        int ciphertextLength, int plaintextLength) throws IOException
    {
        if (isTLSv13)
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
