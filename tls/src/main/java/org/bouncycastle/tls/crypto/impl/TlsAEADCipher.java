package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDecodeResult;

/**
 * A generic TLS 1.2 AEAD cipher.
 */
public class TlsAEADCipher
    implements TlsCipher
{
    public static final int NONCE_RFC5288 = 1;
    public static final int NONCE_RFC7905 = 2;

    protected final TlsCryptoParameters cryptoParams;
    protected final int macSize;
    // TODO SecurityParameters.record_iv_length
    protected final int record_iv_length;

    protected final TlsAEADCipherImpl decryptCipher, encryptCipher;

    protected final byte[] encryptImplicitNonce, decryptImplicitNonce;

    protected final int nonceMode;

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher, TlsAEADCipherImpl decryptCipher,
        int cipherKeySize, int macSize) throws IOException
    {
        this(cryptoParams, encryptCipher, decryptCipher, cipherKeySize, macSize, NONCE_RFC5288);
    }

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher, TlsAEADCipherImpl decryptCipher,
        int cipherKeySize, int macSize, int nonceMode) throws IOException
    {
        if (!TlsImplUtils.isTLSv12(cryptoParams))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.nonceMode = nonceMode;

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

        byte[] dummyNonce = new byte[fixed_iv_length + record_iv_length];

        this.encryptCipher.init(dummyNonce, macSize, null);
        this.decryptCipher.init(dummyNonce, macSize, null);
    }

    public int getCiphertextLimit(int plaintextLimit)
    {
        return plaintextLimit + macSize + record_iv_length;
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        // TODO We ought to be able to ask the decryptCipher (independently of it's current state!)
        return ciphertextLimit - macSize - record_iv_length;
    }

    public byte[] encodePlaintext(long seqNo, short contentType, int headerAllocation, byte[] plaintext, int offset,
        int len) throws IOException
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

        int plaintextOffset = offset;
        int plaintextLength = len;
        int ciphertextLength = encryptCipher.getOutputSize(plaintextLength);

        byte[] output = new byte[headerAllocation + record_iv_length + ciphertextLength];
        int outputPos = headerAllocation;

        if (record_iv_length != 0)
        {
            System.arraycopy(nonce, nonce.length - record_iv_length, output, outputPos, record_iv_length);
            outputPos += record_iv_length;
        }

        byte[] additionalData = getAdditionalData(seqNo, contentType, plaintextLength);

        try
        {
            encryptCipher.init(nonce, macSize, additionalData);
            outputPos += encryptCipher.doFinal(plaintext, plaintextOffset, plaintextLength, output, outputPos);
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

        return output;
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short contentType, byte[] ciphertext, int offset, int len)
        throws IOException
    {
        if (getPlaintextLimit(len) < 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        byte[] nonce = new byte[decryptImplicitNonce.length + record_iv_length];

        switch (nonceMode)
        {
        case NONCE_RFC5288:
            System.arraycopy(decryptImplicitNonce, 0, nonce, 0, decryptImplicitNonce.length);
            System.arraycopy(ciphertext, offset, nonce, nonce.length - record_iv_length, record_iv_length);
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

        int ciphertextOffset = offset + record_iv_length;
        int ciphertextLength = len - record_iv_length;
        int plaintextLength = decryptCipher.getOutputSize(ciphertextLength);
        byte[] additionalData = getAdditionalData(seqNo, contentType, plaintextLength);

        int outputPos;
        try
        {
            decryptCipher.init(nonce, macSize, additionalData);
            outputPos = decryptCipher.doFinal(ciphertext, ciphertextOffset, ciphertextLength, ciphertext, ciphertextOffset);
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

        // TODO[tls13] Strip padding and read true content type
        return new TlsDecodeResult(ciphertext, ciphertextOffset, plaintextLength, contentType);
    }

    protected byte[] getAdditionalData(long seqNo, short type, int len)
        throws IOException
    {
        /*
         * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
         * TLSCompressed.length
         */

        byte[] additional_data = new byte[13];
        TlsUtils.writeUint64(seqNo, additional_data, 0);
        TlsUtils.writeUint8(type, additional_data, 8);
        TlsUtils.writeVersion(cryptoParams.getServerVersion(), additional_data, 9);
        TlsUtils.writeUint16(len, additional_data, 11);

        return additional_data;
    }
}
