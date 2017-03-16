package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.util.Arrays;

/**
 * A generic TLS 1.2 AEAD cipher.
 */
public class TlsAEADCipher
    implements TlsCipher
{
    // TODO[draft-zauner-tls-aes-ocb-04] Apply data volume limit described in section 8.4

    public static final int NONCE_RFC5288 = 1;
    public static final int NONCE_RFC7905 = 2;

    protected TlsCryptoParameters context;
    protected int macSize;
    // TODO SecurityParameters.record_iv_length
    protected int record_iv_length;

    protected TlsAEADCipherImpl encryptor;
    protected TlsAEADCipherImpl decryptor;

    protected byte[] encryptImplicitNonce, decryptImplicitNonce;

    protected int nonceMode;

    public TlsAEADCipher(TlsCryptoParameters context, TlsAEADCipherImpl encryptor, TlsAEADCipherImpl decryptor,
        int cipherKeySize, int macSize) throws IOException
    {
        this(context, encryptor, decryptor, cipherKeySize, macSize, NONCE_RFC5288);
    }

    public TlsAEADCipher(TlsCryptoParameters context, TlsAEADCipherImpl encryptor, TlsAEADCipherImpl decryptor,
        int cipherKeySize, int macSize, int nonceMode) throws IOException
    {
        if (!TlsImplUtils.isTLSv12(context))
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

        this.context = context;
        this.macSize = macSize;

        int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

        byte[] key_block = TlsImplUtils.calculateKeyBlock(context, key_block_size);

        int offset = 0;

        byte[] client_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] server_write_key = Arrays.copyOfRange(key_block, offset, offset + cipherKeySize);
        offset += cipherKeySize;
        byte[] client_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;
        byte[] server_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;

        if (offset != key_block_size)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.encryptor = encryptor;
        this.decryptor = decryptor;
        if (context.isServer())
        {
            this.encryptImplicitNonce = server_write_IV;
            this.decryptImplicitNonce = client_write_IV;
            encryptor.setKey(server_write_key);
            decryptor.setKey(client_write_key);
        }
        else
        {
            this.encryptImplicitNonce = client_write_IV;
            this.decryptImplicitNonce = server_write_IV;
            encryptor.setKey(client_write_key);
            decryptor.setKey(server_write_key);
        }

        byte[] dummyNonce = new byte[fixed_iv_length + record_iv_length];

        this.encryptor.init(dummyNonce, macSize, null);
        this.decryptor.init(dummyNonce, macSize, null);
    }

    public int getPlaintextLimit(int ciphertextLimit)
    {
        // TODO We ought to be able to ask the decryptCipher (independently of it's current state!)
        return ciphertextLimit - macSize - record_iv_length;
    }

    public byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
        throws IOException
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
        int ciphertextLength = encryptor.getOutputSize(plaintextLength);

        byte[] output = new byte[record_iv_length + ciphertextLength];
        if (record_iv_length != 0)
        {
            System.arraycopy(nonce, nonce.length - record_iv_length, output, 0, record_iv_length);
        }
        int outputPos = record_iv_length;

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);

        try
        {
            encryptor.init(nonce, macSize, additionalData);
            outputPos += encryptor.doFinal(plaintext, plaintextOffset, plaintextLength, output, outputPos);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        if (outputPos != output.length)
        {
            // NOTE: Existing AEAD cipher implementations all give exact output lengths
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return output;
    }

    public byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
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
        int plaintextLength = decryptor.getOutputSize(ciphertextLength);

        byte[] output = new byte[plaintextLength];
        int outputPos = 0;

        byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);

        try
        {
            decryptor.init(nonce, macSize, additionalData);
            outputPos += decryptor.doFinal(ciphertext, ciphertextOffset, ciphertextLength, output, outputPos);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        if (outputPos != output.length)
        {
            // NOTE: Existing AEAD cipher implementations all give exact output lengths
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return output;
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
        TlsUtils.writeVersion(context.getServerVersion(), additional_data, 9);
        TlsUtils.writeUint16(len, additional_data, 11);

        return additional_data;
    }
}
