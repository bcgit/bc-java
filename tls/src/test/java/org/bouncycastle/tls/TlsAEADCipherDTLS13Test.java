package org.bouncycastle.tls;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 4: DTLS 1.3 record protection in TlsAEADCipher. The unified header is the AEAD additional data, the
 * nonce uses the 64-bit sequence number without the epoch, the sequence number bytes are masked, and short
 * ciphertexts are padded to (and rejected below) 16 bytes.
 */
public class TlsAEADCipherDTLS13Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    // 0b001 fixed bits, S = 1 (16-bit seq), L = 1 (length present), epoch bits = 3
    private static final int HDR_EPOCH3 = 0x2C | 0x03;

    static AbstractTlsContext createContext(TlsCrypto crypto, boolean server, int cipherSuite, int hash,
        byte[] clientSecret, byte[] serverSecret) throws IOException
    {
        AbstractTlsContext context = server ? (AbstractTlsContext)new TlsServerContextImpl(crypto)
            : (AbstractTlsContext)new TlsClientContextImpl(crypto);

        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };

        context.handshakeBeginning(peer);

        SecurityParameters sp = context.getSecurityParametersHandshake();
        sp.negotiatedVersion = ProtocolVersion.DTLSv13;
        sp.cipherSuite = cipherSuite;
        sp.prfCryptoHashAlgorithm = hash;
        sp.trafficSecretClient = crypto.createSecret(clientSecret);
        sp.trafficSecretServer = crypto.createSecret(serverSecret);
        return context;
    }

    static byte[] header(int firstByte, long seq)
    {
        byte[] header = new byte[5];
        header[0] = (byte)firstByte;
        TlsUtils.writeUint16((int)(seq & 0xFFFF), header, 1);
        TlsUtils.writeUint16(0, header, 3);
        return header;
    }

    /**
     * A unified header in whichever of the four RFC 9147 4 forms 'firstByte' selects (no connection ID). Any
     * length field is left zero for the cipher to fill in.
     */
    static byte[] compactHeader(int firstByte, long seq)
    {
        boolean seq16 = DTLS13UnifiedHeader.hasSeq16(firstByte);
        boolean hasLength = DTLS13UnifiedHeader.hasLength(firstByte);

        byte[] header = new byte[1 + (seq16 ? 2 : 1) + (hasLength ? 2 : 0)];
        header[0] = (byte)firstByte;
        if (seq16)
        {
            TlsUtils.writeUint16((int)(seq & 0xFFFFL), header, 1);
        }
        else
        {
            TlsUtils.writeUint8((int)(seq & 0xFFL), header, 1);
        }
        return header;
    }

    private static TlsDTLS13Cipher[] createPair(TlsCrypto crypto, int cipherSuite, int hash) throws IOException
    {
        byte[] clientSecret = new byte[48];
        byte[] serverSecret = new byte[48];
        RANDOM.nextBytes(clientSecret);
        RANDOM.nextBytes(serverSecret);

        AbstractTlsContext client = createContext(crypto, false, cipherSuite, hash, clientSecret, serverSecret);
        AbstractTlsContext server = createContext(crypto, true, cipherSuite, hash, clientSecret, serverSecret);

        return new TlsDTLS13Cipher[]{ (TlsDTLS13Cipher)TlsUtils.initCipher(client),
            (TlsDTLS13Cipher)TlsUtils.initCipher(server) };
    }

    private void implTestRoundTrip(TlsCrypto crypto, int cipherSuite, int hash, int plaintextLen) throws IOException
    {
        TlsDTLS13Cipher[] pair = createPair(crypto, cipherSuite, hash);
        TlsDTLS13Cipher clientCipher = pair[0], serverCipher = pair[1];

        byte[] plaintext = new byte[plaintextLen];
        RANDOM.nextBytes(plaintext);
        long seq = 0x123456L;

        byte[] header = header(HDR_EPOCH3, seq);
        TlsEncodeResult encoded = clientCipher.encodeDTLS13Plaintext(seq, ContentType.application_data, header, 0,
            header.length, plaintext, 0, plaintext.length);

        assertEquals(HDR_EPOCH3, encoded.recordType);
        assertEquals(HDR_EPOCH3, encoded.buf[encoded.off] & 0xFF);

        int ciphertextLen = TlsUtils.readUint16(encoded.buf, encoded.off + 3);
        assertEquals(encoded.len, 5 + ciphertextLen);
        assertTrue("ciphertext must be at least 16 bytes", ciphertextLen >= 16);

        byte[] record = Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len);

        serverCipher.decryptDTLS13RecordNumber(record, 0, record.length);
        assertEquals((int)(seq & 0xFFFF), TlsUtils.readUint16(record, 1));

        TlsDecodeResult decoded = serverCipher.decodeDTLS13Ciphertext(seq, record, 0, 5, ciphertextLen);
        assertEquals(ContentType.application_data, decoded.contentType);
        assertEquals(plaintextLen, decoded.len);
        assertTrue(Arrays.areEqual(plaintext, Arrays.copyOfRange(decoded.buf, decoded.off, decoded.off + decoded.len)));
    }

    public void testRoundTripAES128GCM() throws Exception
    {
        implTestRoundTrip(new BcTlsCrypto(), CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, 100);
        implTestRoundTrip(new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(RANDOM), CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256, 100);
    }

    public void testRoundTripAES256GCM() throws Exception
    {
        implTestRoundTrip(new BcTlsCrypto(), CipherSuite.TLS_AES_256_GCM_SHA384, CryptoHashAlgorithm.sha384, 1000);
    }

    public void testRoundTripChaCha20() throws Exception
    {
        implTestRoundTrip(new BcTlsCrypto(), CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CryptoHashAlgorithm.sha256, 33);
        implTestRoundTrip(new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(RANDOM), CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CryptoHashAlgorithm.sha256, 33);
    }

    public void testShortPlaintextIsPaddedForCCM8() throws Exception
    {
        // 1 byte content + 1 byte type + 8 byte tag = 10 bytes; RFC 9147 4.2.3 requires padding to 16
        implTestRoundTrip(new BcTlsCrypto(), CipherSuite.TLS_AES_128_CCM_8_SHA256, CryptoHashAlgorithm.sha256, 1);
        implTestRoundTrip(new BcTlsCrypto(), CipherSuite.TLS_AES_128_CCM_8_SHA256, CryptoHashAlgorithm.sha256, 0);
    }

    public void testMaskDiffersFromClearSequenceNumber() throws Exception
    {
        TlsDTLS13Cipher[] pair = createPair(new BcTlsCrypto(), CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256);
        boolean anyMasked = false;
        for (long seq = 0; seq < 8; ++seq)
        {
            byte[] header = header(HDR_EPOCH3, seq);
            TlsEncodeResult encoded = pair[0].encodeDTLS13Plaintext(seq, ContentType.application_data, header, 0,
                header.length, new byte[20], 0, 20);
            if (TlsUtils.readUint16(encoded.buf, encoded.off + 1) != seq)
            {
                anyMasked = true;
            }
        }
        assertTrue("sequence numbers were never masked", anyMasked);
    }

    public void testTamperedHeaderFailsAuthentication() throws Exception
    {
        TlsDTLS13Cipher[] pair = createPair(new BcTlsCrypto(), CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256);
        long seq = 7;
        byte[] header = header(HDR_EPOCH3, seq);
        TlsEncodeResult encoded = pair[0].encodeDTLS13Plaintext(seq, ContentType.handshake, header, 0, header.length,
            new byte[40], 0, 40);
        byte[] record = Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len);
        pair[1].decryptDTLS13RecordNumber(record, 0, record.length);

        // flip an epoch bit in the header: AAD changes, so authentication must fail
        record[0] ^= 0x01;
        try
        {
            pair[1].decodeDTLS13Ciphertext(seq, record, 0, 5, record.length - 5);
            fail("expected bad_record_mac");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.bad_record_mac, e.getAlertDescription());
        }
    }

    public void testShortRecordIsRejected() throws Exception
    {
        TlsDTLS13Cipher[] pair = createPair(new BcTlsCrypto(), CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256);
        byte[] record = new byte[5 + 15];
        record[0] = (byte)HDR_EPOCH3;
        try
        {
            pair[1].decryptDTLS13RecordNumber(record, 0, record.length);
            fail("expected decode_error");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.decode_error, e.getAlertDescription());
        }
        try
        {
            pair[1].decodeDTLS13Ciphertext(0, record, 0, 5, 15);
            fail("expected decode_error");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.decode_error, e.getAlertDescription());
        }
    }

    public void testNonDTLS13CipherRejectsDTLS13Calls() throws Exception
    {
        TlsCrypto crypto = new BcTlsCrypto();
        AbstractTlsContext context = createContext(crypto, false, CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
        // same cipher class, but a non-DTLS-1.3 version must refuse all three DTLS 1.3 entry points
        context.getSecurityParametersHandshake().negotiatedVersion = ProtocolVersion.TLSv13;
        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)TlsUtils.initCipher(context);
        try
        {
            cipher.encodeDTLS13Plaintext(0, ContentType.application_data, header(HDR_EPOCH3, 0), 0, 5, new byte[20],
                0, 20);
            fail("expected internal_error");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
        try
        {
            cipher.decryptDTLS13RecordNumber(new byte[32], 0, 32);
            fail("expected internal_error");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
        try
        {
            cipher.decodeDTLS13Ciphertext(0, new byte[32], 0, 5, 27);
            fail("expected internal_error");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }

    private void implTestCompactRoundTrip(int firstByte, int plaintextLen) throws IOException
    {
        TlsDTLS13Cipher[] pair = createPair(new BcTlsCrypto(), CipherSuite.TLS_AES_128_GCM_SHA256,
            CryptoHashAlgorithm.sha256);

        byte[] plaintext = new byte[plaintextLen];
        RANDOM.nextBytes(plaintext);
        long seq = 0x4BL;

        byte[] header = compactHeader(firstByte, seq);
        int headerLen = header.length;
        assertEquals(DTLS13UnifiedHeader.getHeaderLength(firstByte, 0), headerLen);

        TlsEncodeResult encoded = pair[0].encodeDTLS13Plaintext(seq, ContentType.application_data, header, 0,
            headerLen, plaintext, 0, plaintext.length);
        assertEquals(firstByte, encoded.recordType);

        byte[] record = Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len);

        // With no length field the receiver takes the ciphertext as the rest of the datagram
        int ciphertextLen = record.length - headerLen;
        assertTrue("ciphertext must be at least 16 bytes", ciphertextLen >= 16);
        if (DTLS13UnifiedHeader.hasLength(firstByte))
        {
            assertEquals(ciphertextLen, TlsUtils.readUint16(record, headerLen - 2));
        }

        pair[1].decryptDTLS13RecordNumber(record, 0, record.length);
        if (DTLS13UnifiedHeader.hasSeq16(firstByte))
        {
            assertEquals((int)(seq & 0xFFFFL), TlsUtils.readUint16(record, 1));
        }
        else
        {
            assertEquals((int)(seq & 0xFFL), TlsUtils.readUint8(record, 1));
        }

        TlsDecodeResult decoded = pair[1].decodeDTLS13Ciphertext(seq, record, 0, headerLen, ciphertextLen);
        assertEquals(ContentType.application_data, decoded.contentType);
        assertEquals(plaintextLen, decoded.len);
        assertTrue(Arrays.areEqual(plaintext, Arrays.copyOfRange(decoded.buf, decoded.off, decoded.off + decoded.len)));
    }

    public void testRoundTripCompactHeaders() throws Exception
    {
        // S = 0, L = 1: 8-bit sequence number, length present (4-byte header)
        implTestCompactRoundTrip(0x24 | 0x03, 60);
        // S = 1, L = 0: 16-bit sequence number, no length (3-byte header)
        implTestCompactRoundTrip(0x28 | 0x03, 60);
        // S = 0, L = 0: the minimal 2-byte header
        implTestCompactRoundTrip(0x20 | 0x03, 60);
        // short plaintexts must still be padded up to a 16-byte ciphertext
        implTestCompactRoundTrip(0x20 | 0x03, 0);
    }
}
