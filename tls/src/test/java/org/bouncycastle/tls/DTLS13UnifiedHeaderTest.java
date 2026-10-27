package org.bouncycastle.tls;

import junit.framework.TestCase;

/**
 * RFC 9147 4 unified header (0b001CSLEE) and 4.2.2 sequence number reconstruction.
 */
public class DTLS13UnifiedHeaderTest
    extends TestCase
{
    public void testFixedBits()
    {
        assertTrue(DTLS13UnifiedHeader.isCiphertextRecord(0x20));
        assertTrue(DTLS13UnifiedHeader.isCiphertextRecord(0x3F));
        assertFalse(DTLS13UnifiedHeader.isCiphertextRecord(ContentType.handshake));
        assertFalse(DTLS13UnifiedHeader.isCiphertextRecord(ContentType.alert));
        assertFalse(DTLS13UnifiedHeader.isCiphertextRecord(ContentType.ack));
        assertFalse(DTLS13UnifiedHeader.isCiphertextRecord(0x40));
    }

    public void testHeaderLengths()
    {
        assertEquals(2, DTLS13UnifiedHeader.getHeaderLength(0x20, 0));   // minimal: 8-bit seq, no length
        assertEquals(3, DTLS13UnifiedHeader.getHeaderLength(0x28, 0));   // 16-bit seq
        assertEquals(4, DTLS13UnifiedHeader.getHeaderLength(0x24, 0));   // 8-bit seq + length
        assertEquals(5, DTLS13UnifiedHeader.getHeaderLength(0x2C, 0));   // full
        assertEquals(9, DTLS13UnifiedHeader.getHeaderLength(0x3C, 4));   // full + 4-byte CID
        assertEquals(5, DTLS13UnifiedHeader.getWriteHeaderLength(0));
        assertEquals(9, DTLS13UnifiedHeader.getWriteHeaderLength(4));
        // the receive limit must budget for the smallest header a peer may send, not for our write form
        assertEquals(2, DTLS13UnifiedHeader.getMinReadHeaderLength(0));
        assertEquals(6, DTLS13UnifiedHeader.getMinReadHeaderLength(4));
        assertEquals(DTLS13UnifiedHeader.getHeaderLength(0x20, 0), DTLS13UnifiedHeader.getMinReadHeaderLength(0));
        assertEquals(DTLS13UnifiedHeader.getHeaderLength(0x30, 4), DTLS13UnifiedHeader.getMinReadHeaderLength(4));
        assertEquals(1, DTLS13UnifiedHeader.getSequenceNumberLength(0x20));
        assertEquals(2, DTLS13UnifiedHeader.getSequenceNumberLength(0x28));
    }

    public void testWriteHeaderFullForm()
    {
        byte[] buf = new byte[5];
        int len = DTLS13UnifiedHeader.writeHeader(3, 0x123456L, null, buf, 0);
        assertEquals(5, len);
        assertEquals(0x2F, buf[0] & 0xFF);                 // 001 0 1 1 11
        assertEquals(0x3456, TlsUtils.readUint16(buf, 1)); // low 16 bits of seq
        assertEquals(0, TlsUtils.readUint16(buf, 3));      // length left for the cipher
        assertTrue(DTLS13UnifiedHeader.hasSeq16(buf[0] & 0xFF));
        assertTrue(DTLS13UnifiedHeader.hasLength(buf[0] & 0xFF));
        assertFalse(DTLS13UnifiedHeader.hasConnectionID(buf[0] & 0xFF));
        assertTrue(DTLS13UnifiedHeader.matchesEpoch(buf[0] & 0xFF, 3));
        assertTrue(DTLS13UnifiedHeader.matchesEpoch(buf[0] & 0xFF, 7));
        assertFalse(DTLS13UnifiedHeader.matchesEpoch(buf[0] & 0xFF, 2));

        byte[] cid = new byte[]{ 1, 2, 3 };
        byte[] buf2 = new byte[8];
        assertEquals(8, DTLS13UnifiedHeader.writeHeader(2, 5, cid, buf2, 0));
        assertEquals(0x3E, buf2[0] & 0xFF);                // C bit set, epoch bits 10
        assertEquals(1, buf2[1]);
        assertEquals(3, buf2[3]);
        assertEquals(5, TlsUtils.readUint16(buf2, 4));
    }

    public void testReconstructSequenceNumber()
    {
        // fresh epoch: expected 0
        assertEquals(5L, DTLS13UnifiedHeader.reconstructSequenceNumber(0, 5, 8));
        // exact match in the current window
        assertEquals(300L, DTLS13UnifiedHeader.reconstructSequenceNumber(300, 0x2C, 8));
        // wrap forward: expected 0x1FE, bits 0x02 -> 0x202 is closer than 0x102
        assertEquals(0x202L, DTLS13UnifiedHeader.reconstructSequenceNumber(0x1FE, 0x02, 8));
        // wrap backward: expected 0x203, bits 0xFE -> 0x1FE is closer than 0x2FE
        assertEquals(0x1FEL, DTLS13UnifiedHeader.reconstructSequenceNumber(0x203, 0xFE, 8));
        // 16-bit variants
        assertEquals(0x1FFFEL, DTLS13UnifiedHeader.reconstructSequenceNumber(0x20003, 0xFFFE, 16));
        assertEquals(0x20002L, DTLS13UnifiedHeader.reconstructSequenceNumber(0x1FFFE, 0x0002, 16));
        // never negative
        assertEquals(0xFEL, DTLS13UnifiedHeader.reconstructSequenceNumber(3, 0xFE, 8));
        // never above 2^48 - 1
        long top = (1L << 48) - 3;
        assertEquals(top, DTLS13UnifiedHeader.reconstructSequenceNumber(top, (int)(top & 0xFF), 8));
    }

    public void testReplayWindowExposesLatestConfirmed()
    {
        DTLSReplayWindow w = new DTLSReplayWindow();
        assertEquals(-1L, w.getLatestConfirmedSeq());
        assertTrue(w.reportAuthenticated(10));
        assertEquals(10L, w.getLatestConfirmedSeq());
        assertFalse(w.reportAuthenticated(4));
        assertEquals(10L, w.getLatestConfirmedSeq());
    }
}
