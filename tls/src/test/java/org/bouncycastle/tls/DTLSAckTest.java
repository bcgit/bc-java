package org.bouncycastle.tls;

import java.util.Vector;

import junit.framework.TestCase;

/**
 * RFC 9147 7: the ACK message is a uint16-prefixed list of RecordNumber { uint64 epoch; uint64 sequence_number }.
 */
public class DTLSAckTest
    extends TestCase
{
    public void testEmptyAckRoundTrips() throws Exception
    {
        // RFC 9147 7.1: an ACK carrying no record numbers is legal and is used to shortcut retransmission
        byte[] encoded = DTLSAck.encode(new Vector());
        assertEquals(2, encoded.length);
        assertEquals(0, TlsUtils.readUint16(encoded, 0));

        Vector decoded = DTLSAck.decode(encoded, 0, encoded.length);
        assertNotNull(decoded);
        assertEquals(0, decoded.size());
    }

    public void testRoundTripPreservesOrderAndValues() throws Exception
    {
        Vector in = new Vector();
        in.addElement(new DTLSRecordNumber(2, 0));
        in.addElement(new DTLSRecordNumber(2, 1));
        in.addElement(new DTLSRecordNumber(3, 0x0000FFFFFFFFFFFFL));

        byte[] encoded = DTLSAck.encode(in);
        assertEquals(2 + 3 * 16, encoded.length);
        assertEquals(3 * 16, TlsUtils.readUint16(encoded, 0));

        Vector out = DTLSAck.decode(encoded, 0, encoded.length);
        assertNotNull(out);
        assertEquals(3, out.size());
        for (int i = 0; i < 3; ++i)
        {
            assertEquals(in.elementAt(i), out.elementAt(i));
        }

        DTLSRecordNumber last = (DTLSRecordNumber)out.elementAt(2);
        assertEquals(3L, last.getEpoch());
        assertEquals(0x0000FFFFFFFFFFFFL, last.getSequenceNumber());
    }

    public void testDecodeAtOffset() throws Exception
    {
        Vector in = new Vector();
        in.addElement(new DTLSRecordNumber(4, 7));
        byte[] encoded = DTLSAck.encode(in);

        byte[] padded = new byte[5 + encoded.length];
        System.arraycopy(encoded, 0, padded, 5, encoded.length);

        Vector out = DTLSAck.decode(padded, 5, encoded.length);
        assertNotNull(out);
        assertEquals(1, out.size());
        assertEquals(new DTLSRecordNumber(4, 7), out.elementAt(0));
    }

    public void testMalformedInputsDecodeToNull() throws Exception
    {
        assertNull("truncated length prefix", DTLSAck.decode(new byte[]{ 0 }, 0, 1));
        assertNull("length prefix exceeds buffer", DTLSAck.decode(new byte[]{ 0, 32, 0, 0 }, 0, 4));

        byte[] trailing = new byte[2 + 16 + 1];
        TlsUtils.writeUint16(16, trailing, 0);
        assertNull("trailing bytes", DTLSAck.decode(trailing, 0, trailing.length));

        byte[] notMultiple = new byte[2 + 8];
        TlsUtils.writeUint16(8, notMultiple, 0);
        assertNull("body not a multiple of 16", DTLSAck.decode(notMultiple, 0, notMultiple.length));
    }

    public void testRecordNumberEqualityAndHashing()
    {
        DTLSRecordNumber a = new DTLSRecordNumber(2, 5);
        DTLSRecordNumber b = new DTLSRecordNumber(2, 5);
        DTLSRecordNumber differentSeq = new DTLSRecordNumber(2, 6);
        DTLSRecordNumber differentEpoch = new DTLSRecordNumber(3, 5);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertFalse(a.equals(differentSeq));
        assertFalse(a.equals(differentEpoch));
        assertFalse(a.equals(null));
        assertFalse(a.equals("not a record number"));

        // usable as a Hashtable key, which is how the flight tracker retires fragments
        java.util.Hashtable table = new java.util.Hashtable();
        table.put(a, "value");
        assertEquals("value", table.get(b));
    }

    public void testReadUint64RoundTrip()
    {
        byte[] buf = new byte[8];
        TlsUtils.writeUint64(0x0123456789ABCDEFL, buf, 0);
        assertEquals(0x0123456789ABCDEFL, TlsUtils.readUint64(buf, 0));

        TlsUtils.writeUint64(0L, buf, 0);
        assertEquals(0L, TlsUtils.readUint64(buf, 0));

        TlsUtils.writeUint64(-1L, buf, 0);
        assertEquals(-1L, TlsUtils.readUint64(buf, 0));
    }
}
