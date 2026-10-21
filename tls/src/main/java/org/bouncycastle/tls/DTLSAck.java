package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

/**
 * RFC 9147 7. The ACK message, carried in its own content type rather than as a handshake message so
 * that it is not added to the handshake transcript.
 * <pre>
 * struct {
 *     RecordNumber record_numbers&lt;0..2^16-1&gt;;
 * } ACK;
 * </pre>
 */
class DTLSAck
{
    /** The wire size of one RecordNumber: two uint64. */
    static final int RECORD_NUMBER_LENGTH = 16;

    /**
     * Encode a list of {@link DTLSRecordNumber} as an ACK body. An empty list is valid (RFC 9147 7.1).
     */
    static byte[] encode(Vector recordNumbers) throws IOException
    {
        int count = recordNumbers.size();
        int bodyLength = count * RECORD_NUMBER_LENGTH;
        TlsUtils.checkUint16(bodyLength);

        byte[] buf = new byte[2 + bodyLength];
        TlsUtils.writeUint16(bodyLength, buf, 0);

        int pos = 2;
        for (int i = 0; i < count; ++i)
        {
            DTLSRecordNumber recordNumber = (DTLSRecordNumber)recordNumbers.elementAt(i);
            TlsUtils.writeUint64(recordNumber.getEpoch(), buf, pos);
            TlsUtils.writeUint64(recordNumber.getSequenceNumber(), buf, pos + 8);
            pos += RECORD_NUMBER_LENGTH;
        }

        return buf;
    }

    /**
     * Decode an ACK body.
     *
     * @return the record numbers in wire order, or null if the body is malformed. A malformed ACK is
     *         discarded rather than failing the connection (RFC 9147 4.5.2).
     */
    static Vector decode(byte[] buf, int off, int len) throws IOException
    {
        if (len < 2)
        {
            return null;
        }

        int bodyLength = TlsUtils.readUint16(buf, off);
        if (bodyLength != len - 2 || (bodyLength % RECORD_NUMBER_LENGTH) != 0)
        {
            return null;
        }

        Vector recordNumbers = new Vector();

        int pos = off + 2;
        int count = bodyLength / RECORD_NUMBER_LENGTH;
        for (int i = 0; i < count; ++i)
        {
            long epoch = TlsUtils.readUint64(buf, pos);
            long sequenceNumber = TlsUtils.readUint64(buf, pos + 8);
            recordNumbers.addElement(new DTLSRecordNumber(epoch, sequenceNumber));
            pos += RECORD_NUMBER_LENGTH;
        }

        return recordNumbers;
    }
}
