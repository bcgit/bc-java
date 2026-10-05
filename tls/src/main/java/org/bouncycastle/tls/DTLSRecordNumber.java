package org.bouncycastle.tls;

/**
 * RFC 9147 4. An unpacked record number: the epoch and sequence number of a single DTLS record.
 * <pre>
 * struct {
 *     uint64 epoch;
 *     uint64 sequence_number;
 * } RecordNumber;
 * </pre>
 * Used in the ACK message (RFC 9147 7) and to track which record carried which handshake fragment.
 */
final class DTLSRecordNumber
{
    private final long epoch;
    private final long sequenceNumber;

    DTLSRecordNumber(long epoch, long sequenceNumber)
    {
        this.epoch = epoch;
        this.sequenceNumber = sequenceNumber;
    }

    long getEpoch()
    {
        return epoch;
    }

    long getSequenceNumber()
    {
        return sequenceNumber;
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof DTLSRecordNumber))
        {
            return false;
        }

        DTLSRecordNumber that = (DTLSRecordNumber)other;
        return this.epoch == that.epoch && this.sequenceNumber == that.sequenceNumber;
    }

    public int hashCode()
    {
        long value = epoch * 31 + sequenceNumber;
        return (int)(value ^ (value >>> 32));
    }

    public String toString()
    {
        return "epoch " + epoch + " seq " + sequenceNumber;
    }
}
