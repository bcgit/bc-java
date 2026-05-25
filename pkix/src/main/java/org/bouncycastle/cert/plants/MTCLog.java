package org.bouncycastle.cert.plants;

import org.bouncycastle.util.Arrays;

/**
 * Immutable identifier for an MTC issuance-log subtree window: the CA that
 * operates the log, the log number (the upper 16 bits of the cert serial per
 * Section 6.1 of draft-ietf-plants-merkle-tree-certs) and the subtree's
 * {@code [start, end)} index range (uint48). The bound {@link MTCCertAuth}
 * lets the log derive its own binary trust anchor ID via
 * {@link #getLogId()}, so callers can pass a single {@code MTCLog} where they
 * previously had to thread {@code (ca, logNumber, start, end)} separately.
 */
public class MTCLog
{
    private final MTCCertAuth ca;
    private final long logNumber;
    private final long start;
    private final long end;

    /**
     * @param ca        CA that operates this issuance log
     * @param logNumber log number ({@code 1 <= logNumber <= 2^16-1}, Section 5.2)
     * @param start     subtree start index ({@code 0 <= start <= 2^48-1})
     * @param end       subtree end index ({@code 0 <= end <= 2^48-1})
     */
    public MTCLog(MTCCertAuth ca, long logNumber, long start, long end)
    {
        if (ca == null)
        {
            throw new NullPointerException("ca cannot be null");
        }
        if (logNumber < 1 || logNumber > 0xFFFFL)
        {
            throw new IllegalArgumentException("log_number out of range [1, 65535]: " + logNumber);
        }
        if (start < 0 || start > 0xFFFFFFFFFFFFL)
        {
            throw new IllegalArgumentException("start out of uint48 range: " + start);
        }
        if (end < 0 || end > 0xFFFFFFFFFFFFL)
        {
            throw new IllegalArgumentException("end out of uint48 range: " + end);
        }
        this.ca = ca;
        this.logNumber = logNumber;
        this.start = start;
        this.end = end;
    }

    /** @return the CA that operates this log. */
    public MTCCertAuth getCa()
    {
        return ca;
    }

    public long getLogNumber()
    {
        return logNumber;
    }

    public long getStart()
    {
        return start;
    }

    public long getEnd()
    {
        return end;
    }

    /** @return the binary trust anchor ID of this log (Section 5.2). */
    public byte[] getLogId()
    {
        return ca.logId(logNumber);
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof MTCLog))
        {
            return false;
        }
        MTCLog other = (MTCLog)o;
        return logNumber == other.logNumber
            && start == other.start
            && end == other.end
            && Arrays.areEqual(ca.getCaId(), other.ca.getCaId());
    }

    public int hashCode()
    {
        int h = Arrays.hashCode(ca.getCaId());
        h = 31 * h + (int)(logNumber ^ (logNumber >>> 32));
        h = 31 * h + (int)(start ^ (start >>> 32));
        h = 31 * h + (int)(end ^ (end >>> 32));
        return h;
    }

    public String toString()
    {
        return "MTCLog{ca=" + ca.getDottedCaId() + ", log=" + logNumber
            + ", [" + start + ", " + end + ")}";
    }
}
