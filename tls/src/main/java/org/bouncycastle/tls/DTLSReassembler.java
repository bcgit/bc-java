package org.bouncycastle.tls;

import java.util.Vector;

class DTLSReassembler
{
    /*
     * Bounds the number of gaps tracked for one message.
     * <p>
     * Limits the amount of fragmentation a malicious peer can cause. While at the limit a fragment that would
     * split a range is ignored; retransmission is then relied on to complete the message.
     */
    private static final int MIN_MISSING_RANGES_LIMIT = 64;

    /*
     * No 'final' modifiers so that it works in earlier JDKs
     */
    private short msg_type;
    private byte[] body;
    private int maxMissingRanges;

    private Vector missing = new Vector();

    DTLSReassembler(short msg_type, int length)
    {
        this.msg_type = msg_type;
        this.body = new byte[length];
        this.maxMissingRanges = Math.max(MIN_MISSING_RANGES_LIMIT, length / 1024);
        this.missing.addElement(new Range(0, length));
    }

    short getMsgType()
    {
        return msg_type;
    }

    byte[] getBodyIfComplete()
    {
        return missing.isEmpty() ? body : null;
    }

    /**
     * @return the offset of the first byte of this message that has not been received yet, or -1 once the
     *         message is complete. Supports the RFC 9147 7.1 out-of-order ACK trigger: a fragment that does
     *         not begin here is not the next piece of this message.
     */
    int getNextExpectedOffset()
    {
        return missing.isEmpty() ? -1 : ((Range)missing.firstElement()).start;
    }

    /**
     * Whether a fragment with these parameters is one this reassembler could hold, which is the difference
     * between a fragment that is rejected outright and one that is merely already held. RFC 9147 7.1
     * acknowledges a record whose message was discarded because a previous copy had been received, but not
     * one whose message was rejected, and only the reassembler knows which of the two happened.
     *
     * @return true if the fragment belongs to this message.
     */
    boolean acceptsFragment(short msg_type, int length, int fragment_offset, int fragment_length)
    {
        return this.msg_type == msg_type && this.body.length == length
            && fragment_offset + fragment_length <= length;
    }

    /**
     * @return true if the fragment contributed at least one byte (or completed an empty message), false if
     *         it was ignored, whether because it was rejected or because every byte of it was already held.
     *         {@link #acceptsFragment(short, int, int, int)} separates those two cases.
     */
    boolean contributeFragment(short msg_type, int length, byte[] buf, int off, int fragment_offset,
        int fragment_length)
    {
        int fragment_end = fragment_offset + fragment_length;

        if (!acceptsFragment(msg_type, length, fragment_offset, fragment_length))
        {
            return false;
        }

        // NOTE: Empty messages still require an empty fragment to complete it
        if (fragment_length == 0)
        {
            if (fragment_offset == 0 && !missing.isEmpty() && ((Range)missing.firstElement()).end == 0)
            {
                missing.removeElementAt(0);
                return true;
            }
            return false;
        }

        boolean contributed = false;

        for (int i = findStartIndex(fragment_offset); i < missing.size(); ++i)
        {
            Range range = (Range)missing.elementAt(i);
            if (range.start >= fragment_end)
            {
                break;
            }
            if (range.end <= fragment_offset)
            {
                continue;
            }

            int copyStart = Math.max(range.start, fragment_offset);
            int copyEnd = Math.min(range.end, fragment_end);
            int copyLength = copyEnd - copyStart;

            if (copyStart == range.start)
            {
                if (copyEnd == range.end)
                {
                    // TODO[tls] It should be possible to handle all removals together at the end (linearly)
                    missing.removeElementAt(i--);
                }
                else
                {
                    range.start = copyEnd;
                }
            }
            else
            {
                if (copyEnd != range.end)
                {
                    // Splitting this range would exceed the limit, so ignore the fragment
                    if (missing.size() >= maxMissingRanges)
                    {
                        continue;
                    }

                    missing.insertElementAt(new Range(copyEnd, range.end), ++i);
                }
                range.end = copyStart;
            }

            System.arraycopy(buf, off + copyStart - fragment_offset, body, copyStart, copyLength);
            contributed = true;
        }

        return contributed;
    }

    /**
     * Find the index of the first range that might overlap a fragment starting at fragment_offset. The ranges are
     * sorted and disjoint, so every earlier one ends at or below fragment_offset and could only be skipped over.
     */
    private int findStartIndex(int fragment_offset)
    {
        int lo = 0, hi = missing.size();
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (((Range)missing.elementAt(mid)).end > fragment_offset)
            {
                hi = mid;
            }
            else
            {
                lo = mid + 1;
            }
        }
        return lo;
    }

    void reset()
    {
        this.missing.removeAllElements();
        this.missing.addElement(new Range(0, body.length));
    }

    private static class Range
    {
        int start, end;

        Range(int start, int end)
        {
            this.start = start;
            this.end = end;
        }
    }
}
