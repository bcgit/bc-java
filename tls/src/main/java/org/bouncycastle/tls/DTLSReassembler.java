package org.bouncycastle.tls;

import java.util.Vector;

class DTLSReassembler
{
    /*
     * Bounds the number of gaps tracked for one message. Each interior fragment splits a gap in two,
     * so an unbounded list lets single-byte fragments at alternating offsets take a 32KiB message to
     * 16K gaps, at a cost quadratic in the message length - seconds of CPU per message_seq in the
     * flight, spent before anything about the peer has been verified. A cooperating peer fragments
     * to the path MTU, so its gap count tracks its fragment count: a 1MiB message in 516-byte
     * fragments arriving in fully random order peaks at 536 gaps, hence one gap per 512 bytes with a
     * floor for small messages. At the cap a fragment that would split a gap is ignored for that gap
     * - and not recorded as received, so a byte already held is still never overwritten - leaving the
     * peer's normal retransmission of the flight to complete the message once the gaps close.
     */
    private static final int MIN_MAX_MISSING_RANGES = 1024;

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
        this.maxMissingRanges = Math.max(MIN_MAX_MISSING_RANGES, length / 512);
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

    void contributeFragment(short msg_type, int length, byte[] buf, int off, int fragment_offset,
        int fragment_length)
    {
        int fragment_end = fragment_offset + fragment_length;

        if (this.msg_type != msg_type || this.body.length != length || fragment_end > length)
        {
            return;
        }

        if (fragment_length == 0)
        {
            // NOTE: Empty messages still require an empty fragment to complete it
            if (fragment_offset == 0 && !missing.isEmpty())
            {
                Range firstRange = (Range)missing.firstElement();
                if (firstRange.getEnd() == 0)
                {
                    missing.removeElementAt(0);
                }
            }
            return;
        }

        for (int i = firstCandidate(fragment_offset); i < missing.size(); ++i)
        {
            Range range = (Range)missing.elementAt(i);
            if (range.getStart() >= fragment_end)
            {
                break;
            }
            if (range.getEnd() > fragment_offset)
            {

                int copyStart = Math.max(range.getStart(), fragment_offset);
                int copyEnd = Math.min(range.getEnd(), fragment_end);
                int copyLength = copyEnd - copyStart;

                if (copyStart != range.getStart() && copyEnd != range.getEnd()
                    && missing.size() >= maxMissingRanges)
                {
                    // splitting this range would pass the cap, so ignore the fragment for it
                    continue;
                }

                System.arraycopy(buf, off + copyStart - fragment_offset, body, copyStart,
                    copyLength);

                if (copyStart == range.getStart())
                {
                    if (copyEnd == range.getEnd())
                    {
                        missing.removeElementAt(i--);
                    }
                    else
                    {
                        range.setStart(copyEnd);
                    }
                }
                else
                {
                    if (copyEnd != range.getEnd())
                    {
                        missing.insertElementAt(new Range(copyEnd, range.getEnd()), ++i);
                    }
                    range.setEnd(copyStart);
                }
            }
        }
    }

    /**
     * Index of the first range that can overlap a fragment starting at fragment_offset. The ranges
     * are sorted and disjoint, so every earlier one ends at or below fragment_offset and could only
     * be skipped over; searching for the start rather than rescanning from zero is what keeps the
     * cost of a fragment independent of how many gaps precede it.
     */
    private int firstCandidate(int fragment_offset)
    {
        int lo = 0, hi = missing.size();
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (((Range)missing.elementAt(mid)).getEnd() > fragment_offset)
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
        private int start, end;

        Range(int start, int end)
        {
            this.start = start;
            this.end = end;
        }

        int getStart()
        {
            return start;
        }

        void setStart(int start)
        {
            this.start = start;
        }

        int getEnd()
        {
            return end;
        }

        void setEnd(int end)
        {
            this.end = end;
        }
    }
}
