package org.bouncycastle.tls;

/**
 * RFC 9147 4. The DTLS 1.3 unified header for DTLSCiphertext records.
 * <pre>
 *  0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+
 * |0|0|1|C|S|L|E E|
 * +-+-+-+-+-+-+-+-+
 * </pre>
 * C: connection ID present, S: 16-bit (1) or 8-bit (0) sequence number, L: length present, EE: low two bits of
 * the epoch. Records written by this implementation always use the full form (S = 1, L = 1).
 */
class DTLS13UnifiedHeader
{
    static final int FIXED_BITS = 0x20;
    static final int FIXED_BITS_MASK = 0xE0;
    static final int FLAG_CID = 0x10;
    static final int FLAG_SEQ16 = 0x08;
    static final int FLAG_LENGTH = 0x04;
    static final int EPOCH_BITS_MASK = 0x03;

    /** RFC 9147 4.2.3. Record number encryption needs at least 16 bytes of ciphertext. */
    static final int MIN_CIPHERTEXT_LENGTH = 16;

    private static final long MAX_SEQUENCE_NUMBER = (1L << 48) - 1;

    static boolean isCiphertextRecord(int firstByte)
    {
        return (firstByte & FIXED_BITS_MASK) == FIXED_BITS;
    }

    static boolean hasConnectionID(int firstByte)
    {
        return (firstByte & FLAG_CID) != 0;
    }

    static boolean hasSeq16(int firstByte)
    {
        return (firstByte & FLAG_SEQ16) != 0;
    }

    static boolean hasLength(int firstByte)
    {
        return (firstByte & FLAG_LENGTH) != 0;
    }

    static boolean matchesEpoch(int firstByte, int epoch)
    {
        return (firstByte & EPOCH_BITS_MASK) == (epoch & EPOCH_BITS_MASK);
    }

    static int getSequenceNumberLength(int firstByte)
    {
        return hasSeq16(firstByte) ? 2 : 1;
    }

    static int getHeaderLength(int firstByte, int connectionIDLength)
    {
        return 1 + connectionIDLength + getSequenceNumberLength(firstByte) + (hasLength(firstByte) ? 2 : 0);
    }

    static int getWriteHeaderLength(int connectionIDLength)
    {
        return 1 + connectionIDLength + 2 + 2;
    }

    /**
     * The smallest conforming header a peer may send per RFC 9147 4: first byte, connection ID, and an 8-bit
     * sequence number, with no length field (S = 0, L = 0). Since a peer is free to use that compact form,
     * this is what the receive limit must budget for; assuming our own (full) write form would under-report the
     * plaintext limit and reject legal records.
     *
     * @return the minimum length of a header that may be received.
     */
    static int getMinReadHeaderLength(int connectionIDLength)
    {
        return 1 + connectionIDLength + 1;
    }

    /**
     * Write a full-form header (16-bit sequence number, length present). The length field is left zero for the
     * cipher to fill in once the ciphertext length is known.
     *
     * @return the header length.
     */
    static int writeHeader(int epoch, long sequenceNumber, byte[] connectionID, byte[] buf, int off)
    {
        int cidLength = null == connectionID ? 0 : connectionID.length;

        int firstByte = FIXED_BITS | FLAG_SEQ16 | FLAG_LENGTH | (epoch & EPOCH_BITS_MASK);
        if (cidLength > 0)
        {
            firstByte |= FLAG_CID;
        }

        int pos = off;
        buf[pos++] = (byte)firstByte;
        if (cidLength > 0)
        {
            System.arraycopy(connectionID, 0, buf, pos, cidLength);
            pos += cidLength;
        }
        TlsUtils.writeUint16((int)(sequenceNumber & 0xFFFFL), buf, pos);
        pos += 2;
        TlsUtils.writeUint16(0, buf, pos);
        pos += 2;
        return pos - off;
    }

    /**
     * RFC 9147 4.2.2. Reconstruct the full sequence number as the value numerically closest to 'expected' (one
     * plus the highest successfully deprotected sequence number) whose low 'seqBitCount' bits equal 'seqBits'.
     */
    static long reconstructSequenceNumber(long expected, int seqBits, int seqBitCount)
    {
        long modulus = 1L << seqBitCount;
        long lowMask = modulus - 1;

        long candidate = (expected & ~lowMask) | (seqBits & lowMask);
        long best = candidate;
        long bestDistance = distance(candidate, expected);

        long lower = candidate - modulus;
        if (lower >= 0)
        {
            long d = distance(lower, expected);
            if (d < bestDistance)
            {
                best = lower;
                bestDistance = d;
            }
        }

        long upper = candidate + modulus;
        if (upper <= MAX_SEQUENCE_NUMBER)
        {
            long d = distance(upper, expected);
            if (d < bestDistance)
            {
                best = upper;
            }
        }

        return best;
    }

    private static long distance(long a, long b)
    {
        return a > b ? a - b : b - a;
    }
}
