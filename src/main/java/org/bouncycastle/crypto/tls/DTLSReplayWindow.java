package org.bouncycastle.crypto.tls;

/**
 * RFC 4347 4.1.2.5 Anti-replay
 */
class DTLSReplayWindow {

    private static final long VALID_SEQ_MASK = 0x0000FFFFFFFFFFFFL;

    private static final long WINDOW_SIZE = 64L;

    private long latestConfirmedSeq = -1;
    private long bitmap = 0;

    boolean shouldDiscard(long seq)
    {
        if ((seq & VALID_SEQ_MASK) != seq)
            return true;

        if (seq <= latestConfirmedSeq)
        {
            long diff = latestConfirmedSeq - seq;
            if (diff >= WINDOW_SIZE)
                return true;
            if ((bitmap & (1L << diff)) != 0)
                return true;
        }

        return false;
    }

    void reportAuthenticated(long seq)
    {
        if ((seq & VALID_SEQ_MASK) != seq)
            throw new IllegalArgumentException("'seq' out of range");

        if (seq <= latestConfirmedSeq)
        {
            long diff = latestConfirmedSeq - seq;
            if (diff < WINDOW_SIZE) {
                bitmap |= (1L << diff);
            }
        }
        else
        {
            long diff = seq - latestConfirmedSeq;
            if (diff >= WINDOW_SIZE) {
                bitmap = 1;
            }
            else {
                bitmap <<= diff;
                bitmap |= 1;
            }
        }
    }
}
