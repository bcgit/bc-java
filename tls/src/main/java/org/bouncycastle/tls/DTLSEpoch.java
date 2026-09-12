package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCipher;

class DTLSEpoch
{
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();

    private final int epoch;
    private final TlsCipher cipher;
    private final int recordHeaderLengthRead, recordHeaderLengthWrite;

    /*
     * RFC 9147 8. True for an epoch built from the PEER's updated traffic secret, i.e. one created by
     * DTLSRecordLayer.updatePeerReadEpoch. Such an epoch can be read at and must never be written at: its
     * cipher is keyed for the peer's sending direction and its single sequence number counter is the peer's,
     * so allocating from it would encrypt our records under the peer's key at sequence numbers the peer has
     * already used - AEAD nonce reuse, and the worst outcome an epoch lookup can have.
     *
     * Every other epoch this record layer holds is one both directions shared (the handshake installs one
     * epoch for both) or one of our own making, and each of those is legitimately writable.
     */
    private final boolean peerKeyed;

    private long sequenceNumber = 0;

    DTLSEpoch(int epoch, TlsCipher cipher, int recordHeaderLengthRead, int recordHeaderLengthWrite)    
    {
        this(epoch, cipher, recordHeaderLengthRead, recordHeaderLengthWrite, false);
    }

    DTLSEpoch(int epoch, TlsCipher cipher, int recordHeaderLengthRead, int recordHeaderLengthWrite,
        boolean peerKeyed)
    {
        if (epoch < 0)
        {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        }
        if (cipher == null)
        {
            throw new IllegalArgumentException("'cipher' cannot be null");
        }

        this.epoch = epoch;
        this.cipher = cipher;
        this.recordHeaderLengthRead = recordHeaderLengthRead;
        this.recordHeaderLengthWrite = recordHeaderLengthWrite;
        this.peerKeyed = peerKeyed;
    }

    /** @return true if this epoch is keyed from the peer's traffic secret and may only be read at. */
    boolean isPeerKeyed()
    {
        return peerKeyed;
    }

    synchronized long allocateSequenceNumber() throws IOException
    {
        if (sequenceNumber >= (1L << 48))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return sequenceNumber++;
    }

    TlsCipher getCipher()
    {
        return cipher;
    }

    int getEpoch()
    {
        return epoch;
    }

    int getRecordHeaderLengthRead()
    {
        return recordHeaderLengthRead;
    }

    int getRecordHeaderLengthWrite()
    {
        return recordHeaderLengthWrite;
    }

    DTLSReplayWindow getReplayWindow()
    {
        return replayWindow;
    }

    synchronized long getSequenceNumber()
    {
        return sequenceNumber;
    }

    synchronized void setSequenceNumber(long sequenceNumber)
    {
        this.sequenceNumber = sequenceNumber;
    }
}
