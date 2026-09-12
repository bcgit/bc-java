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
     * DTLSRecordLayer.updatePeerReadEpoch. Such an epoch can be read at and must never be written at.
     *
     * Not because writing at it would use the peer's key - it would not. TlsUtils.initCipher builds a cipher
     * for BOTH directions: TlsAEADCipher's (D)TLS 1.3 constructor calls rekeyCipher once for the decrypt side,
     * keyed from the peer's traffic secret, and once for the encrypt side, keyed from the LOCAL one.
     * updatePeerReadEpoch updates only the peer's secret (TlsUtils.update13TrafficSecretPeer), so the epoch it
     * builds carries an encrypt side keyed IDENTICALLY to the current write epoch's, paired with a sequence
     * number counter of its own that starts at zero.
     *
     * So allocating a record from this epoch would not produce something the peer cannot read. It would
     * produce records encrypted under the SAME AEAD key, at nonces already used for records sent at the
     * current write epoch. That is AEAD nonce reuse: silent, with the connection still working, and for GCM it
     * is enough to recover the authentication key. It is the worst outcome an epoch lookup can have, and
     * nothing observable would report it.
     *
     * The structural cause, which is why this flag has to exist at all: updatePeerReadEpoch builds a full
     * bidirectional cipher when it needs only the read direction, and so leaves a correctly-keyed encryptor in
     * an object that must never encrypt.
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
