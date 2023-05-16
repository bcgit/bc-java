package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCipher;

class DTLSEpoch
{
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();

    private final int epoch;
    private final TlsCipher cipher;
    private final int recordHeaderLengthRead, recordHeaderLengthWrite;

    private long sequenceNumber = 0;

    DTLSEpoch(int epoch, TlsCipher cipher, int recordHeaderLengthRead, int recordHeaderLengthWrite)    
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
