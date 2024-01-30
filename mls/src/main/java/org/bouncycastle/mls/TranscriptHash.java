package org.bouncycastle.mls;

import java.io.IOException;

import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.util.Arrays;

public class TranscriptHash
{

    private MlsCipherSuite suite;
    byte[] confirmed;
    byte[] interim;

    public byte[] getConfirmed()
    {
        return confirmed;
    }

    public byte[] getInterim()
    {
        return interim;
    }

    public void setInterim(byte[] interim)
    {
        this.interim = interim;
    }

    public TranscriptHash(MlsCipherSuite suite)
    {
        this.suite = suite;
        confirmed = new byte[0];
    }

    public TranscriptHash(MlsCipherSuite suite, byte[] confirmed, byte[] interim)
    {
        this.suite = suite;
        this.confirmed = confirmed;
        this.interim = interim;
    }

    static public TranscriptHash fromConfirmationTag(MlsCipherSuite suite, byte[] confirmed, byte[] confirmationTag)
        throws IOException
    {
        TranscriptHash out = new TranscriptHash(suite, confirmed.clone(), new byte[0]);
        out.updateInterim(confirmationTag);
        return out;
    }

    public TranscriptHash copy()
    {
        return new TranscriptHash(suite, confirmed, interim);
    }

    public void update(AuthenticatedContent auth)
        throws IOException
    {
        updateConfirmed(auth);
        updateInterim(auth);
    }

    public void updateConfirmed(AuthenticatedContent auth)
        throws IOException
    {
        byte[] transcript = Arrays.concatenate(interim, auth.getConfirmedTranscriptHashInput());
        confirmed = suite.hash(transcript);
    }

    public void updateInterim(AuthenticatedContent auth)
        throws IOException
    {
        byte[] transcript = Arrays.concatenate(confirmed, auth.getInterimTranscriptHashInput());
        interim = suite.hash(transcript);

    }

    public void updateInterim(byte[] confirmationTag)
        throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.writeOpaque(confirmationTag);
        byte[] transcript = Arrays.concatenate(confirmed, stream.toByteArray());
        interim = suite.hash(transcript);
    }
}
