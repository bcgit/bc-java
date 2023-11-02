package org.bouncycastle.mls;

import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class TranscriptHash
{

    private CipherSuite suite;
    public byte[] confirmed;
    public byte[] interim;

    public void setInterim(byte[] interim)
    {
        this.interim = interim;
    }

    public TranscriptHash(CipherSuite suite)
    {
        this.suite = suite;
    }
    public TranscriptHash(CipherSuite suite, byte[] confirmed, byte[] interim)
    {
        this.suite = suite;
        this.confirmed = confirmed.clone();
        this.interim = interim.clone();
    }
    public TranscriptHash copy()
    {
        return new TranscriptHash(suite, confirmed, interim);
    }

    public void update(AuthenticatedContent auth) throws IOException
    {
        updateConfirmed(auth);
        updateInterim(auth);
    }

    public void updateConfirmed(AuthenticatedContent auth) throws IOException
    {
        byte[] transcript = Arrays.concatenate(interim, auth.getConfirmedTranscriptHashInput());
        confirmed = suite.hash(transcript);
    }
    public void updateInterim(AuthenticatedContent auth) throws IOException
    {
        byte[] transcript = Arrays.concatenate(confirmed, auth.getInterimTranscriptHashInput());
        interim = suite.hash(transcript);

    }
    public void updateInterim(byte[] confirmationTag) throws IOException
    {
        MLSOutputStream stream = new MLSOutputStream();
        stream.writeOpaque(confirmationTag);
        byte[] transcript = Arrays.concatenate(confirmed, stream.toByteArray());
        interim = suite.hash(transcript);
    }
}
