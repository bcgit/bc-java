package org.bouncycastle.mls;

import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.util.Arrays;

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

    public void update(AuthenticatedContent auth) throws IOException
    {
        updateConfirmed(auth);
        updateInterim(auth);
    }

    private void updateConfirmed(AuthenticatedContent auth) throws IOException
    {
        byte[] transcript = Arrays.concatenate(interim, auth.getConfirmedTranscriptHashInput());
        confirmed = suite.hash(transcript);
    }
    private void updateInterim(AuthenticatedContent auth) throws IOException
    {
        byte[] transcript = Arrays.concatenate(confirmed, auth.getInterimTranscriptHashInput());
        interim = suite.hash(transcript);
    }
}
