package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class TlsHybridAgreement
    implements TlsAgreement
{
    private final TlsCrypto crypto;
    private final TlsAgreement firstAgreement;
    private final TlsAgreement secondAgreement;
    private final int peerValueSplit;

    public TlsHybridAgreement(TlsCrypto crypto, TlsAgreement firstAgreement, TlsAgreement secondAgreement,
        int peerValueSplit)
    {
        this.crypto = crypto;
        this.firstAgreement = firstAgreement;
        this.secondAgreement = secondAgreement;
        this.peerValueSplit = peerValueSplit;
    }

    public byte[] generateEphemeral() throws IOException
    {
        byte[] firstEphemeral = firstAgreement.generateEphemeral();
        byte[] secondEphemeral = secondAgreement.generateEphemeral();
        return Arrays.concatenate(firstEphemeral, secondEphemeral);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (peerValue.length < peerValueSplit)
        {
            throw new IllegalArgumentException("'peerValue' is too short");
        }

        this.firstAgreement.receivePeerValue(Arrays.copyOfRange(peerValue, 0, peerValueSplit));
        this.secondAgreement.receivePeerValue(Arrays.copyOfRange(peerValue, peerValueSplit, peerValue.length));
    }

    public TlsSecret calculateSecret() throws IOException
    {
        TlsSecret firstSecret = firstAgreement.calculateSecret();
        TlsSecret secondSecret = secondAgreement.calculateSecret();
        return crypto.createHybridSecret(firstSecret, secondSecret);
    }
}
