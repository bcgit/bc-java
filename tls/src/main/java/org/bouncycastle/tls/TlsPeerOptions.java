package org.bouncycastle.tls;

public class TlsPeerOptions
{
    boolean checkSigAlgOfPeerCerts = true;

    public boolean isCheckSigAlgOfPeerCerts()
    {
        return checkSigAlgOfPeerCerts;
    }
}
