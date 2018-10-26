package org.bouncycastle.tls;

public class TlsPeerOptions
{
    boolean checkPeerCertSigAlg = true;

    public boolean isCheckPeerCertSigAlg()
    {
        return checkPeerCertSigAlg;
    }
}
