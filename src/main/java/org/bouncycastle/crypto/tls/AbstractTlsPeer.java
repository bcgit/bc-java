package org.bouncycastle.crypto.tls;

public abstract class AbstractTlsPeer
    implements TlsPeer
{

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
    {
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
    }
}
