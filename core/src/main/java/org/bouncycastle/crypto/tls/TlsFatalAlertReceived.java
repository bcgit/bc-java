package org.bouncycastle.crypto.tls;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class TlsFatalAlertReceived
    extends TlsException
{
    protected short alertDescription;

    public TlsFatalAlertReceived(short alertDescription)
    {
        super(AlertDescription.getText(alertDescription), null);

        this.alertDescription = alertDescription;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }
}
