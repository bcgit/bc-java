package org.bouncycastle.crypto.tls;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class TlsFatalAlert
    extends TlsException
{
    protected short alertDescription;

    public TlsFatalAlert(short alertDescription)
    {
        this(alertDescription, null);
    }

    public TlsFatalAlert(short alertDescription, Throwable alertCause)
    {
        super(AlertDescription.getText(alertDescription), alertCause);

        this.alertDescription = alertDescription;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }
}
