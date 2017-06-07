package org.bouncycastle.crypto.tls;

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
