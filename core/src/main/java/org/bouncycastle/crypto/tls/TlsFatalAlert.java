package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class TlsFatalAlert
    extends IOException
{
    private static final long serialVersionUID = 3584313123679111168L;

    protected short alertDescription;

    // TODO Some day we might be able to just pass this down to IOException (1.6+)
    protected Throwable alertCause;

    public TlsFatalAlert(short alertDescription)
    {
        this(alertDescription, null);
    }

    public TlsFatalAlert(short alertDescription, Throwable alertCause)
    {
        super(AlertDescription.getText(alertDescription));

        this.alertDescription = alertDescription;
        this.alertCause = alertCause;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }

    public Throwable getCause()
    {
        return alertCause;
    }
}
