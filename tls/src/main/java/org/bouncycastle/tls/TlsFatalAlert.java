package org.bouncycastle.tls;

public class TlsFatalAlert
    extends TlsException
{
    private static String getMessage(short alertDescription, String detailMessage)
    {
        String msg = AlertDescription.getText(alertDescription);
        if (null != detailMessage)
        {
            msg += "; " + detailMessage;
        }
        return msg;
    }

    protected short alertDescription;

    public TlsFatalAlert(short alertDescription)
    {
        this(alertDescription, (String)null);
    }

    public TlsFatalAlert(short alertDescription, String detailMessage)
    {
        this(alertDescription, detailMessage, null);
    }

    public TlsFatalAlert(short alertDescription, Throwable alertCause)
    {
        this(alertDescription, null, alertCause);
    }

    public TlsFatalAlert(short alertDescription, String detailMessage, Throwable alertCause)
    {
        super(getMessage(alertDescription, detailMessage), alertCause);

        this.alertDescription = alertDescription;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }
}
