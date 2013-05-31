package org.bouncycastle.crypto.tls;

public interface TlsPeer
{

    /**
     * This method will be called when an alert is raised by the protocol.
     *
     * @param alertLevel       {@link AlertLevel}
     * @param alertDescription {@link AlertDescription}
     * @param message          A human-readable message explaining what caused this alert. May be null.
     * @param cause            The exception that caused this alert to be raised. May be null.
     */
    void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause);

    /**
     * This method will be called when an alert is received from the remote peer.
     *
     * @param alertLevel       {@link AlertLevel}
     * @param alertDescription {@link AlertDescription}
     */
    void notifyAlertReceived(short alertLevel, short alertDescription);
}
