package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsPeer
{
    /**
     * This implementation supports RFC 7627 and will always negotiate the extended_master_secret
     * extension where possible. When connecting to a peer that does not offer/accept this
     * extension, it is recommended to abort the handshake. This option is provided for
     * interoperability with legacy peers, although some TLS features will be disabled in that case
     * (see RFC 7627 5.4).
     * 
     * @return <code>true</code> if the handshake should be aborted when the peer does not negotiate
     *         the extended_master_secret extension, or <code>false</code> to support legacy
     *         interoperability.
     */
    boolean requiresExtendedMasterSecret();

    /**
     * draft-mathewson-no-gmtunixtime-00 2. "If existing users of a TLS implementation may rely on
     * gmt_unix_time containing the current time, we recommend that implementors MAY provide the
     * ability to set gmt_unix_time as an option only, off by default."
     * 
     * @return <code>true</code> if the current time should be used in the gmt_unix_time field of
     *         Random, or <code>false</code> if gmt_unix_time should contain a cryptographically
     *         random value.
     */
    boolean shouldUseGMTUnixTime();

    void notifySecureRenegotiation(boolean secureNegotiation) throws IOException;

    TlsCompression getCompression() throws IOException;

    TlsCipher getCipher() throws IOException;

    /**
     * This method will be called when an alert is raised by the protocol.
     *
     * @param alertLevel       {@link AlertLevel}
     * @param alertDescription {@link AlertDescription}
     * @param message          A human-readable message explaining what caused this alert. May be null.
     * @param cause            The {@link Throwable} that caused this alert to be raised. May be null.
     */
    void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause);

    /**
     * This method will be called when an alert is received from the remote peer.
     *
     * @param alertLevel       {@link AlertLevel}
     * @param alertDescription {@link AlertDescription}
     */
    void notifyAlertReceived(short alertLevel, short alertDescription);

    /**
     * Notifies the peer that the handshake has been successfully completed.
     */
    void notifyHandshakeComplete() throws IOException;
}
