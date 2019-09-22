package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * Base interface for a (D)TLS endpoint.
 */
public interface TlsPeer
{
    TlsCrypto getCrypto();

    void notifyCloseHandle(TlsCloseable closehandle);

    void cancel() throws IOException;

    ProtocolVersion[] getProtocolVersions();

    int[] getCipherSuites();

    /**
     * Notifies the peer that a new handshake is about to begin.
     */
    void notifyHandshakeBeginning() throws IOException;

    /**
     * <p>
     * NOTE: Currently only respected by DTLS protocols.
     * </p>
     * <p>
     * Specify the timeout, in milliseconds, to use for the complete handshake process. Negative
     * values are not allowed. A timeout of zero means an infinite timeout (i.e. the handshake will
     * never time out).
     * </p>
     * 
     * @return the handshake timeout, in milliseconds.
     */
    int getHandshakeTimeoutMillis();

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
     * Controls whether the protocol will check the 'signatureAlgorithm' of received certificates as
     * specified in RFC 5246 7.4.2, 7.4.4, 7.4.6 and similar rules for earlier TLS versions. We
     * recommend to enable these checks, but this option is provided for cases where the default
     * checks are for some reason too strict.
     * 
     * @return <code>true</code> if the 'signatureAlgorithm' of received certificates should be
     *         checked, or <code>false</code> to skip those checks.
     */
    boolean shouldCheckSigAlgOfPeerCerts();

    /**
     * See RFC 5246 6.2.3.2. Controls whether block cipher encryption may randomly add extra padding
     * beyond the minimum. Note that in configurations where this is known to be potential security
     * risk this setting will be ignored (and extended padding disabled). Extra padding is always
     * supported when decrypting received records.
     * 
     * @return <code>true</code> if random extra padding should be added during block cipher
     *         encryption, or <code>false</code> to always use the minimum amount of required
     *         padding.
     */
    boolean shouldUseExtendedPadding();

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

    TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException;

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

    /**
     * Return a {@link TlsHeartbeat} instance that will control the generation of heartbeats locally
     * (if permitted by the remote peer), or null to not generate heartbeats. Heartbeats are
     * described in RFC 6520.
     * 
     * @return an instance of {@link TlsHeartbeat}.
     * @see DefaultTlsHeartbeat
     */
    TlsHeartbeat getHeartbeat();

    /**
     * <p>
     * Return the heartbeat mode applicable to the remote peer. Heartbeats are described in RFC
     * 6520.
     * </p>
     * <p>
     * See enumeration class {@link HeartbeatMode} for appropriate return values.
     * </p>
     * 
     * @return the {@link HeartbeatMode} value.
     */
    short getHeartbeatPolicy();

    /**
     * WARNING: EXPERIMENTAL FEATURE
     * 
     * Return this peer's policy on renegotiation requests from the remote peer. This will be called
     * only outside of ongoing handshakes, either when a remote server has sent a hello_request, or
     * a remote client has sent a new ClientHello, and only when the requirements for secure
     * renegotiation (including those of RFC 5746) have been met.
     * 
     * @return The {@link RenegotiationPolicy} constant corresponding to the desired policy.
     * @see RenegotiationPolicy
     */
    int getRenegotiationPolicy();
}
