package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;

/**
 * Base interface for a TLS context implementation.
 */
public interface TlsContext
{
    TlsCrypto getCrypto();

    TlsNonceGenerator getNonceGenerator();

    SecurityParameters getSecurityParameters();

    SecurityParameters getSecurityParametersConnection();

    SecurityParameters getSecurityParametersHandshake();

    /**
     * Return true if this context is for a server, false otherwise.
     *
     * @return true for a server based context, false for a client based one.
     */
    boolean isServer();

    ProtocolVersion[] getClientSupportedVersions();

    ProtocolVersion getClientVersion();

    ProtocolVersion getRSAPreMasterSecretVersion();

    ProtocolVersion getServerVersion();

    /**
     * Used to get the resumable session, if any, used by this connection. Only available after the
     * handshake has successfully completed.
     * 
     * @return A {@link TlsSession} representing the resumable session used by this connection, or
     *         null if no resumable session available.
     * @see TlsPeer#notifyHandshakeComplete()
     */
    TlsSession getResumableSession();

    /**
     * Used to get the session information for this connection. Only available after the handshake
     * has successfully completed. Use {@link TlsSession#isResumable()} to find out if the session
     * is resumable.
     * 
     * @return A {@link TlsSession} representing the session used by this connection.
     * @see TlsPeer#notifyHandshakeComplete()
     */
    TlsSession getSession();

    Object getUserObject();

    void setUserObject(Object userObject);

    /**
     * Export the value of the specified channel binding. Only available after the handshake has
     * successfully completed.
     * 
     * @param channelBinding
     *            A {@link ChannelBinding} constant specifying the channel binding to export.
     * @return A copy of the channel binding data as a {@link byte[]}, or null if the binding could
     *         not be determined.
     */
    byte[] exportChannelBinding(int channelBinding);

    /**
     * Export (early data) keying material according to RFC 5705: "Keying Material Exporters for
     * TLS", as updated for TLS 1.3 (RFC 8446). NOTE: for use in settings where an exporter is
     * needed for 0-RTT data.
     *
     * @param asciiLabel
     *            indicates which application will use the exported keys.
     * @param context_value
     *            allows the application using the exporter to mix its own data with the TLS PRF for
     *            the exporter output.
     * @param length
     *            the number of bytes to generate
     * @return a pseudorandom bit string of 'length' bytes generated from the
     *         (exporter_)master_secret.
     */
    byte[] exportEarlyKeyingMaterial(String asciiLabel, byte[] context_value, int length);

    /**
     * Export keying material according to RFC 5705: "Keying Material Exporters for TLS", as updated
     * for TLS 1.3 (RFC 8446) when negotiated.
     *
     * @param asciiLabel
     *            indicates which application will use the exported keys.
     * @param context_value
     *            allows the application using the exporter to mix its own data with the TLS PRF for
     *            the exporter output.
     * @param length
     *            the number of bytes to generate
     * @return a pseudorandom bit string of 'length' bytes generated from the
     *         (exporter_)master_secret.
     */
    byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length);
}
