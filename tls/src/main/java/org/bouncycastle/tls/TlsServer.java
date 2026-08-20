package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/**
 * Interface describing a TLS server endpoint.
 */
public interface TlsServer
    extends TlsPeer
{
    boolean preferLocalSupportedGroups();

    void init(TlsServerContext context);

    /**
     * Return the specified session, if available. Note that the peer's certificate
     * chain for the session (if any) may need to be periodically revalidated.
     * 
     * @param sessionID the ID of the session to resume.
     * @return A {@link TlsSession} with the specified session ID, or null.
     * @see SessionParameters#getPeerCertificate()
     */
    TlsSession getSessionToResume(byte[] sessionID);

    byte[] getNewSessionID();

    /**
     * WARNING: EXPERIMENTAL FEATURE, UNSTABLE API
     * 
     * Return the {@link TlsPSKExternal external PSK} to select from the ClientHello. Note that this will only
     * be called when TLS 1.3 or higher is amongst the offered protocol versions, and one or more PSKs are
     * actually offered.
     * 
     * @param identities a {@link Vector} of {@link PskIdentity} instances.
     * @return the {@link TlsPSKExternal} corresponding to the selected identity, or null to not select any.
     * @throws IOException if the handshake should be aborted. An implementation may throw a
     *             {@link TlsFatalAlert} to control the alert sent to the peer - e.g.
     *             {@link AlertDescription#unknown_psk_identity} when none of the offered identities is
     *             recognised, or {@link AlertDescription#decrypt_error} when an identity is recognised
     *             but is invalid or expired (see RFC 8446 6.2). Returning null instead leaves PSK
     *             unselected without aborting.
     */
    TlsPSKExternal getExternalPSK(Vector identities) throws IOException;

    void notifySession(TlsSession session);

    void notifyClientVersion(ProtocolVersion clientVersion) throws IOException;

    void notifyFallback(boolean isFallback) throws IOException;

    void notifyOfferedCipherSuites(int[] offeredCipherSuites)
        throws IOException;

    // Hashtable is (Integer -> byte[])
    void processClientExtensions(Hashtable clientExtensions)
        throws IOException;

    ProtocolVersion getServerVersion()
        throws IOException;

    int[] getSupportedGroups()
        throws IOException;

    int getSelectedCipherSuite()
        throws IOException;

    // Hashtable is (Integer -> byte[])
    Hashtable getServerExtensions()
        throws IOException;

    // Hashtable is (Integer -> byte[])
    void getServerExtensionsForConnection(Hashtable serverExtensions)
        throws IOException;

    // Vector is (SupplementalDataEntry)
    Vector getServerSupplementalData()
        throws IOException;

    /**
     * Return server credentials to use. The returned value may be null, or else it MUST implement
     * <em>exactly one</em> of {@link TlsCredentialedAgreement}, {@link TlsCredentialedDecryptor}, or
     * {@link TlsCredentialedSigner}, depending on the key exchange that was negotiated.
     *
     * @return a TlsCredentials object or null for anonymous key exchanges
     * @throws IOException
     */
    TlsCredentials getCredentials()
        throws IOException;

    /**
     * This method will be called (only) if {@link SecurityParameters#getStatusRequestVersion()} is
     * non-zero, meaning the client asked for a stapled response and the server undertook to answer:
     * up to (D)TLS 1.2, that it echoed an extension of type "status_request" (<i>RFC 6066 sec. 8.
     * Certificate Status Request</i>) or "status_request_v2" (<i>RFC 6961 sec. 2.2. Multiple
     * Certificate Status Request Record</i>) with empty "extension_data" in the extended server
     * hello; in TLS 1.3, simply that the client offered "status_request".
     * <p>
     * The status request version says which of the two shapes the client will accept; returning
     * the other one is a fatal alert at the client:
     * <ul>
     * <li><b>1</b> &ndash; "status_request". Return a {@link CertificateStatusType#ocsp} status
     * carrying a single response, for the end-entity certificate.</li>
     * <li><b>2</b> &ndash; "status_request_v2" was echoed. Return a
     * {@link CertificateStatusType#ocsp_multi} status carrying one entry per certificate in the
     * chain that was sent, in the same order, with a null entry wherever no response is
     * available.</li>
     * </ul>
     * Whether either extension is echoed at all up to (D)TLS 1.2 is decided by
     * {@link AbstractTlsServer#allowCertificateStatus()} (defaults to true) and
     * {@link AbstractTlsServer#allowMultiCertStatus()} (defaults to <b>false</b>).
     * <p>
     * How the returned status reaches the client depends on the negotiated version. Up to (D)TLS 1.2
     * it is sent as a handshake message of type "certificate_status", for the whole chain at once. In
     * TLS 1.3 there is no such message: the response travels in a "status_request" extension of the
     * {@link CertificateEntry} containing the certificate it answers for (<i>RFC 8446
     * sec. 4.4.2.1</i>), and the protocol distributes what this callback returns across those
     * entries - an {@link CertificateStatusType#ocsp} status answering for the end-entity
     * certificate, an {@link CertificateStatusType#ocsp_multi} status answering positionally, entry
     * <code>i</code> of its list for certificate <code>i</code> of the chain. So a TLS 1.3 server with
     * a response for more than the end-entity certificate returns the ocsp_multi shape even though
     * the status request version is 1. An entry the server has itself given a "status_request"
     * extension - by attaching it to the {@link Certificate} its credentials supply, which was
     * previously the only way to staple in TLS 1.3 - is left as it stands.
     * <p>
     * {@code OCSPStaplingServerExample} in the misc module is a worked example.
     *
     * @return A {@link CertificateStatus} to be sent to the client (or null for none).
     * @throws IOException
     */
    CertificateStatus getCertificateStatus()
        throws IOException;

    CertificateRequest getCertificateRequest()
        throws IOException;

    TlsPSKIdentityManager getPSKIdentityManager() throws IOException;

    TlsSRPLoginParameters getSRPLoginParameters() throws IOException;

    TlsDHConfig getDHConfig() throws IOException;

    TlsECConfig getECDHConfig() throws IOException;

    // Vector is (SupplementalDataEntry)
    void processClientSupplementalData(Vector clientSupplementalData)
        throws IOException;

    /**
     * Called by the protocol handler to report the client certificate, only if
     * {@link #getCertificateRequest()} returned non-null.
     * 
     * Note: this method is responsible for certificate verification and validation.
     * 
     * @param clientCertificate
     *            the effective client certificate (may be an empty chain).
     * @throws IOException
     */
    void notifyClientCertificate(Certificate clientCertificate)
        throws IOException;

    /**
     * RFC 5077 3.3. NewSessionTicket Handshake Message.
     * <p>
     * This method will be called (only) if a NewSessionTicket extension was sent by the server. See
     * <i>RFC 5077 4. Recommended Ticket Construction</i> for recommended format and protection.
     *
     * @return The ticket.
     * @throws IOException
     */
    NewSessionTicket getNewSessionTicket()
        throws IOException;
}
