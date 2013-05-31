package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class TlsServerProtocol
    extends TlsProtocol
{

    protected TlsServer tlsServer = null;
    protected TlsServerContextImpl tlsServerContext = null;

    protected int[] offeredCipherSuites;
    protected short[] offeredCompressionMethods;
    protected Hashtable clientExtensions;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;
    protected Hashtable serverExtensions;

    protected TlsKeyExchange keyExchange = null;
    protected TlsCredentials serverCredentials = null;
    protected CertificateRequest certificateRequest = null;

    protected short clientCertificateType = -1;
    protected Certificate clientCertificate = null;
    protected byte[] certificateVerifyHash = null;

    public TlsServerProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        super(input, output, secureRandom);
    }

    /**
     * Receives a TLS handshake in the role of server
     *
     * @param tlsServer
     * @throws IOException If handshake was not successful.
     */
    public void accept(TlsServer tlsServer)
        throws IOException
    {

        if (tlsServer == null)
        {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        }
        if (this.tlsServer != null)
        {
            throw new IllegalStateException("accept can only be called once");
        }

        this.tlsServer = tlsServer;

        this.securityParameters = new SecurityParameters();
        this.securityParameters.entity = ConnectionEnd.server;
        this.securityParameters.serverRandom = createRandomBlock(secureRandom);

        this.tlsServerContext = new TlsServerContextImpl(secureRandom, securityParameters);
        this.tlsServer.init(tlsServerContext);
        this.recordStream.init(tlsServerContext);

        this.recordStream.setRestrictReadVersion(false);

        completeHandshake();

        this.tlsServer.notifyHandshakeComplete();
    }

    protected AbstractTlsContext getContext()
    {
        return tlsServerContext;
    }

    protected TlsPeer getPeer()
    {
        return tlsServer;
    }

    protected void handleChangeCipherSpecMessage()
        throws IOException
    {

        switch (this.connection_state)
        {
        case CS_CLIENT_KEY_EXCHANGE:
        {
            if (this.certificateVerifyHash != null)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            // NB: Fall through to next case label
        }
        case CS_CERTIFICATE_VERIFY:
        {
            this.connection_state = CS_CLIENT_CHANGE_CIPHER_SPEC;
            break;
        }
        default:
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
        }
    }

    protected void handleHandshakeMessage(short type, byte[] data)
        throws IOException
    {

        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        switch (type)
        {
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_START:
            {
                receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                sendServerHelloMessage();
                this.connection_state = CS_SERVER_HELLO;

                // TODO This block could really be done before actually sending the hello
                {
                    securityParameters.prfAlgorithm = getPRFAlgorithm(selectedCipherSuite);
                    securityParameters.compressionAlgorithm = this.selectedCompressionMethod;

                    /*
                     * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify
                     * verify_data_length has a verify_data_length equal to 12. This includes all
                     * existing cipher suites.
                     */
                    securityParameters.verifyDataLength = 12;

                    recordStream.notifyHelloComplete();
                }

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null)
                {
                    sendSupplementalDataMessage(serverSupplementalData);
                }
                this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

                this.keyExchange = tlsServer.getKeyExchange();
                this.keyExchange.init(getContext());

                this.serverCredentials = tlsServer.getCredentials();
                if (this.serverCredentials == null)
                {
                    this.keyExchange.skipServerCredentials();
                }
                else
                {
                    this.keyExchange.processServerCredentials(this.serverCredentials);
                    sendCertificateMessage(this.serverCredentials.getCertificate());
                }
                this.connection_state = CS_SERVER_CERTIFICATE;

                byte[] serverKeyExchange = this.keyExchange.generateServerKeyExchange();
                if (serverKeyExchange != null)
                {
                    sendServerKeyExchangeMessage(serverKeyExchange);
                }
                this.connection_state = CS_SERVER_KEY_EXCHANGE;

                if (this.serverCredentials != null)
                {
                    this.certificateRequest = tlsServer.getCertificateRequest();
                    if (this.certificateRequest != null)
                    {
                        this.keyExchange.validateCertificateRequest(certificateRequest);
                        sendCertificateRequestMessage(certificateRequest);
                    }
                }
                this.connection_state = CS_CERTIFICATE_REQUEST;

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;

                break;
            }
            default:
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.supplemental_data:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(readSupplementalDataMessage(buf));
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
                break;
            }
            default:
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            {
                if (this.certificateRequest == null)
                {
                    this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                }
                receiveCertificateMessage(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
                break;
            }
            default:
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.client_key_exchange:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            {
                if (this.certificateRequest == null)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else
                {

                    ProtocolVersion equivalentTLSVersion = getContext().getServerVersion().getEquivalentTLSVersion();

                    if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(equivalentTLSVersion))
                    {
                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                        this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                    }
                    else if (equivalentTLSVersion.isSSL())
                    {
                        if (clientCertificate == null)
                        {
                            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                        }
                    }
                    else
                    {
                        notifyClientCertificate(Certificate.EMPTY_CHAIN);
                    }
                }
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE:
            {
                receiveClientKeyExchangeMessage(buf);
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;
                break;
            }
            default:
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.certificate_verify:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_KEY_EXCHANGE:
            {
                /*
                 * RFC 5246 7.4.8 This message is only sent following a client certificate that has
                 * signing capability (i.e., all certificates except those containing fixed
                 * Diffie-Hellman parameters).
                 */
                if (this.certificateVerifyHash == null)
                {
                    this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                }
                receiveCertificateVerifyMessage(buf);
                this.connection_state = CS_CERTIFICATE_VERIFY;
                break;
            }
            default:
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.finished:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_CHANGE_CIPHER_SPEC:
                processFinishedMessage(buf);
                this.connection_state = CS_CLIENT_FINISHED;

                if (expectSessionTicket)
                {
                    sendNewSessionTicketMessage(tlsServer.getNewSessionTicket());
                }
                this.connection_state = CS_SERVER_SESSION_TICKET;

                sendChangeCipherSpecMessage();
                this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC;

                sendFinishedMessage();
                this.connection_state = CS_SERVER_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.server_hello:
        case HandshakeType.server_key_exchange:
        case HandshakeType.certificate_request:
        case HandshakeType.server_hello_done:
        case HandshakeType.session_ticket:
        default:
            // We do not support this!
            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            break;
        }
    }

    protected void handleWarningMessage(short description)
        throws IOException
    {
        switch (description)
        {
        case AlertDescription.no_certificate:
        {
            /*
             * SSL 3.0 If the server has sent a certificate request Message, the client must send
             * either the certificate message or a no_certificate alert.
             */
            if (getContext().getServerVersion().isSSL() && certificateRequest != null)
            {
                notifyClientCertificate(Certificate.EMPTY_CHAIN);
            }
            break;
        }
        default:
        {
            super.handleWarningMessage(description);
        }
        }
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {

        if (certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        if (this.clientCertificate != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        this.clientCertificate = clientCertificate;

        if (clientCertificate.isEmpty())
        {
            this.keyExchange.skipClientCredentials();
        }
        else
        {

            /*
             * TODO RFC 5246 7.4.6. If the certificate_authorities list in the certificate request
             * message was non-empty, one of the certificates in the certificate chain SHOULD be
             * issued by one of the listed CAs.
             */

            this.clientCertificateType = TlsUtils.getClientCertificateType(clientCertificate,
                this.serverCredentials.getCertificate());

            this.keyExchange.processClientCertificate(clientCertificate);
        }

        /*
         * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        this.tlsServer.notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf)
        throws IOException
    {

        Certificate clientCertificate = Certificate.parse(buf);

        assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf)
        throws IOException
    {

        byte[] clientCertificateSignature = TlsUtils.readOpaque16(buf);

        assertEmpty(buf);

        // Verify the CertificateVerify message contains a correct signature.
        try
        {
            TlsSigner tlsSigner = TlsUtils.createTlsSigner(this.clientCertificateType);
            tlsSigner.init(getContext());

            org.bouncycastle.asn1.x509.Certificate x509Cert = this.clientCertificate.getCertificateAt(0);
            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);

            tlsSigner.verifyRawSignature(clientCertificateSignature, publicKey, this.certificateVerifyHash);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }
    }

    protected void receiveClientHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {

        ProtocolVersion client_version = TlsUtils.readVersion(buf);
        if (client_version.isDTLS())
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        /*
         * Read the client random
         */
        byte[] client_random = TlsUtils.readFully(32, buf);

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        int cipher_suites_length = TlsUtils.readUint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.decode_error);
        }

        /*
         * NOTE: "If the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        this.offeredCipherSuites = TlsUtils.readUint16Array(cipher_suites_length / 2, buf);

        int compression_methods_length = TlsUtils.readUint8(buf);
        if (compression_methods_length < 1)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        this.offeredCompressionMethods = TlsUtils.readUint8Array(compression_methods_length, buf);

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        this.clientExtensions = readExtensions(buf);

        getContext().setClientVersion(client_version);

        tlsServer.notifyClientVersion(client_version);

        securityParameters.clientRandom = client_random;

        tlsServer.notifyOfferedCipherSuites(offeredCipherSuites);
        tlsServer.notifyOfferedCompressionMethods(offeredCompressionMethods);

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */

            /*
             * When a ClientHello is received, the server MUST check if it includes the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If it does, set the secure_renegotiation flag
             * to TRUE.
             */
            if (arrayContains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                this.secure_renegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            if (clientExtensions != null)
            {
                byte[] renegExtValue = (byte[])clientExtensions.get(EXT_RenegotiationInfo);
                if (renegExtValue != null)
                {
                    /*
                     * If the extension is present, set secure_renegotiation flag to TRUE. The
                     * server MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake.
                     */
                    this.secure_renegotiation = true;

                    if (!Arrays.constantTimeAreEqual(renegExtValue, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                    {
                        this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                    }
                }
            }
        }

        tlsServer.notifySecureRenegotiation(this.secure_renegotiation);

        if (clientExtensions != null)
        {
            tlsServer.processClientExtensions(clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf)
        throws IOException
    {

        this.keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        establishMasterSecret(getContext(), keyExchange);

        /*
         * Initialize our cipher suite
         */
        recordStream.setPendingConnectionState(tlsServer.getCompression(), tlsServer.getCipher());

        if (expectCertificateVerifyMessage())
        {
            this.certificateVerifyHash = recordStream.getCurrentHash(null);
        }
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest)
        throws IOException
    {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.certificate_request, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        certificateRequest.encode(buf);
        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        throws IOException
    {

        if (newSessionTicket == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.session_ticket, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        newSessionTicket.encode(buf);
        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerHelloMessage()
        throws IOException
    {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.server_hello, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        ProtocolVersion server_version = tlsServer.getServerVersion();
        if (!server_version.isEqualOrEarlierVersionOf(getContext().getClientVersion()))
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        recordStream.setReadVersion(server_version);
        recordStream.setWriteVersion(server_version);
        recordStream.setRestrictReadVersion(true);
        getContext().setServerVersion(server_version);

        TlsUtils.writeVersion(server_version, buf);

        buf.write(this.securityParameters.serverRandom);

        /*
         * The server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        this.selectedCipherSuite = tlsServer.getSelectedCipherSuite();
        if (!arrayContains(this.offeredCipherSuites, this.selectedCipherSuite)
            || this.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || this.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        this.selectedCompressionMethod = tlsServer.getSelectedCompressionMethod();
        if (!arrayContains(this.offeredCompressionMethods, this.selectedCompressionMethod))
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        TlsUtils.writeUint16(this.selectedCipherSuite, buf);
        TlsUtils.writeUint8(this.selectedCompressionMethod, buf);

        this.serverExtensions = tlsServer.getServerExtensions();

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (this.secure_renegotiation)
        {

            boolean noRenegExt = this.serverExtensions == null
                || !this.serverExtensions.containsKey(EXT_RenegotiationInfo);

            if (noRenegExt)
            {
                /*
                 * Note that sending a "renegotiation_info" extension in response to a ClientHello
                 * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                 * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                 * because the client is signaling its willingness to receive the extension via the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */
                if (this.serverExtensions == null)
                {
                    this.serverExtensions = new Hashtable();
                }

                /*
                 * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                 * "renegotiation_info" extension in the ServerHello message.
                 */
                this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }

        if (this.serverExtensions != null)
        {
            this.expectSessionTicket = serverExtensions.containsKey(EXT_SessionTicket);
            writeExtensions(buf, this.serverExtensions);
        }

        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerHelloDoneMessage()
        throws IOException
    {

        byte[] message = new byte[4];
        TlsUtils.writeUint8(HandshakeType.server_hello_done, message, 0);
        TlsUtils.writeUint24(0, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        TlsUtils.writeUint8(HandshakeType.server_key_exchange, bos);
        TlsUtils.writeUint24(serverKeyExchange.length, bos);
        bos.write(serverKeyExchange);
        byte[] message = bos.toByteArray();

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected boolean expectCertificateVerifyMessage()
    {
        return this.clientCertificateType >= 0 && TlsUtils.hasSigningCapability(this.clientCertificateType);
    }
}
