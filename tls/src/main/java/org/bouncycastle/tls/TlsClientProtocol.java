package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

public class TlsClientProtocol
    extends TlsProtocol
{
    protected TlsClient tlsClient = null;
    TlsClientContextImpl tlsClientContext = null;

    protected Hashtable clientAgreements = null;
    protected TlsKeyExchange keyExchange = null;
    protected TlsAuthentication authentication = null;

    protected CertificateStatus certificateStatus = null;
    protected CertificateRequest certificateRequest = null;

    /**
     * Constructor for non-blocking mode.<br>
     * <br>
     * When data is received, use {@link #offerInput(byte[])} to provide the received ciphertext,
     * then use {@link #readInput(byte[], int, int)} to read the corresponding cleartext.<br>
     * <br>
     * Similarly, when data needs to be sent, use {@link #writeApplicationData(byte[], int, int)} to
     * provide the cleartext, then use {@link #readOutput(byte[], int, int)} to get the
     * corresponding ciphertext.
     */
    public TlsClientProtocol()
    {
        super();
    }

    /**
     * Constructor for blocking mode.
     * @param input The stream of data from the server
     * @param output The stream of data to the server
     */
    public TlsClientProtocol(InputStream input, OutputStream output)
    {
        super(input, output);
    }

    /**
     * Initiates a TLS handshake in the role of client.<br>
     * <br>
     * In blocking mode, this will not return until the handshake is complete.
     * In non-blocking mode, use {@link TlsPeer#notifyHandshakeComplete()} to
     * receive a callback when the handshake is complete.
     *
     * @param tlsClient The {@link TlsClient} to use for the handshake.
     * @throws IOException If in blocking mode and handshake was not successful.
     */
    public void connect(TlsClient tlsClient) throws IOException
    {
        if (tlsClient == null)
        {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        }
        if (this.tlsClient != null)
        {
            throw new IllegalStateException("'connect' can only be called once");
        }

        this.tlsClient = tlsClient;
        this.tlsClientContext = new TlsClientContextImpl(tlsClient.getCrypto());

        this.tlsClient.init(tlsClientContext);
        this.recordStream.init(tlsClientContext);

        tlsClient.notifyCloseHandle(this);

        beginHandshake(false);

        if (blocking)
        {
            blockForHandshake();
        }
    }

//    public boolean renegotiate() throws IOException
//    {
//        boolean allowed = super.renegotiate();
//        if (allowed)
//        {
//            beginHandshake(true);
//        }
//        return allowed;
//    }

    protected void beginHandshake(boolean renegotiation) throws IOException
    {
        super.beginHandshake(renegotiation);

        TlsSession sessionToResume = tlsClient.getSessionToResume();
        if (sessionToResume != null && sessionToResume.isResumable())
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if (sessionParameters != null && sessionParameters.isExtendedMasterSecret())
            {
                this.tlsSession = sessionToResume;
                this.sessionParameters = sessionParameters;
            }
        }

        sendClientHelloMessage();
        this.connection_state = CS_CLIENT_HELLO;
    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();

        this.keyExchange = null;
        this.authentication = null;
        this.certificateStatus = null;
        this.certificateRequest = null;
    }

    protected TlsContext getContext()
    {
        return tlsClientContext;
    }

    AbstractTlsContext getContextAdmin()
    {
        return tlsClientContext;
    }
    
    protected TlsPeer getPeer()
    {
        return tlsClient;
    }

    protected void handleHandshakeMessage(short type, ByteArrayInputStream buf)
        throws IOException
    {
        if (this.resumedSession)
        {
            if (type != HandshakeType.finished || this.connection_state != CS_SERVER_HELLO)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processFinishedMessage(buf);
            this.connection_state = CS_SERVER_FINISHED;

            sendChangeCipherSpecMessage();
            sendFinishedMessage();
            this.connection_state = CS_CLIENT_FINISHED;

            completeHandshake();
            return;
        }

        switch (type)
        {
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                TlsUtils.receiveServerCertificate(tlsClientContext, buf);

                this.authentication = tlsClient.getAuthentication();
                if (null == this.authentication)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_CERTIFICATE;
            break;
        }
        case HandshakeType.certificate_status:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_CERTIFICATE:
            {
                if (!this.allowCertificateStatus)
                {
                    /*
                     * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
                     * server MUST have included an extension of type "status_request" with empty
                     * "extension_data" in the extended server hello..
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                this.certificateStatus = CertificateStatus.parse(buf);

                assertEmpty(buf);

                this.connection_state = CS_CERTIFICATE_STATUS;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.finished:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_FINISHED:
            {
                if (this.expectSessionTicket)
                {
                    /*
                     * RFC 5077 3.3. This message MUST be sent if the server included a
                     * SessionTicket extension in the ServerHello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                // NB: Fall through to next case label
            }
            case CS_SERVER_SESSION_TICKET:
            {
                processFinishedMessage(buf);
                this.connection_state = CS_SERVER_FINISHED;

                completeHandshake();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.server_hello:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_HELLO:
            {
                receiveServerHelloMessage(buf);
                this.connection_state = CS_SERVER_HELLO;

                this.recordStream.notifyHelloComplete();

                applyMaxFragmentLengthExtension();

                SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();
                if (this.resumedSession)
                {
                    securityParameters.masterSecret = tlsClientContext.getCrypto()
                        .adoptSecret(sessionParameters.getMasterSecret());
                    this.recordStream.setPendingConnectionState(TlsUtils.initCipher(getContext()));
                }
                else
                {
                    invalidateSession();

                    this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
                    this.sessionParameters = null;
                }

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.supplemental_data:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(readSupplementalDataMessage(buf));
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.server_hello_done:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                handleServerCertificate();

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            case CS_CERTIFICATE_REQUEST:
            {
                assertEmpty(buf);

                this.connection_state = CS_SERVER_HELLO_DONE;

                Vector clientSupplementalData = tlsClient.getClientSupplementalData();
                if (clientSupplementalData != null)
                {
                    sendSupplementalDataMessage(clientSupplementalData);
                }
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;

                TlsCredentials clientCredentials = null;
                TlsCredentialedSigner credentialedSigner = null;
                TlsStreamSigner streamSigner = null;

                if (certificateRequest == null)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else
                {
                    Certificate clientCertificate = null;

                    clientCredentials = validateCredentials(this.authentication.getClientCredentials(certificateRequest));
                    if (null == clientCredentials)
                    {
                        this.keyExchange.skipClientCredentials();

                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                    }
                    else
                    {
                        this.keyExchange.processClientCredentials(clientCredentials);

                        clientCertificate = clientCredentials.getCertificate();

                        if (clientCredentials instanceof TlsCredentialedSigner)
                        {
                            credentialedSigner = (TlsCredentialedSigner)clientCredentials;
                            streamSigner = credentialedSigner.getStreamSigner();
                        }
                    }

                    sendCertificateMessage(clientCertificate, null);
                }

                this.connection_state = CS_CLIENT_CERTIFICATE;

                boolean forceBuffering = streamSigner != null;
                TlsUtils.sealHandshakeHash(getContext(), this.recordStream.getHandshakeHash(), forceBuffering);

                /*
                 * Send the client key exchange message, depending on the key exchange we are using
                 * in our CipherSuite.
                 */
                sendClientKeyExchangeMessage();
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                TlsHandshakeHash prepareFinishHash = recordStream.prepareToFinish();
                tlsClientContext.getSecurityParametersHandshake().sessionHash = TlsUtils
                    .getCurrentPRFHash(prepareFinishHash);

                establishMasterSecret(getContext(), keyExchange);
                recordStream.setPendingConnectionState(TlsUtils.initCipher(getContext()));

                if (credentialedSigner != null)
                {
                    DigitallySigned certificateVerify = TlsUtils.generateCertificateVerify(getContext(),
                        credentialedSigner, streamSigner, prepareFinishHash);
                    sendCertificateVerifyMessage(certificateVerify);
                    this.connection_state = CS_CERTIFICATE_VERIFY;
                }

                sendChangeCipherSpecMessage();
                sendFinishedMessage();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_CLIENT_FINISHED;
            break;
        }
        case HandshakeType.server_key_exchange:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                handleServerCertificate();

                this.keyExchange.processServerKeyExchange(buf);

                assertEmpty(buf);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_KEY_EXCHANGE;
            break;
        }
        case HandshakeType.certificate_request:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_CERTIFICATE:
            case CS_CERTIFICATE_STATUS:
            {
                handleServerCertificate();

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            {
                if (this.authentication == null)
                {
                    /*
                     * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
                     * to request client identification.
                     */
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                this.certificateRequest = CertificateRequest.parse(getContext(), buf);

                assertEmpty(buf);

                this.certificateRequest = TlsUtils.validateCertificateRequest(this.certificateRequest, this.keyExchange);

                /*
                 * TODO Give the client a chance to immediately select the CertificateVerify hash
                 * algorithm here to avoid tracking the other hash algorithms unnecessarily?
                 */
                TlsUtils.trackHashAlgorithms(this.recordStream.getHandshakeHash(),
                    this.certificateRequest.getSupportedSignatureAlgorithms());

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_CERTIFICATE_REQUEST;
            break;
        }
        case HandshakeType.new_session_ticket:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_FINISHED:
            {
                if (!this.expectSessionTicket)
                {
                    /*
                     * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
                     * SessionTicket extension in the ServerHello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                /*
                 * RFC 5077 3.4. If the client receives a session ticket from the server, then it
                 * discards any Session ID that was sent in the ServerHello.
                 */
                invalidateSession();

                receiveNewSessionTicketMessage(buf);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_SESSION_TICKET;
            break;
        }
        case HandshakeType.hello_request:
        {
            assertEmpty(buf);

            /*
             * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
             * client is currently negotiating a session. This message may be ignored by the client
             * if it does not wish to renegotiate a session, or the client may, if it wishes,
             * respond with a no_renegotiation alert.
             */
            if (this.connection_state == CS_END)
            {
                handleRenegotiation();
            }
            break;
        }
        case HandshakeType.client_hello:
        case HandshakeType.client_key_exchange:
        case HandshakeType.certificate_verify:
        case HandshakeType.hello_verify_request:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleServerCertificate()
        throws IOException
    {
        TlsUtils.processServerCertificate(tlsClientContext, tlsClient, certificateStatus, keyExchange, authentication,
            clientExtensions, serverExtensions);
    }

    protected void handleSupplementalData(Vector serverSupplementalData)
        throws IOException
    {
        this.tlsClient.processServerSupplementalData(serverSupplementalData);
        this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

        this.keyExchange = TlsUtils.initKeyExchangeClient(tlsClientContext, tlsClient);
    }

    protected void receiveNewSessionTicketMessage(ByteArrayInputStream buf)
        throws IOException
    {
        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        assertEmpty(buf);

        tlsClient.notifyNewSessionTicket(newSessionTicket);
    }

    protected void receiveServerHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        ProtocolVersion server_version = TlsUtils.readVersion(buf);

        byte[] server_random = TlsUtils.readFully(32, buf);

        byte[] selectedSessionID = TlsUtils.readOpaque8(buf, 0, 32);

        int selectedCipherSuite = TlsUtils.readUint16(buf);

        short selectedCompressionMethod = TlsUtils.readUint8(buf);

        /*
         * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in Section 2.1. ... Note that the extended server hello
         * message is only sent in response to an extended client hello message. This prevents the
         * possibility that the extended server hello message could "break" existing TLS 1.0
         * clients.
         */
        this.serverExtensions = readExtensions(buf);



        SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        // TODO[tls13] Check supported_version extension for negotiated version

        if (securityParameters.isRenegotiating())
        {
            // Check that this matches the negotiated version from the initial handshake
            if (!server_version.equals(tlsClientContext.getServerVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            if (!ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(server_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            if (!ProtocolVersion.contains(tlsClientContext.getClientSupportedVersions(), server_version))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }

            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.TLSv12)
                ? ProtocolVersion.TLSv12
                : server_version;

            this.recordStream.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = server_version;
        }

        this.tlsClient.notifyServerVersion(server_version);

        if (!tlsClientContext.getClientVersion().equals(server_version))
        {
            TlsUtils.checkDowngradeMarker(server_version, server_random);
        }
        securityParameters.serverRandom = server_random;

        securityParameters.sessionID = selectedSessionID;
        this.tlsClient.notifySessionID(selectedSessionID);
        this.resumedSession = selectedSessionID.length > 0 && this.tlsSession != null
            && Arrays.areEqual(selectedSessionID, this.tlsSession.getSessionID());

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones, and is a valid selection for the negotiated version.
         */
        {
            if (!Arrays.contains(this.offeredCipherSuites, selectedCipherSuite)
                || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || CipherSuite.isSCSV(selectedCipherSuite)
                || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, tlsClientContext.getServerVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            securityParameters.cipherSuite = selectedCipherSuite;
            this.tlsClient.notifySelectedCipherSuite(selectedCipherSuite);
        }

        if (CompressionMethod._null != selectedCompressionMethod)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         */
        securityParameters.extendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(serverExtensions);

        if (!securityParameters.isExtendedMasterSecret()
            && (resumedSession || tlsClient.requiresExtendedMasterSecret()))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message.
         * 
         * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
         * Hello is always allowed.
         */
        if (this.serverExtensions != null)
        {
            Enumeration e = this.serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                /*
                 * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */
                if (extType.equals(EXT_RenegotiationInfo))
                {
                    continue;
                }

                /*
                 * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
                 * same extension type appeared in the corresponding ClientHello. If a client
                 * receives an extension type in ServerHello that it did not request in the
                 * associated ClientHello, it MUST abort the handshake with an unsupported_extension
                 * fatal alert.
                 */
                if (null == TlsUtils.getExtensionData(this.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }

                /*
                 * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                 * extensions appearing in the client hello, and send a server hello containing no
                 * extensions[.]
                 */
                if (this.resumedSession)
                {
                    // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        byte[] renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);

        if (securityParameters.isRenegotiating())
        {
            /*
             * RFC 5746 3.5. Client Behavior: Secure Renegotiation
             * 
             * This text applies if the connection's "secure_renegotiation" flag is set to TRUE.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * When a ServerHello is received, the client MUST verify that the "renegotiation_info"
             * extension is present; if it is not, the client MUST abort the handshake.
             */
            if (renegExtData == null)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            /*
             * The client MUST then verify that the first half of the "renegotiated_connection"
             * field is equal to the saved client_verify_data value, and the second half is equal to
             * the saved server_verify_data value. If they are not, the client MUST abort the
             * handshake.
             */
            SecurityParameters saved = tlsClientContext.getSecurityParametersConnection();
            byte[] reneg_conn_info = TlsUtils.concat(saved.getLocalVerifyData(), saved.getPeerVerifyData());

            if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(reneg_conn_info)))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        else
        {
            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake
             */

            /*
             * When a ServerHello is received, the client MUST check if it includes the
             * "renegotiation_info" extension:
             */
            if (renegExtData == null)
            {
                /*
                 * If the extension is not present, the server does not support secure
                 * renegotiation; set secure_renegotiation flag to FALSE. In this case, some clients
                 * may want to terminate the handshake instead of continuing; see Section 4.1 for
                 * discussion.
                 */
                securityParameters.secureRenegotiation = false;
            }
            else
            {
                /*
                 * If the extension is present, set the secure_renegotiation flag to TRUE. The
                 * client MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                 * handshake_failure alert).
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
        this.tlsClient.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        Hashtable sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;
        if (this.resumedSession)
        {
            if (securityParameters.getCipherSuite() != this.sessionParameters.getCipherSuite()
                || CompressionMethod._null != this.sessionParameters.getCompressionAlgorithm()
                || !server_version.equals(this.sessionParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = this.sessionParameters.readServerExtensions();
        }

        if (sessionServerExtensions != null && !sessionServerExtensions.isEmpty())
        {
            {
                /*
                 * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
                 * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
                 * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
                 * client.
                 */
                boolean serverSentEncryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);
                if (serverSentEncryptThenMAC && !TlsUtils.isBlockCipherSuite(securityParameters.getCipherSuite()))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
                securityParameters.encryptThenMAC = serverSentEncryptThenMAC;
            }

            securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(sessionClientExtensions,
                sessionServerExtensions, AlertDescription.illegal_parameter);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            this.allowCertificateStatus = !this.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

            this.expectSessionTicket = !this.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.illegal_parameter);
        }

        if (sessionClientExtensions != null)
        {
            this.tlsClient.processServerExtensions(sessionServerExtensions);
        }

        securityParameters.prfAlgorithm = getPRFAlgorithm(tlsClientContext, securityParameters.getCipherSuite());

        /*
         * RFC 5246 7.4.9. Any cipher suite which does not explicitly specify
         * verify_data_length has a verify_data_length equal to 12. This includes all
         * existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate_verify);

        certificateVerify.encode(message);

        message.writeToRecordStream();
    }

    protected void sendClientHelloMessage()
        throws IOException
    {
        SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        ProtocolVersion client_version;
        if (securityParameters.isRenegotiating())
        {
            client_version = tlsClientContext.getClientVersion();
        }
        else
        {
            // TODO[tls13] Subsequent ClientHello messages (of a TLSv13 handshake) should use TLSv12
            this.recordStream.setWriteVersion(ProtocolVersion.TLSv10);

            tlsClientContext.setClientSupportedVersions(tlsClient.getProtocolVersions());

            client_version = ProtocolVersion.getLatestTLS(tlsClientContext.getClientSupportedVersions());
            if (null == client_version
                || client_version.isEarlierVersionOf(ProtocolVersion.TLSv10)
                || client_version.isLaterVersionOf(ProtocolVersion.TLSv12))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            tlsClientContext.setClientVersion(client_version);
        }

        /*
         * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
         * Session ID in the TLS ClientHello.
         */
        byte[] session_id = TlsUtils.EMPTY_BYTES;
        if (this.tlsSession != null)
        {
            session_id = this.tlsSession.getSessionID();
            if (session_id == null || session_id.length > 32)
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        boolean fallback = this.tlsClient.isFallback();

        this.offeredCipherSuites = this.tlsClient.getCipherSuites();

        if (session_id.length > 0 && this.sessionParameters != null)
        {
            /*
             * NOTE: If we ever enable session resumption without extended_master_secret, then
             * renegotiation MUST be disabled (see RFC 7627 5.4).
             */
            if (!sessionParameters.isExtendedMasterSecret()
                || !Arrays.contains(this.offeredCipherSuites, sessionParameters.getCipherSuite())
                || CompressionMethod._null != sessionParameters.getCompressionAlgorithm())
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsClient.getClientExtensions());

        ProtocolVersion legacy_version = client_version;
        if (client_version.isLaterVersionOf(ProtocolVersion.TLSv12))
        {
            legacy_version = ProtocolVersion.TLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                tlsClientContext.getClientSupportedVersions());
        }

        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
        {
            securityParameters.clientSigAlgs = TlsExtensionsUtils.getSignatureAlgorithmsExtension(clientExtensions);
            securityParameters.clientSigAlgsCert = TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(clientExtensions);
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

        this.clientAgreements = TlsUtils.addEarlyKeySharesToClientHello(tlsClientContext, tlsClient, clientExtensions);

        TlsExtensionsUtils.addExtendedMasterSecretExtension(this.clientExtensions);

        securityParameters.clientRandom = createRandomBlock(tlsClient.shouldUseGMTUnixTime(), tlsClientContext);

        if (securityParameters.isRenegotiating())
        {
            /*
             * RFC 5746 3.5. Client Behavior: Secure Renegotiation
             * 
             * This text applies if the connection's "secure_renegotiation" flag is set to TRUE.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * The client MUST include the "renegotiation_info" extension in the ClientHello,
             * containing the saved client_verify_data. The SCSV MUST NOT be included.
             */
            SecurityParameters saved = tlsClientContext.getSecurityParametersConnection();

            this.clientExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(saved.getLocalVerifyData()));
        }
        else
        {
            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake
             */

            /*
             * The client MUST include either an empty "renegotiation_info" extension, or the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the ClientHello.
             * Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = (null == TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo));
            boolean noRenegSCSV = !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noRenegSCSV)
            {
                this.offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }
        }

        /*
         * (Fallback SCSV)
         * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
         * than the latest (highest-valued) version supported by the client, it SHOULD include
         * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
         * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
         * to negotiate.)
         */
        if (fallback && !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
        {
            this.offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
        }



        ClientHello clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(), session_id,
            null, offeredCipherSuites, clientExtensions);

        HandshakeMessage message = new HandshakeMessage(HandshakeType.client_hello);
        clientHello.encode(tlsClientContext, message);
        message.writeToRecordStream();
    }

    protected void sendClientKeyExchangeMessage()
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.client_key_exchange);

        this.keyExchange.generateClientKeyExchange(message);

        message.writeToRecordStream();
    }
}
