package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class TlsServerProtocol
    extends TlsProtocol
{
    protected TlsServer tlsServer = null;
    TlsServerContextImpl tlsServerContext = null;

    protected TlsKeyExchange keyExchange = null;
    protected TlsCredentials serverCredentials = null;
    protected CertificateRequest certificateRequest = null;

    protected TlsHandshakeHash prepareFinishHash = null;

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
    public TlsServerProtocol()
    {
        super();
    }

    /**
     * Constructor for blocking mode.
     * @param input The stream of data from the client
     * @param output The stream of data to the client
     */
    public TlsServerProtocol(InputStream input, OutputStream output)
    {
        super(input, output);
    }

    /**
     * Receives a TLS handshake in the role of server.<br>
     * <br>
     * In blocking mode, this will not return until the handshake is complete.
     * In non-blocking mode, use {@link TlsPeer#notifyHandshakeComplete()} to
     * receive a callback when the handshake is complete.
     *
     * @param tlsServer
     * @throws IOException If in blocking mode and handshake was not successful.
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
            throw new IllegalStateException("'accept' can only be called once");
        }

        this.tlsServer = tlsServer;
        this.tlsServerContext = new TlsServerContextImpl(tlsServer.getCrypto());

        this.tlsServer.init(tlsServerContext);
        this.recordStream.init(tlsServerContext);

        tlsServer.notifyCloseHandle(this);

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
//            sendHelloRequestMessage();
//        }
//        return allowed;
//    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();
        
        this.keyExchange = null;
        this.serverCredentials = null;
        this.certificateRequest = null;
        this.prepareFinishHash = null;
    }

    protected TlsContext getContext()
    {
        return tlsServerContext;
    }

    AbstractTlsContext getContextAdmin()
    {
        return tlsServerContext;
    }

    protected TlsPeer getPeer()
    {
        return tlsServer;
    }

    protected void handleHandshakeMessage(short type, ByteArrayInputStream buf)
        throws IOException
    {
        switch (type)
        {
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_END:
            {
                if (!handleRenegotiation())
                {
                    break;
                }

                // NB: Fall through to next case label
            }
            case CS_START:
            {
                SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

                receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                /*
                 * NOTE: Currently no server support for session resumption
                 * 
                 * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
                 * ONLY when extended_master_secret has been negotiated (otherwise NULL).
                 */
                {
                    invalidateSession();

                    securityParameters.sessionID = TlsUtils.EMPTY_BYTES;

                    this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
                    this.sessionParameters = null;
                }

                sendServerHelloMessage();
                this.connection_state = CS_SERVER_HELLO;

                recordStream.notifyHelloComplete();

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null)
                {
                    sendSupplementalDataMessage(serverSupplementalData);
                }
                this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

                this.keyExchange = TlsUtils.initKeyExchangeServer(tlsServerContext, tlsServer);

                this.serverCredentials = validateCredentials(tlsServer.getCredentials());

                // Server certificate
                {
                    Certificate serverCertificate = null;

                    ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
                    if (null == this.serverCredentials)
                    {
                        this.keyExchange.skipServerCredentials();
                    }
                    else
                    {
                        this.keyExchange.processServerCredentials(this.serverCredentials);

                        serverCertificate = this.serverCredentials.getCertificate();
                        sendCertificateMessage(serverCertificate, endPointHash);
                    }
                    securityParameters.tlsServerEndPoint = endPointHash.toByteArray();
                    this.connection_state = CS_SERVER_CERTIFICATE;

                    // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                    if (null == serverCertificate || serverCertificate.isEmpty())
                    {
                        this.allowCertificateStatus = false;
                    }
                }

                if (this.allowCertificateStatus)
                {
                    CertificateStatus certificateStatus = tlsServer.getCertificateStatus();
                    if (certificateStatus != null)
                    {
                        sendCertificateStatusMessage(certificateStatus);
                    }
                }

                this.connection_state = CS_CERTIFICATE_STATUS;

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
                        if (TlsUtils.isTLSv12(getContext()) != (certificateRequest.getSupportedSignatureAlgorithms() != null))
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }

                        this.certificateRequest = TlsUtils.validateCertificateRequest(this.certificateRequest, this.keyExchange);

                        sendCertificateRequestMessage(certificateRequest);

                        TlsUtils.trackHashAlgorithms(this.recordStream.getHandshakeHash(),
                            this.certificateRequest.getSupportedSignatureAlgorithms());
                    }
                }
                this.connection_state = CS_CERTIFICATE_REQUEST;

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;

                boolean forceBuffering = false;
                TlsUtils.sealHandshakeHash(getContext(), this.recordStream.getHandshakeHash(), forceBuffering);

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
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(readSupplementalDataMessage(buf));
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
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
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                receiveCertificateMessage(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
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
                    if (TlsUtils.isTLSv12(getContext()))
                    {
                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
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
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
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
                if (!expectCertificateVerifyMessage())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                receiveCertificateVerifyMessage(buf);
                this.connection_state = CS_CERTIFICATE_VERIFY;

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
            case CS_CLIENT_KEY_EXCHANGE:
            {
                if (expectCertificateVerifyMessage())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                // NB: Fall through to next case label
            }
            case CS_CERTIFICATE_VERIFY:
            {
                processFinishedMessage(buf);
                this.connection_state = CS_CLIENT_FINISHED;

                if (this.expectSessionTicket)
                {
                    sendNewSessionTicketMessage(tlsServer.getNewSessionTicket());
                }
                this.connection_state = CS_SERVER_SESSION_TICKET;

                sendChangeCipherSpecMessage();
                sendFinishedMessage();
                this.connection_state = CS_SERVER_FINISHED;

                completeHandshake();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.server_hello:
        case HandshakeType.server_key_exchange:
        case HandshakeType.certificate_request:
        case HandshakeType.server_hello_done:
        case HandshakeType.new_session_ticket:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleAlertWarningMessage(short alertDescription)
        throws IOException
    {
        super.handleAlertWarningMessage(alertDescription);

        switch (alertDescription)
        {
        case AlertDescription.no_certificate:
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
        }
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {
        TlsUtils.processClientCertificate(tlsServerContext, clientCertificate, certificateRequest, keyExchange,
            tlsServer);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf)
        throws IOException
    {
        Certificate clientCertificate = Certificate.parse(getContext(), buf, null);

        assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf)
        throws IOException
    {
        if (certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        DigitallySigned clientCertificateVerify = DigitallySigned.parse(tlsServerContext, buf);

        assertEmpty(buf);

        TlsUtils.verifyCertificateVerify(tlsServerContext, certificateRequest, clientCertificateVerify, prepareFinishHash);
    }

    protected void receiveClientHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13] For subsequent ClientHello messages (of a TLSv13 handshake) don't do this!
        recordStream.setWriteVersion(ProtocolVersion.TLSv10);

        ClientHello clientHello = ClientHello.parse(buf, null);
        ProtocolVersion client_version = clientHello.getClientVersion();
        this.offeredCipherSuites = clientHello.getCipherSuites();

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        this.clientExtensions = clientHello.getExtensions();


 
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        tlsServerContext.setClientSupportedVersions(
            TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientExtensions));
        if (null == tlsServerContext.getClientSupportedVersions())
        {
            if (client_version.isLaterVersionOf(ProtocolVersion.TLSv12))
            {
                client_version = ProtocolVersion.TLSv12;
            }

            tlsServerContext.setClientSupportedVersions(client_version.downTo(ProtocolVersion.TLSv10));
        }
        else
        {
            client_version = ProtocolVersion.getLatestTLS(tlsServerContext.getClientSupportedVersions());
        }

        if (null == client_version || !ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        if (securityParameters.isRenegotiating())
        {
            // Check that this is either the originally offered version or the negotiated version
            if (!client_version.equals(tlsServerContext.getClientVersion())
                && !client_version.equals(tlsServerContext.getServerVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            tlsServerContext.setClientVersion(client_version);
        }

        tlsServer.notifyClientVersion(tlsServerContext.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        tlsServer.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        tlsServer.notifyOfferedCipherSuites(offeredCipherSuites);

        /*
         * TODO[resumption] Check RFC 7627 5.4. for required behaviour 
         */

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         */
        securityParameters.extendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientExtensions);

        if (!securityParameters.isExtendedMasterSecret()
            && (resumedSession || tlsServer.requiresExtendedMasterSecret()))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);

        if (securityParameters.isRenegotiating())
        {
            /*
             * RFC 5746 3.7. Server Behavior: Secure Renegotiation
             * 
             * This text applies if the connection's "secure_renegotiation" flag is set to TRUE.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * When a ClientHello is received, the server MUST verify that it does not contain the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If the SCSV is present, the server MUST abort
             * the handshake.
             */
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            /*
             * The server MUST verify that the "renegotiation_info" extension is present; if it is
             * not, the server MUST abort the handshake.
             */
            if (null == renegExtData)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            /*
             * The server MUST verify that the value of the "renegotiated_connection" field is equal
             * to the saved client_verify_data value; if it is not, the server MUST abort the
             * handshake.
             */
            SecurityParameters saved = tlsServerContext.getSecurityParametersConnection();
            byte[] reneg_conn_info = saved.getPeerVerifyData();

            if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(reneg_conn_info)))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        else
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */

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
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                securityParameters.secureRenegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        tlsServer.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        if (clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
            {
                securityParameters.clientSigAlgs = TlsExtensionsUtils.getSignatureAlgorithmsExtension(clientExtensions);
                securityParameters.clientSigAlgsCert = TlsExtensionsUtils.getSignatureAlgorithmsCertExtension(clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

            tlsServer.processClientExtensions(clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf)
        throws IOException
    {
        keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        this.prepareFinishHash = recordStream.prepareToFinish();
        tlsServerContext.getSecurityParametersHandshake().sessionHash = TlsUtils.getCurrentPRFHash(prepareFinishHash);

        establishMasterSecret(getContext(), keyExchange);
        recordStream.setPendingConnectionState(TlsUtils.initCipher(getContext()));
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate_request);

        certificateRequest.encode(message);

        message.writeToRecordStream();
    }

    protected void sendCertificateStatusMessage(CertificateStatus certificateStatus)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate_status);

        certificateStatus.encode(message);

        message.writeToRecordStream();
    }

    protected void sendHelloRequestMessage()
        throws IOException
    {
        byte[] message = new byte[4];
        TlsUtils.writeUint8(HandshakeType.hello_request, message, 0);
        TlsUtils.writeUint24(0, message, 1);

        writeHandshakeMessage(message, 0, message.length);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        throws IOException
    {
        if (newSessionTicket == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        HandshakeMessage message = new HandshakeMessage(HandshakeType.new_session_ticket);

        newSessionTicket.encode(message);

        message.writeToRecordStream();
    }

    protected void sendServerHelloMessage()
        throws IOException
    {
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        ProtocolVersion server_version;
        if (securityParameters.isRenegotiating())
        {
            // Always select the negotiated version from the initial handshake
            server_version = tlsServerContext.getServerVersion();
        }
        else
        {
            server_version = tlsServer.getServerVersion();
            if (null == server_version
                || server_version.isEarlierVersionOf(ProtocolVersion.TLSv10)
                || server_version.isLaterVersionOf(ProtocolVersion.TLSv12)
                || !ProtocolVersion.contains(tlsServerContext.getClientSupportedVersions(), server_version))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.TLSv12)
                ? ProtocolVersion.TLSv12
                : server_version;

            recordStream.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = server_version;
        }

        securityParameters.serverRandom = createRandomBlock(tlsServer.shouldUseGMTUnixTime(), tlsServerContext);
        if (!server_version.equals(ProtocolVersion.getLatestTLS(tlsServer.getProtocolVersions())))
        {
            TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
        }

        {
            int selectedCipherSuite = tlsServer.getSelectedCipherSuite();
            if (!Arrays.contains(offeredCipherSuites, selectedCipherSuite)
                || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || CipherSuite.isSCSV(selectedCipherSuite)
                || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, tlsServerContext.getServerVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            securityParameters.cipherSuite = selectedCipherSuite;
        }

        this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(tlsServer.getServerExtensions());

        ProtocolVersion legacy_version = server_version;
        if (server_version.isLaterVersionOf(ProtocolVersion.TLSv12))
        {
            legacy_version = ProtocolVersion.TLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverExtensions, server_version);
        }

        if (securityParameters.isRenegotiating())
        {
            /*
             * The server MUST include a "renegotiation_info" extension containing the saved
             * client_verify_data and server_verify_data in the ServerHello.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            SecurityParameters saved = tlsServerContext.getSecurityParametersConnection();
            byte[] reneg_conn_info = TlsUtils.concat(saved.getPeerVerifyData(), saved.getLocalVerifyData());

            this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(reneg_conn_info));
        }
        else
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */
            if (securityParameters.isSecureRenegotiation())
            {
                byte[] renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                boolean noRenegExt = (null == renegExtData);

                if (noRenegExt)
                {
                    /*
                     * Note that sending a "renegotiation_info" extension in response to a ClientHello
                     * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                     * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                     * because the client is signaling its willingness to receive the extension via the
                     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                     */

                    /*
                     * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                     * "renegotiation_info" extension in the ServerHello message.
                     */
                    this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                }
            }
        }

        if (securityParameters.isExtendedMasterSecret())
        {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
        }

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        if (!this.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(clientExtensions,
                serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            this.allowCertificateStatus = !resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request,
                    AlertDescription.internal_error);

            this.expectSessionTicket = !resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);
        }

        securityParameters.prfAlgorithm = getPRFAlgorithm(tlsServerContext, securityParameters.getCipherSuite());

        /*
         * RFC 5246 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;

        applyMaxFragmentLengthExtension();



        HandshakeMessage message = new HandshakeMessage(HandshakeType.server_hello);

        TlsUtils.writeVersion(legacy_version, message);

        message.write(securityParameters.getServerRandom());

        /*
         * The server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        TlsUtils.writeOpaque8(tlsSession.getSessionID(), message);

        TlsUtils.writeUint16(securityParameters.getCipherSuite(), message);

        TlsUtils.writeUint8(CompressionMethod._null, message);

        writeExtensions(message, serverExtensions);

        message.writeToRecordStream();
    }

    protected void sendServerHelloDoneMessage()
        throws IOException
    {
        byte[] message = new byte[4];
        TlsUtils.writeUint8(HandshakeType.server_hello_done, message, 0);
        TlsUtils.writeUint24(0, message, 1);

        writeHandshakeMessage(message, 0, message.length);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.server_key_exchange, serverKeyExchange.length);

        message.write(serverKeyExchange);

        message.writeToRecordStream();
    }

    protected boolean expectCertificateVerifyMessage()
    {
        Certificate clientCertificate = tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();

        return null != clientCertificate && !clientCertificate.isEmpty() && keyExchange.requiresCertificateVerify();
    }
}
