package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class TlsClientProtocol
    extends TlsProtocol
{
    protected TlsClient tlsClient = null;
    TlsClientContextImpl tlsClientContext = null;

    protected Hashtable clientAgreements = null;
    protected ClientHello clientHello = null;
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

        tlsClient.init(tlsClientContext);
        tlsClient.notifyCloseHandle(this);

        beginHandshake();

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

    protected void beginHandshake() throws IOException
    {
        super.beginHandshake();

        establishSession(tlsClient.getSessionToResume());

        sendClientHello();
        this.connection_state = CS_CLIENT_HELLO;
    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();

        this.clientAgreements = null;
        this.clientHello = null;
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

    protected void handle13HandshakeMessage(short type, HandshakeMessageInput buf)
        throws IOException
    {
        if (!isTLSv13ConnectionState())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (this.resumedSession)
        {
            /*
             * TODO[tls13] Resumption/PSK
             * 
             * NOTE: No CertificateRequest, Certificate, CertificateVerify messages, but client
             * might now send EndOfEarlyData after receiving server Finished message.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        switch (type)
        {
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_ENCRYPTED_EXTENSIONS:
            {
                skip13CertificateRequest();
                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE_REQUEST:
            {
                /*
                 * TODO[tls13] For PSK-only key exchange, there's no Certificate message.
                 */
                receive13ServerCertificate(buf);
                this.connection_state = CS_SERVER_CERTIFICATE;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.certificate_request:
        {
            switch (this.connection_state)
            {
            case CS_END:
            {
                // TODO[tls13] Permit post-handshake authentication if we sent post_handshake_auth extension
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            case CS_SERVER_ENCRYPTED_EXTENSIONS:
            {
                receive13CertificateRequest(buf, false);
                this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
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
            case CS_SERVER_CERTIFICATE:
            {
                receive13ServerCertificateVerify(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_SERVER_CERTIFICATE_VERIFY;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.encrypted_extensions:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                receive13EncryptedExtensions(buf);
                this.connection_state = CS_SERVER_ENCRYPTED_EXTENSIONS;
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
            case CS_SERVER_ENCRYPTED_EXTENSIONS:
            {
                skip13CertificateRequest();
                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE_REQUEST:
            {
                skip13ServerCertificate();
                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE_VERIFY:
            {
                receive13ServerFinished(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_SERVER_FINISHED;

                byte[] serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

                // See RFC 8446 D.4.
                recordStream.setIgnoreChangeCipherSpec(false);

                if (null != certificateRequest)
                {
                    TlsCredentialedSigner clientCredentials = TlsUtils.establish13ClientCredentials(authentication,
                        certificateRequest);

                    Certificate clientCertificate = null;
                    if (null != clientCredentials)
                    {
                        clientCertificate = clientCredentials.getCertificate();
                    }

                    if (null == clientCertificate)
                    {
                        // In this calling context, certificate_request_context is length 0
                        clientCertificate = Certificate.EMPTY_CHAIN_TLS13;
                    }

                    send13CertificateMessage(clientCertificate);
                    this.connection_state = CS_CLIENT_CERTIFICATE;

                    if (null != clientCredentials)
                    {
                        DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(tlsClientContext,
                            clientCredentials, handshakeHash);
                        send13CertificateVerifyMessage(certificateVerify);
                        this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
                    }
                }

                send13FinishedMessage();
                this.connection_state = CS_CLIENT_FINISHED;

                TlsUtils.establish13PhaseApplication(tlsClientContext, serverFinishedTranscriptHash, recordStream);

                recordStream.enablePendingCipherWrite();
                recordStream.enablePendingCipherRead(false);

                completeHandshake();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.key_update:
        {
            receive13KeyUpdate(buf);
            break;
        }
        case HandshakeType.new_session_ticket:
        {
            receive13NewSessionTicket(buf);
            break;
        }
        case HandshakeType.server_hello:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_HELLO:
            {
                // NOTE: Legacy handler should be dispatching initial ServerHello/HelloRetryRequest.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            case CS_CLIENT_HELLO_RETRY:
            {
                ServerHello serverHello = receiveServerHelloMessage(buf);
                if (serverHello.isHelloRetryRequest())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                process13ServerHello(serverHello, true);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_SERVER_HELLO;

                process13ServerHelloCoda(serverHello, true);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }

        case HandshakeType.certificate_status:
        case HandshakeType.certificate_url:
        case HandshakeType.client_hello:
        case HandshakeType.client_key_exchange:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.message_hash:
        case HandshakeType.server_hello_done:
        case HandshakeType.server_key_exchange:
        case HandshakeType.supplemental_data:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleHandshakeMessage(short type, HandshakeMessageInput buf)
        throws IOException
    {
        final SecurityParameters securityParameters = tlsClientContext.getSecurityParameters();

        if (connection_state > CS_CLIENT_HELLO
            && TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            handle13HandshakeMessage(type, buf);
            return;
        }

        if (!isLegacyConnectionState())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (this.resumedSession)
        {
            if (type != HandshakeType.finished || this.connection_state != CS_SERVER_HELLO)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processFinishedMessage(buf);
            buf.updateHash(handshakeHash);
            this.connection_state = CS_SERVER_FINISHED;

            sendChangeCipherSpec();
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
                /*
                 * NOTE: Certificate processing (including authentication) is delayed to allow for a
                 * possible CertificateStatus message.
                 */
                this.authentication = TlsUtils.receiveServerCertificate(tlsClientContext, tlsClient, buf);
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
                if (securityParameters.getStatusRequestVersion() < 1)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                this.certificateStatus = CertificateStatus.parse(tlsClientContext, buf);

                assertEmpty(buf);

                this.connection_state = CS_SERVER_CERTIFICATE_STATUS;
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
                ServerHello serverHello = receiveServerHelloMessage(buf);

                // TODO[tls13] Only treat as HRR if it's TLS 1.3??
                if (serverHello.isHelloRetryRequest())
                {
                    process13HelloRetryRequest(serverHello);
                    handshakeHash.notifyPRFDetermined();
                    TlsUtils.adjustTranscriptForRetry(handshakeHash);
                    buf.updateHash(handshakeHash);
                    this.connection_state = CS_SERVER_HELLO_RETRY_REQUEST;

                    send13ClientHelloRetry();
                    this.connection_state = CS_CLIENT_HELLO_RETRY;
                }
                else
                {
                    processServerHello(serverHello);
                    handshakeHash.notifyPRFDetermined();
                    buf.updateHash(handshakeHash);
                    this.connection_state = CS_SERVER_HELLO;

                    if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
                    {
                        process13ServerHelloCoda(serverHello, false);
                    }
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
            case CS_SERVER_CERTIFICATE_STATUS:
            {
                handleServerCertificate();

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            case CS_SERVER_CERTIFICATE_REQUEST:
            {
                assertEmpty(buf);

                this.connection_state = CS_SERVER_HELLO_DONE;

                Vector clientSupplementalData = tlsClient.getClientSupplementalData();
                if (clientSupplementalData != null)
                {
                    sendSupplementalDataMessage(clientSupplementalData);
                    this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
                }

                TlsCredentialedSigner credentialedSigner = null;
                TlsStreamSigner streamSigner = null;

                if (certificateRequest == null)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else
                {
                    Certificate clientCertificate = null;

                    TlsCredentials clientCredentials = TlsUtils.establishClientCredentials(authentication,
                        certificateRequest);
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
                    this.connection_state = CS_CLIENT_CERTIFICATE;
                }

                boolean forceBuffering = streamSigner != null;
                TlsUtils.sealHandshakeHash(tlsClientContext, handshakeHash, forceBuffering);

                /*
                 * Send the client key exchange message, depending on the key exchange we are using
                 * in our CipherSuite.
                 */
                sendClientKeyExchange();
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                final boolean isSSL = TlsUtils.isSSL(tlsClientContext);
                if (isSSL)
                {
                    // NOTE: For SSLv3 (only), master_secret needed to calculate session hash
                    establishMasterSecret(tlsClientContext, keyExchange);
                }

                securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshakeHash);

                if (!isSSL)
                {
                    // NOTE: For (D)TLS, session hash potentially needed for extended_master_secret
                    establishMasterSecret(tlsClientContext, keyExchange);
                }

                recordStream.setPendingCipher(TlsUtils.initCipher(tlsClientContext));

                if (credentialedSigner != null)
                {
                    DigitallySigned certificateVerify = TlsUtils.generateCertificateVerifyClient(tlsClientContext,
                        credentialedSigner, streamSigner, handshakeHash);
                    sendCertificateVerifyMessage(certificateVerify);
                    this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
                }

                this.handshakeHash = handshakeHash.stopTracking();

                sendChangeCipherSpec();
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
            case CS_SERVER_CERTIFICATE_STATUS:
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
            case CS_SERVER_CERTIFICATE_STATUS:
            {
                handleServerCertificate();

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label
            }
            case CS_SERVER_KEY_EXCHANGE:
            {
                receiveCertificateRequest(buf);

                TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                /*
                 * TODO Give the client a chance to immediately select the CertificateVerify hash
                 * algorithm here to avoid tracking the other hash algorithms unnecessarily?
                 */
                TlsUtils.trackHashAlgorithms(handshakeHash, securityParameters.getServerSigAlgs());

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
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

                receiveNewSessionTicket(buf);
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
            if (isApplicationDataReady())
            {
                refuseRenegotiation();
            }
            break;
        }

        case HandshakeType.certificate_url:
        case HandshakeType.certificate_verify:
        case HandshakeType.client_hello:
        case HandshakeType.client_key_exchange:
        case HandshakeType.encrypted_extensions:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
        case HandshakeType.message_hash:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleServerCertificate()
        throws IOException
    {
        TlsUtils.processServerCertificate(tlsClientContext, certificateStatus, keyExchange, authentication,
            clientExtensions, serverExtensions);
    }

    protected void handleSupplementalData(Vector serverSupplementalData)
        throws IOException
    {
        tlsClient.processServerSupplementalData(serverSupplementalData);
        this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

        this.keyExchange = TlsUtils.initKeyExchangeClient(tlsClientContext, tlsClient);
    }

    protected void process13HelloRetryRequest(ServerHello helloRetryRequest)
        throws IOException
    {
        final ProtocolVersion legacy_record_version = ProtocolVersion.TLSv12;
        recordStream.setWriteVersion(legacy_record_version);

        final SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        /*
         * RFC 8446 4.1.4. Upon receipt of a HelloRetryRequest, the client MUST check the
         * legacy_version, legacy_session_id_echo, cipher_suite, and legacy_compression_method as
         * specified in Section 4.1.3 and then process the extensions, starting with determining the
         * version using "supported_versions".
         */
        final ProtocolVersion legacy_version = helloRetryRequest.getVersion();
        final byte[] legacy_session_id_echo = helloRetryRequest.getSessionID();
        final int cipherSuite = helloRetryRequest.getCipherSuite();
        // NOTE: legacy_compression_method checked during ServerHello parsing

        if (!ProtocolVersion.TLSv12.equals(legacy_version) ||
            !Arrays.areEqual(clientHello.getSessionID(), legacy_session_id_echo) ||
            !TlsUtils.isValidCipherSuiteSelection(clientHello.getCipherSuites(), cipherSuite))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        final Hashtable extensions = helloRetryRequest.getExtensions();
        if (null == extensions)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        TlsUtils.checkExtensionData13(extensions, HandshakeType.hello_retry_request, AlertDescription.illegal_parameter);

        {
            /*
             * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote
             * endpoint did not send the corresponding extension requests, with the exception of the
             * "cookie" extension in the HelloRetryRequest. Upon receiving such an extension, an
             * endpoint MUST abort the handshake with an "unsupported_extension" alert.
             */
            Enumeration e = extensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                if (ExtensionType.cookie == extType.intValue())
                {
                    continue;
                }

                if (null == TlsUtils.getExtensionData(clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }
            }
        }

        final ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
        if (null == server_version)
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension);
        }

        if (!ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(server_version) ||
            !ProtocolVersion.contains(tlsClientContext.getClientSupportedVersions(), server_version) ||
            !TlsUtils.isValidVersionForCipherSuite(cipherSuite, server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * RFC 8446 4.2.8. Upon receipt of this [Key Share] extension in a HelloRetryRequest, the
         * client MUST verify that (1) the selected_group field corresponds to a group which was
         * provided in the "supported_groups" extension in the original ClientHello and (2) the
         * selected_group field does not correspond to a group which was provided in the "key_share"
         * extension in the original ClientHello. If either of these checks fails, then the client
         * MUST abort the handshake with an "illegal_parameter" alert.
         */
        final int selected_group = TlsExtensionsUtils.getKeyShareHelloRetryRequest(extensions);

        if (!TlsUtils.isValidKeyShareSelection(server_version, securityParameters.getClientSupportedGroups(),
            clientAgreements, selected_group))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        final byte[] cookie = TlsExtensionsUtils.getCookieExtension(extensions);



        securityParameters.negotiatedVersion = server_version;
        TlsUtils.negotiatedVersionTLSClient(tlsClientContext, tlsClient);

        this.resumedSession = false;
        securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
        tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);

        TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        tlsClient.notifySelectedCipherSuite(cipherSuite);

        this.clientAgreements = null;
        this.retryCookie = cookie;
        this.retryGroup = selected_group;
    }

    protected void process13ServerHello(ServerHello serverHello, boolean afterHelloRetryRequest)
        throws IOException
    {
        final SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        final ProtocolVersion legacy_version = serverHello.getVersion();
        final byte[] legacy_session_id_echo = serverHello.getSessionID();
        final int cipherSuite = serverHello.getCipherSuite();
        // NOTE: legacy_compression_method checked during ServerHello parsing

        if (!ProtocolVersion.TLSv12.equals(legacy_version) ||
            !Arrays.areEqual(clientHello.getSessionID(), legacy_session_id_echo))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        final Hashtable extensions = serverHello.getExtensions();
        if (null == extensions)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        TlsUtils.checkExtensionData13(extensions, HandshakeType.server_hello, AlertDescription.illegal_parameter);

        if (afterHelloRetryRequest)
        {
            final ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
            if (null == server_version)
            {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }

            if (!securityParameters.getNegotiatedVersion().equals(server_version) ||
                securityParameters.getCipherSuite() != cipherSuite)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            if (!TlsUtils.isValidCipherSuiteSelection(clientHello.getCipherSuites(), cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.resumedSession = false;
            securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
            tlsClient.notifySessionID(TlsUtils.EMPTY_BYTES);

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            tlsClient.notifySelectedCipherSuite(cipherSuite);
        }

        this.clientHello = null;

        // NOTE: Apparently downgrade marker mechanism not used for TLS 1.3+?
        securityParameters.serverRandom = serverHello.getRandom();

        securityParameters.secureRenegotiation = false;

        /*
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        securityParameters.extendedMasterSecret = true;

        /*
         * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
         * 
         * OCSP information is carried in an extension for a CertificateEntry.
         */
        securityParameters.statusRequestVersion = clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;

        {
            KeyShareEntry keyShareEntry = TlsExtensionsUtils.getKeyShareServerHello(extensions);
            if (null == keyShareEntry)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            TlsAgreement agreement = (TlsAgreement)clientAgreements.get(Integers.valueOf(keyShareEntry.getNamedGroup()));
            if (null == agreement)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.clientAgreements = null;

            agreement.receivePeerValue(keyShareEntry.getKeyExchange());
            securityParameters.sharedSecret = agreement.calculateSecret();

            TlsUtils.establish13PhaseSecrets(tlsClientContext);
        }

        {
            invalidateSession();

            this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
            this.sessionParameters = null;
            this.sessionMasterSecret = null;
        }
    }

    protected void process13ServerHelloCoda(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException
    {
        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        TlsUtils.establish13PhaseHandshake(tlsClientContext, serverHelloTranscriptHash, recordStream);

        // See RFC 8446 D.4.
        if (!afterHelloRetryRequest)
        {
            recordStream.setIgnoreChangeCipherSpec(true);

            // TODO[tls13] If offering early data, the record is placed immediately after the first ClientHello.
            /*
             * TODO[tls13] Ideally wait until just after Server Finished received, but then we'd need to defer
             * the enabling of the pending write cipher
             */
            sendChangeCipherSpecMessage();
        }

        recordStream.enablePendingCipherWrite();
        recordStream.enablePendingCipherRead(false);
    }

    protected void processServerHello(ServerHello serverHello)
        throws IOException
    {
        Hashtable serverHelloExtensions = serverHello.getExtensions();

        final ProtocolVersion legacy_version = serverHello.getVersion();
        final ProtocolVersion supported_version = TlsExtensionsUtils
            .getSupportedVersionsExtensionServer(serverHelloExtensions);

        final ProtocolVersion server_version;
        if (null == supported_version)
        {
            server_version = legacy_version;
        }
        else
        {
            if (!ProtocolVersion.TLSv12.equals(legacy_version) ||
                !ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(supported_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            server_version = supported_version;
        }

        final SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        // NOT renegotiating
        {
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

        TlsUtils.negotiatedVersionTLSClient(tlsClientContext, tlsClient);

        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(server_version))
        {
            process13ServerHello(serverHello, false);
            return;
        }

        int[] offeredCipherSuites = clientHello.getCipherSuites();

        this.clientHello = null;
        this.retryCookie = null;
        this.retryGroup = -1;

        securityParameters.serverRandom = serverHello.getRandom();

        if (!tlsClientContext.getClientVersion().equals(server_version))
        {
            TlsUtils.checkDowngradeMarker(server_version, securityParameters.getServerRandom());
        }

        {
            byte[] selectedSessionID = serverHello.getSessionID();
            securityParameters.sessionID = selectedSessionID;
            tlsClient.notifySessionID(selectedSessionID);
            this.resumedSession = selectedSessionID.length > 0 && this.tlsSession != null
                && Arrays.areEqual(selectedSessionID, this.tlsSession.getSessionID());
        }

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones, and is a valid selection for the negotiated version.
         */
        {
            int cipherSuite = serverHello.getCipherSuite();

            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            tlsClient.notifySelectedCipherSuite(cipherSuite);
        }

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message.
         * 
         * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
         * Hello is always allowed.
         */
        this.serverExtensions = serverHelloExtensions;
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

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
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
        tlsClient.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         * 
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        {
            final boolean acceptedExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(
                serverExtensions);

            if (acceptedExtendedMasterSecret)
            {
                if (server_version.isSSL()
                    || (!resumedSession && !tlsClient.shouldUseExtendedMasterSecret()))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
            else
            {
                if (tlsClient.requiresExtendedMasterSecret()
                    || (resumedSession && !tlsClient.allowLegacyResumption()))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }

            securityParameters.extendedMasterSecret = acceptedExtendedMasterSecret;
        }

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
            if (!this.resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request_v2,
                    AlertDescription.illegal_parameter))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request,
                    AlertDescription.illegal_parameter))
                {
                    securityParameters.statusRequestVersion = 1;
                }

                this.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.illegal_parameter);
            }
        }

        if (sessionClientExtensions != null)
        {
            tlsClient.processServerExtensions(sessionServerExtensions);
        }

        applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());

        if (this.resumedSession)
        {
            securityParameters.masterSecret = sessionMasterSecret;
            this.recordStream.setPendingCipher(TlsUtils.initCipher(tlsClientContext));
        }
        else
        {
            invalidateSession();

            this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
            this.sessionParameters = null;
            this.sessionMasterSecret = null;
        }
    }

    protected void receive13CertificateRequest(ByteArrayInputStream buf, boolean postHandshakeAuth)
        throws IOException
    {
        /* 
         * RFC 8446 4.3.2. A server which is authenticating with a certificate MAY optionally
         * request a certificate from the client.
         */

        /*
         * TODO[tls13] Currently all handshakes are certificate-authenticated. When PSK-only becomes an option,
         * then check here that a certificate message is expected (else fatal unexpected_message alert).
         */

        CertificateRequest certificateRequest = CertificateRequest.parse(tlsClientContext, buf);

        assertEmpty(buf);

        if (postHandshakeAuth)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.certificateRequest = certificateRequest;

        TlsUtils.establishServerSigAlgs(tlsClientContext.getSecurityParametersHandshake(), certificateRequest);
    }

    protected void receive13EncryptedExtensions(ByteArrayInputStream buf)
        throws IOException
    {
        byte[] extBytes = TlsUtils.readOpaque16(buf);

        assertEmpty(buf);


        this.serverExtensions = readExtensionsData13(HandshakeType.encrypted_extensions, extBytes);

        {
            /*
             * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote
             * endpoint did not send the corresponding extension requests, with the exception of the
             * "cookie" extension in the HelloRetryRequest. Upon receiving such an extension, an
             * endpoint MUST abort the handshake with an "unsupported_extension" alert.
             */
            Enumeration e = serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                if (null == TlsUtils.getExtensionData(clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }
            }
        }


        final SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();
        final ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();

        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        Hashtable sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;
        if (resumedSession)
        {
            if (securityParameters.getCipherSuite() != sessionParameters.getCipherSuite()
                || CompressionMethod._null != sessionParameters.getCompressionAlgorithm()
                || !negotiatedVersion.equals(sessionParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = sessionParameters.readServerExtensions();
        }

        securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(sessionClientExtensions,
            sessionServerExtensions, AlertDescription.illegal_parameter);

        securityParameters.encryptThenMAC = false;
        securityParameters.truncatedHMac = false;

        /*
         * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
         * 
         * OCSP information is carried in an extension for a CertificateEntry.
         */
        securityParameters.statusRequestVersion = clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request)
            ? 1 : 0;

        this.expectSessionTicket = false;

        if (null != sessionClientExtensions)
        {
            tlsClient.processServerExtensions(serverExtensions);
        }

        applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());
    }

    protected void receive13NewSessionTicket(ByteArrayInputStream buf)
        throws IOException
    {
        if (!isApplicationDataReady())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        // TODO[tls13] Do something more than just ignore them

//        struct {
//            uint32 ticket_lifetime;
//            uint32 ticket_age_add;
//            opaque ticket_nonce<0..255>;
//            opaque ticket<1..2^16-1>;
//            Extension extensions<0..2^16-2>;
//        } NewSessionTicket;

        TlsUtils.readUint32(buf);
        TlsUtils.readUint32(buf);
        TlsUtils.readOpaque8(buf);
        TlsUtils.readOpaque16(buf);
        TlsUtils.readOpaque16(buf);
        assertEmpty(buf);
    }

    protected void receive13ServerCertificate(ByteArrayInputStream buf)
        throws IOException
    {
        this.authentication = TlsUtils.receive13ServerCertificate(tlsClientContext, tlsClient, buf);

        // NOTE: In TLS 1.3 we don't have to wait for a possible CertificateStatus message.
        handleServerCertificate();
    }

    protected void receive13ServerCertificateVerify(ByteArrayInputStream buf)
        throws IOException
    {
        Certificate serverCertificate = tlsClientContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null == serverCertificate || serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO[tls13] Actual structure is 'CertificateVerify' in RFC 8446, consider adding for clarity
        DigitallySigned certificateVerify = DigitallySigned.parse(tlsClientContext, buf);

        assertEmpty(buf);

        TlsUtils.verify13CertificateVerifyServer(tlsClientContext, certificateVerify, handshakeHash);
    }

    protected void receive13ServerFinished(ByteArrayInputStream buf)
        throws IOException
    {
        process13FinishedMessage(buf);
    }

    protected void receiveCertificateRequest(ByteArrayInputStream buf) throws IOException
    {
        if (null == authentication)
        {
            /*
             * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        CertificateRequest certificateRequest = CertificateRequest.parse(tlsClientContext, buf);

        assertEmpty(buf);

        this.certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, keyExchange);
    }

    protected void receiveNewSessionTicket(ByteArrayInputStream buf)
        throws IOException
    {
        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        assertEmpty(buf);

        tlsClient.notifyNewSessionTicket(newSessionTicket);
    }

    protected ServerHello receiveServerHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        return ServerHello.parse(buf);
    }

    protected void send13ClientHelloRetry() throws IOException
    {
        Hashtable clientHelloExtensions = clientHello.getExtensions();

        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_cookie);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_early_data);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_key_share);

        /*
         * RFC 4.2.2. When sending the new ClientHello, the client MUST copy the contents of the
         * extension received in the HelloRetryRequest into a "cookie" extension in the new
         * ClientHello.
         */
        if (null != retryCookie)
        {
            TlsExtensionsUtils.addCookieExtension(clientHelloExtensions, retryCookie);
            this.retryCookie = null;
        }

        /*
         * RFC 8446 4.2.8. [..] when sending the new ClientHello, the client MUST replace the
         * original "key_share" extension with one containing only a new KeyShareEntry for the group
         * indicated in the selected_group field of the triggering HelloRetryRequest.
         */
        if (retryGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.clientAgreements = TlsUtils.addKeyShareToClientHelloRetry(tlsClientContext, clientHelloExtensions,
            retryGroup);

        /*
         * TODO[tls13] Updating the "pre_shared_key" extension if present by recomputing the
         * "obfuscated_ticket_age" and binder values and (optionally) removing any PSKs which are
         * incompatible with the server's indicated cipher suite.
         */

        /*
         * TODO[tls13] Optionally adding, removing, or changing the length of the "padding"
         * extension [RFC7685].
         */

        // See RFC 8446 D.4.
        {
            recordStream.setIgnoreChangeCipherSpec(true);

            // TODO[tls13] If offering early data, the record is placed immediately after the first ClientHello.
            sendChangeCipherSpecMessage();
        }

        sendClientHelloMessage();
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.certificate_verify);
        certificateVerify.encode(message);
        message.send(this);
    }

    protected void sendClientHello()
        throws IOException
    {
        SecurityParameters securityParameters = tlsClientContext.getSecurityParametersHandshake();

        ProtocolVersion client_version;

        // NOT renegotiating
        {
            tlsClientContext.setClientSupportedVersions(tlsClient.getProtocolVersions());

            if (ProtocolVersion.contains(tlsClientContext.getClientSupportedVersions(), ProtocolVersion.SSLv3))
            {
                // TODO[tls13] Prevent offering SSLv3 AND TLSv13?
                recordStream.setWriteVersion(ProtocolVersion.SSLv3);
            }
            else
            {
                recordStream.setWriteVersion(ProtocolVersion.TLSv10);
            }

            client_version = ProtocolVersion.getLatestTLS(tlsClientContext.getClientSupportedVersions());

            if (!ProtocolVersion.isSupportedTLSVersionClient(client_version))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            tlsClientContext.setClientVersion(client_version);
        }

        final boolean offeringTLSv13Plus = ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(client_version);

        /*
         * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
         * Session ID in the TLS ClientHello.
         */
        byte[] legacy_session_id = TlsUtils.getSessionID(tlsSession);

        boolean fallback = tlsClient.isFallback();

        int[] offeredCipherSuites = tlsClient.getCipherSuites();

        if (legacy_session_id.length > 0 && this.sessionParameters != null)
        {
            if (!Arrays.contains(offeredCipherSuites, sessionParameters.getCipherSuite())
                || CompressionMethod._null != sessionParameters.getCompressionAlgorithm())
            {
                legacy_session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(tlsClient.getClientExtensions());

        ProtocolVersion legacy_version = client_version;
        if (offeringTLSv13Plus)
        {
            legacy_version = ProtocolVersion.TLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                tlsClientContext.getClientSupportedVersions());

            /*
             * RFC 8446 4.2.1. In compatibility mode [..], this field MUST be non-empty, so a client
             * not offering a pre-TLS 1.3 session MUST generate a new 32-byte value.
             */
            if (legacy_session_id.length < 1)
            {
                legacy_session_id = tlsClientContext.getNonceGenerator().generateNonce(32);
            }
        }

        tlsClientContext.setRSAPreMasterSecretVersion(legacy_version);

        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
        {
            TlsUtils.establishClientSigAlgs(securityParameters, clientExtensions);
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

        this.clientAgreements = TlsUtils.addEarlyKeySharesToClientHello(tlsClientContext, tlsClient, clientExtensions);

        if (TlsUtils.isExtendedMasterSecretOptionalTLS(tlsClientContext.getClientSupportedVersions())
            && (tlsClient.shouldUseExtendedMasterSecret() ||
                (null != sessionParameters && sessionParameters.isExtendedMasterSecret())))
        {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(this.clientExtensions);
        }
        else if (!offeringTLSv13Plus && tlsClient.requiresExtendedMasterSecret())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        {
            boolean useGMTUnixTime = !offeringTLSv13Plus && tlsClient.shouldUseGMTUnixTime();

            securityParameters.clientRandom = createRandomBlock(useGMTUnixTime, tlsClientContext);
        }

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
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
                // TODO[tls13] Probably want to not add this if no pre-TLSv13 versions offered?
                offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
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
            offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
        }



        this.clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(), legacy_session_id,
            null, offeredCipherSuites, clientExtensions);

        sendClientHelloMessage();
    }

    protected void sendClientHelloMessage() throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.client_hello);
        clientHello.encode(tlsClientContext, message);
        message.send(this);
    }

    protected void sendClientKeyExchange()
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.client_key_exchange);
        this.keyExchange.generateClientKeyExchange(message);
        message.send(this);
    }

    protected void skip13CertificateRequest()
        throws IOException
    {
        this.certificateRequest = null;
    }

    protected void skip13ServerCertificate()
        throws IOException
    {
        this.authentication = null;

        // TODO[tls13] May be skipped for PSK handshakes?
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }
}
