package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

public class TlsServerProtocol
    extends TlsProtocol
{
    protected TlsServer tlsServer = null;
    TlsServerContextImpl tlsServerContext = null;

    protected int[] offeredCipherSuites = null;
    protected TlsKeyExchange keyExchange = null;
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
    public void accept(TlsServer tlsServer) throws IOException
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

        tlsServer.init(tlsServerContext);
        tlsServer.notifyCloseHandle(this);

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
//            sendHelloRequestMessage();
//        }
//        return allowed;
//    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();

        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
    }

    protected boolean expectCertificateVerifyMessage()
    {
        if (null == certificateRequest)
        {
            return false;
        }

        Certificate clientCertificate = tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();

        return null != clientCertificate && !clientCertificate.isEmpty()
            && (null == keyExchange || keyExchange.requiresCertificateVerify());
    }

    protected ServerHello generate13HelloRetryRequest(ClientHello clientHello) throws IOException
    {
        // TODO[tls13] In future there might be other reasons for a HelloRetryRequest.
        if (retryGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();
        ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();

        Hashtable serverHelloExtensions = new Hashtable();
        TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);
        if (retryGroup >= 0)
        {
            TlsExtensionsUtils.addKeyShareHelloRetryRequest(serverHelloExtensions, retryGroup);
        }
        if (null != retryCookie)
        {
            TlsExtensionsUtils.addCookieExtension(serverHelloExtensions, retryCookie);
        }

        TlsUtils.checkExtensionData13(serverHelloExtensions, HandshakeType.hello_retry_request,
            AlertDescription.internal_error);

        return new ServerHello(clientHello.getSessionID(), securityParameters.getCipherSuite(), serverHelloExtensions);
    }

    protected ServerHello generate13ServerHello(ClientHello clientHello, boolean afterHelloRetryRequest)
        throws IOException
    {
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();


        byte[] legacy_session_id = clientHello.getSessionID();

        Hashtable clientHelloExtensions = clientHello.getExtensions();
        if (null == clientHelloExtensions)
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension);
        }


        ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();
        TlsCrypto crypto = tlsServerContext.getCrypto();

        Vector clientShares = TlsExtensionsUtils.getKeyShareClientHello(clientHelloExtensions);
        KeyShareEntry clientShare = null;

        if (afterHelloRetryRequest)
        {
            if (retryGroup < 0)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * TODO[tls13] Confirm fields in the ClientHello haven't changed
             * 
             * RFC 8446 4.1.2 [..] when the server has responded to its ClientHello with a
             * HelloRetryRequest [..] the client MUST send the same ClientHello without
             * modification, except as follows: [key_share, early_data, cookie, pre_shared_key,
             * padding].
             */

            byte[] cookie = TlsExtensionsUtils.getCookieExtension(clientHelloExtensions);
            if (!Arrays.areEqual(retryCookie, cookie))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            this.retryCookie = null;

            clientShare = TlsUtils.selectKeyShare(clientShares, retryGroup);
            if (null == clientShare)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            this.clientExtensions = clientHelloExtensions;

            securityParameters.secureRenegotiation = false;

            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientHelloExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils
                .getServerNameExtensionClient(clientHelloExtensions);

            TlsUtils.establishClientSigAlgs(securityParameters, clientHelloExtensions);

            /*
             * RFC 8446 4.2.3. If a server is authenticating via a certificate and the client has
             * not sent a "signature_algorithms" extension, then the server MUST abort the handshake
             * with a "missing_extension" alert.
             */
            // TODO[tls13] Revisit this check if we add support for PSK-only key exchange.
            if (null == securityParameters.getClientSigAlgs())
            {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }

            tlsServer.processClientExtensions(clientHelloExtensions);

            /*
             * NOTE: Currently no server support for session resumption
             * 
             * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
             * ONLY when extended_master_secret has been negotiated (otherwise NULL).
             */
            {
                // TODO[tls13] Resumption/PSK

                this.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
                this.sessionParameters = null;
                this.sessionMasterSecret = null;
            }

            securityParameters.sessionID = tlsSession.getSessionID();

            tlsServer.notifySession(tlsSession);

            TlsUtils.negotiatedVersionTLSServer(tlsServerContext);

            {
                securityParameters.serverRandom = createRandomBlock(false, tlsServerContext);

                if (!serverVersion.equals(ProtocolVersion.getLatestTLS(tlsServer.getProtocolVersions())))
                {
                    TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
                }
            }

            {
                int cipherSuite = tlsServer.getSelectedCipherSuite();

                if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                    !TlsUtils.isValidVersionForCipherSuite(cipherSuite, serverVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            }

            int[] clientSupportedGroups = securityParameters.getClientSupportedGroups();
            int[] serverSupportedGroups = securityParameters.getServerSupportedGroups();

            clientShare = TlsUtils.selectKeyShare(crypto, serverVersion, clientShares, clientSupportedGroups,
                serverSupportedGroups);

            if (null == clientShare)
            {
                this.retryGroup = TlsUtils.selectKeyShareGroup(crypto, serverVersion, clientSupportedGroups,
                    serverSupportedGroups);
                if (retryGroup < 0)
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }

                this.retryCookie = tlsServerContext.getNonceGenerator().generateNonce(16);

                return generate13HelloRetryRequest(clientHello);
            }

            if (clientShare.getNamedGroup() != serverSupportedGroups[0])
            {
                /*
                 * TODO[tls13] RFC 8446 4.2.7. As of TLS 1.3, servers are permitted to send the
                 * "supported_groups" extension to the client. Clients MUST NOT act upon any
                 * information found in "supported_groups" prior to successful completion of the
                 * handshake but MAY use the information learned from a successfully completed
                 * handshake to change what groups they use in their "key_share" extension in
                 * subsequent connections. If the server has a group it prefers to the ones in the
                 * "key_share" extension but is still willing to accept the ClientHello, it SHOULD
                 * send "supported_groups" to update the client's view of its preferences; this
                 * extension SHOULD contain all groups the server supports, regardless of whether
                 * they are currently supported by the client.
                 */
            }
        }


        Hashtable serverHelloExtensions = new Hashtable();
        Hashtable serverEncryptedExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(tlsServer.getServerExtensions());

        tlsServer.getServerExtensionsForConnection(serverEncryptedExtensions);

        ProtocolVersion serverLegacyVersion = ProtocolVersion.TLSv12;
        TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);

        /*
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        securityParameters.extendedMasterSecret = true;

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverEncryptedExtensions);
        securityParameters.applicationProtocolSet = true;

        if (!serverEncryptedExtensions.isEmpty())
        {
            securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(clientHelloExtensions,
                serverEncryptedExtensions, AlertDescription.internal_error);
        }

        securityParameters.encryptThenMAC = false;
        securityParameters.truncatedHMac = false;

        /*
         * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
         * 
         * OCSP information is carried in an extension for a CertificateEntry.
         */
        securityParameters.statusRequestVersion = clientHelloExtensions.containsKey(TlsExtensionsUtils.EXT_status_request)
            ? 1 : 0;

        this.expectSessionTicket = false;

        {
            int namedGroup = clientShare.getNamedGroup();
    
            TlsAgreement agreement;
            if (NamedGroup.refersToASpecificCurve(namedGroup))
            {
                agreement = crypto.createECDomain(new TlsECConfig(namedGroup)).createECDH();
            }
            else if (NamedGroup.refersToASpecificFiniteField(namedGroup))
            {
                agreement = crypto.createDHDomain(new TlsDHConfig(namedGroup, true)).createDH();
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            byte[] key_exchange = agreement.generateEphemeral();
            KeyShareEntry serverShare = new KeyShareEntry(namedGroup, key_exchange);
            TlsExtensionsUtils.addKeyShareServerHello(serverHelloExtensions, serverShare);

            agreement.receivePeerValue(clientShare.getKeyExchange());
            securityParameters.sharedSecret = agreement.calculateSecret();
            TlsUtils.establish13PhaseSecrets(tlsServerContext);
        }

        this.serverExtensions = serverEncryptedExtensions;

        applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());

        TlsUtils.checkExtensionData13(serverHelloExtensions, HandshakeType.server_hello,
            AlertDescription.internal_error);

        return new ServerHello(serverLegacyVersion, securityParameters.getServerRandom(), legacy_session_id,
            securityParameters.getCipherSuite(), serverHelloExtensions);
    }

    protected ServerHello generateServerHello(ClientHello clientHello) throws IOException
    {
        ProtocolVersion clientLegacyVersion = clientHello.getVersion();
        if (!clientLegacyVersion.isTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.offeredCipherSuites = clientHello.getCipherSuites();


 
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        tlsServerContext.setClientSupportedVersions(
            TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientHello.getExtensions()));

        ProtocolVersion clientVersion = clientLegacyVersion;
        if (null == tlsServerContext.getClientSupportedVersions())
        {
            if (clientVersion.isLaterVersionOf(ProtocolVersion.TLSv12))
            {
                clientVersion = ProtocolVersion.TLSv12;
            }

            tlsServerContext.setClientSupportedVersions(clientVersion.downTo(ProtocolVersion.SSLv3));
        }
        else
        {
            clientVersion = ProtocolVersion.getLatestTLS(tlsServerContext.getClientSupportedVersions());
        }

        // Set the legacy_record_version to use for early alerts 
        recordStream.setWriteVersion(clientVersion);

        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_TLS.isEqualOrEarlierVersionOf(clientVersion))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        // NOT renegotiating
        {
            tlsServerContext.setClientVersion(clientVersion);
        }

        tlsServer.notifyClientVersion(tlsServerContext.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        tlsServer.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        tlsServer.notifyOfferedCipherSuites(offeredCipherSuites);

        // TODO[tls13] Negotiate cipher suite first?

        ProtocolVersion serverVersion;

        // NOT renegotiating
        {
            serverVersion = tlsServer.getServerVersion();
            if (!ProtocolVersion.contains(tlsServerContext.getClientSupportedVersions(), serverVersion))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            securityParameters.negotiatedVersion = serverVersion;
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(
            clientHello.getExtensions());
        securityParameters.serverSupportedGroups = tlsServer.getSupportedGroups();

        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(serverVersion))
        {
            // See RFC 8446 D.4.
            recordStream.setIgnoreChangeCipherSpec(true);

            recordStream.setWriteVersion(ProtocolVersion.TLSv12);

            return generate13ServerHello(clientHello, false);
        }

        recordStream.setWriteVersion(serverVersion);

        this.clientExtensions = clientHello.getExtensions();

        byte[] clientRenegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
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
            if (clientRenegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(clientRenegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        tlsServer.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        boolean offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientExtensions);

        if (clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
            {
                TlsUtils.establishClientSigAlgs(securityParameters, clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

            tlsServer.processClientExtensions(clientExtensions);
        }

        this.resumedSession = establishSession(tlsServer.getSessionToResume(clientHello.getSessionID()));

        if (!resumedSession)
        {
            byte[] newSessionID = tlsServer.getNewSessionID();
            if (null == newSessionID)
            {
                newSessionID = TlsUtils.EMPTY_BYTES;
            }

            this.tlsSession = TlsUtils.importSession(newSessionID, null);
            this.sessionParameters = null;
            this.sessionMasterSecret = null;
        }

        securityParameters.sessionID = tlsSession.getSessionID();

        tlsServer.notifySession(tlsSession);

        TlsUtils.negotiatedVersionTLSServer(tlsServerContext);

        {
            boolean useGMTUnixTime = tlsServer.shouldUseGMTUnixTime();

            securityParameters.serverRandom = createRandomBlock(useGMTUnixTime, tlsServerContext);

            if (!serverVersion.equals(ProtocolVersion.getLatestTLS(tlsServer.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
            }
        }

        {
            int cipherSuite = resumedSession ? sessionParameters.getCipherSuite() : tlsServer.getSelectedCipherSuite();

            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, serverVersion))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        tlsServerContext.setRSAPreMasterSecretVersion(clientLegacyVersion);

        {
            Hashtable sessionServerExtensions = resumedSession
                ?   sessionParameters.readServerExtensions()
                :   tlsServer.getServerExtensions();

            this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(sessionServerExtensions);
        }

        tlsServer.getServerExtensionsForConnection(serverExtensions);

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
             */
            if (securityParameters.isSecureRenegotiation())
            {
                byte[] serverRenegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                boolean noRenegExt = (null == serverRenegExtData);

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

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         */
        if (resumedSession)
        {
            if (!sessionParameters.isExtendedMasterSecret())
            {
                /*
                 * TODO[resumption] ProvTlsServer currently only resumes EMS sessions. Revisit this
                 * in relation to 'tlsServer.allowLegacyResumption()'.
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            if (!offeredExtendedMasterSecret)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            securityParameters.extendedMasterSecret = true;

            TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
        }
        else
        {
            securityParameters.extendedMasterSecret = offeredExtendedMasterSecret && !serverVersion.isSSL()
                && tlsServer.shouldUseExtendedMasterSecret();

            if (securityParameters.isExtendedMasterSecret())
            {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
            }
            else if (tlsServer.requiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        if (!this.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(clientExtensions,
                serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

            if (!resumedSession)
            {
                if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request_v2,
                    AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request,
                    AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 1;
                }

                this.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(serverExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.internal_error);
            }
        }

        applyMaxFragmentLengthExtension(securityParameters.getMaxFragmentLength());

        return new ServerHello(serverVersion, securityParameters.getServerRandom(), tlsSession.getSessionID(),
            securityParameters.getCipherSuite(), serverExtensions);
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

    protected void handle13HandshakeMessage(short type, HandshakeMessageInput buf)
        throws IOException
    {
        if (!isTLSv13ConnectionState())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (resumedSession)
        {
            /*
             * TODO[tls13] Abbreviated handshakes (PSK resumption)
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
            case CS_SERVER_FINISHED:
            {
                receive13ClientCertificate(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
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
            case CS_CLIENT_CERTIFICATE:
            {
                receive13ClientCertificateVerify(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_START:
            {
                // NOTE: Legacy handler should be dispatching initial ClientHello.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            case CS_SERVER_HELLO_RETRY_REQUEST:
            {
                ClientHello clientHelloRetry = receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO_RETRY;

                ServerHello serverHello = generate13ServerHello(clientHelloRetry, true);
                sendServerHelloMessage(serverHello);
                this.connection_state = CS_SERVER_HELLO;

                send13ServerHelloCoda(serverHello, true);
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
            case CS_SERVER_FINISHED:
            {
                skip13ClientCertificate();
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE:
            {
                skip13ClientCertificateVerify();
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE_VERIFY:
            {
                receive13ClientFinished(buf);
                this.connection_state = CS_CLIENT_FINISHED;

                // See RFC 8446 D.4.
                recordStream.setIgnoreChangeCipherSpec(false);

                // NOTE: Completes the switch to application-data phase (server entered after CS_SERVER_FINISHED).
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

        case HandshakeType.certificate_request:
        case HandshakeType.certificate_status:
        case HandshakeType.certificate_url:
        case HandshakeType.client_key_exchange:
        case HandshakeType.encrypted_extensions:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.message_hash:
        case HandshakeType.new_session_ticket:
        case HandshakeType.server_hello:
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
        final SecurityParameters securityParameters = tlsServerContext.getSecurityParameters();

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

        if (resumedSession)
        {
            if (type != HandshakeType.finished || this.connection_state != CS_SERVER_FINISHED)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processFinishedMessage(buf);
            this.connection_state = CS_CLIENT_FINISHED;

            completeHandshake();
            return;
        }

        switch (type)
        {
        case HandshakeType.client_hello:
        {
            if (isApplicationDataReady())
            {
                refuseRenegotiation();
                break;
            }

            switch (this.connection_state)
            {
            case CS_END:
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            case CS_START:
            {
                ClientHello clientHello = receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                ServerHello serverHello = generateServerHello(clientHello);
                handshakeHash.notifyPRFDetermined();

                if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
                {
                    if (serverHello.isHelloRetryRequest())
                    {
                        TlsUtils.adjustTranscriptForRetry(handshakeHash);
                        sendServerHelloMessage(serverHello);
                        this.connection_state = CS_SERVER_HELLO_RETRY_REQUEST;

                        // See RFC 8446 D.4.
                        sendChangeCipherSpecMessage();
                    }
                    else
                    {
                        sendServerHelloMessage(serverHello);
                        this.connection_state = CS_SERVER_HELLO;

                        // See RFC 8446 D.4.
                        sendChangeCipherSpecMessage();

                        send13ServerHelloCoda(serverHello, false);
                    }
                    break;
                }

                sendServerHelloMessage(serverHello);
                this.connection_state = CS_SERVER_HELLO;

                if (resumedSession)
                {
                    securityParameters.masterSecret = sessionMasterSecret;
                    recordStream.setPendingCipher(TlsUtils.initCipher(tlsServerContext));

                    sendChangeCipherSpec();
                    sendFinishedMessage();
                    this.connection_state = CS_SERVER_FINISHED;
                    break;
                }

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null)
                {
                    sendSupplementalDataMessage(serverSupplementalData);
                    this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;
                }

                this.keyExchange = TlsUtils.initKeyExchangeServer(tlsServerContext, tlsServer);

                TlsCredentials serverCredentials = TlsUtils.establishServerCredentials(tlsServer);

                // Server certificate
                {
                    Certificate serverCertificate = null;

                    ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
                    if (null == serverCredentials)
                    {
                        this.keyExchange.skipServerCredentials();
                    }
                    else
                    {
                        this.keyExchange.processServerCredentials(serverCredentials);

                        serverCertificate = serverCredentials.getCertificate();
                        sendCertificateMessage(serverCertificate, endPointHash);
                        this.connection_state = CS_SERVER_CERTIFICATE;
                    }

                    securityParameters.tlsServerEndPoint = endPointHash.toByteArray();

                    // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                    if (null == serverCertificate || serverCertificate.isEmpty())
                    {
                        securityParameters.statusRequestVersion = 0;
                    }
                }

                if (securityParameters.getStatusRequestVersion() > 0)
                {
                    CertificateStatus certificateStatus = tlsServer.getCertificateStatus();
                    if (certificateStatus != null)
                    {
                        sendCertificateStatusMessage(certificateStatus);
                        this.connection_state = CS_SERVER_CERTIFICATE_STATUS;
                    }
                }

                byte[] serverKeyExchange = this.keyExchange.generateServerKeyExchange();
                if (serverKeyExchange != null)
                {
                    sendServerKeyExchangeMessage(serverKeyExchange);
                    this.connection_state = CS_SERVER_KEY_EXCHANGE;
                }

                if (null != serverCredentials)
                {
                    this.certificateRequest = tlsServer.getCertificateRequest();

                    if (null == this.certificateRequest)
                    {
                        /*
                         * For static agreement key exchanges, CertificateRequest is required since
                         * the client Certificate message is mandatory but can only be sent if the
                         * server requests it.
                         */
                        if (!keyExchange.requiresCertificateVerify())
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }
                    }
                    else
                    {
                        if (TlsUtils.isTLSv12(tlsServerContext) != (certificateRequest.getSupportedSignatureAlgorithms() != null))
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }

                        this.certificateRequest = TlsUtils.validateCertificateRequest(this.certificateRequest, this.keyExchange);

                        TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                        TlsUtils.trackHashAlgorithms(handshakeHash, securityParameters.getServerSigAlgs());

                        sendCertificateRequestMessage(certificateRequest);
                        this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
                    }
                }

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;

                boolean forceBuffering = false;
                TlsUtils.sealHandshakeHash(tlsServerContext, handshakeHash, forceBuffering);

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
                if (null == certificateRequest)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else if (TlsUtils.isTLSv12(tlsServerContext))
                {
                    /*
                     * RFC 5246 If no suitable certificate is available, the client MUST send a
                     * certificate message containing no certificates.
                     * 
                     * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                else if (TlsUtils.isSSL(tlsServerContext))
                {
                    /*
                     * SSL 3.0 If the server has sent a certificate request Message, the client must
                     * send either the certificate message or a no_certificate alert.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                else
                {
                    notifyClientCertificate(Certificate.EMPTY_CHAIN);
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
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
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
            case CS_CLIENT_CERTIFICATE_VERIFY:
            {
                processFinishedMessage(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_FINISHED;

                if (this.expectSessionTicket)
                {
                    sendNewSessionTicketMessage(tlsServer.getNewSessionTicket());
                    this.connection_state = CS_SERVER_SESSION_TICKET;
                }

                sendChangeCipherSpec();
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

        case HandshakeType.certificate_request:
        case HandshakeType.certificate_status:
        case HandshakeType.certificate_url:
        case HandshakeType.encrypted_extensions:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
        case HandshakeType.message_hash:
        case HandshakeType.new_session_ticket:
        case HandshakeType.server_hello:
        case HandshakeType.server_hello_done:
        case HandshakeType.server_key_exchange:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleAlertWarningMessage(short alertDescription)
        throws IOException
    {
        /*
         * SSL 3.0 If the server has sent a certificate request Message, the client must send
         * either the certificate message or a no_certificate alert.
         */
        if (AlertDescription.no_certificate == alertDescription && null != certificateRequest
            && TlsUtils.isSSL(tlsServerContext))
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
                notifyClientCertificate(Certificate.EMPTY_CHAIN);
                this.connection_state = CS_CLIENT_CERTIFICATE;
                return;
            }
            }
        }

        super.handleAlertWarningMessage(alertDescription);
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {
        if (null == certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.processClientCertificate(tlsServerContext, clientCertificate, keyExchange, tlsServer);
    }

    protected void receive13ClientCertificate(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13] This currently just duplicates 'receiveCertificateMessage'

        Certificate clientCertificate = Certificate.parse(tlsServerContext, buf, null);

        assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void receive13ClientCertificateVerify(ByteArrayInputStream buf)
        throws IOException
    {
        Certificate clientCertificate = tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null == clientCertificate || clientCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO[tls13] Actual structure is 'CertificateVerify' in RFC 8446, consider adding for clarity
        DigitallySigned certificateVerify = DigitallySigned.parse(tlsServerContext, buf);

        assertEmpty(buf);

        TlsUtils.verify13CertificateVerifyClient(tlsServerContext, certificateRequest, certificateVerify,
            handshakeHash);
    }

    protected void receive13ClientFinished(ByteArrayInputStream buf) throws IOException
    {
        process13FinishedMessage(buf);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf)
        throws IOException
    {
        Certificate clientCertificate = Certificate.parse(tlsServerContext, buf, null);

        assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf)
        throws IOException
    {
        DigitallySigned certificateVerify = DigitallySigned.parse(tlsServerContext, buf);

        assertEmpty(buf);

        TlsUtils.verifyCertificateVerifyClient(tlsServerContext, certificateRequest, certificateVerify, handshakeHash);

        this.handshakeHash = handshakeHash.stopTracking();
    }

    protected ClientHello receiveClientHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        return ClientHello.parse(buf, null);
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf)
        throws IOException
    {
        keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        final boolean isSSL = TlsUtils.isSSL(tlsServerContext);
        if (isSSL)
        {
            // NOTE: For SSLv3 (only), master_secret needed to calculate session hash
            establishMasterSecret(tlsServerContext, keyExchange);
        }

        tlsServerContext.getSecurityParametersHandshake().sessionHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        if (!isSSL)
        {
            // NOTE: For (D)TLS, session hash potentially needed for extended_master_secret
            establishMasterSecret(tlsServerContext, keyExchange);
        }

        recordStream.setPendingCipher(TlsUtils.initCipher(tlsServerContext));

        if (!expectCertificateVerifyMessage())
        {
            this.handshakeHash = handshakeHash.stopTracking();
        }
    }

    protected void send13EncryptedExtensionsMessage(Hashtable serverExtensions) throws IOException
    {
        // TODO[tls13] Avoid extra copy; use placeholder to write opaque-16 data directly to message buffer

        byte[] extBytes = writeExtensionsData(serverExtensions);

        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.encrypted_extensions);
        TlsUtils.writeOpaque16(extBytes, message);
        message.send(this);
    }

    protected void send13ServerHelloCoda(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException
    {
        final SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        TlsUtils.establish13PhaseHandshake(tlsServerContext, serverHelloTranscriptHash, recordStream);

        recordStream.enablePendingCipherWrite();
        recordStream.enablePendingCipherRead(true);

        send13EncryptedExtensionsMessage(serverExtensions);
        this.connection_state = CS_SERVER_ENCRYPTED_EXTENSIONS;

        // CertificateRequest
        {
            this.certificateRequest = tlsServer.getCertificateRequest();
            if (null != certificateRequest)
            {
                if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                sendCertificateRequestMessage(certificateRequest);
                this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
            }
        }

        /*
         * TODO[tls13] For PSK-only key exchange, there's no Certificate message.
         */

        TlsCredentialedSigner serverCredentials = TlsUtils.establish13ServerCredentials(tlsServer);
        if (null == serverCredentials)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // Certificate
        {
            /*
             * TODO[tls13] Note that we are expecting the TlsServer implementation to take care of
             * e.g. adding optional "status_request" extension to each CertificateEntry.
             */
            /*
             * No CertificateStatus message is sent; TLS 1.3 uses per-CertificateEntry
             * "status_request" extension instead.
             */

            Certificate serverCertificate = serverCredentials.getCertificate();
            send13CertificateMessage(serverCertificate);
            securityParameters.tlsServerEndPoint = null;
            this.connection_state = CS_SERVER_CERTIFICATE;
        }

        // CertificateVerify
        {
            DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(tlsServerContext, serverCredentials,
                handshakeHash);
            send13CertificateVerifyMessage(certificateVerify);
            this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
        }

        // Finished
        {
            send13FinishedMessage();
            this.connection_state = CS_SERVER_FINISHED;
        }

        byte[] serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        TlsUtils.establish13PhaseApplication(tlsServerContext, serverFinishedTranscriptHash, recordStream);

        recordStream.enablePendingCipherWrite();
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.certificate_request);
        certificateRequest.encode(tlsServerContext, message);
        message.send(this);
    }

    protected void sendCertificateStatusMessage(CertificateStatus certificateStatus)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.certificate_status);
        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        certificateStatus.encode(message);
        message.send(this);
    }

    protected void sendHelloRequestMessage()
        throws IOException
    {
        HandshakeMessageOutput.send(this, HandshakeType.hello_request, TlsUtils.EMPTY_BYTES);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        throws IOException
    {
        if (newSessionTicket == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.new_session_ticket);
        newSessionTicket.encode(message);
        message.send(this);
    }

    protected void sendServerHelloDoneMessage()
        throws IOException
    {
        HandshakeMessageOutput.send(this, HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);
    }

    protected void sendServerHelloMessage(ServerHello serverHello)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.server_hello);
        serverHello.encode(tlsServerContext, message);
        message.send(this);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange)
        throws IOException
    {
        HandshakeMessageOutput.send(this, HandshakeType.server_key_exchange, serverKeyExchange);
    }

    protected void skip13ClientCertificate() throws IOException
    {
        if (null != certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void skip13ClientCertificateVerify() throws IOException
    {
        if (expectCertificateVerifyMessage())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }
}
