package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class DTLSServerProtocol
    extends DTLSProtocol
{
    protected boolean verifyRequests = true;

    public DTLSServerProtocol()
    {
        super();
    }

    public boolean getVerifyRequests()
    {
        return verifyRequests;
    }

    public void setVerifyRequests(boolean verifyRequests)
    {
        this.verifyRequests = verifyRequests;
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport)
        throws IOException
    {
        return accept(server, transport, null);
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport, DTLSRequest request)
        throws IOException
    {
        if (server == null)
        {
            throw new IllegalArgumentException("'server' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        ServerHandshakeState state = new ServerHandshakeState();
        state.server = server;
        state.serverContext = new TlsServerContextImpl(server.getCrypto());
        server.init(state.serverContext);
        state.serverContext.handshakeBeginning(server);

        SecurityParameters securityParameters = state.serverContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = server.shouldUseExtendedPadding();

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(state.serverContext, state.server, transport);
        server.notifyCloseHandle(recordLayer);

        try
        {
            return serverHandshake(state, recordLayer, request);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            abortServerHandshake(state, recordLayer, fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            abortServerHandshake(state, recordLayer, AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            abortServerHandshake(state, recordLayer, AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        finally
        {
            securityParameters.clear();
        }
    }

    protected void abortServerHandshake(ServerHandshakeState state, DTLSRecordLayer recordLayer, short alertDescription)
    {
        recordLayer.fail(alertDescription);
        invalidateSession(state);
    }

    protected DTLSTransport serverHandshake(ServerHandshakeState state, DTLSRecordLayer recordLayer,
        DTLSRequest request) throws IOException
    {
        SecurityParameters securityParameters = state.serverContext.getSecurityParametersHandshake();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.serverContext, recordLayer,
            state.server.getHandshakeTimeoutMillis(), request);

        DTLSReliableHandshake.Message clientMessage = null;

        if (null == request)
        {
            clientMessage = handshake.receiveMessage();

            // NOTE: DTLSRecordLayer requires any DTLS version, we don't otherwise constrain this
//            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();

            if (clientMessage.getType() == HandshakeType.client_hello)
            {
                processClientHello(state, clientMessage.getBody());
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }
        else
        {
            processClientHello(state, request.getClientHello());
        }

        /*
         * NOTE: Currently no server support for session resumption
         * 
         * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
         * ONLY when extended_master_secret has been negotiated (otherwise NULL).
         */
        {
            // TODO[resumption]

            state.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
            state.sessionParameters = null;
            state.sessionMasterSecret = null;
        }

        securityParameters.sessionID = state.tlsSession.getSessionID();

        state.server.notifySession(state.tlsSession);

        {
            byte[] serverHelloBody = generateServerHello(state, recordLayer);

            // TODO[dtls13] Ideally, move this into generateServerHello once legacy_record_version clarified
            {
                ProtocolVersion recordLayerVersion = state.serverContext.getServerVersion();
                recordLayer.setReadVersion(recordLayerVersion);
                recordLayer.setWriteVersion(recordLayerVersion);
            }

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        Vector serverSupplementalData = state.server.getServerSupplementalData();
        if (serverSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        state.keyExchange = TlsUtils.initKeyExchangeServer(state.serverContext, state.server);
        state.serverCredentials = TlsUtils.establishServerCredentials(state.server);

        // Server certificate
        {
            Certificate serverCertificate = null;

            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            if (state.serverCredentials == null)
            {
                state.keyExchange.skipServerCredentials();
            }
            else
            {
                state.keyExchange.processServerCredentials(state.serverCredentials);

                serverCertificate = state.serverCredentials.getCertificate();

                sendCertificateMessage(state.serverContext, handshake, serverCertificate, endPointHash);
            }
            securityParameters.tlsServerEndPoint = endPointHash.toByteArray();

            // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
            if (serverCertificate == null || serverCertificate.isEmpty())
            {
                securityParameters.statusRequestVersion = 0;
            }
        }

        if (securityParameters.getStatusRequestVersion() > 0)
        {
            CertificateStatus certificateStatus = state.server.getCertificateStatus();
            if (certificateStatus != null)
            {
                byte[] certificateStatusBody = generateCertificateStatus(state, certificateStatus);
                handshake.sendMessage(HandshakeType.certificate_status, certificateStatusBody);
            }
        }

        byte[] serverKeyExchange = state.keyExchange.generateServerKeyExchange();
        if (serverKeyExchange != null)
        {
            handshake.sendMessage(HandshakeType.server_key_exchange, serverKeyExchange);
        }

        if (state.serverCredentials != null)
        {
            state.certificateRequest = state.server.getCertificateRequest();

            if (null == state.certificateRequest)
            {
                /*
                 * For static agreement key exchanges, CertificateRequest is required since
                 * the client Certificate message is mandatory but can only be sent if the
                 * server requests it.
                 */
                if (!state.keyExchange.requiresCertificateVerify())
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
            else
            {
                if (TlsUtils.isTLSv12(state.serverContext) != (state.certificateRequest.getSupportedSignatureAlgorithms() != null))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                state.certificateRequest = TlsUtils.validateCertificateRequest(state.certificateRequest, state.keyExchange);

                TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);

                TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());

                byte[] certificateRequestBody = generateCertificateRequest(state, state.certificateRequest);
                handshake.sendMessage(HandshakeType.certificate_request, certificateRequestBody);
            }
        }

        handshake.sendMessage(HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);

        boolean forceBuffering = false;
        TlsUtils.sealHandshakeHash(state.serverContext, handshake.getHandshakeHash(), forceBuffering);

        clientMessage = handshake.receiveMessage();

        if (clientMessage.getType() == HandshakeType.supplemental_data)
        {
            processClientSupplementalData(state, clientMessage.getBody());
            clientMessage = handshake.receiveMessage();
        }
        else
        {
            state.server.processClientSupplementalData(null);
        }

        if (state.certificateRequest == null)
        {
            state.keyExchange.skipClientCredentials();
        }
        else
        {
            if (clientMessage.getType() == HandshakeType.certificate)
            {
                processClientCertificate(state, clientMessage.getBody());
                clientMessage = handshake.receiveMessage();
            }
            else
            {
                if (TlsUtils.isTLSv12(state.serverContext))
                {
                    /*
                     * RFC 5246 If no suitable certificate is available, the client MUST send a
                     * certificate message containing no certificates.
                     * 
                     * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                notifyClientCertificate(state, Certificate.EMPTY_CHAIN);
            }
        }

        if (clientMessage.getType() == HandshakeType.client_key_exchange)
        {
            processClientKeyExchange(state, clientMessage.getBody());
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsProtocol.establishMasterSecret(state.serverContext, state.keyExchange);
        recordLayer.initPendingEpoch(TlsUtils.initCipher(state.serverContext));

        /*
         * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed Diffie-Hellman
         * parameters).
         */
        {
            TlsHandshakeHash certificateVerifyHash = handshake.prepareToFinish();

            if (expectCertificateVerifyMessage(state))
            {
                byte[] certificateVerifyBody = handshake.receiveMessageBody(HandshakeType.certificate_verify);
                processCertificateVerify(state, certificateVerifyBody, certificateVerifyHash);
            }
        }

        // NOTE: Calculated exclusive of the actual Finished message from the client
        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(state.serverContext,
            handshake.getHandshakeHash(), false);
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), securityParameters.getPeerVerifyData());

        if (state.expectSessionTicket)
        {
            NewSessionTicket newSessionTicket = state.server.getNewSessionTicket();
            byte[] newSessionTicketBody = generateNewSessionTicket(state, newSessionTicket);
            handshake.sendMessage(HandshakeType.new_session_ticket, newSessionTicketBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(state.serverContext,
            handshake.getHandshakeHash(), true);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        handshake.finish();

        state.sessionMasterSecret = securityParameters.getMasterSecret();

        state.sessionParameters = new SessionParameters.Builder()
            .setCipherSuite(securityParameters.getCipherSuite())
            .setCompressionAlgorithm(securityParameters.getCompressionAlgorithm())
            .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
            .setLocalCertificate(securityParameters.getLocalCertificate())
            .setMasterSecret(state.serverContext.getCrypto().adoptSecret(state.sessionMasterSecret))
            .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
            .setPeerCertificate(securityParameters.getPeerCertificate())
            .setPSKIdentity(securityParameters.getPSKIdentity())
            .setSRPIdentity(securityParameters.getSRPIdentity())
            // TODO Consider filtering extensions that aren't relevant to resumed sessions
            .setServerExtensions(state.serverExtensions)
            .build();

        state.tlsSession = TlsUtils.importSession(state.tlsSession.getSessionID(), state.sessionParameters);

        securityParameters.tlsUnique = securityParameters.getPeerVerifyData();

        state.serverContext.handshakeComplete(state.server, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateRequest(ServerHandshakeState state, CertificateRequest certificateRequest)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateRequest.encode(state.serverContext, buf);
        return buf.toByteArray();
    }

    protected byte[] generateCertificateStatus(ServerHandshakeState state, CertificateStatus certificateStatus)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        certificateStatus.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateNewSessionTicket(ServerHandshakeState state, NewSessionTicket newSessionTicket)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        newSessionTicket.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateServerHello(ServerHandshakeState state, DTLSRecordLayer recordLayer)
        throws IOException
    {
        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        ProtocolVersion server_version = state.server.getServerVersion();
        {
            if (!ProtocolVersion.contains(context.getClientSupportedVersions(), server_version))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO[dtls13] Read draft/RFC for guidance on the legacy_record_version field
//            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.DTLSv12)
//                ? ProtocolVersion.DTLSv12
//                : server_version;
//
//            recordLayer.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = server_version;

            TlsUtils.negotiatedVersionDTLSServer(context);
        }

        {
            boolean useGMTUnixTime = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(server_version)
                && state.server.shouldUseGMTUnixTime();

            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, context);

            if (!server_version.equals(ProtocolVersion.getLatestDTLS(state.server.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
            }
        }

        {
            int cipherSuite = validateSelectedCipherSuite(state.server.getSelectedCipherSuite(),
                AlertDescription.internal_error);

            if (!TlsUtils.isValidCipherSuiteSelection(state.offeredCipherSuites, cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.server.getServerExtensions());

        state.server.getServerExtensionsForConnection(state.serverExtensions);

        ProtocolVersion legacy_version = server_version;
        if (server_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
        {
            legacy_version = ProtocolVersion.DTLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionServer(state.serverExtensions, server_version);
        }

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake 
         */
        if (securityParameters.isSecureRenegotiation())
        {
            byte[] renegExtData = TlsUtils.getExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
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
                state.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo,
                    TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         * 
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        if (TlsUtils.isTLSv13(server_version))
        {
            securityParameters.extendedMasterSecret = true;
        }
        else
        {
            securityParameters.extendedMasterSecret = state.offeredExtendedMasterSecret
                && state.server.shouldUseExtendedMasterSecret();

            if (securityParameters.isExtendedMasterSecret())
            {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(state.serverExtensions);
            }
            else if (state.server.requiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            else if (state.resumedSession && !state.server.allowLegacyResumption())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        // Heartbeats
        if (null != state.heartbeat || HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy)
        {
            TlsExtensionsUtils.addHeartbeatExtension(state.serverExtensions, new HeartbeatExtension(state.heartbeatPolicy));
        }



        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
        securityParameters.applicationProtocolSet = true;

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        if (!state.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(state.serverExtensions);

            securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.resumedSession,
                state.clientExtensions, state.serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(state.serverExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            if (!state.resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsExtensionsUtils.EXT_status_request_v2, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 1;
                }
            }

            state.expectSessionTicket = !state.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);
        }

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());



        ServerHello serverHello = new ServerHello(legacy_version, securityParameters.getServerRandom(),
            state.tlsSession.getSessionID(), securityParameters.getCipherSuite(), state.serverExtensions);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        serverHello.encode(state.serverContext, buf);
        return buf.toByteArray();
    }

    protected void invalidateSession(ServerHandshakeState state)
    {
        if (state.sessionMasterSecret != null)
        {
            state.sessionMasterSecret.destroy();
            state.sessionMasterSecret = null;
        }

        if (state.sessionParameters != null)
        {
            state.sessionParameters.clear();
            state.sessionParameters = null;
        }

        if (state.tlsSession != null)
        {
            state.tlsSession.invalidate();
            state.tlsSession = null;
        }
    }

    protected void notifyClientCertificate(ServerHandshakeState state, Certificate clientCertificate)
        throws IOException
    {
        if (null == state.certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.processClientCertificate(state.serverContext, clientCertificate, state.keyExchange, state.server);
    }

    protected void processClientCertificate(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate clientCertificate = Certificate.parse(state.serverContext, buf, null);

        TlsProtocol.assertEmpty(buf);

        notifyClientCertificate(state, clientCertificate);
    }

    protected void processCertificateVerify(ServerHandshakeState state, byte[] body, TlsHandshakeHash handshakeHash)
        throws IOException
    {
        if (state.certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        TlsServerContextImpl context = state.serverContext;
        DigitallySigned certificateVerify = DigitallySigned.parse(context, buf);

        TlsProtocol.assertEmpty(buf);

        TlsUtils.verifyCertificateVerifyClient(context, state.certificateRequest, certificateVerify, handshakeHash);
    }

    protected void processClientHello(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ClientHello clientHello = ClientHello.parse(buf, NullOutputStream.INSTANCE);
        processClientHello(state, clientHello);
    }

    protected void processClientHello(ServerHandshakeState state, ClientHello clientHello)
        throws IOException
    {
        // TODO Read RFCs for guidance on the expected record layer version number
        ProtocolVersion legacy_version = clientHello.getVersion();
        state.offeredCipherSuites = clientHello.getCipherSuites();

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        state.clientExtensions = clientHello.getExtensions();

    
    
        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();

        if (!legacy_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        context.setRSAPreMasterSecretVersion(legacy_version);

        context.setClientSupportedVersions(
            TlsExtensionsUtils.getSupportedVersionsExtensionClient(state.clientExtensions));

        ProtocolVersion client_version = legacy_version;
        if (null == context.getClientSupportedVersions())
        {
            if (client_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
            {
                client_version = ProtocolVersion.DTLSv12;
            }

            context.setClientSupportedVersions(client_version.downTo(ProtocolVersion.DTLSv10));
        }
        else
        {
            client_version = ProtocolVersion.getLatestDTLS(context.getClientSupportedVersions());
        }

        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        context.setClientVersion(client_version);

        state.server.notifyClientVersion(context.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        state.server.notifyFallback(Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        state.server.notifyOfferedCipherSuites(state.offeredCipherSuites);

        /*
         * TODO[resumption] Check RFC 7627 5.4. for required behaviour 
         */

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
            if (Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                securityParameters.secureRenegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        state.server.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        state.offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(state.clientExtensions);

        if (state.clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(state.clientExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(state.clientExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
            {
                TlsUtils.establishClientSigAlgs(securityParameters, state.clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(state.clientExtensions);

            // Heartbeats
            {
                HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(state.clientExtensions);
                if (null != heartbeatExtension)
                {
                    if (HeartbeatMode.peer_allowed_to_send == heartbeatExtension.getMode())
                    {
                        state.heartbeat = state.server.getHeartbeat();
                    }

                    state.heartbeatPolicy = state.server.getHeartbeatPolicy();
                }
            }

            state.server.processClientExtensions(state.clientExtensions);
        }
    }

    protected void processClientKeyExchange(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.keyExchange.processClientKeyExchange(buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected void processClientSupplementalData(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector clientSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        state.server.processClientSupplementalData(clientSupplementalData);
    }

    protected boolean expectCertificateVerifyMessage(ServerHandshakeState state)
    {
        if (null == state.certificateRequest)
        {
            return false;
        }

        Certificate clientCertificate = state.serverContext.getSecurityParametersHandshake().getPeerCertificate();

        return null != clientCertificate && !clientCertificate.isEmpty()
            && (null == state.keyExchange || state.keyExchange.requiresCertificateVerify());
    }

    protected static class ServerHandshakeState
    {
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean offeredExtendedMasterSecret = false;
        boolean resumedSession = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsCredentials serverCredentials = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
    }
}
