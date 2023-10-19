package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCrypto;
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

        TlsServerContextImpl serverContext = new TlsServerContextImpl(server.getCrypto());

        ServerHandshakeState state = new ServerHandshakeState();
        state.server = server;
        state.serverContext = serverContext;

        server.init(serverContext);
        serverContext.handshakeBeginning(server);

        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = server.shouldUseExtendedPadding();

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(serverContext, server, transport);
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
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        DTLSReliableHandshake handshake = new DTLSReliableHandshake(serverContext, recordLayer,
            server.getHandshakeTimeoutMillis(), server.getHandshakeResendTimeMillis(), request);

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

            clientMessage = null;
        }
        else
        {
            processClientHello(state, request.getClientHello());

            request = null;
        }

        {
            byte[] serverHelloBody = generateServerHello(state, recordLayer);

            // TODO[dtls13] Ideally, move this into generateServerHello once legacy_record_version clarified
            {
                ProtocolVersion recordLayerVersion = serverContext.getServerVersion();
                recordLayer.setReadVersion(recordLayerVersion);
                recordLayer.setWriteVersion(recordLayerVersion);
            }

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        if (securityParameters.isResumedSession())
        {
            securityParameters.masterSecret = state.sessionMasterSecret;
            recordLayer.initPendingEpoch(TlsUtils.initCipher(serverContext));

            // NOTE: Calculated exclusive of the Finished message itself
            securityParameters.localVerifyData = TlsUtils.calculateVerifyData(serverContext,
                handshake.getHandshakeHash(), true);
            handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

            // NOTE: Calculated exclusive of the actual Finished message from the client
            securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(serverContext,
                handshake.getHandshakeHash(), false);
            processFinished(handshake.receiveMessageBody(HandshakeType.finished),
                securityParameters.getPeerVerifyData());

            handshake.finish();

            if (securityParameters.isExtendedMasterSecret())
            {
                securityParameters.tlsUnique = securityParameters.getLocalVerifyData();
            }

            securityParameters.localCertificate = state.sessionParameters.getLocalCertificate();
            securityParameters.peerCertificate = state.sessionParameters.getPeerCertificate();
            securityParameters.pskIdentity = state.sessionParameters.getPSKIdentity();
            securityParameters.srpIdentity = state.sessionParameters.getSRPIdentity();

            serverContext.handshakeComplete(server, state.tlsSession);

            recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

            return new DTLSTransport(recordLayer);
        }

        Vector serverSupplementalData = server.getServerSupplementalData();
        if (serverSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        state.keyExchange = TlsUtils.initKeyExchangeServer(serverContext, server);

        state.serverCredentials = null;

        if (!KeyExchangeAlgorithm.isAnonymous(securityParameters.getKeyExchangeAlgorithm()))
        {
            state.serverCredentials = TlsUtils.establishServerCredentials(server);
        }

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

                sendCertificateMessage(serverContext, handshake, serverCertificate, endPointHash);
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
            CertificateStatus certificateStatus = server.getCertificateStatus();
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
            state.certificateRequest = server.getCertificateRequest();

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
                if (TlsUtils.isTLSv12(serverContext) != (state.certificateRequest.getSupportedSignatureAlgorithms() != null))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                state.certificateRequest = TlsUtils.validateCertificateRequest(state.certificateRequest, state.keyExchange);

                TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);

                if (ProtocolVersion.DTLSv12.equals(securityParameters.getNegotiatedVersion()))
                {
                    TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(), securityParameters.getServerSigAlgs());

                    if (serverContext.getCrypto().hasAnyStreamVerifiers(securityParameters.getServerSigAlgs()))
                    {
                        handshake.getHandshakeHash().forceBuffering();
                    }
                }
                else
                {
                    if (serverContext.getCrypto().hasAnyStreamVerifiersLegacy(state.certificateRequest.getCertificateTypes()))
                    {
                        handshake.getHandshakeHash().forceBuffering();
                    }
                }
            }
        }

        handshake.getHandshakeHash().sealHashAlgorithms();

        if (null != state.certificateRequest)
        {
            byte[] certificateRequestBody = generateCertificateRequest(state, state.certificateRequest);
            handshake.sendMessage(HandshakeType.certificate_request, certificateRequestBody);
        }

        handshake.sendMessage(HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);

        clientMessage = handshake.receiveMessage();

        if (clientMessage.getType() == HandshakeType.supplemental_data)
        {
            processClientSupplementalData(state, clientMessage.getBody());
            clientMessage = handshake.receiveMessage();
        }
        else
        {
            server.processClientSupplementalData(null);
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
                if (TlsUtils.isTLSv12(serverContext))
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

        TlsProtocol.establishMasterSecret(serverContext, state.keyExchange);
        recordLayer.initPendingEpoch(TlsUtils.initCipher(serverContext));

        /*
         * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed Diffie-Hellman
         * parameters).
         */
        {
            if (expectCertificateVerifyMessage(state))
            {
                clientMessage = handshake.receiveMessageDelayedDigest(HandshakeType.certificate_verify);
                byte[] certificateVerifyBody = clientMessage.getBody();
                processCertificateVerify(state, certificateVerifyBody, handshake.getHandshakeHash());
                handshake.prepareToFinish();
                handshake.updateHandshakeMessagesDigest(clientMessage);
            }
            else
            {
                handshake.prepareToFinish();
            }
        }

        clientMessage = null;

        // NOTE: Calculated exclusive of the actual Finished message from the client
        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(serverContext, handshake.getHandshakeHash(),
            false);
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), securityParameters.getPeerVerifyData());

        if (state.expectSessionTicket)
        {
            /*
             * TODO[new_session_ticket] Check the server-side rules regarding the session ID, since the client
             * is going to ignore any session ID it received once it sees the new_session_ticket message.
             */

            NewSessionTicket newSessionTicket = server.getNewSessionTicket();
            byte[] newSessionTicketBody = generateNewSessionTicket(state, newSessionTicket);
            handshake.sendMessage(HandshakeType.new_session_ticket, newSessionTicketBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(serverContext, handshake.getHandshakeHash(),
            true);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        handshake.finish();

        state.sessionMasterSecret = securityParameters.getMasterSecret();

        state.sessionParameters = new SessionParameters.Builder()
            .setCipherSuite(securityParameters.getCipherSuite())
            .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
            .setLocalCertificate(securityParameters.getLocalCertificate())
            .setMasterSecret(serverContext.getCrypto().adoptSecret(state.sessionMasterSecret))
            .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
            .setPeerCertificate(securityParameters.getPeerCertificate())
            .setPSKIdentity(securityParameters.getPSKIdentity())
            .setSRPIdentity(securityParameters.getSRPIdentity())
            // TODO Consider filtering extensions that aren't relevant to resumed sessions
            .setServerExtensions(state.serverExtensions)
            .build();

        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), state.sessionParameters);

        securityParameters.tlsUnique = securityParameters.getPeerVerifyData();

        serverContext.handshakeComplete(server, state.tlsSession);

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
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        // TODO[dtls13] Negotiate cipher suite first?

        ProtocolVersion serverVersion;

        // NOT renegotiating
        {
            serverVersion = server.getServerVersion();
            if (!ProtocolVersion.contains(serverContext.getClientSupportedVersions(), serverVersion))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO[dtls13] Read draft/RFC for guidance on the legacy_record_version field
//            ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.DTLSv12)
//                ? ProtocolVersion.DTLSv12
//                : server_version;
//
//            recordLayer.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = serverVersion;
        }

        // TODO[dtls13]
//        if (ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(serverVersion))
//        {
//            // See RFC 8446 D.4.
//            recordStream.setIgnoreChangeCipherSpec(true);
//
//            recordStream.setWriteVersion(ProtocolVersion.DTLSv12);
//
//            return generate13ServerHello(clientHello, clientHelloMessage, false);
//        }
//
//        recordStream.setWriteVersion(serverVersion);

        {
            boolean useGMTUnixTime = server.shouldUseGMTUnixTime();

            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, serverContext);

            if (!serverVersion.equals(ProtocolVersion.getLatestDTLS(server.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
            }
        }

        Hashtable clientHelloExtensions = state.clientHello.getExtensions();

        TlsSession sessionToResume = server.getSessionToResume(state.clientHello.getSessionID());

        boolean resumedSession = establishSession(state, sessionToResume);

        if (resumedSession && !serverVersion.equals(state.sessionParameters.getNegotiatedVersion()))
        {
            resumedSession = false;
        }

        // TODO Check the session cipher suite is selectable by the same rules that getSelectedCipherSuite uses

        // TODO Check the resumed session has a peer certificate if we NEED client-auth

        // extended_master_secret
        {
            boolean negotiateEMS = false;

            if (TlsUtils.isExtendedMasterSecretOptional(serverVersion) &&
                server.shouldUseExtendedMasterSecret())
            {
                if (TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientHelloExtensions))
                {
                    negotiateEMS = true;
                }
                else if (server.requiresExtendedMasterSecret())
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure,
                        "Extended Master Secret extension is required");
                }
                else if (resumedSession)
                {
                    if (state.sessionParameters.isExtendedMasterSecret())
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure,
                            "Extended Master Secret extension is required for EMS session resumption");
                    }

                    if (!server.allowLegacyResumption())
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure,
                            "Extended Master Secret extension is required for legacy session resumption");
                    }
                }
            }

            if (resumedSession && negotiateEMS != state.sessionParameters.isExtendedMasterSecret())
            {
                resumedSession = false;
            }

            securityParameters.extendedMasterSecret = negotiateEMS;
        }

        if (!resumedSession)
        {
            cancelSession(state);

            byte[] newSessionID = server.getNewSessionID();
            if (null == newSessionID)
            {
                newSessionID = TlsUtils.EMPTY_BYTES;
            }

            state.tlsSession = TlsUtils.importSession(newSessionID, null);
        }

        securityParameters.resumedSession = resumedSession;
        securityParameters.sessionID = state.tlsSession.getSessionID();

        server.notifySession(state.tlsSession);

        TlsUtils.negotiatedVersionDTLSServer(serverContext);

        {
            int cipherSuite = validateSelectedCipherSuite(server.getSelectedCipherSuite(),
                AlertDescription.internal_error);

            if (!TlsUtils.isValidCipherSuiteSelection(state.clientHello.getCipherSuites(), cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        {
            Hashtable sessionServerExtensions = resumedSession
                ?   state.sessionParameters.readServerExtensions()
                :   server.getServerExtensions();

            state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(sessionServerExtensions);
        }

        server.getServerExtensionsForConnection(state.serverExtensions);

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
             */
            if (securityParameters.isSecureRenegotiation())
            {
                byte[] serverRenegExtData = TlsUtils.getExtensionData(state.serverExtensions,
                    TlsProtocol.EXT_RenegotiationInfo);
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
                    state.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo,
                        TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                }
            }
        }

        if (securityParameters.isExtendedMasterSecret())
        {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(state.serverExtensions);
        }
        else
        {
            state.serverExtensions.remove(TlsExtensionsUtils.EXT_extended_master_secret);
        }

        // Heartbeats
        if (null != state.heartbeat || HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy)
        {
            TlsExtensionsUtils.addHeartbeatExtension(state.serverExtensions, new HeartbeatExtension(state.heartbeatPolicy));
        }

        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
        securityParameters.applicationProtocolSet = true;

        // Connection ID
        if (ProtocolVersion.DTLSv12.equals(securityParameters.getNegotiatedVersion()))
        {
            /*
             * RFC 9146 3. When a DTLS session is resumed or renegotiated, the "connection_id" extension is
             * negotiated afresh.
             */
            byte[] serverConnectionID = TlsExtensionsUtils.getConnectionIDExtension(state.serverExtensions);
            if (serverConnectionID != null)
            {
                byte[] clientConnectionID = TlsExtensionsUtils.getConnectionIDExtension(clientHelloExtensions);
                if (clientConnectionID == null)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                securityParameters.connectionIDLocal = clientConnectionID;
                securityParameters.connectionIDPeer = serverConnectionID;
            }
        }

        if (!state.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(state.serverExtensions);

            securityParameters.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(
                resumedSession ? null : clientHelloExtensions, state.serverExtensions,
                AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(state.serverExtensions);

            if (!resumedSession)
            {
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

                securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension(
                    clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);
                securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension(
                    clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);

                state.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.internal_error);
            }
        }

        ServerHello serverHello = new ServerHello(serverVersion, securityParameters.getServerRandom(),
            securityParameters.getSessionID(), securityParameters.getCipherSuite(), state.serverExtensions);

        state.clientHello = null;

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        serverHello.encode(serverContext, buf);
        return buf.toByteArray();
    }

    protected void cancelSession(ServerHandshakeState state)
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

        state.tlsSession = null;
    }

    protected boolean establishSession(ServerHandshakeState state, TlsSession sessionToResume)
    {
        state.tlsSession = null;
        state.sessionParameters = null;
        state.sessionMasterSecret = null;

        if (null == sessionToResume || !sessionToResume.isResumable())
        {
            return false;
        }

        SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
        if (null == sessionParameters)
        {
            return false;
        }

        ProtocolVersion sessionVersion = sessionParameters.getNegotiatedVersion();
        if (null == sessionVersion || !sessionVersion.isDTLS())
        {
            return false;
        }

        boolean isEMS = sessionParameters.isExtendedMasterSecret();
        if (!TlsUtils.isExtendedMasterSecretOptional(sessionVersion))
        {
            if (!isEMS)
            {
                return false;
            }
        }

        TlsCrypto crypto = state.serverContext.getCrypto();
        TlsSecret sessionMasterSecret = TlsUtils.getSessionMasterSecret(crypto, sessionParameters.getMasterSecret());
        if (null == sessionMasterSecret)
        {
            return false;
        }

        state.tlsSession = sessionToResume;
        state.sessionParameters = sessionParameters;
        state.sessionMasterSecret = sessionMasterSecret;

        return true;
    }

    protected void invalidateSession(ServerHandshakeState state)
    {
        if (state.tlsSession != null)
        {
            state.tlsSession.invalidate();
        }

        cancelSession(state);
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

        Certificate.ParseOptions options = new Certificate.ParseOptions()
            .setCertificateType(state.serverContext.getSecurityParametersHandshake().getClientCertificateType())
            .setMaxChainLength(state.server.getMaxCertificateChainLength());

        Certificate clientCertificate = Certificate.parse(options, state.serverContext, buf, null);

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

        TlsServerContextImpl serverContext = state.serverContext;
        DigitallySigned certificateVerify = DigitallySigned.parse(serverContext, buf);

        TlsProtocol.assertEmpty(buf);

        TlsUtils.verifyCertificateVerifyClient(serverContext, state.certificateRequest, certificateVerify,
            handshakeHash);
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
        state.clientHello = clientHello;

        // TODO Read RFCs for guidance on the expected record layer version number
        ProtocolVersion legacy_version = clientHello.getVersion();
        int[] offeredCipherSuites = clientHello.getCipherSuites();
        Hashtable clientHelloExtensions = clientHello.getExtensions();



        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        if (!legacy_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        serverContext.setRSAPreMasterSecretVersion(legacy_version);

        serverContext.setClientSupportedVersions(
            TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientHelloExtensions));

        ProtocolVersion client_version = legacy_version;
        if (null == serverContext.getClientSupportedVersions())
        {
            if (client_version.isLaterVersionOf(ProtocolVersion.DTLSv12))
            {
                client_version = ProtocolVersion.DTLSv12;
            }

            serverContext.setClientSupportedVersions(client_version.downTo(ProtocolVersion.DTLSv10));
        }
        else
        {
            client_version = ProtocolVersion.getLatestDTLS(serverContext.getClientSupportedVersions());
        }

        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        serverContext.setClientVersion(client_version);

        server.notifyClientVersion(serverContext.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        server.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        server.notifyOfferedCipherSuites(offeredCipherSuites);

        /*
         * TODO[resumption] Check RFC 7627 5.4. for required behaviour 
         */

        byte[] clientRenegExtData = TlsUtils.getExtensionData(clientHelloExtensions,
            TlsProtocol.EXT_RenegotiationInfo);

        // NOT renegotiatiing
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

                if (!Arrays.constantTimeAreEqual(clientRenegExtData,
                    TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        server.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        if (clientHelloExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientHelloExtensions);

            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientHelloExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
            {
                TlsUtils.establishClientSigAlgs(securityParameters, clientHelloExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientHelloExtensions);

            // Heartbeats
            {
                HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(clientHelloExtensions);
                if (null != heartbeatExtension)
                {
                    if (HeartbeatMode.peer_allowed_to_send == heartbeatExtension.getMode())
                    {
                        state.heartbeat = server.getHeartbeat();
                    }

                    state.heartbeatPolicy = server.getHeartbeatPolicy();
                }
            }

            server.processClientExtensions(clientHelloExtensions);
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
        ClientHello clientHello = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsCredentials serverCredentials = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
    }
}
