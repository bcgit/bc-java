package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
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

        server.init(serverContext);
        serverContext.handshakeBeginning(server);

        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = server.shouldUseExtendedPadding();

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(serverContext, server, transport);
        server.notifyCloseHandle(recordLayer);

        ServerHandshakeState state = new ServerHandshakeState();
        state.server = server;
        state.serverContext = serverContext;
        state.recordLayer = recordLayer;

        try
        {
            return serverHandshake(state, request);
        }
        catch (TlsFatalAlertReceived fatalAlertReceived)
        {
//            assert recordLayer.isFailed();
            invalidateSession(state);
            throw fatalAlertReceived;
        }
        catch (TlsFatalAlert fatalAlert)
        {
            abortServerHandshake(state, fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            abortServerHandshake(state, AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            abortServerHandshake(state, AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        finally
        {
            securityParameters.clear();
        }
    }

    protected void abortServerHandshake(ServerHandshakeState state, short alertDescription)
    {
        state.recordLayer.fail(alertDescription);
        invalidateSession(state);
    }

    protected DTLSTransport serverHandshake(ServerHandshakeState state, DTLSRequest request) throws IOException
    {
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        DTLSRecordLayer recordLayer = state.recordLayer;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        DTLSReliableHandshake handshake = new DTLSReliableHandshake(serverContext, recordLayer,
            server.getHandshakeTimeoutMillis(), server.getHandshakeResendTimeMillis(), request,
            TlsUtils.getMaxHandshakeMessageSize(server));

        DTLSReliableHandshake.Message clientMessage = null;

        if (null == request)
        {
            clientMessage = handshake.receiveMessage();

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
            /*
             * Reached through accept(TlsServer, DatagramTransport, DTLSRequest), i.e. behind DTLSVerifier,
             * so this ClientHello arrived through the DTLS 1.2 cookie exchange: DTLSVerifier only produces a
             * DTLSRequest for a ClientHello carrying a cookie it has verified, though it need not have sent
             * the HelloVerifyRequest itself during this call - see the check in generateServerHello.
             */
            state.afterHelloVerifyRequest = true;

            processClientHello(state, request.getClientHello());

            request = null;
        }

        {
            byte[] serverHelloBody = generateServerHello(state);

            if (state.helloRetryRequestSent)
            {
                /*
                 * RFC 8446 4.4.1. The transcript of a handshake with a HelloRetryRequest begins with a
                 * synthetic "message_hash" message standing in for the first ClientHello, so the first
                 * ClientHello must be hashed and replaced before the HelloRetryRequest is hashed after it.
                 * DTLSReliableHandshake digests a message as it is sent or received, so the substitution has
                 * to happen here, between the two.
                 */
                TlsHandshakeHash handshakeHash = handshake.getHandshakeHash();
                handshakeHash.notifyPRFDetermined();

                TlsUtils.adjustTranscriptForRetry(handshakeHash);

                handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);

                /*
                 * RFC 8446 4.1.2. The client answers with a fresh ClientHello echoing the cookie; RFC 9147
                 * 5.2 gives it the next message_seq, as the DTLS 1.2 cookie exchange does.
                 */
                processClientHelloRetry(state, handshake.receiveMessageBody(HandshakeType.client_hello));

                serverHelloBody = generate13ServerHello(state, true);
            }

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            handshake.getHandshakeHash().sealHashAlgorithms();

            return serverHandshake13(state, handshake, state.helloRetryRequestSent);
        }

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

            if (securityParameters.isExtendedMasterSecret() &&
                ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(securityParameters.getNegotiatedVersion()))
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

        TlsCredentials serverCredentials = null;

        if (!KeyExchangeAlgorithm.isAnonymous(securityParameters.getKeyExchangeAlgorithm()))
        {
            serverCredentials = TlsUtils.establishServerCredentials(server);
        }

        // Server certificate
        {
            Certificate serverCertificate = null;

            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            if (serverCredentials == null)
            {
                state.keyExchange.skipServerCredentials();
            }
            else
            {
                state.keyExchange.processServerCredentials(serverCredentials);

                serverCertificate = serverCredentials.getCertificate();

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

        if (serverCredentials != null)
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
        state.keyExchange = null;

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

        if (ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(securityParameters.getNegotiatedVersion()))
        {
            securityParameters.tlsUnique = securityParameters.getPeerVerifyData();
        }

        serverContext.handshakeComplete(server, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

        return new DTLSTransport(recordLayer);
    }

    /**
     * The DTLS 1.3 server handshake, entered once the ServerHello selecting DTLS 1.3 has been sent. Mirrors
     * the 1.3 portions of TlsServerProtocol.send13ServerHelloCoda and handle13HandshakeMessage: the server's
     * flight goes out under the handshake traffic keys at epoch 2, and both directions move to the
     * application traffic keys at epoch 3 once the client's Finished has been verified.
     */
    protected DTLSTransport serverHandshake13(ServerHandshakeState state, DTLSReliableHandshake handshake,
        boolean afterHelloRetryRequest) throws IOException
    {
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        DTLSRecordLayer recordLayer = state.recordLayer;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        byte[] serverFinishedTranscriptHash = send13ServerHelloCoda(state, handshake, afterHelloRetryRequest);

        /*
         * RFC 8446 4.4.2. A client that was sent a CertificateRequest always answers with a Certificate,
         * carrying an empty certificate list when it declines, and follows it with a CertificateVerify only
         * when that list is not empty. With no CertificateRequest sent, the client's flight is its Finished
         * alone, and a Certificate or CertificateVerify here is unexpected - which is what the type check in
         * receiveMessageDelayedDigest reports. This is the counterpart of TlsServerProtocol's
         * skip13ClientCertificate and skip13ClientCertificateVerify, which make the same two rules explicit
         * because its dispatcher reaches the Finished handler from either state.
         */
        if (null != state.certificateRequest)
        {
            receive13ClientCertificate(state, handshake.receiveMessageBody(HandshakeType.certificate));

            if (expectCertificateVerifyMessage(state))
            {
                // NOTE: Verified over the transcript excluding the CertificateVerify message itself
                DTLSReliableHandshake.Message certificateVerifyMessage = handshake.receiveMessageDelayedDigest(
                    HandshakeType.certificate_verify);
                receive13ClientCertificateVerify(state, certificateVerifyMessage.getBody(),
                    handshake.getHandshakeHash());
                handshake.updateHandshakeMessagesDigest(certificateVerifyMessage);
            }
        }

        {
            // NOTE: Calculated exclusive of the actual Finished message from the client
            DTLSReliableHandshake.Message finishedMessage = handshake.receiveMessageDelayedDigest(
                HandshakeType.finished);
            receive13ClientFinished(state, finishedMessage.getBody(), handshake.getHandshakeHash());
            handshake.updateHandshakeMessagesDigest(finishedMessage);
        }

        /*
         * RFC 9147 6.1. The application traffic keys are epoch 3. Unlike TLS 1.3, the write direction is
         * not switched early: the server's flight must remain retransmissible at epoch 2 until the client's
         * Finished proves it arrived.
         */
        TlsUtils.establish13PhaseApplication(serverContext, serverFinishedTranscriptHash, null);

        recordLayer.initPendingEpoch(TlsUtils.initCipher(serverContext));
        recordLayer.enablePendingEpochWrite();
        recordLayer.enablePendingEpochRead();

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
            .setServerExtensions(state.serverExtensions)
            .build();

        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), state.sessionParameters);

        serverContext.handshakeComplete(server, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

        return new DTLSTransport(recordLayer);
    }

    /**
     * Mirrors TlsServerProtocol.send13ServerHelloCoda: install the handshake traffic keys, then send
     * EncryptedExtensions, Certificate, CertificateVerify and Finished.
     *
     * @return the transcript hash through the server's Finished, which the application traffic secrets are
     *         derived from once the client's Finished has been received.
     */
    protected byte[] send13ServerHelloCoda(ServerHandshakeState state, DTLSReliableHandshake handshake,
        boolean afterHelloRetryRequest) throws IOException
    {
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        DTLSRecordLayer recordLayer = state.recordLayer;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsUtils.establish13PhaseHandshake(serverContext, serverHelloTranscriptHash, null);

        /*
         * RFC 9147 6.1. Epoch 1 is reserved for early data, so the handshake traffic keys are epoch 2. Both
         * directions switch: the rest of the server's flight and the client's whole flight are protected.
         */
        recordLayer.initPendingEpoch(TlsUtils.initCipher(serverContext));
        recordLayer.enablePendingEpochWrite();
        recordLayer.enablePendingEpochRead();

        handshake.sendMessage(HandshakeType.encrypted_extensions,
            generate13EncryptedExtensions(state.serverExtensions));

        if (state.selectedPSK13)
        {
            /*
             * For PSK-only key exchange, there's no CertificateRequest, Certificate, CertificateVerify.
             */
        }
        else
        {
            // CertificateRequest
            {
                state.certificateRequest = server.getCertificateRequest();
                if (null != state.certificateRequest)
                {
                    /*
                     * RFC 8446 4.3.2. In a handshake the 'certificate_request_context' is zero length; a
                     * non-empty one belongs to post-handshake authentication, which this does not support.
                     */
                    if (!state.certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES))
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                    }

                    TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);

                    handshake.sendMessage(HandshakeType.certificate_request,
                        generateCertificateRequest(state, state.certificateRequest));
                }
            }

            TlsCredentialedSigner serverCredentials = TlsUtils.establish13ServerCredentials(server);
            if (null == serverCredentials)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // Certificate
            {
                /*
                 * RFC 8446 4.4.2.1. No CertificateStatus message is sent; the response travels in a
                 * "status_request" extension of the CertificateEntry it answers for.
                 */
                Certificate serverCertificate = serverCredentials.getCertificate();

                if (securityParameters.getStatusRequestVersion() > 0)
                {
                    serverCertificate = TlsUtils.add13CertificateStatus(serverCertificate,
                        server.getCertificateStatus());
                }

                sendCertificateMessage(serverContext, handshake, serverCertificate, null);
                securityParameters.tlsServerEndPoint = null;
            }

            // CertificateVerify
            {
                DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(serverContext,
                    serverCredentials, handshake.getHandshakeHash());
                handshake.sendMessage(HandshakeType.certificate_verify,
                    generateCertificateVerify(state, certificateVerify));
            }
        }

        // Finished
        {
            // NOTE: Calculated exclusive of the Finished message itself
            securityParameters.localVerifyData = TlsUtils.calculateVerifyData(serverContext,
                handshake.getHandshakeHash(), true);
            securityParameters.tlsUnique = null;

            handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());
        }

        return TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());
    }

    /**
     * Mirrors TlsServerProtocol.generate13ServerHello. Everything the DTLS 1.2 path already performed in
     * {@link #processClientHello(ServerHandshakeState, ClientHello)} - the padding check, server names,
     * client signature algorithms, supported groups, heartbeat and TlsServer.processClientExtensions - is
     * not repeated here.
     */
    protected byte[] generate13ServerHello(ServerHandshakeState state, boolean afterHelloRetryRequest)
        throws IOException
    {
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        TlsCrypto crypto = serverContext.getCrypto();

        ClientHello clientHello = state.clientHello;

        byte[] legacy_session_id = clientHello.getSessionID();

        Hashtable clientHelloExtensions = clientHello.getExtensions();
        if (null == clientHelloExtensions)
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension);
        }

        ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();

        /*
         * TODO[dtls13-psk] TlsUtils.selectPreSharedKey needs the raw ClientHello message to recompute the
         * binders over it, and DTLSReliableHandshake does not expose one. No PSK is selected, so an offered
         * pre_shared_key is simply declined and a full handshake follows - a legitimate server choice.
         */
        state.selectedPSK13 = false;
        TlsSecret pskEarlySecret = null;

        Vector clientShares = TlsExtensionsUtils.getKeyShareClientHello(clientHelloExtensions);

        int[] serverSupportedGroups = null;
        KeyShareEntry clientShare;
        if (afterHelloRetryRequest)
        {
            if (state.retryGroup < 0)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * RFC 8446 4.2.3. If a server is authenticating via a certificate and the client has not sent
             * a "signature_algorithms" extension, then the server MUST abort the handshake with a
             * "missing_extension" alert. (Established from the first ClientHello, which RFC 8446 4.1.2 does
             * not permit the second to change this part of.)
             */
            if (null == securityParameters.getClientSigAlgs())
            {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }

            /*
             * RFC 8446 4.2.2. When sending the new ClientHello, the client MUST copy the contents of the
             * extension received in the HelloRetryRequest into a "cookie" extension in the new ClientHello.
             * If the value does not match, this is not the answer to the HelloRetryRequest we sent.
             */
            byte[] cookie = TlsExtensionsUtils.getCookieExtension(clientHelloExtensions);
            if (!Arrays.areEqual(state.retryCookie, cookie))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "Second ClientHello did not echo the HelloRetryRequest cookie");
            }
            state.retryCookie = null;

            /*
             * RFC 8446 4.2.8. The client MUST replace the original "key_share" extension with one
             * containing only a new KeyShareEntry for the group indicated in the selected_group field.
             */
            clientShare = TlsUtils.getRetryKeyShare(clientShares, state.retryGroup);
            if (null == clientShare)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "Second ClientHello did not carry the requested key_share");
            }
        }
        else
        {
            {
                securityParameters.serverRandom = TlsProtocol.createRandomBlock(false, serverContext);

                if (!serverVersion.equals(ProtocolVersion.getLatestDTLS(server.getProtocolVersions())))
                {
                    TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
                }
            }

            securityParameters.secureRenegotiation = false;

            /*
             * RFC 8446 4.2.3. If a server is authenticating via a certificate and the client has not sent
             * a "signature_algorithms" extension, then the server MUST abort the handshake with a
             * "missing_extension" alert. (A selected PSK would exempt it; none is ever selected yet.)
             */
            if (null == securityParameters.getClientSigAlgs())
            {
                throw new TlsFatalAlert(AlertDescription.missing_extension);
            }

            /*
             * NOTE: Currently no server support for session resumption in (D)TLS 1.3.
             */
            {
                cancelSession(state);

                securityParameters.resumedSession = false;

                state.tlsSession = TlsUtils.importSession(TlsUtils.EMPTY_BYTES, null);
            }

            securityParameters.sessionID = state.tlsSession.getSessionID();

            server.notifySession(state.tlsSession);

            TlsUtils.negotiatedVersionDTLSServer(serverContext);

            {
                int cipherSuite = validateSelectedCipherSuite(server.getSelectedCipherSuite(),
                    AlertDescription.internal_error);

                if (!TlsUtils.isValidCipherSuiteSelection(clientHello.getCipherSuites(), cipherSuite) ||
                    !TlsUtils.isValidVersionForCipherSuite(cipherSuite, serverVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            }

            securityParameters.serverSupportedGroups = server.getSupportedGroups();

            int[] clientSupportedGroups = securityParameters.getClientSupportedGroups();
            serverSupportedGroups = securityParameters.getServerSupportedGroups();
            boolean useServerOrder = server.preferLocalSupportedGroups();

            int selectedGroup = TlsUtils.selectKeyShareGroup(crypto, serverVersion, clientSupportedGroups,
                serverSupportedGroups, useServerOrder);
            if (selectedGroup < 0)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            securityParameters.negotiatedGroup = selectedGroup;

            clientShare = TlsUtils.findEarlyKeyShare(clientShares, selectedGroup);

            if (null == clientShare)
            {
                /*
                 * RFC 8446 4.1.4. The client offered no share for the group we selected, so ask for one. The
                 * cookie that rides along is the retry token of RFC 8446 4.2.2: it is what the second
                 * ClientHello has to echo for us to accept it as the answer to this HelloRetryRequest. It is
                 * not address validation - that is what a DTLSVerifier front end does for DTLS 1.2, and
                 * doing it for DTLS 1.3 needs a front end of its own (see generate13HelloRetryRequest).
                 */
                state.retryGroup = selectedGroup;
                state.retryCookie = serverContext.getNonceGenerator().generateNonce(16);

                return generate13HelloRetryRequest(state);
            }
        }

        Hashtable serverHelloExtensions = new Hashtable();
        Hashtable serverEncryptedExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(
            server.getServerExtensions());

        server.getServerExtensionsForConnection(serverEncryptedExtensions);

        /*
         * RFC 8446 4.2.7. As of TLS 1.3, servers are permitted to send the "supported_groups" extension to
         * the client. [..] If the server has a group it prefers to the ones in the "key_share" extension
         * but is still willing to accept the ClientHello, it SHOULD send "supported_groups" to update the
         * client's view of its preferences.
         */
        if (!afterHelloRetryRequest)
        {
            if (!TlsUtils.isNullOrEmpty(serverSupportedGroups) &&
                serverSupportedGroups[0] != securityParameters.getNegotiatedGroup() &&
                !serverEncryptedExtensions.containsKey(TlsExtensionsUtils.EXT_supported_groups))
            {
                TlsExtensionsUtils.addSupportedGroupsExtension(serverEncryptedExtensions, serverSupportedGroups);
            }
        }

        ProtocolVersion serverLegacyVersion = ProtocolVersion.DTLSv12;
        TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);

        /*
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server Finished,
         * implementations which support both TLS 1.3 and earlier versions SHOULD indicate the use of the
         * Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        securityParameters.extendedMasterSecret = true;

        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(
            serverEncryptedExtensions);
        securityParameters.applicationProtocolSet = true;

        if (!serverEncryptedExtensions.isEmpty())
        {
            securityParameters.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(
                clientHelloExtensions, serverEncryptedExtensions, AlertDescription.internal_error);

            securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension13(
                crypto, clientHelloExtensions, serverEncryptedExtensions, AlertDescription.internal_error);
            securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension13(
                crypto, clientHelloExtensions, serverEncryptedExtensions, AlertDescription.internal_error);
        }

        securityParameters.encryptThenMAC = false;
        securityParameters.truncatedHMac = false;

        /*
         * RFC 8446 4.4.2.1. OCSP information is carried in an extension of the CertificateEntry the
         * certificate it answers for is in, so there is nothing to echo here and nothing to send as a
         * "certificate_status" message; a version of 1 records only that the client asked.
         */
        securityParameters.statusRequestVersion =
            clientHelloExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;

        state.expectSessionTicket = false;

        TlsSecret sharedSecret;
        {
            int negotiatedGroup = securityParameters.getNegotiatedGroup();

            if (clientShare.getNamedGroup() != negotiatedGroup)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            TlsAgreement agreement = TlsUtils.createKeyShare(crypto, negotiatedGroup, true);
            if (agreement == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            agreement.receivePeerValue(clientShare.getKeyExchange());

            byte[] key_exchange = agreement.generateEphemeral();
            KeyShareEntry serverShare = new KeyShareEntry(negotiatedGroup, key_exchange);
            TlsExtensionsUtils.addKeyShareServerHello(serverHelloExtensions, serverShare);

            sharedSecret = agreement.calculateSecret();
        }

        TlsUtils.establish13PhaseSecrets(serverContext, pskEarlySecret, sharedSecret);

        state.serverExtensions = serverEncryptedExtensions;

        applyMaxFragmentLengthExtension(state.recordLayer, securityParameters.getMaxFragmentLength());

        TlsUtils.checkExtensionData13(serverHelloExtensions, HandshakeType.server_hello,
            AlertDescription.internal_error);

        ServerHello serverHello = new ServerHello(serverLegacyVersion, securityParameters.getServerRandom(),
            legacy_session_id, securityParameters.getCipherSuite(), serverHelloExtensions);

        state.clientHello = null;

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        serverHello.encode(serverContext, buf);
        return buf.toByteArray();
    }

    /**
     * Mirrors TlsServerProtocol.generate13HelloRetryRequest. A HelloRetryRequest is a ServerHello - same
     * handshake type, 'random' set to the RFC 8446 4.1.3 magic value - and is sent through the ordinary
     * flight machinery at epoch 0.
     * <p>
     * The "cookie" extension here is the RFC 8446 4.2.2 retry token, opaque to the client and echoed back in
     * its second ClientHello, exactly as TlsServerProtocol's is. It is deliberately <em>not</em> the RFC 9147
     * 5.1 denial-of-service countermeasure: that requires the cookie to be verifiable without any retained
     * per-connection state, which cannot be done from inside accept() - the handshake object already exists
     * by the time this runs. DTLS 1.2 gets that property from {@link DTLSVerifier} sitting in front of
     * accept(), and DTLS 1.3 needs an equivalent front end, carrying the first ClientHello's transcript hash
     * and the selected parameters in the cookie and reconstructing the transcript from the RFC 8446 4.4.1
     * "message_hash".
     * </p>
     *
     * TODO[dtls13] A stateless HelloRetryRequest front end, as above.
     */
    protected byte[] generate13HelloRetryRequest(ServerHandshakeState state)
        throws IOException
    {
        if (state.retryGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /*
         * RFC 8446 4.1.4. A server MUST NOT send a HelloRetryRequest in response to a ClientHello that was
         * itself in response to one. The decision to retry is only ever taken on the first ClientHello, so
         * reaching this twice would be a routing defect rather than anything the peer did.
         */
        if (state.helloRetryRequestSent)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "Attempted to send a second HelloRetryRequest");
        }

        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();
        ProtocolVersion serverVersion = securityParameters.getNegotiatedVersion();

        Hashtable serverHelloExtensions = new Hashtable();
        TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverHelloExtensions, serverVersion);
        TlsExtensionsUtils.addKeyShareHelloRetryRequest(serverHelloExtensions, state.retryGroup);
        if (null != state.retryCookie)
        {
            TlsExtensionsUtils.addCookieExtension(serverHelloExtensions, state.retryCookie);
        }

        TlsUtils.checkExtensionData13(serverHelloExtensions, HandshakeType.hello_retry_request,
            AlertDescription.internal_error);

        /*
         * RFC 9147 5.3. 'legacy_version' is 0xFEFD (DTLS 1.2), not the TLS 1.3 value, and the selected
         * version travels in "supported_versions".
         */
        ServerHello helloRetryRequest = new ServerHello(ProtocolVersion.DTLSv12, state.clientHello.getSessionID(),
            securityParameters.getCipherSuite(), serverHelloExtensions);

        state.helloRetryRequestSent = true;

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        helloRetryRequest.encode(serverContext, buf);
        return buf.toByteArray();
    }

    /**
     * RFC 8446 4.1.2. The second ClientHello must repeat the first without modification except for the
     * "key_share", "early_data", "cookie", "pre_shared_key" and "padding" extensions, so none of the
     * first-ClientHello processing is repeated: the fields checked here are the ones everything after this
     * depends on having stayed put. The cookie itself is checked in
     * {@link #generate13ServerHello(ServerHandshakeState, boolean)}, where the retry state is consumed.
     * <p>
     * TODO[dtls13] Confirm the extensions in the ClientHello haven't changed either, which RFC 8446 4.1.2
     * also makes a MUST. Only the outer fields are compared below; TlsServerProtocol.generate13ServerHello
     * carries the same gap, under its own "TODO[tls13] Confirm fields in the ClientHello haven't changed".
     * </p>
     * <p>
     * RFC 9147 5.3. The ClientHello's 'legacy_cookie' field exists for backwards compatibility with the DTLS
     * 1.2 HelloVerifyRequest exchange and MUST be ignored by a DTLS 1.3 server, so it is not looked at here
     * or anywhere on the 1.3 path.
     * </p>
     */
    protected void processClientHelloRetry(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ClientHello clientHello = ClientHello.parse(buf, NullOutputStream.INSTANCE);

        ClientHello firstClientHello = state.clientHello;
        if (null == firstClientHello)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (!firstClientHello.getVersion().equals(clientHello.getVersion()) ||
            !Arrays.areEqual(firstClientHello.getRandom(), clientHello.getRandom()) ||
            !Arrays.areEqual(firstClientHello.getSessionID(), clientHello.getSessionID()) ||
            !Arrays.areEqual(firstClientHello.getCipherSuites(), clientHello.getCipherSuites()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                "Second ClientHello did not repeat the first");
        }

        if (null == clientHello.getExtensions())
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension);
        }

        state.clientHello = clientHello;
    }

    /**
     * Mirrors TlsServerProtocol.send13EncryptedExtensionsMessage.
     */
    protected byte[] generate13EncryptedExtensions(Hashtable serverExtensions)
        throws IOException
    {
        byte[] extBytes = TlsProtocol.writeExtensionsData(serverExtensions);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeOpaque16(extBytes, buf);
        return buf.toByteArray();
    }

    protected byte[] generateCertificateVerify(ServerHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    /**
     * Mirrors TlsServerProtocol.receive13ClientCertificate. The message is parsed exactly as the DTLS 1.2
     * path parses it; RFC 8446 4.4.2's extra rule is only that the client must not send one unasked.
     */
    protected void receive13ClientCertificate(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        if (null == state.certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        processClientCertificate(state, body);
    }

    /**
     * Mirrors TlsServerProtocol.receive13ClientCertificateVerify. The transcript passed in must exclude the
     * CertificateVerify message itself, which is why it is read with a delayed digest.
     */
    protected void receive13ClientCertificateVerify(ServerHandshakeState state, byte[] body,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        TlsServerContextImpl serverContext = state.serverContext;

        Certificate clientCertificate = serverContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null == clientCertificate || clientCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        CertificateVerify certificateVerify = CertificateVerify.parse(serverContext, buf);

        TlsProtocol.assertEmpty(buf);

        TlsUtils.verify13CertificateVerifyClient(serverContext, handshakeHash, certificateVerify);
    }

    /**
     * Mirrors TlsServerProtocol.receive13ClientFinished (TlsProtocol.process13FinishedMessage). The
     * transcript passed in must exclude the Finished message itself.
     */
    protected void receive13ClientFinished(ServerHandshakeState state, byte[] body,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

        byte[] expected_verify_data = TlsUtils.calculateVerifyData(serverContext, handshakeHash, false);

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        TlsProtocol.assertEmpty(buf);

        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }

        securityParameters.peerVerifyData = expected_verify_data;
        securityParameters.tlsUnique = null;
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

    protected byte[] generateServerHello(ServerHandshakeState state)
        throws IOException
    {
        TlsServer server = state.server;
        TlsServerContextImpl serverContext = state.serverContext;
        SecurityParameters securityParameters = serverContext.getSecurityParametersHandshake();

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
//            state.recordLayer.setWriteVersion(legacy_record_version);
            securityParameters.negotiatedVersion = serverVersion;
        }

        if (ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(serverVersion))
        {
            /*
             * RFC 9147 5.1. DTLS 1.3 has no HelloVerifyRequest at all: its denial-of-service cookie is
             * carried by a HelloRetryRequest instead. A connection reached through DTLSVerifier has already
             * had a HelloVerifyRequest sent on it, and DTLSClientProtocol rightly refuses a DTLS 1.3
             * selection that arrives after one, so this handshake cannot complete. Fail here, where the cause
             * is known, rather than leave the operator to diagnose their own configuration from an alert
             * raised on the client.
             *
             * NOTE: Capping the offered versions at DTLS 1.2 instead is not an option: the RFC 8446 4.1.3
             * downgrade sentinel written below is derived from server.getProtocolVersions(), not from the
             * capped list, so a 1.3-capable client would abort on the sentinel regardless.
             *
             * TODO[dtls13] Support the RFC 9147 5.1 stateless HelloRetryRequest cookie exchange in
             * DTLSVerifier, so that a DTLS 1.3 handshake can be fronted by a cookie exchange too.
             */
            if (state.afterHelloVerifyRequest)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error,
                    "DTLS 1.3 cannot be negotiated behind a HelloVerifyRequest front end");
            }

            /*
             * RFC 9147 5.1. DTLS 1.3 records carry 'legacy_record_version' 0xfefd (DTLS 1.2) in the
             * plaintext records that precede the first protected epoch.
             *
             * NOTE: RFC 9147 5 drops the TLS 1.3 "compatibility mode", so unlike TLS there is no
             * change_cipher_spec to send or to ignore.
             */
            state.recordLayer.setReadVersion(ProtocolVersion.DTLSv12);
            state.recordLayer.setWriteVersion(ProtocolVersion.DTLSv12);

            return generate13ServerHello(state, false);
        }

        state.recordLayer.setReadVersion(serverVersion);
        state.recordLayer.setWriteVersion(serverVersion);

        {
            boolean useGMTUnixTime = server.shouldUseGMTUnixTime();

            securityParameters.serverRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, serverContext);

            if (!serverVersion.equals(ProtocolVersion.getLatestDTLS(server.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(serverVersion, securityParameters.getServerRandom());
            }
        }

        server.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

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

            if (resumedSession)
            {
                TlsExtensionsUtils.removeStatusRequestExtensions(state.serverExtensions);
            }
        }

        server.getServerExtensionsForConnection(state.serverExtensions);

        // NOT renegotiating
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
             */
            if (securityParameters.isSecureRenegotiation())
            {
                boolean noRenegExt = !TlsUtils.hasExtension(state.serverExtensions,
                    TlsProtocol.EXT_RenegotiationInfo);

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

                TlsCrypto crypto = serverContext.getCrypto();
                securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension(
                    crypto, clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);
                securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension(
                    crypto, clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);

                state.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.internal_error);
            }
        }

        ServerHello serverHello = new ServerHello(serverVersion, securityParameters.getServerRandom(),
            securityParameters.getSessionID(), securityParameters.getCipherSuite(), state.serverExtensions);

        state.clientHello = null;

        applyMaxFragmentLengthExtension(state.recordLayer, securityParameters.getMaxFragmentLength());

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

        if (!sessionParameters.isExtendedMasterSecret() &&
            !TlsUtils.isExtendedMasterSecretOptional(sessionVersion))
        {
            return false;
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
        state.recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);

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

        /*
         * NOTE: server.notifySecureRenegotiation is called from generateServerHello, in the
         * DTLS-1.2-and-below portion past the point where the DTLS 1.3 path has returned. That mirrors the
         * version gating of TlsServerProtocol.generateServerHello, which likewise notifies only once a
         * version at or below 1.2 has been selected. It does NOT mirror its ordering relative to the other
         * TlsServer callbacks: DTLS selects the version in generateServerHello, so by the time the
         * notification is made here establishClientSigAlgs and server.processClientExtensions have already
         * run from processClientHello, whereas TlsServerProtocol notifies before both.
         *
         * RFC 8446 / RFC 9147 remove renegotiation, so a client offering only DTLS 1.3 (or later)
         * legitimately sends neither the "renegotiation_info" extension nor the SCSV - see the matching
         * 'offeringDTLSv12Minus' gate in DTLSClientProtocol.generateClientHello - and gating on the selected
         * version rather than on the client's offer is what keeps a {1.3, 1.2} offer with neither of them
         * acceptable.
         */

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
        DTLSRecordLayer recordLayer = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        ClientHello clientHello = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        boolean helloRetryRequestSent = false;
        boolean afterHelloVerifyRequest = false;
        byte[] retryCookie = null;
        int retryGroup = -1;
        TlsKeyExchange keyExchange = null;
        CertificateRequest certificateRequest = null;
        boolean selectedPSK13 = false;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
    }
}
