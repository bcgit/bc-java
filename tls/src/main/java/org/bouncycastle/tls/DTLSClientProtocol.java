package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class DTLSClientProtocol
    extends DTLSProtocol
{
    public DTLSClientProtocol()
    {
        super();
    }

    public DTLSTransport connect(TlsClient client, DatagramTransport transport)
        throws IOException
    {
        if (client == null)
        {
            throw new IllegalArgumentException("'client' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        TlsClientContextImpl clientContext = new TlsClientContextImpl(client.getCrypto());

        client.init(clientContext);
        clientContext.handshakeBeginning(client);

        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = client.shouldUseExtendedPadding();

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(clientContext, client, transport);
        client.notifyCloseHandle(recordLayer);

        ClientHandshakeState state = new ClientHandshakeState();
        state.client = client;
        state.clientContext = clientContext;
        state.recordLayer = recordLayer;

        try
        {
            return clientHandshake(state);
        }
        catch (TlsFatalAlertReceived fatalAlertReceived)
        {
//            assert recordLayer.isFailed();
            invalidateSession(state);
            throw fatalAlertReceived;
        }
        catch (TlsFatalAlert fatalAlert)
        {
            abortClientHandshake(state, fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            abortClientHandshake(state, AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            abortClientHandshake(state, AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        finally
        {
            securityParameters.clear();
        }
    }

    protected void abortClientHandshake(ClientHandshakeState state, short alertDescription)
    {
        state.recordLayer.fail(alertDescription);
        invalidateSession(state);
    }

    protected DTLSTransport clientHandshake(ClientHandshakeState state)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        DTLSRecordLayer recordLayer = state.recordLayer;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        DTLSReliableHandshake handshake = new DTLSReliableHandshake(clientContext, recordLayer,
            client.getHandshakeTimeoutMillis(), client.getHandshakeResendTimeMillis(), null,
            TlsUtils.getMaxHandshakeMessageSize(client));

        byte[] clientHelloBody = generateClientHello(state);

        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);

        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        /*
         * NOTE: Received without being digested. A HelloRetryRequest must not go into the transcript until
         * the first ClientHello in it has been replaced by RFC 8446 4.4.1's synthetic "message_hash"
         * message, and whether this is one is only known once its body has been read.
         */
        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessageDelayedDigest();

        // TODO Consider stricter HelloVerifyRequest protocol
//        if (serverMessage.getType() == HandshakeType.hello_verify_request)
        while (serverMessage.getType() == HandshakeType.hello_verify_request)
        {
            /*
             * RFC 9147 5.1. HelloVerifyRequest has no place in DTLS 1.3 at all; its denial-of-service
             * countermeasure is a HelloRetryRequest cookie instead. A client that offered nothing earlier
             * than DTLS 1.3 therefore has no use for one, and accepting it would let an attacker drive the
             * 1.2 cookie exchange ahead of a 1.3 handshake.
             */
            if (!state.offeringDTLSv12Minus)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message,
                    "HelloVerifyRequest received, but only DTLS 1.3 was offered");
            }

            state.helloVerifyRequested = true;

            byte[] cookie = processHelloVerifyRequest(state, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetAfterHelloVerifyRequestClient();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessageDelayedDigest();
        }

        if (serverMessage.getType() == HandshakeType.server_hello && isHelloRetryRequest(serverMessage.getBody()))
        {
            /*
             * RFC 9147 5.1. A HelloRetryRequest means DTLS 1.3, which does not have HelloVerifyRequest, so
             * the two cannot both have happened.
             */
            if (state.helloVerifyRequested)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "HelloRetryRequest received after a HelloVerifyRequest");
            }

            process13HelloRetryRequest(state, serverMessage.getBody());

            /*
             * RFC 8446 4.4.1. The transcript for a handshake with a HelloRetryRequest begins with a
             * synthetic "message_hash" message carrying the hash of the first ClientHello alone, which
             * replaces it. So the first ClientHello is hashed and substituted here - reading the transcript
             * is what flushes it, in the DTLS 1.3 header form now that the negotiated version is known - and
             * only then is the HelloRetryRequest hashed after it.
             */
            TlsHandshakeHash handshakeHash = handshake.getHandshakeHash();
            handshakeHash.notifyPRFDetermined();

            TlsUtils.adjustTranscriptForRetry(handshakeHash);

            handshake.updateHandshakeMessagesDigest(serverMessage);

            handshake.sendMessage(HandshakeType.client_hello, generate13ClientHelloRetry(state));

            state.afterHelloRetryRequest = true;

            serverMessage = handshake.receiveMessageDelayedDigest();

            /*
             * RFC 8446 4.1.4. If a client receives a second HelloRetryRequest in the same connection (i.e.,
             * where the ClientHello was itself in response to a HelloRetryRequest), it MUST abort the
             * handshake with an "unexpected_message" alert.
             */
            if (serverMessage.getType() == HandshakeType.server_hello && isHelloRetryRequest(serverMessage.getBody()))
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message,
                    "Second HelloRetryRequest received");
            }
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            handshake.updateHandshakeMessagesDigest(serverMessage);

            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();

            /*
             * NOTE: The version the server actually selected is only visible once the ServerHello body has
             * been read; the record-layer version is 'legacy_record_version' and says nothing for DTLS 1.3.
             */
            ProtocolVersion server_version = readSelectedVersion(serverMessage.getBody());

            /*
             * Refuse anything later than the latest version this implementation actually knows how to
             * process. Neither of the other version checks catches it: 'reportServerVersion' only tests the
             * versions this client offered, and the DTLS 1.3 routing below is a lower bound, so without this
             * a future version would be processed with DTLS 1.3 semantics.
             */
            if (server_version.isLaterVersionOf(ProtocolVersion.DTLSv13))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version,
                    "Server selected an unsupported protocol version: " + server_version);
            }

            boolean isDTLSv13 = ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(server_version);

            /*
             * RFC 9147 5.1. DTLS 1.3 has no HelloVerifyRequest, so a server that sent one cannot then select
             * DTLS 1.3: either it is confused, or the cookie exchange was driven by something in the middle.
             * Without this a 1.3 handshake could be reached through the 1.2 countermeasure.
             */
            if (isDTLSv13 && state.helloVerifyRequested)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "Server selected DTLS 1.3 after sending a HelloVerifyRequest");
            }

            if (!isDTLSv13)
            {
                reportServerVersion(state, recordLayerVersion);
            }

            recordLayer.setWriteVersion(recordLayerVersion);

            processServerHello(state, serverMessage.getBody());

            if (isDTLSv13)
            {
                handshake.getHandshakeHash().notifyPRFDetermined();
                handshake.getHandshakeHash().sealHashAlgorithms();

                process13ServerHelloCoda(state, handshake.getHandshakeHash(), state.afterHelloRetryRequest);

                return clientHandshake13(state, handshake);
            }

            applyMaxFragmentLengthExtension(recordLayer, securityParameters.getMaxFragmentLength());
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        handshake.getHandshakeHash().notifyPRFDetermined();

        if (securityParameters.isResumedSession())
        {
            securityParameters.masterSecret = state.sessionMasterSecret;
            recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));

            // NOTE: Calculated exclusive of the actual Finished message from the server
            securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(clientContext,
                handshake.getHandshakeHash(), true);
            processFinished(handshake.receiveMessageBody(HandshakeType.finished),
                securityParameters.getPeerVerifyData());

            // NOTE: Calculated exclusive of the Finished message itself
            securityParameters.localVerifyData = TlsUtils.calculateVerifyData(clientContext,
                handshake.getHandshakeHash(), false);
            handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

            handshake.finish();

            if (securityParameters.isExtendedMasterSecret() &&
                ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(securityParameters.getNegotiatedVersion()))
            {
                securityParameters.tlsUnique = securityParameters.getPeerVerifyData();
            }

            securityParameters.localCertificate = state.sessionParameters.getLocalCertificate();
            securityParameters.peerCertificate = state.sessionParameters.getPeerCertificate();
            securityParameters.pskIdentity = state.sessionParameters.getPSKIdentity();
            securityParameters.srpIdentity = state.sessionParameters.getSRPIdentity();

            clientContext.handshakeComplete(client, state.tlsSession);

            recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

            return new DTLSTransport(recordLayer);
        }

        invalidateSession(state);
        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);

        serverMessage = handshake.receiveMessage();

        if (serverMessage.getType() == HandshakeType.supplemental_data)
        {
            processServerSupplementalData(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            client.processServerSupplementalData(null);
        }

        state.keyExchange = TlsUtils.initKeyExchangeClient(clientContext, client);

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            processServerCertificate(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, Certificate is optional
            state.authentication = null;
        }

        if (serverMessage.getType() == HandshakeType.certificate_status)
        {
            if (securityParameters.getStatusRequestVersion() < 1)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processCertificateStatus(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, CertificateStatus is optional
        }

        TlsUtils.processServerCertificate(clientContext, state.certificateStatus, state.keyExchange,
            state.authentication, state.clientExtensions, state.serverExtensions);

        if (serverMessage.getType() == HandshakeType.server_key_exchange)
        {
            processServerKeyExchange(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, ServerKeyExchange is optional
            state.keyExchange.skipServerKeyExchange();
        }

        if (serverMessage.getType() == HandshakeType.certificate_request)
        {
            processCertificateRequest(state, serverMessage.getBody());

            TlsUtils.establishServerSigAlgs(securityParameters, state.certificateRequest);

            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, CertificateRequest is optional
        }

        if (serverMessage.getType() == HandshakeType.server_hello_done)
        {
            if (serverMessage.getBody().length != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        TlsCredentials clientAuthCredentials = null;
        TlsCredentialedSigner clientAuthSigner = null;
        Certificate clientAuthCertificate = null;
        SignatureAndHashAlgorithm clientAuthAlgorithm = null;
        TlsStreamSigner clientAuthStreamSigner = null;

        if (state.certificateRequest != null)
        {
            clientAuthCredentials = TlsUtils.establishClientCredentials(state.authentication, state.certificateRequest);
            if (clientAuthCredentials != null)
            {
                clientAuthCertificate = clientAuthCredentials.getCertificate();

                if (clientAuthCredentials instanceof TlsCredentialedSigner)
                {
                    clientAuthSigner = (TlsCredentialedSigner)clientAuthCredentials;
                    clientAuthAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(
                        securityParameters.getNegotiatedVersion(), clientAuthSigner);
                    clientAuthStreamSigner = clientAuthSigner.getStreamSigner();

                    TlsUtils.verify12SignatureAlgorithm(clientAuthAlgorithm, AlertDescription.internal_error);

                    if (ProtocolVersion.DTLSv12.equals(securityParameters.getNegotiatedVersion()))
                    {
                        TlsUtils.verifySupportedSignatureAlgorithm(securityParameters.getServerSigAlgs(),
                            clientAuthAlgorithm, AlertDescription.internal_error);

                        if (clientAuthStreamSigner == null)
                        {
                            TlsUtils.trackHashAlgorithmClient(handshake.getHandshakeHash(), clientAuthAlgorithm);
                        }
                    }

                    if (clientAuthStreamSigner != null)
                    {
                        handshake.getHandshakeHash().forceBuffering();
                    }
                }
            }
        }

        handshake.getHandshakeHash().sealHashAlgorithms();

        if (clientAuthCredentials == null)
        {
            state.keyExchange.skipClientCredentials();
        }
        else
        {
            state.keyExchange.processClientCredentials(clientAuthCredentials);
        }

        Vector clientSupplementalData = client.getClientSupplementalData();
        if (clientSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(clientSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        if (null != state.certificateRequest)
        {
            sendCertificateMessage(clientContext, handshake, clientAuthCertificate, null);
        }

        byte[] clientKeyExchangeBody = generateClientKeyExchange(state);
        handshake.sendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

        securityParameters.sessionHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());

        TlsProtocol.establishMasterSecret(clientContext, state.keyExchange);
        state.keyExchange = null;

        recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));

        if (clientAuthSigner != null)
        {
            DigitallySigned certificateVerify = TlsUtils.generateCertificateVerifyClient(clientContext,
                clientAuthSigner, clientAuthAlgorithm, clientAuthStreamSigner, handshake.getHandshakeHash());
            byte[] certificateVerifyBody = generateCertificateVerify(state, certificateVerify);
            handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
        }

        handshake.prepareToFinish();

        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(clientContext, handshake.getHandshakeHash(),
            false);
        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        if (state.expectSessionTicket)
        {
            serverMessage = handshake.receiveMessage();
            if (serverMessage.getType() == HandshakeType.new_session_ticket)
            {
                /*
                 * RFC 5077 3.4. If the client receives a session ticket from the server, then it
                 * discards any Session ID that was sent in the ServerHello.
                 */
                securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
                invalidateSession(state);
                state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);

                processNewSessionTicket(state, serverMessage.getBody());
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        // NOTE: Calculated exclusive of the actual Finished message from the server
        securityParameters.peerVerifyData = TlsUtils.calculateVerifyData(clientContext, handshake.getHandshakeHash(),
            true);
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), securityParameters.getPeerVerifyData());

        handshake.finish();

        state.sessionMasterSecret = securityParameters.getMasterSecret();

        state.sessionParameters = new SessionParameters.Builder()
            .setCipherSuite(securityParameters.getCipherSuite())
            .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
            .setLocalCertificate(securityParameters.getLocalCertificate())
            .setMasterSecret(clientContext.getCrypto().adoptSecret(state.sessionMasterSecret))
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
            securityParameters.tlsUnique = securityParameters.getLocalVerifyData();
        }

        clientContext.handshakeComplete(client, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

        return new DTLSTransport(recordLayer);
    }

    /**
     * RFC 9147: the client half of a DTLS 1.3 handshake, from just after the ServerHello (handshake traffic
     * keys installed at epoch 2) through to sending the client's Finished and installing the application
     * traffic keys at epoch 3.
     */
    protected DTLSTransport clientHandshake13(ClientHandshakeState state, DTLSReliableHandshake handshake)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        DTLSRecordLayer recordLayer = state.recordLayer;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        receive13EncryptedExtensions(state, handshake.receiveMessageBody(HandshakeType.encrypted_extensions));

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        if (serverMessage.getType() == HandshakeType.certificate_request)
        {
            /*
             * RFC 8446 4.3.2. A server which is authenticating with a certificate MAY optionally request a
             * certificate from the client. Answered at the end of this method, once the server's Finished has
             * been verified. If no CertificateRequest arrives, 'state.certificateRequest' simply stays null,
             * which is what TlsClientProtocol.skip13CertificateRequest expresses for its dispatcher.
             */
            receive13CertificateRequest(state, serverMessage.getBody());

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            receive13ServerCertificate(state, serverMessage.getBody());
        }
        else
        {
            // TODO[dtls13-psk] A PSK handshake has no server Certificate (see skip13ServerCertificate)
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        {
            // NOTE: Verified over the transcript excluding the CertificateVerify message itself
            DTLSReliableHandshake.Message certificateVerifyMessage = handshake.receiveMessageDelayedDigest(
                HandshakeType.certificate_verify);
            receive13ServerCertificateVerify(state, certificateVerifyMessage.getBody(),
                handshake.getHandshakeHash());
            handshake.updateHandshakeMessagesDigest(certificateVerifyMessage);
        }

        byte[] serverFinishedTranscriptHash;
        {
            // NOTE: Calculated exclusive of the actual Finished message from the server
            DTLSReliableHandshake.Message finishedMessage = handshake.receiveMessageDelayedDigest(
                HandshakeType.finished);
            receive13ServerFinished(state, finishedMessage.getBody(), handshake.getHandshakeHash());
            handshake.updateHandshakeMessagesDigest(finishedMessage);

            serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(handshake.getHandshakeHash());
        }

        /*
         * RFC 9147 5. DTLS 1.3 does not use the TLS 1.3 "compatibility mode", so there is no
         * change_cipher_spec message in either direction.
         */

        if (null != state.certificateRequest)
        {
            TlsCredentialedSigner clientCredentials = TlsUtils.establish13ClientCredentials(state.authentication,
                state.certificateRequest);

            Certificate clientCertificate = null;
            if (null != clientCredentials)
            {
                clientCertificate = clientCredentials.getCertificate();
            }

            if (null == clientCertificate)
            {
                /*
                 * RFC 8446 4.4.2. A client that declines still answers, with an empty certificate list. In
                 * this calling context, certificate_request_context is length 0.
                 */
                clientCertificate = Certificate.EMPTY_CHAIN_TLS13;
            }

            sendCertificateMessage(clientContext, handshake, clientCertificate, null);

            if (null != clientCredentials)
            {
                /*
                 * NOTE: Signed over the transcript through the Certificate just sent, and exclusive of the
                 * CertificateVerify message itself.
                 */
                DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(clientContext,
                    clientCredentials, handshake.getHandshakeHash());
                handshake.sendMessage(HandshakeType.certificate_verify,
                    generateCertificateVerify(state, certificateVerify));
            }
        }

        // NOTE: Calculated exclusive of the Finished message itself, and sent at the handshake epoch
        securityParameters.localVerifyData = TlsUtils.calculateVerifyData(clientContext,
            handshake.getHandshakeHash(), false);
        securityParameters.tlsUnique = null;

        handshake.sendMessage(HandshakeType.finished, securityParameters.getLocalVerifyData());

        /*
         * RFC 9147 6.1. The application traffic keys are epoch 3; both directions switch to it only after
         * the client's Finished has gone out under the handshake traffic keys of epoch 2.
         */
        TlsUtils.establish13PhaseApplication(clientContext, serverFinishedTranscriptHash, null);

        recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));
        recordLayer.enablePendingEpochWrite();
        recordLayer.enablePendingEpochRead();

        handshake.finish();

        state.sessionMasterSecret = securityParameters.getMasterSecret();

        state.sessionParameters = new SessionParameters.Builder()
            .setCipherSuite(securityParameters.getCipherSuite())
            .setExtendedMasterSecret(securityParameters.isExtendedMasterSecret())
            .setLocalCertificate(securityParameters.getLocalCertificate())
            .setMasterSecret(clientContext.getCrypto().adoptSecret(state.sessionMasterSecret))
            .setNegotiatedVersion(securityParameters.getNegotiatedVersion())
            .setPeerCertificate(securityParameters.getPeerCertificate())
            .setPSKIdentity(securityParameters.getPSKIdentity())
            .setSRPIdentity(securityParameters.getSRPIdentity())
            .setServerExtensions(state.serverExtensions)
            .build();

        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), state.sessionParameters);

        clientContext.handshakeComplete(client, state.tlsSession);

        recordLayer.initHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientHello(ClientHandshakeState state)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        ProtocolVersion[] supportedVersions = client.getProtocolVersions();

        ProtocolVersion earliestVersion = ProtocolVersion.getEarliestDTLS(supportedVersions);
        ProtocolVersion latestVersion = ProtocolVersion.getLatestDTLS(supportedVersions);

        if (!ProtocolVersion.isSupportedDTLSVersionClient(latestVersion))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        clientContext.setClientVersion(latestVersion);
        clientContext.setClientSupportedVersions(supportedVersions);

        boolean offeringDTLSv12Minus = ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(earliestVersion);
        boolean offeringDTLSv13Plus = ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(latestVersion);

        // NOTE: Whether a HelloVerifyRequest is a legal answer at all - see clientHandshake
        state.offeringDTLSv12Minus = offeringDTLSv12Minus;

        {
            boolean useGMTUnixTime = !offeringDTLSv13Plus && client.shouldUseGMTUnixTime();

            securityParameters.clientRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, clientContext);
        }

        TlsSession sessionToResume = offeringDTLSv12Minus ? client.getSessionToResume() : null;

        // NOTE: Client is free to modify the cipher suites up until getSessionToResume
        state.offeredCipherSuites = client.getCipherSuites();

        boolean fallback = client.isFallback();

        state.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(client.getClientExtensions());

        final boolean shouldUseEMS = client.shouldUseExtendedMasterSecret();

        establishSession(state, sessionToResume);

        byte[] legacy_session_id = TlsUtils.getSessionID(state.tlsSession);

        if (legacy_session_id.length > 0)
        {
            if (!Arrays.contains(state.offeredCipherSuites, state.sessionParameters.getCipherSuite()))
            {
                legacy_session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        ProtocolVersion sessionVersion = null;
        if (legacy_session_id.length > 0)
        {
            sessionVersion = state.sessionParameters.getNegotiatedVersion();

            if (!ProtocolVersion.contains(supportedVersions, sessionVersion))
            {
                legacy_session_id = TlsUtils.EMPTY_BYTES;
            }
        }

        if (legacy_session_id.length > 0 && TlsUtils.isExtendedMasterSecretOptional(sessionVersion))
        {
            if (shouldUseEMS)
            {
                if (!state.sessionParameters.isExtendedMasterSecret() &&
                    !client.allowLegacyResumption())
                {
                    legacy_session_id = TlsUtils.EMPTY_BYTES;
                }
            }
            else
            {
                if (state.sessionParameters.isExtendedMasterSecret())
                {
                    legacy_session_id = TlsUtils.EMPTY_BYTES;
                }
            }
        }

        if (legacy_session_id.length < 1)
        {
            cancelSession(state);
        }

        client.notifySessionToResume(state.tlsSession);

        ProtocolVersion legacy_version = latestVersion;
        if (offeringDTLSv13Plus)
        {
            legacy_version = ProtocolVersion.DTLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionClient(state.clientExtensions, supportedVersions);

            /*
             * RFC 9147 5. DTLS implementations do not use the TLS 1.3 "compatibility mode" [..].
             */
        }

        clientContext.setRSAPreMasterSecretVersion(legacy_version);

        securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(state.clientExtensions);

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(latestVersion))
        {
            TlsUtils.establishClientSigAlgs(securityParameters, state.clientExtensions);
        }

        securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(state.clientExtensions);

        // TODO[dtls13]
//        state.clientBinders = TlsUtils.addPreSharedKeyToClientHello(clientContext, client, state.clientExtensions,
//            state.offeredCipherSuites);
        state.clientBinders = null;

        // TODO[tls13-psk] Perhaps don't add key_share if external PSK(s) offered and 'psk_dhe_ke' not offered
        state.clientAgreements = TlsUtils.addKeyShareToClientHello(clientContext, client, state.clientExtensions);

        if (shouldUseEMS && TlsUtils.isExtendedMasterSecretOptional(supportedVersions))
        {
            TlsExtensionsUtils.addExtendedMasterSecretExtension(state.clientExtensions);
        }
        else
        {
            state.clientExtensions.remove(TlsExtensionsUtils.EXT_extended_master_secret);
        }

        // NOT renegotiating
        if (offeringDTLSv12Minus)
        {
            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
             */

            /*
             * The client MUST include either an empty "renegotiation_info" extension, or the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the ClientHello.
             * Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = !TlsUtils.hasExtension(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            boolean noRenegSCSV = !Arrays.contains(state.offeredCipherSuites,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noRenegSCSV)
            {
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }
        }

        /* (Fallback SCSV)
         * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
         * than the latest (highest-valued) version supported by the client, it SHOULD include
         * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
         * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
         * to negotiate.)
         */
        if (fallback && !Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
        {
            state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
        }

        // Heartbeats
        {
            state.heartbeat = client.getHeartbeat();
            state.heartbeatPolicy = client.getHeartbeatPolicy();

            if (null != state.heartbeat || HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy)
            {
                TlsExtensionsUtils.addHeartbeatExtension(state.clientExtensions, new HeartbeatExtension(state.heartbeatPolicy));
            }
        }



        int bindersSize = null == state.clientBinders ? 0 : state.clientBinders.bindersSize;

        ClientHello clientHello = new ClientHello(legacy_version, securityParameters.getClientRandom(),
            legacy_session_id, TlsUtils.EMPTY_BYTES, state.offeredCipherSuites, state.clientExtensions, bindersSize);

        // NOTE: (D)TLS 1.3 checks the ServerHello against the ClientHello that was actually sent
        state.clientHello = clientHello;

        /*
         * TODO[dtls13] See TlsClientProtocol.sendClientHelloMessage for how to prepare/encode binders and also consider
         * the impact of binders on cookie patching after HelloVerifyRequest.
         */
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        clientHello.encode(clientContext, buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientKeyExchange(ClientHandshakeState state)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.keyExchange.generateClientKeyExchange(buf);
        return buf.toByteArray();
    }

    protected void cancelSession(ClientHandshakeState state)
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

    protected boolean establishSession(ClientHandshakeState state, TlsSession sessionToResume)
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

        TlsCrypto crypto = state.clientContext.getCrypto();
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

    protected void invalidateSession(ClientHandshakeState state)
    {
        if (state.tlsSession != null)
        {
            state.tlsSession.invalidate();
        }

        cancelSession(state);
    }

    /**
     * Whether a ServerHello body is a HelloRetryRequest (RFC 8446 4.1.3: a ServerHello whose 'random' is the
     * special value). Used only to route the message; all validation is left to
     * {@link #process13HelloRetryRequest} or {@link #processServerHello}.
     */
    protected static boolean isHelloRetryRequest(byte[] body)
        throws IOException
    {
        return ServerHello.parse(new ByteArrayInputStream(body)).isHelloRetryRequest();
    }

    /**
     * Mirrors TlsClientProtocol.process13HelloRetryRequest. The "cookie" extension carried here is the
     * RFC 8446 4.2.2 retry token: opaque to the client, which simply echoes it in its second ClientHello.
     */
    protected void process13HelloRetryRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        /*
         * RFC 9147 5.3. The second ClientHello is still a plaintext record, carrying 'legacy_record_version'
         * 0xFEFD.
         */
        state.recordLayer.setWriteVersion(ProtocolVersion.DTLSv12);

        ServerHello helloRetryRequest = ServerHello.parse(new ByteArrayInputStream(body));

        /*
         * RFC 8446 4.1.4. Upon receipt of a HelloRetryRequest, the client MUST check the legacy_version,
         * legacy_session_id_echo, cipher_suite, and legacy_compression_method as specified in Section 4.1.3
         * and then process the extensions, starting with determining the version using "supported_versions".
         */
        ProtocolVersion legacy_version = helloRetryRequest.getVersion();
        byte[] legacy_session_id_echo = helloRetryRequest.getSessionID();
        int cipherSuite = helloRetryRequest.getCipherSuite();
        // NOTE: legacy_compression_method checked during ServerHello parsing

        if (!ProtocolVersion.DTLSv12.equals(legacy_version) ||
            !Arrays.areEqual(state.clientHello.getSessionID(), legacy_session_id_echo) ||
            !TlsUtils.isValidCipherSuiteSelection(state.clientHello.getCipherSuites(), cipherSuite))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        Hashtable extensions = helloRetryRequest.getExtensions();
        if (null == extensions)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, "no extensions found");
        }
        TlsUtils.checkExtensionData13(extensions, HandshakeType.hello_retry_request,
            AlertDescription.illegal_parameter);

        {
            /*
             * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote endpoint did not
             * send the corresponding extension requests, with the exception of the "cookie" extension in the
             * HelloRetryRequest. Upon receiving such an extension, an endpoint MUST abort the handshake with
             * an "unsupported_extension" alert.
             */
            Enumeration e = extensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();
                int extensionType = extType.intValue();

                if (ExtensionType.cookie == extensionType)
                {
                    continue;
                }

                if (null == TlsUtils.getExtensionData(state.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension,
                        "Unrequested extension in HelloRetryRequest: " + ExtensionType.getText(extensionType));
                }
            }
        }

        ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
        if (null == server_version)
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension,
                "missing extension response: " + ExtensionType.getText(ExtensionType.supported_versions));
        }

        if (!ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(server_version) ||
            server_version.isLaterVersionOf(ProtocolVersion.DTLSv13))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                "invalid version selected: " + server_version);
        }

        if (!TlsUtils.isValidVersionForCipherSuite(cipherSuite, server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, "invalid cipher suite for selected version");
        }

        if (null != state.clientBinders)
        {
            if (!Arrays.contains(state.clientBinders.pskKeyExchangeModes, PskKeyExchangeMode.psk_dhe_ke))
            {
                state.clientBinders = null;

                client.notifySelectedPSK(null);
            }
        }

        int selectedGroup = TlsExtensionsUtils.getKeyShareHelloRetryRequest(extensions);

        /*
         * TODO[dtls13:psk_ke] RFC 8446 4.2.8. Servers [..] MUST NOT send a KeyShareEntry when using the
         * "psk_ke" PskKeyExchangeMode - and RFC 8446 4.1.4 permits a HelloRetryRequest that carries only a
         * cookie, which this does not yet accept.
         */
        if (selectedGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.missing_extension,
                "missing extension response: " + ExtensionType.getText(ExtensionType.key_share));
        }

        /*
         * RFC 8446 4.2.8. Upon receipt of this [Key Share] extension in a HelloRetryRequest, the client MUST
         * verify that (1) the selected_group field corresponds to a group which was provided in the
         * "supported_groups" extension in the original ClientHello and (2) the selected_group field does not
         * correspond to a group which was provided in the "key_share" extension in the original ClientHello.
         * If either of these checks fails, then the client MUST abort the handshake with an
         * "illegal_parameter" alert.
         */
        if (!TlsUtils.isValidKeyShareSelection(server_version, securityParameters.getClientSupportedGroups(),
            state.clientAgreements, selectedGroup))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, "invalid key_share selected");
        }

        byte[] cookie = TlsExtensionsUtils.getCookieExtension(extensions);

        // NOTE: Also checks that this is a version the client offered, and notifies the TlsClient
        reportServerVersion(state, server_version);

        securityParameters.resumedSession = false;
        securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
        client.notifySessionID(TlsUtils.EMPTY_BYTES);

        TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        client.notifySelectedCipherSuite(cipherSuite);

        securityParameters.negotiatedGroup = selectedGroup;

        state.clientAgreements = null;
        state.retryCookie = cookie;
        state.retryGroup = selectedGroup;
    }

    /**
     * Mirrors TlsClientProtocol.send13ClientHelloRetry, except that the message goes out through
     * DTLSReliableHandshake and RFC 9147 5 drops the TLS 1.3 compatibility-mode change_cipher_spec that
     * precedes it there.
     * <p>
     * RFC 8446 4.1.2: the second ClientHello repeats the first unchanged except for the "key_share",
     * "early_data", "cookie", "pre_shared_key" and "padding" extensions, which is why the ClientHello object
     * itself is kept and re-encoded. Its 'legacy_cookie' field stays empty: RFC 9147 5.3 keeps that field
     * only for backwards compatibility with the DTLS 1.2 HelloVerifyRequest exchange.
     * </p>
     */
    protected byte[] generate13ClientHelloRetry(ClientHandshakeState state)
        throws IOException
    {
        ClientHello clientHello = state.clientHello;
        Hashtable clientHelloExtensions = clientHello.getExtensions();

        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_cookie);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_early_data);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_key_share);
        clientHelloExtensions.remove(TlsExtensionsUtils.EXT_pre_shared_key);

        /*
         * RFC 8446 4.2.2. When sending the new ClientHello, the client MUST copy the contents of the
         * extension received in the HelloRetryRequest into a "cookie" extension in the new ClientHello.
         */
        if (null != state.retryCookie)
        {
            TlsExtensionsUtils.addCookieExtension(clientHelloExtensions, state.retryCookie);
            state.retryCookie = null;
        }

        /*
         * TODO[dtls13-psk] Update the "pre_shared_key" extension if present, by recomputing the
         * "obfuscated_ticket_age" and binder values (TlsUtils.addPreSharedKeyToClientHelloRetry). No PSK is
         * ever offered yet, so there is nothing to recompute.
         */

        /*
         * RFC 8446 4.2.8. [..] when sending the new ClientHello, the client MUST replace the original
         * "key_share" extension with one containing only a new KeyShareEntry for the group indicated in the
         * selected_group field of the triggering HelloRetryRequest.
         */
        if (state.retryGroup < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        state.clientAgreements = TlsUtils.addKeyShareToClientHelloRetry(state.clientContext,
            clientHelloExtensions, state.retryGroup);

        /*
         * TODO[dtls13] Optionally adding, removing, or changing the length of the "padding" extension
         * [RFC7685].
         */

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        clientHello.encode(state.clientContext, buf);
        return buf.toByteArray();
    }

    /**
     * Mirrors TlsClientProtocol.process13ServerHello: check the ServerHello against the ClientHello that was
     * sent, then run the RFC 8446 7.1 key schedule as far as the handshake secret.
     */
    protected void process13ServerHello(ClientHandshakeState state, ServerHello serverHello,
        boolean afterHelloRetryRequest) throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        /*
         * RFC 8446 4.1.4. A HelloRetryRequest is handled in clientHandshake, ahead of this; reaching here
         * with one means a second one, which must be refused.
         */
        if (serverHello.isHelloRetryRequest())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message,
                "HelloRetryRequest received where a ServerHello was expected");
        }

        ProtocolVersion legacy_version = serverHello.getVersion();
        byte[] legacy_session_id_echo = serverHello.getSessionID();
        int cipherSuite = serverHello.getCipherSuite();
        // NOTE: legacy_compression_method checked during ServerHello parsing

        if (!ProtocolVersion.DTLSv12.equals(legacy_version) ||
            !Arrays.areEqual(state.clientHello.getSessionID(), legacy_session_id_echo))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        Hashtable extensions = serverHello.getExtensions();
        if (null == extensions)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        TlsUtils.checkExtensionData13(extensions, HandshakeType.server_hello, AlertDescription.illegal_parameter);

        if (afterHelloRetryRequest)
        {
            ProtocolVersion server_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(extensions);
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
            if (!TlsUtils.isValidCipherSuiteSelection(state.clientHello.getCipherSuites(), cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            securityParameters.resumedSession = false;
            securityParameters.sessionID = TlsUtils.EMPTY_BYTES;
            client.notifySessionID(TlsUtils.EMPTY_BYTES);

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            client.notifySelectedCipherSuite(cipherSuite);
        }

        state.clientHello = null;

        // NOTE: Apparently downgrade marker mechanism not used for (D)TLS 1.3+
        securityParameters.serverRandom = serverHello.getRandom();

        securityParameters.secureRenegotiation = false;

        /*
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        securityParameters.extendedMasterSecret = true;

        /*
         * RFC 8446 4.4.2.1. OCSP information is carried in an extension of the CertificateEntry for the
         * certificate it answers for, so there is nothing to echo here and no "certificate_status" message
         * to expect; a version of 1 records only that we asked.
         */
        securityParameters.statusRequestVersion =
            state.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;

        TlsSecret pskEarlySecret = null;
        {
            int selected_identity = TlsExtensionsUtils.getPreSharedKeyServerHello(extensions);
            TlsPSK selectedPSK = null;

            if (selected_identity >= 0)
            {
                if (null == state.clientBinders || selected_identity >= state.clientBinders.psks.length)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                selectedPSK = state.clientBinders.psks[selected_identity];
                if (selectedPSK.getPRFAlgorithm() != securityParameters.getPRFAlgorithm())
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                pskEarlySecret = state.clientBinders.earlySecrets[selected_identity];

                state.selectedPSK13 = true;
            }

            client.notifySelectedPSK(selectedPSK);
        }

        TlsSecret sharedSecret = null;
        {
            KeyShareEntry serverShare = TlsExtensionsUtils.getKeyShareServerHello(extensions);
            if (null == serverShare)
            {
                if (afterHelloRetryRequest ||
                    pskEarlySecret == null ||
                    !Arrays.contains(state.clientBinders.pskKeyExchangeModes, PskKeyExchangeMode.psk_ke))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
            else
            {
                if (pskEarlySecret != null &&
                    !Arrays.contains(state.clientBinders.pskKeyExchangeModes, PskKeyExchangeMode.psk_dhe_ke))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                int namedGroup = serverShare.getNamedGroup();

                TlsAgreement agreement = (TlsAgreement)state.clientAgreements.get(Integers.valueOf(namedGroup));
                if (null == agreement)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                agreement.receivePeerValue(serverShare.getKeyExchange());
                sharedSecret = agreement.calculateSecret();

                if (!afterHelloRetryRequest)
                {
                    securityParameters.negotiatedGroup = namedGroup;
                }
            }
        }

        state.clientAgreements = null;
        state.clientBinders = null;

        TlsUtils.establish13PhaseSecrets(clientContext, pskEarlySecret, sharedSecret);

        invalidateSession(state);
        state.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
    }

    /**
     * Mirrors TlsClientProtocol.process13ServerHelloCoda. Where the stream class hands the new cipher to
     * RecordStream, DTLS installs it as the pending epoch and switches both directions to it: RFC 9147 6.1
     * reserves epoch 1 for early data, so the handshake traffic keys are epoch 2. RFC 9147 5 drops the TLS
     * 1.3 compatibility-mode change_cipher_spec, so none is sent.
     */
    protected void process13ServerHelloCoda(ClientHandshakeState state, TlsHandshakeHash handshakeHash,
        boolean afterHelloRetryRequest) throws IOException
    {
        TlsClientContextImpl clientContext = state.clientContext;
        DTLSRecordLayer recordLayer = state.recordLayer;

        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        TlsUtils.establish13PhaseHandshake(clientContext, serverHelloTranscriptHash, null);

        recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));
        recordLayer.enablePendingEpochWrite();
        recordLayer.enablePendingEpochRead();
    }

    /**
     * Mirrors TlsClientProtocol.receive13CertificateRequest.
     */
    protected void receive13CertificateRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        /*
         * RFC 8446 4.3.2. A server which is authenticating with a certificate MAY optionally
         * request a certificate from the client.
         */
        if (state.selectedPSK13)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        CertificateRequest certificateRequest = CertificateRequest.parse(state.clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        state.certificateRequest = certificateRequest;

        TlsUtils.establishServerSigAlgs(state.clientContext.getSecurityParametersHandshake(), certificateRequest);
    }

    /**
     * Mirrors TlsClientProtocol.receive13EncryptedExtensions.
     */
    protected void receive13EncryptedExtensions(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] extBytes = TlsUtils.readOpaque16(buf);

        TlsProtocol.assertEmpty(buf);

        state.serverExtensions = TlsProtocol.readExtensionsData13(HandshakeType.encrypted_extensions, extBytes);

        {
            /*
             * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote
             * endpoint did not send the corresponding extension requests, with the exception of the
             * "cookie" extension in the HelloRetryRequest. Upon receiving such an extension, an
             * endpoint MUST abort the handshake with an "unsupported_extension" alert.
             */
            Enumeration e = state.serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                if (null == TlsUtils.getExtensionData(state.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension,
                        "Unrequested extension in EncryptedExtensions: " + ExtensionType.getText(extType.intValue()));
                }
            }
        }

        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(state.serverExtensions);
        securityParameters.applicationProtocolSet = true;

        Hashtable sessionClientExtensions = state.clientExtensions, sessionServerExtensions = state.serverExtensions;
        if (securityParameters.isResumedSession())
        {
            sessionClientExtensions = null;
            sessionServerExtensions = state.sessionParameters.readServerExtensions();
        }

        securityParameters.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(sessionClientExtensions,
            sessionServerExtensions, AlertDescription.illegal_parameter);

        securityParameters.encryptThenMAC = false;
        securityParameters.truncatedHMac = false;

        if (!securityParameters.isResumedSession())
        {
            // RFC 8446 4.4.2.1. See the note in process13ServerHello.
            securityParameters.statusRequestVersion =
                state.clientExtensions.containsKey(TlsExtensionsUtils.EXT_status_request) ? 1 : 0;

            TlsCrypto crypto = clientContext.getCrypto();
            securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension13(
                crypto, sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
            securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension13(
                crypto, sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
        }

        state.expectSessionTicket = false;

        if (null != sessionClientExtensions)
        {
            client.processServerExtensions(state.serverExtensions);
        }

        applyMaxFragmentLengthExtension(state.recordLayer, securityParameters.getMaxFragmentLength());
    }

    /**
     * Mirrors TlsClientProtocol.receive13ServerCertificate.
     */
    protected void receive13ServerCertificate(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        if (state.selectedPSK13)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        state.authentication = TlsUtils.receive13ServerCertificate(state.clientContext, state.client,
            new ByteArrayInputStream(body));

        // NOTE: In (D)TLS 1.3 we don't have to wait for a possible CertificateStatus message.
        TlsUtils.processServerCertificate(state.clientContext, null, null, state.authentication,
            state.clientExtensions, state.serverExtensions);
    }

    /**
     * Mirrors TlsClientProtocol.receive13ServerCertificateVerify. The transcript passed in must exclude the
     * CertificateVerify message itself, which is why it is read with a delayed digest.
     */
    protected void receive13ServerCertificateVerify(ClientHandshakeState state, byte[] body,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        TlsClientContextImpl clientContext = state.clientContext;

        Certificate serverCertificate = clientContext.getSecurityParametersHandshake().getPeerCertificate();
        if (null == serverCertificate || serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        CertificateVerify certificateVerify = CertificateVerify.parse(clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        TlsUtils.verify13CertificateVerifyServer(clientContext, handshakeHash, certificateVerify);
    }

    /**
     * Mirrors TlsClientProtocol.receive13ServerFinished (TlsProtocol.process13FinishedMessage). The
     * transcript passed in must exclude the Finished message itself.
     */
    protected void receive13ServerFinished(ClientHandshakeState state, byte[] body,
        TlsHandshakeHash handshakeHash) throws IOException
    {
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        byte[] expected_verify_data = TlsUtils.calculateVerifyData(clientContext, handshakeHash, true);

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

    protected void processCertificateRequest(ClientHandshakeState state, byte[] body) throws IOException
    {
        if (null == state.authentication)
        {
            /*
             * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        CertificateRequest certificateRequest = CertificateRequest.parse(state.clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        state.certificateRequest = TlsUtils.validateCertificateRequest(certificateRequest, state.keyExchange);
    }

    protected void processCertificateStatus(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        state.certificateStatus = CertificateStatus.parse(state.clientContext, buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected byte[] processHelloVerifyRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);

        /*
         * RFC 6347 This specification increases the cookie size limit to 255 bytes for greater
         * future flexibility. The limit remains 32 for previous versions of DTLS.
         */
        int maxCookieLength = ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) ? 255 : 32;

        byte[] cookie = TlsUtils.readOpaque8(buf, 0, maxCookieLength);

        TlsProtocol.assertEmpty(buf);

        // TODO Seems this behaviour is not yet in line with OpenSSL for DTLS 1.2
//        reportServerVersion(state, server_version);
        if (!server_version.isEqualOrEarlierVersionOf(state.clientContext.getClientVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return cookie;
    }

    protected void processNewSessionTicket(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.client.notifyNewSessionTicket(newSessionTicket);
    }

    protected void processServerCertificate(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        state.authentication = TlsUtils.receiveServerCertificate(state.clientContext, state.client,
            new ByteArrayInputStream(body));
    }

    protected void processServerHello(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        ServerHello serverHello = ServerHello.parse(buf);

        Hashtable serverHelloExtensions = serverHello.getExtensions();

        ProtocolVersion legacy_version = serverHello.getVersion();
        ProtocolVersion supported_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(
            serverHelloExtensions);

        ProtocolVersion server_version;
        if (null == supported_version)
        {
            server_version = legacy_version;
        }
        else
        {
            if (!ProtocolVersion.DTLSv12.equals(legacy_version) ||
                !ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(supported_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            server_version = supported_version;
        }

        // NOT renegotiating
        {
            reportServerVersion(state, server_version);
        }

        // NOTE: This is integrated into reportServerVersion call above
//        TlsUtils.negotiatedVersionDTLSClient(clientContext, state.client);

        if (ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(server_version))
        {
            process13ServerHello(state, serverHello, state.afterHelloRetryRequest);
            return;
        }

        int[] offeredCipherSuites = state.offeredCipherSuites;

        state.clientHello = null;

        state.retryCookie = null;
        state.retryGroup = -1;

        securityParameters.serverRandom = serverHello.getRandom();

        if (!clientContext.getClientVersion().equals(server_version))
        {
            TlsUtils.checkDowngradeMarker(server_version, securityParameters.getServerRandom());
        }

        {
            byte[] selectedSessionID = serverHello.getSessionID();
            securityParameters.sessionID = selectedSessionID;
            client.notifySessionID(selectedSessionID);
            securityParameters.resumedSession = selectedSessionID.length > 0 && state.tlsSession != null
                && Arrays.areEqual(selectedSessionID, state.tlsSession.getSessionID());

            if (securityParameters.isResumedSession())
            {
                if (serverHello.getCipherSuite() != state.sessionParameters.getCipherSuite() ||
                    !securityParameters.getNegotiatedVersion().equals(state.sessionParameters.getNegotiatedVersion()))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                        "ServerHello parameters do not match resumed session");
                }
            }
        }

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones, and is a valid selection for the negotiated version.
         */
        {
            int cipherSuite = validateSelectedCipherSuite(serverHello.getCipherSuite(),
                AlertDescription.illegal_parameter);

            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "ServerHello selected invalid cipher suite");
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
            client.notifySelectedCipherSuite(cipherSuite);
        }

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message. However, see RFC 5746 exception below. We always include
         * the SCSV, so an Extended Server Hello is always allowed.
         */
        state.serverExtensions = serverHelloExtensions;
        if (serverHelloExtensions != null)
        {
            Enumeration e = serverHelloExtensions.keys();
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
                if (extType.equals(TlsProtocol.EXT_RenegotiationInfo))
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
                if (!TlsUtils.hasExtension(state.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension,
                        "Unrequested extension in ServerHello: " + ExtensionType.getText(extType.intValue()));
                }

                /*
                 * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                 * extensions appearing in the client hello, and send a server hello containing no
                 * extensions[.]
                 */
                if (securityParameters.isResumedSession())
                {
                    // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        byte[] renegExtData = TlsUtils.getExtensionData(serverHelloExtensions, TlsProtocol.EXT_RenegotiationInfo);

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

                if (!Arrays.constantTimeAreEqual(renegExtData,
                    TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
        client.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        // extended_master_secret
        {
            boolean negotiatedEMS = false;

            if (TlsExtensionsUtils.hasExtendedMasterSecretExtension(state.clientExtensions))
            {
                negotiatedEMS = TlsExtensionsUtils.hasExtendedMasterSecretExtension(serverHelloExtensions);

                if (TlsUtils.isExtendedMasterSecretOptional(server_version))
                {
                    if (!negotiatedEMS &&
                        client.requiresExtendedMasterSecret())
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure,
                            "Extended Master Secret extension is required");
                    }
                }
                else
                {
                    if (negotiatedEMS)
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "Server sent an unexpected extended_master_secret extension negotiating " + server_version);
                    }
                }
            }

            securityParameters.extendedMasterSecret = negotiatedEMS;
        }

        if (securityParameters.isResumedSession() &&
            securityParameters.isExtendedMasterSecret() != state.sessionParameters.isExtendedMasterSecret())
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure,
                "Server resumed session with mismatched extended_master_secret negotiation");
        }

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverHelloExtensions);
        securityParameters.applicationProtocolSet = true;

        // Connection ID
        if (ProtocolVersion.DTLSv12.equals(securityParameters.getNegotiatedVersion()))
        {
            /*
             * RFC 9146 3. When a DTLS session is resumed or renegotiated, the "connection_id" extension is
             * negotiated afresh.
             */
            byte[] serverConnectionID = TlsExtensionsUtils.getConnectionIDExtension(serverHelloExtensions);
            if (serverConnectionID != null)
            {
                byte[] clientConnectionID = TlsExtensionsUtils.getConnectionIDExtension(state.clientExtensions);
                if (clientConnectionID == null)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                securityParameters.connectionIDLocal = serverConnectionID;
                securityParameters.connectionIDPeer = clientConnectionID;
            }
        }

        // Heartbeats
        {
            HeartbeatExtension heartbeatExtension = TlsExtensionsUtils.getHeartbeatExtension(serverHelloExtensions);
            if (null == heartbeatExtension)
            {
                state.heartbeat = null;
                state.heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
            }
            else if (HeartbeatMode.peer_allowed_to_send != heartbeatExtension.getMode())
            {
                state.heartbeat = null;
            }
        }

        Hashtable sessionClientExtensions = state.clientExtensions, sessionServerExtensions = serverHelloExtensions;

        if (securityParameters.isResumedSession())
        {
            sessionClientExtensions = null;
            sessionServerExtensions = state.sessionParameters.readServerExtensions();
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

            securityParameters.maxFragmentLength = TlsUtils.processMaxFragmentLengthExtension(sessionClientExtensions,
                sessionServerExtensions, AlertDescription.illegal_parameter);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

            if (!securityParameters.isResumedSession())
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

                TlsCrypto crypto = clientContext.getCrypto();
                securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension(
                    crypto, sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
                securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension(
                    crypto, sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

                state.expectSessionTicket = TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.illegal_parameter);
            }
        }

        if (sessionClientExtensions != null)
        {
            client.processServerExtensions(sessionServerExtensions);
        }
    }

    protected void processServerKeyExchange(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.keyExchange.processServerKeyExchange(buf);

        TlsProtocol.assertEmpty(buf);
    }

    protected void processServerSupplementalData(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);
        Vector serverSupplementalData = TlsProtocol.readSupplementalDataMessage(buf);
        state.client.processServerSupplementalData(serverSupplementalData);
    }

    /**
     * Determine the protocol version a ServerHello selects, without otherwise processing it: the
     * "supported_versions" extension if present (RFC 8446 4.2.1), else 'legacy_version'. Used only to route
     * the ServerHello; all validation of the pair is left to {@link #processServerHello}.
     */
    protected static ProtocolVersion readSelectedVersion(byte[] body)
        throws IOException
    {
        ServerHello serverHello = ServerHello.parse(new ByteArrayInputStream(body));

        ProtocolVersion supported_version = TlsExtensionsUtils.getSupportedVersionsExtensionServer(
            serverHello.getExtensions());

        return null != supported_version ? supported_version : serverHello.getVersion();
    }

    protected void reportServerVersion(ClientHandshakeState state, ProtocolVersion server_version)
        throws IOException
    {
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        ProtocolVersion currentServerVersion = securityParameters.getNegotiatedVersion();
        if (null != currentServerVersion)
        {
            if (!currentServerVersion.equals(server_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            return;
        }

        if (!ProtocolVersion.contains(clientContext.getClientSupportedVersions(), server_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        // TODO[dtls13] Read draft/RFC for guidance on the legacy_record_version field
//        ProtocolVersion legacy_record_version = server_version.isLaterVersionOf(ProtocolVersion.DTLSv12)
//            ?   ProtocolVersion.DTLSv12
//            :   server_version;
//
//        recordLayer.setWriteVersion(legacy_record_version);
        securityParameters.negotiatedVersion = server_version;

        TlsUtils.negotiatedVersionDTLSClient(clientContext, state.client);
    }

    protected static byte[] patchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie)
        throws IOException
    {
        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHelloBody, sessionIDPos);

        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;

        byte[] patched = new byte[clientHelloBody.length + cookie.length];
        System.arraycopy(clientHelloBody, 0, patched, 0, cookieLengthPos);
        TlsUtils.checkUint8(cookie.length);
        TlsUtils.writeUint8(cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length,
            clientHelloBody.length - cookiePos);

        return patched;
    }

    protected static class ClientHandshakeState
    {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        DTLSRecordLayer recordLayer = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        ClientHello clientHello = null;
        int[] offeredCipherSuites = null;
        boolean selectedPSK13 = false;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        Hashtable clientAgreements = null;
        OfferedPsks.BindersConfig clientBinders = null;
        boolean offeringDTLSv12Minus = false;
        boolean helloVerifyRequested = false;
        boolean afterHelloRetryRequest = false;
        byte[] retryCookie = null;
        int retryGroup = -1;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
    }
}
