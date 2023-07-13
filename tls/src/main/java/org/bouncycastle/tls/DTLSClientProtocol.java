package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

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

        ClientHandshakeState state = new ClientHandshakeState();
        state.client = client;
        state.clientContext = clientContext;

        client.init(clientContext);
        clientContext.handshakeBeginning(client);

        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();
        securityParameters.extendedPadding = client.shouldUseExtendedPadding();

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(clientContext, client, transport);
        client.notifyCloseHandle(recordLayer);

        try
        {
            return clientHandshake(state, recordLayer);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            abortClientHandshake(state, recordLayer, fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            abortClientHandshake(state, recordLayer, AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            abortClientHandshake(state, recordLayer, AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
        finally
        {
            securityParameters.clear();
        }
    }

    protected void abortClientHandshake(ClientHandshakeState state, DTLSRecordLayer recordLayer, short alertDescription)
    {
        recordLayer.fail(alertDescription);
        invalidateSession(state);
    }

    protected DTLSTransport clientHandshake(ClientHandshakeState state, DTLSRecordLayer recordLayer)
        throws IOException
    {
        TlsClient client = state.client;
        TlsClientContextImpl clientContext = state.clientContext;
        SecurityParameters securityParameters = clientContext.getSecurityParametersHandshake();

        DTLSReliableHandshake handshake = new DTLSReliableHandshake(clientContext, recordLayer,
            client.getHandshakeTimeoutMillis(), client.getHandshakeResendTimeMillis(), null);

        byte[] clientHelloBody = generateClientHello(state);

        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);

        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        // TODO Consider stricter HelloVerifyRequest protocol
//        if (serverMessage.getType() == HandshakeType.hello_verify_request)
        while (serverMessage.getType() == HandshakeType.hello_verify_request)
        {
            byte[] cookie = processHelloVerifyRequest(state, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetAfterHelloVerifyRequestClient();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
            reportServerVersion(state, recordLayerVersion);
            recordLayer.setWriteVersion(recordLayerVersion);

            processServerHello(state, serverMessage.getBody());

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

            if (securityParameters.isExtendedMasterSecret())
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

        securityParameters.tlsUnique = securityParameters.getLocalVerifyData();

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

        {
            boolean useGMTUnixTime = !offeringDTLSv13Plus && client.shouldUseGMTUnixTime();

            securityParameters.clientRandom = TlsProtocol.createRandomBlock(useGMTUnixTime, clientContext);
        }

        TlsSession sessionToResume = offeringDTLSv12Minus ? client.getSessionToResume() : null;

        boolean fallback = client.isFallback();

        state.offeredCipherSuites = client.getCipherSuites();

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

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = (null == TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo));
            boolean noRenegSCSV = !Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noRenegSCSV)
            {
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
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

        boolean isEMS = sessionParameters.isExtendedMasterSecret();
        if (!TlsUtils.isExtendedMasterSecretOptional(sessionVersion))
        {
            if (!isEMS)
            {
                return false;
            }
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
            new ByteArrayInputStream(body), state.serverExtensions);
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

        // TODO[dtls13]
//        if (ProtocolVersion.DTLSv13.isEqualOrEarlierVersionOf(server_version))
//        {
//            process13ServerHello(serverHello, false);
//            return;
//        }

        int[] offeredCipherSuites = state.offeredCipherSuites;

        // TODO[dtls13]
//      state.clientHello = null;
//      state.retryCookie = null;
//      state.retryGroup = -1;

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
         * 
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
                if (null == TlsUtils.getExtensionData(state.clientExtensions, extType))
                {
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
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

                securityParameters.clientCertificateType = TlsUtils.processClientCertificateTypeExtension(
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
                securityParameters.serverCertificateType = TlsUtils.processServerCertificateTypeExtension(
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

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
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        TlsSecret sessionMasterSecret = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean expectSessionTicket = false;
        Hashtable clientAgreements = null;
        OfferedPsks.BindersConfig clientBinders = null;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsHeartbeat heartbeat = null;
        short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
    }
}
