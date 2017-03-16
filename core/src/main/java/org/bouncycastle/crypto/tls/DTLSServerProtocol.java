package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class DTLSServerProtocol
    extends DTLSProtocol
{
    protected boolean verifyRequests = true;

    public DTLSServerProtocol(SecureRandom secureRandom)
    {
        super(secureRandom);
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
        if (server == null)
        {
            throw new IllegalArgumentException("'server' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.entity = ConnectionEnd.server;

        ServerHandshakeState state = new ServerHandshakeState();
        state.server = server;
        state.serverContext = new TlsServerContextImpl(secureRandom, securityParameters);

        securityParameters.serverRandom = TlsProtocol.createRandomBlock(server.shouldUseGMTUnixTime(),
            state.serverContext.getNonceRandomGenerator());

        server.init(state.serverContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.serverContext, server, ContentType.handshake);

        // TODO Need to handle sending of HelloVerifyRequest without entering a full connection

        try
        {
            return serverHandshake(state, recordLayer);
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

    protected DTLSTransport serverHandshake(ServerHandshakeState state, DTLSRecordLayer recordLayer)
        throws IOException
    {
        SecurityParameters securityParameters = state.serverContext.getSecurityParameters();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.serverContext, recordLayer);

        DTLSReliableHandshake.Message clientMessage = handshake.receiveMessage();

        // NOTE: DTLSRecordLayer requires any DTLS version, we don't otherwise constrain this
//        ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();

        if (clientMessage.getType() == HandshakeType.client_hello)
        {
            processClientHello(state, clientMessage.getBody());
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        {
            byte[] serverHelloBody = generateServerHello(state);

            applyMaxFragmentLengthExtension(recordLayer, securityParameters.maxFragmentLength);

            ProtocolVersion recordLayerVersion = state.serverContext.getServerVersion();
            recordLayer.setReadVersion(recordLayerVersion);
            recordLayer.setWriteVersion(recordLayerVersion);

            handshake.sendMessage(HandshakeType.server_hello, serverHelloBody);
        }

        handshake.notifyHelloComplete();

        Vector serverSupplementalData = state.server.getServerSupplementalData();
        if (serverSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(serverSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        state.keyExchange = state.server.getKeyExchange();
        state.keyExchange.init(state.serverContext);

        state.serverCredentials = state.server.getCredentials();

        Certificate serverCertificate = null;

        if (state.serverCredentials == null)
        {
            state.keyExchange.skipServerCredentials();
        }
        else
        {
            state.keyExchange.processServerCredentials(state.serverCredentials);

            serverCertificate = state.serverCredentials.getCertificate();
            byte[] certificateBody = generateCertificate(serverCertificate);
            handshake.sendMessage(HandshakeType.certificate, certificateBody);
        }

        // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
        if (serverCertificate == null || serverCertificate.isEmpty())
        {
            state.allowCertificateStatus = false;
        }

        if (state.allowCertificateStatus)
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
            if (state.certificateRequest != null)
            {
                if (TlsUtils.isTLSv12(state.serverContext) != (state.certificateRequest.getSupportedSignatureAlgorithms() != null))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                state.keyExchange.validateCertificateRequest(state.certificateRequest);

                byte[] certificateRequestBody = generateCertificateRequest(state, state.certificateRequest);
                handshake.sendMessage(HandshakeType.certificate_request, certificateRequestBody);

                TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(),
                    state.certificateRequest.getSupportedSignatureAlgorithms());
            }
        }

        handshake.sendMessage(HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);

        handshake.getHandshakeHash().sealHashAlgorithms();

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

        TlsHandshakeHash prepareFinishHash = handshake.prepareToFinish();
        securityParameters.sessionHash = TlsProtocol.getCurrentPRFHash(state.serverContext, prepareFinishHash, null);

        TlsProtocol.establishMasterSecret(state.serverContext, state.keyExchange);
        recordLayer.initPendingEpoch(state.server.getCipher());

        /*
         * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed Diffie-Hellman
         * parameters).
         */
        if (expectCertificateVerifyMessage(state))
        {
            byte[] certificateVerifyBody = handshake.receiveMessageBody(HandshakeType.certificate_verify);
            processCertificateVerify(state, certificateVerifyBody, prepareFinishHash);
        }

        // NOTE: Calculated exclusive of the actual Finished message from the client
        byte[] expectedClientVerifyData = TlsUtils.calculateVerifyData(state.serverContext, ExporterLabel.client_finished,
            TlsProtocol.getCurrentPRFHash(state.serverContext, handshake.getHandshakeHash(), null));
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), expectedClientVerifyData);

        if (state.expectSessionTicket)
        {
            NewSessionTicket newSessionTicket = state.server.getNewSessionTicket();
            byte[] newSessionTicketBody = generateNewSessionTicket(state, newSessionTicket);
            handshake.sendMessage(HandshakeType.session_ticket, newSessionTicketBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        byte[] serverVerifyData = TlsUtils.calculateVerifyData(state.serverContext, ExporterLabel.server_finished,
            TlsProtocol.getCurrentPRFHash(state.serverContext, handshake.getHandshakeHash(), null));
        handshake.sendMessage(HandshakeType.finished, serverVerifyData);

        handshake.finish();

        state.server.notifyHandshakeComplete();

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateRequest(ServerHandshakeState state, CertificateRequest certificateRequest)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateRequest.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateCertificateStatus(ServerHandshakeState state, CertificateStatus certificateStatus)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
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
        SecurityParameters securityParameters = state.serverContext.getSecurityParameters();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        {
            ProtocolVersion server_version = state.server.getServerVersion();
            if (!server_version.isEqualOrEarlierVersionOf(state.serverContext.getClientVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
    
            // TODO Read RFCs for guidance on the expected record layer version number
            // recordStream.setReadVersion(server_version);
            // recordStream.setWriteVersion(server_version);
            // recordStream.setRestrictReadVersion(true);
            state.serverContext.setServerVersion(server_version);
    
            TlsUtils.writeVersion(state.serverContext.getServerVersion(), buf);
        }

        buf.write(securityParameters.getServerRandom());

        /*
         * The server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        int selectedCipherSuite = state.server.getSelectedCipherSuite();
        if (!Arrays.contains(state.offeredCipherSuites, selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || CipherSuite.isSCSV(selectedCipherSuite)
            || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, state.serverContext.getServerVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        validateSelectedCipherSuite(selectedCipherSuite, AlertDescription.internal_error);
        securityParameters.cipherSuite = selectedCipherSuite;

        short selectedCompressionMethod = state.server.getSelectedCompressionMethod();
        if (!Arrays.contains(state.offeredCompressionMethods, selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        securityParameters.compressionAlgorithm = selectedCompressionMethod;

        TlsUtils.writeUint16(selectedCipherSuite, buf);
        TlsUtils.writeUint8(selectedCompressionMethod, buf);

        state.serverExtensions = state.server.getServerExtensions();

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (state.secure_renegotiation)
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
                state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.serverExtensions);
                state.serverExtensions.put(TlsProtocol.EXT_RenegotiationInfo,
                    TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }

        if (securityParameters.extendedMasterSecret)
        {
            state.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(state.serverExtensions);
            TlsExtensionsUtils.addExtendedMasterSecretExtension(state.serverExtensions);
        }

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        if (state.serverExtensions != null)
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(state.serverExtensions);

            securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.resumedSession,
                state.clientExtensions, state.serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(state.serverExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
             * a session resumption handshake.
             */
            state.allowCertificateStatus = !state.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.internal_error);

            state.expectSessionTicket = !state.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(state.serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);

            TlsProtocol.writeExtensions(buf, state.serverExtensions);
        }

        securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(state.serverContext,
            securityParameters.getCipherSuite());

        /*
         * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length
         * has a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;

        return buf.toByteArray();
    }

    protected void invalidateSession(ServerHandshakeState state)
    {
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
        if (state.certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        if (state.clientCertificate != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        state.clientCertificate = clientCertificate;

        if (clientCertificate.isEmpty())
        {
            state.keyExchange.skipClientCredentials();
        }
        else
        {

            /*
             * TODO RFC 5246 7.4.6. If the certificate_authorities list in the certificate request
             * message was non-empty, one of the certificates in the certificate chain SHOULD be
             * issued by one of the listed CAs.
             */

            state.clientCertificateType = TlsUtils.getClientCertificateType(clientCertificate,
                state.serverCredentials.getCertificate());

            state.keyExchange.processClientCertificate(clientCertificate);
        }

        /*
         * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        state.server.notifyClientCertificate(clientCertificate);
    }

    protected void processClientCertificate(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate clientCertificate = Certificate.parse(buf);

        TlsProtocol.assertEmpty(buf);

        notifyClientCertificate(state, clientCertificate);
    }

    protected void processCertificateVerify(ServerHandshakeState state, byte[] body, TlsHandshakeHash prepareFinishHash)
        throws IOException
    {
        if (state.certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        TlsServerContextImpl context = state.serverContext;
        DigitallySigned clientCertificateVerify = DigitallySigned.parse(context, buf);

        TlsProtocol.assertEmpty(buf);

        // Verify the CertificateVerify message contains a correct signature.
        try
        {
            SignatureAndHashAlgorithm signatureAlgorithm = clientCertificateVerify.getAlgorithm();

            byte[] hash;
            if (TlsUtils.isTLSv12(context))
            {
                TlsUtils.verifySupportedSignatureAlgorithm(state.certificateRequest.getSupportedSignatureAlgorithms(), signatureAlgorithm);
                hash = prepareFinishHash.getFinalHash(signatureAlgorithm.getHash());
            }
            else
            {
                hash = context.getSecurityParameters().getSessionHash();
            }

            org.bouncycastle.asn1.x509.Certificate x509Cert = state.clientCertificate.getCertificateAt(0);
            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);

            TlsSigner tlsSigner = TlsUtils.createTlsSigner(state.clientCertificateType);
            tlsSigner.init(context);
            if (!tlsSigner.verifyRawSignature(signatureAlgorithm, clientCertificateVerify.getSignature(), publicKey, hash))
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
        }
    }

    protected void processClientHello(ServerHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        // TODO Read RFCs for guidance on the expected record layer version number
        ProtocolVersion client_version = TlsUtils.readVersion(buf);
        if (!client_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * Read the client random
         */
        byte[] client_random = TlsUtils.readFully(32, buf);

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        // TODO RFC 4347 has the cookie length restricted to 32, but not in RFC 6347
        byte[] cookie = TlsUtils.readOpaque8(buf);

        int cipher_suites_length = TlsUtils.readUint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        /*
         * NOTE: "If the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        state.offeredCipherSuites = TlsUtils.readUint16Array(cipher_suites_length / 2, buf);

        int compression_methods_length = TlsUtils.readUint8(buf);
        if (compression_methods_length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        state.offeredCompressionMethods = TlsUtils.readUint8Array(compression_methods_length, buf);

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        state.clientExtensions = TlsProtocol.readExtensions(buf);

        TlsServerContextImpl context = state.serverContext;
        SecurityParameters securityParameters = context.getSecurityParameters();

        /*
         * TODO[session-hash]
         * 
         * draft-ietf-tls-session-hash-04 4. Clients and servers SHOULD NOT accept handshakes
         * that do not use the extended master secret [..]. (and see 5.2, 5.3)
         */
        securityParameters.extendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(state.clientExtensions);

        context.setClientVersion(client_version);

        state.server.notifyClientVersion(client_version);
        state.server.notifyFallback(Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        securityParameters.clientRandom = client_random;

        state.server.notifyOfferedCipherSuites(state.offeredCipherSuites);
        state.server.notifyOfferedCompressionMethods(state.offeredCompressionMethods);

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
                state.secure_renegotiation = true;
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
                state.secure_renegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        state.server.notifySecureRenegotiation(state.secure_renegotiation);

        if (state.clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(state.clientExtensions);

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
        return state.clientCertificateType >= 0 && TlsUtils.hasSigningCapability(state.clientCertificateType);
    }

    protected static class ServerHandshakeState
    {
        TlsServer server = null;
        TlsServerContextImpl serverContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        short[] offeredCompressionMethods = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        boolean resumedSession = false;
        boolean secure_renegotiation = false;
        boolean allowCertificateStatus = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsCredentials serverCredentials = null;
        CertificateRequest certificateRequest = null;
        short clientCertificateType = -1;
        Certificate clientCertificate = null;
    }
}
