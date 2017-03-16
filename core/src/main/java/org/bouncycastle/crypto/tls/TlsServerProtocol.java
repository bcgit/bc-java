package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class TlsServerProtocol
    extends TlsProtocol
{
    protected TlsServer tlsServer = null;
    TlsServerContextImpl tlsServerContext = null;

    protected TlsKeyExchange keyExchange = null;
    protected TlsCredentials serverCredentials = null;
    protected CertificateRequest certificateRequest = null;

    protected short clientCertificateType = -1;
    protected TlsHandshakeHash prepareFinishHash = null;

    /**
     * Constructor for blocking mode.
     * @param input The stream of data from the client
     * @param output The stream of data to the client
     * @param secureRandom Random number generator for various cryptographic functions
     */
    public TlsServerProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        super(input, output, secureRandom);
    }

    /**
     * Constructor for non-blocking mode.<br>
     * <br>
     * When data is received, use {@link #offerInput(java.nio.ByteBuffer)} to
     * provide the received ciphertext, then use
     * {@link #readInput(byte[], int, int)} to read the corresponding cleartext.<br>
     * <br>
     * Similarly, when data needs to be sent, use
     * {@link #offerOutput(byte[], int, int)} to provide the cleartext, then use
     * {@link #readOutput(byte[], int, int)} to get the corresponding
     * ciphertext.
     * 
     * @param secureRandom
     *            Random number generator for various cryptographic functions
     */
    public TlsServerProtocol(SecureRandom secureRandom)
    {
        super(secureRandom);
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

        this.securityParameters = new SecurityParameters();
        this.securityParameters.entity = ConnectionEnd.server;

        this.tlsServerContext = new TlsServerContextImpl(secureRandom, securityParameters);

        this.securityParameters.serverRandom = createRandomBlock(tlsServer.shouldUseGMTUnixTime(),
            tlsServerContext.getNonceRandomGenerator());

        this.tlsServer.init(tlsServerContext);
        this.recordStream.init(tlsServerContext);

        this.recordStream.setRestrictReadVersion(false);

        blockForHandshake();
    }

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

    protected void handleHandshakeMessage(short type, byte[] data)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        switch (type)
        {
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_START:
            {
                receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                sendServerHelloMessage();
                this.connection_state = CS_SERVER_HELLO;

                recordStream.notifyHelloComplete();

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null)
                {
                    sendSupplementalDataMessage(serverSupplementalData);
                }
                this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

                this.keyExchange = tlsServer.getKeyExchange();
                this.keyExchange.init(getContext());

                this.serverCredentials = tlsServer.getCredentials();

                Certificate serverCertificate = null;

                if (this.serverCredentials == null)
                {
                    this.keyExchange.skipServerCredentials();
                }
                else
                {
                    this.keyExchange.processServerCredentials(this.serverCredentials);

                    serverCertificate = this.serverCredentials.getCertificate();
                    sendCertificateMessage(serverCertificate);
                }
                this.connection_state = CS_SERVER_CERTIFICATE;

                // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                if (serverCertificate == null || serverCertificate.isEmpty())
                {
                    this.allowCertificateStatus = false;
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

                        this.keyExchange.validateCertificateRequest(certificateRequest);

                        sendCertificateRequestMessage(certificateRequest);

                        TlsUtils.trackHashAlgorithms(this.recordStream.getHandshakeHash(),
                            this.certificateRequest.getSupportedSignatureAlgorithms());
                    }
                }
                this.connection_state = CS_CERTIFICATE_REQUEST;

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;

                this.recordStream.getHandshakeHash().sealHashAlgorithms();

                break;
            }
            case CS_END:
            {
                refuseRenegotiation();
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
                    else if (TlsUtils.isSSL(getContext()))
                    {
                        if (this.peerCertificate == null)
                        {
                            throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
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
                    sendChangeCipherSpecMessage();
                }
                this.connection_state = CS_SERVER_SESSION_TICKET;

                sendFinishedMessage();
                this.connection_state = CS_SERVER_FINISHED;
                this.connection_state = CS_END;

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
        case HandshakeType.session_ticket:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleWarningMessage(short description)
        throws IOException
    {
        switch (description)
        {
        case AlertDescription.no_certificate:
        {
            /*
             * SSL 3.0 If the server has sent a certificate request Message, the client must send
             * either the certificate message or a no_certificate alert.
             */
            if (TlsUtils.isSSL(getContext()) && certificateRequest != null)
            {
                notifyClientCertificate(Certificate.EMPTY_CHAIN);
            }
            break;
        }
        default:
        {
            super.handleWarningMessage(description);
            break;
        }
        }
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {
        if (certificateRequest == null)
        {
            throw new IllegalStateException();
        }

        if (peerCertificate != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        this.peerCertificate = clientCertificate;

        if (clientCertificate.isEmpty())
        {
            this.keyExchange.skipClientCredentials();
        }
        else
        {

            /*
             * TODO RFC 5246 7.4.6. If the certificate_authorities list in the certificate request
             * message was non-empty, one of the certificates in the certificate chain SHOULD be
             * issued by one of the listed CAs.
             */

            this.clientCertificateType = TlsUtils.getClientCertificateType(clientCertificate,
                this.serverCredentials.getCertificate());

            this.keyExchange.processClientCertificate(clientCertificate);
        }

        /*
         * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        this.tlsServer.notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf)
        throws IOException
    {
        Certificate clientCertificate = Certificate.parse(buf);

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

        DigitallySigned clientCertificateVerify = DigitallySigned.parse(getContext(), buf);

        assertEmpty(buf);

        // Verify the CertificateVerify message contains a correct signature.
        try
        {
            SignatureAndHashAlgorithm signatureAlgorithm = clientCertificateVerify.getAlgorithm();

            byte[] hash;
            if (TlsUtils.isTLSv12(getContext()))
            {
                TlsUtils.verifySupportedSignatureAlgorithm(certificateRequest.getSupportedSignatureAlgorithms(), signatureAlgorithm);
                hash = prepareFinishHash.getFinalHash(signatureAlgorithm.getHash());
            }
            else
            {
                hash = securityParameters.getSessionHash();
            }

            org.bouncycastle.asn1.x509.Certificate x509Cert = peerCertificate.getCertificateAt(0);
            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);

            TlsSigner tlsSigner = TlsUtils.createTlsSigner(clientCertificateType);
            tlsSigner.init(getContext());
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

    protected void receiveClientHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
        ProtocolVersion client_version = TlsUtils.readVersion(buf);
        recordStream.setWriteVersion(client_version);

        if (client_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        byte[] client_random = TlsUtils.readFully(32, buf);

        /*
         * TODO RFC 5077 3.4. If a ticket is presented by the client, the server MUST NOT attempt to
         * use the Session ID in the ClientHello for stateful session resumption.
         */
        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * TODO RFC 5246 7.4.1.2. If the session_id field is not empty (implying a session
         * resumption request), this vector MUST include at least the cipher_suite from that
         * session.
         */
        int cipher_suites_length = TlsUtils.readUint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        this.offeredCipherSuites = TlsUtils.readUint16Array(cipher_suites_length / 2, buf);

        /*
         * TODO RFC 5246 7.4.1.2. If the session_id field is not empty (implying a session
         * resumption request), it MUST include the compression_method from that session.
         */
        int compression_methods_length = TlsUtils.readUint8(buf);
        if (compression_methods_length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        this.offeredCompressionMethods = TlsUtils.readUint8Array(compression_methods_length, buf);

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        this.clientExtensions = readExtensions(buf);

        /*
         * TODO[session-hash]
         * 
         * draft-ietf-tls-session-hash-04 4. Clients and servers SHOULD NOT accept handshakes
         * that do not use the extended master secret [..]. (and see 5.2, 5.3)
         */
        this.securityParameters.extendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientExtensions);

        getContextAdmin().setClientVersion(client_version);

        tlsServer.notifyClientVersion(client_version);
        tlsServer.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

        securityParameters.clientRandom = client_random;

        tlsServer.notifyOfferedCipherSuites(offeredCipherSuites);
        tlsServer.notifyOfferedCompressionMethods(offeredCompressionMethods);

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
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                this.secure_renegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                this.secure_renegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        tlsServer.notifySecureRenegotiation(this.secure_renegotiation);

        if (clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientExtensions);

            tlsServer.processClientExtensions(clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf)
        throws IOException
    {
        keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        this.prepareFinishHash = recordStream.prepareToFinish();
        this.securityParameters.sessionHash = getCurrentPRFHash(getContext(), prepareFinishHash, null);

        establishMasterSecret(getContext(), keyExchange);
        recordStream.setPendingConnectionState(getPeer().getCompression(), getPeer().getCipher());

        if (!expectSessionTicket)
        {
            sendChangeCipherSpecMessage();
        }
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

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        throws IOException
    {
        if (newSessionTicket == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        HandshakeMessage message = new HandshakeMessage(HandshakeType.session_ticket);

        newSessionTicket.encode(message);

        message.writeToRecordStream();
    }

    protected void sendServerHelloMessage()
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.server_hello);

        {
            ProtocolVersion server_version = tlsServer.getServerVersion();
            if (!server_version.isEqualOrEarlierVersionOf(getContext().getClientVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
    
            recordStream.setReadVersion(server_version);
            recordStream.setWriteVersion(server_version);
            recordStream.setRestrictReadVersion(true);
            getContextAdmin().setServerVersion(server_version);
    
            TlsUtils.writeVersion(server_version, message);
        }

        message.write(this.securityParameters.serverRandom);

        /*
         * The server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, message);

        int selectedCipherSuite = tlsServer.getSelectedCipherSuite();
        if (!Arrays.contains(offeredCipherSuites, selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || CipherSuite.isSCSV(selectedCipherSuite)
            || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, getContext().getServerVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        securityParameters.cipherSuite = selectedCipherSuite;

        short selectedCompressionMethod = tlsServer.getSelectedCompressionMethod();
        if (!Arrays.contains(offeredCompressionMethods, selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        securityParameters.compressionAlgorithm = selectedCompressionMethod;

        TlsUtils.writeUint16(selectedCipherSuite, message);
        TlsUtils.writeUint8(selectedCompressionMethod, message);

        this.serverExtensions = tlsServer.getServerExtensions();

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (this.secure_renegotiation)
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
                this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(serverExtensions);
                this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
            }
        }

        if (securityParameters.extendedMasterSecret)
        {
            this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(serverExtensions);
            TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
        }

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        if (this.serverExtensions != null)
        {
            this.securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            this.securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(clientExtensions,
                serverExtensions, AlertDescription.internal_error);

            this.securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

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

            writeExtensions(message, serverExtensions);
        }

        securityParameters.prfAlgorithm = getPRFAlgorithm(getContext(), securityParameters.getCipherSuite());

        /*
         * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;

        applyMaxFragmentLengthExtension();

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
        return clientCertificateType >= 0 && TlsUtils.hasSigningCapability(clientCertificateType);
    }
}
