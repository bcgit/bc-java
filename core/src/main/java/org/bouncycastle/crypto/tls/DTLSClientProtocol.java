package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class DTLSClientProtocol
    extends DTLSProtocol
{
    public DTLSClientProtocol(SecureRandom secureRandom)
    {
        super(secureRandom);
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

        SecurityParameters securityParameters = new SecurityParameters();
        securityParameters.entity = ConnectionEnd.client;

        ClientHandshakeState state = new ClientHandshakeState();
        state.client = client;
        state.clientContext = new TlsClientContextImpl(secureRandom, securityParameters);

        securityParameters.clientRandom = TlsProtocol.createRandomBlock(client.shouldUseGMTUnixTime(),
            state.clientContext.getNonceRandomGenerator());

        client.init(state.clientContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.clientContext, client, ContentType.handshake);

        TlsSession sessionToResume = state.client.getSessionToResume();
        if (sessionToResume != null && sessionToResume.isResumable())
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if (sessionParameters != null)
            {
                state.tlsSession = sessionToResume;
                state.sessionParameters = sessionParameters;
            }
        }

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
        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.clientContext, recordLayer);

        byte[] clientHelloBody = generateClientHello(state, state.client);

        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);

        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        while (serverMessage.getType() == HandshakeType.hello_verify_request)
        {
            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
            ProtocolVersion client_version = state.clientContext.getClientVersion();

            /*
             * RFC 6347 4.2.1 DTLS 1.2 server implementations SHOULD use DTLS version 1.0 regardless of
             * the version of TLS that is expected to be negotiated. DTLS 1.2 and 1.0 clients MUST use
             * the version solely to indicate packet formatting (which is the same in both DTLS 1.2 and
             * 1.0) and not as part of version negotiation.
             */
            if (!recordLayerVersion.isEqualOrEarlierVersionOf(client_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            recordLayer.setReadVersion(null);

            byte[] cookie = processHelloVerifyRequest(state, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetHandshakeMessagesDigest();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
            reportServerVersion(state, recordLayerVersion);
            recordLayer.setWriteVersion(recordLayerVersion);

            processServerHello(state, serverMessage.getBody());
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        handshake.notifyHelloComplete();

        applyMaxFragmentLengthExtension(recordLayer, securityParameters.maxFragmentLength);

        if (state.resumedSession)
        {
            securityParameters.masterSecret = Arrays.clone(state.sessionParameters.getMasterSecret());
            recordLayer.initPendingEpoch(state.client.getCipher());

            // NOTE: Calculated exclusive of the actual Finished message from the server
            byte[] expectedServerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.server_finished,
                TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
            processFinished(handshake.receiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

            // NOTE: Calculated exclusive of the Finished message itself
            byte[] clientVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.client_finished,
                TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
            handshake.sendMessage(HandshakeType.finished, clientVerifyData);

            handshake.finish();

            state.clientContext.setResumableSession(state.tlsSession);

            state.client.notifyHandshakeComplete();

            return new DTLSTransport(recordLayer);
        }

        invalidateSession(state);

        if (state.selectedSessionID.length > 0)
        {
            state.tlsSession = new TlsSessionImpl(state.selectedSessionID, null);
        }

        serverMessage = handshake.receiveMessage();

        if (serverMessage.getType() == HandshakeType.supplemental_data)
        {
            processServerSupplementalData(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            state.client.processServerSupplementalData(null);
        }

        state.keyExchange = state.client.getKeyExchange();
        state.keyExchange.init(state.clientContext);

        Certificate serverCertificate = null;

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            serverCertificate = processServerCertificate(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, Certificate is optional
            state.keyExchange.skipServerCredentials();
        }

        // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
        if (serverCertificate == null || serverCertificate.isEmpty())
        {
            state.allowCertificateStatus = false;
        }

        if (serverMessage.getType() == HandshakeType.certificate_status)
        {
            processCertificateStatus(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, CertificateStatus is optional
        }

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

            /*
             * TODO Give the client a chance to immediately select the CertificateVerify hash
             * algorithm here to avoid tracking the other hash algorithms unnecessarily?
             */
            TlsUtils.trackHashAlgorithms(handshake.getHandshakeHash(),
                state.certificateRequest.getSupportedSignatureAlgorithms());

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

        handshake.getHandshakeHash().sealHashAlgorithms();

        Vector clientSupplementalData = state.client.getClientSupplementalData();
        if (clientSupplementalData != null)
        {
            byte[] supplementalDataBody = generateSupplementalData(clientSupplementalData);
            handshake.sendMessage(HandshakeType.supplemental_data, supplementalDataBody);
        }

        if (state.certificateRequest != null)
        {
            state.clientCredentials = state.authentication.getClientCredentials(state.certificateRequest);

            /*
             * RFC 5246 If no suitable certificate is available, the client MUST send a certificate
             * message containing no certificates.
             * 
             * NOTE: In previous RFCs, this was SHOULD instead of MUST.
             */
            Certificate clientCertificate = null;
            if (state.clientCredentials != null)
            {
                clientCertificate = state.clientCredentials.getCertificate();
            }
            if (clientCertificate == null)
            {
                clientCertificate = Certificate.EMPTY_CHAIN;
            }

            byte[] certificateBody = generateCertificate(clientCertificate);
            handshake.sendMessage(HandshakeType.certificate, certificateBody);
        }

        if (state.clientCredentials != null)
        {
            state.keyExchange.processClientCredentials(state.clientCredentials);
        }
        else
        {
            state.keyExchange.skipClientCredentials();
        }

        byte[] clientKeyExchangeBody = generateClientKeyExchange(state);
        handshake.sendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

        TlsHandshakeHash prepareFinishHash = handshake.prepareToFinish();
        securityParameters.sessionHash = TlsProtocol.getCurrentPRFHash(state.clientContext, prepareFinishHash, null);

        TlsProtocol.establishMasterSecret(state.clientContext, state.keyExchange);
        recordLayer.initPendingEpoch(state.client.getCipher());

        if (state.clientCredentials != null && state.clientCredentials instanceof TlsSignerCredentials)
        {
            TlsSignerCredentials signerCredentials = (TlsSignerCredentials)state.clientCredentials;

            /*
             * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
             */
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(
                state.clientContext, signerCredentials);

            byte[] hash;
            if (signatureAndHashAlgorithm == null)
            {
                hash = securityParameters.getSessionHash();
            }
            else
            {
                hash = prepareFinishHash.getFinalHash(signatureAndHashAlgorithm.getHash());
            }

            byte[] signature = signerCredentials.generateCertificateSignature(hash);
            DigitallySigned certificateVerify = new DigitallySigned(signatureAndHashAlgorithm, signature);
            byte[] certificateVerifyBody = generateCertificateVerify(state, certificateVerify);
            handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
        }

        // NOTE: Calculated exclusive of the Finished message itself
        byte[] clientVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.client_finished,
            TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
        handshake.sendMessage(HandshakeType.finished, clientVerifyData);

        if (state.expectSessionTicket)
        {
            serverMessage = handshake.receiveMessage();
            if (serverMessage.getType() == HandshakeType.session_ticket)
            {
                processNewSessionTicket(state, serverMessage.getBody());
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        // NOTE: Calculated exclusive of the actual Finished message from the server
        byte[] expectedServerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, ExporterLabel.server_finished,
            TlsProtocol.getCurrentPRFHash(state.clientContext, handshake.getHandshakeHash(), null));
        processFinished(handshake.receiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

        handshake.finish();

        if (state.tlsSession != null)
        {
            state.sessionParameters = new SessionParameters.Builder()
                .setCipherSuite(securityParameters.getCipherSuite())
                .setCompressionAlgorithm(securityParameters.getCompressionAlgorithm())
                .setMasterSecret(securityParameters.getMasterSecret())
                .setPeerCertificate(serverCertificate)
                .setPSKIdentity(securityParameters.getPSKIdentity())
                .setSRPIdentity(securityParameters.getSRPIdentity())
                // TODO Consider filtering extensions that aren't relevant to resumed sessions
                .setServerExtensions(state.serverExtensions)
                .build();

            state.tlsSession = TlsUtils.importSession(state.tlsSession.getSessionID(), state.sessionParameters);

            state.clientContext.setResumableSession(state.tlsSession);
        }

        state.client.notifyHandshakeComplete();

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificateVerify.encode(buf);
        return buf.toByteArray();
    }

    protected byte[] generateClientHello(ClientHandshakeState state, TlsClient client)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ProtocolVersion client_version = client.getClientVersion();
        if (!client_version.isDTLS())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsClientContextImpl context = state.clientContext;

        context.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        SecurityParameters securityParameters = context.getSecurityParameters();
        buf.write(securityParameters.getClientRandom());

        // Session ID
        byte[] session_id = TlsUtils.EMPTY_BYTES;
        if (state.tlsSession != null)
        {
            session_id = state.tlsSession.getSessionID();
            if (session_id == null || session_id.length > 32)
            {
                session_id = TlsUtils.EMPTY_BYTES;
            }
        }
        TlsUtils.writeOpaque8(session_id, buf);

        // Cookie
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        boolean fallback = client.isFallback();

        /*
         * Cipher suites
         */
        state.offeredCipherSuites = client.getCipherSuites();

        // Integer -> byte[]
        state.clientExtensions = client.getClientExtensions();

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            byte[] renegExtData = TlsUtils.getExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
            boolean noRenegExt = (null == renegExtData);

            boolean noRenegSCSV = !Arrays.contains(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

            if (noRenegExt && noRenegSCSV)
            {
                // TODO Consider whether to default to a client extension instead
                state.offeredCipherSuites = Arrays.append(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            }

            /*
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

            TlsUtils.writeUint16ArrayWithUint16Length(state.offeredCipherSuites, buf);
        }

        // TODO Add support for compression
        // Compression methods
        // state.offeredCompressionMethods = client.getCompressionMethods();
        state.offeredCompressionMethods = new short[]{ CompressionMethod._null };

        TlsUtils.writeUint8ArrayWithUint8Length(state.offeredCompressionMethods, buf);

        // Extensions
        if (state.clientExtensions != null)
        {
            TlsProtocol.writeExtensions(buf, state.clientExtensions);
        }

        return buf.toByteArray();
    }

    protected byte[] generateClientKeyExchange(ClientHandshakeState state)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.keyExchange.generateClientKeyExchange(buf);
        return buf.toByteArray();
    }

    protected void invalidateSession(ClientHandshakeState state)
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

    protected void processCertificateRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        if (state.authentication == null)
        {
            /*
             * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.certificateRequest = CertificateRequest.parse(state.clientContext, buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.validateCertificateRequest(state.certificateRequest);
    }

    protected void processCertificateStatus(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        if (!state.allowCertificateStatus)
        {
            /*
             * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
             * server MUST have included an extension of type "status_request" with empty
             * "extension_data" in the extended server hello..
             */
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.certificateStatus = CertificateStatus.parse(buf);

        TlsProtocol.assertEmpty(buf);

        // TODO[RFC 3546] Figure out how to provide this to the client/authentication.
    }

    protected byte[] processHelloVerifyRequest(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        byte[] cookie = TlsUtils.readOpaque8(buf);

        TlsProtocol.assertEmpty(buf);

        // TODO Seems this behaviour is not yet in line with OpenSSL for DTLS 1.2
//        reportServerVersion(state, server_version);
        if (!server_version.isEqualOrEarlierVersionOf(state.clientContext.getClientVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        /*
         * RFC 6347 This specification increases the cookie size limit to 255 bytes for greater
         * future flexibility. The limit remains 32 for previous versions of DTLS.
         */
        if (!ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) && cookie.length > 32)
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

    protected Certificate processServerCertificate(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate serverCertificate = Certificate.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.processServerCertificate(serverCertificate);
        state.authentication = state.client.getAuthentication();
        state.authentication.notifyServerCertificate(serverCertificate);

        return serverCertificate;
    }

    protected void processServerHello(ClientHandshakeState state, byte[] body)
        throws IOException
    {
        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        {
            ProtocolVersion server_version = TlsUtils.readVersion(buf);
            reportServerVersion(state, server_version);
        }

        securityParameters.serverRandom = TlsUtils.readFully(32, buf);

        state.selectedSessionID = TlsUtils.readOpaque8(buf);
        if (state.selectedSessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySessionID(state.selectedSessionID);
        state.resumedSession = state.selectedSessionID.length > 0 && state.tlsSession != null
            && Arrays.areEqual(state.selectedSessionID, state.tlsSession.getSessionID());

        int selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!Arrays.contains(state.offeredCipherSuites, selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || CipherSuite.isSCSV(selectedCipherSuite)
            || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, state.clientContext.getServerVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        validateSelectedCipherSuite(selectedCipherSuite, AlertDescription.illegal_parameter);
        state.client.notifySelectedCipherSuite(selectedCipherSuite);

        short selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!Arrays.contains(state.offeredCompressionMethods, selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySelectedCompressionMethod(selectedCompressionMethod);

        /*
         * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in Section 2.1. ... Note that the extended server hello
         * message is only sent in response to an extended client hello message. This prevents the
         * possibility that the extended server hello message could "break" existing TLS 1.0
         * clients.
         */

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        // Integer -> byte[]
        state.serverExtensions = TlsProtocol.readExtensions(buf);

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message. However, see RFC 5746 exception below. We always include
         * the SCSV, so an Extended Server Hello is always allowed.
         */
        if (state.serverExtensions != null)
        {
            Enumeration e = state.serverExtensions.keys();
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
                if (state.resumedSession)
                {
                    // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                    // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        /*
         * RFC 5746 3.4. Client Behavior: Initial Handshake
         */
        {
            /*
             * When a ServerHello is received, the client MUST check if it includes the
             * "renegotiation_info" extension:
             */
            byte[] renegExtData = TlsUtils.getExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set the secure_renegotiation flag to TRUE. The
                 * client MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                 * handshake_failure alert).
                 */
                state.secure_renegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData,
                    TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
        state.client.notifySecureRenegotiation(state.secure_renegotiation);

        Hashtable sessionClientExtensions = state.clientExtensions, sessionServerExtensions = state.serverExtensions;
        if (state.resumedSession)
        {
            if (selectedCipherSuite != state.sessionParameters.getCipherSuite()
                || selectedCompressionMethod != state.sessionParameters.getCompressionAlgorithm())
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            sessionClientExtensions = null;
            sessionServerExtensions = state.sessionParameters.readServerExtensions();
        }

        securityParameters.cipherSuite = selectedCipherSuite;
        securityParameters.compressionAlgorithm = selectedCompressionMethod;

        if (sessionServerExtensions != null)
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

            securityParameters.extendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(sessionServerExtensions);

            securityParameters.maxFragmentLength = evaluateMaxFragmentLengthExtension(state.resumedSession,
                sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

            /*
             * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be
             * sent in a session resumption handshake.
             */
            state.allowCertificateStatus = !state.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request,
                    AlertDescription.illegal_parameter);

            state.expectSessionTicket = !state.resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.illegal_parameter);
        }

        /*
         * TODO[session-hash]
         * 
         * draft-ietf-tls-session-hash-04 4. Clients and servers SHOULD NOT accept handshakes
         * that do not use the extended master secret [..]. (and see 5.2, 5.3)
         */

        if (sessionClientExtensions != null)
        {
            state.client.processServerExtensions(sessionServerExtensions);
        }

        securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(state.clientContext,
            securityParameters.getCipherSuite());

        /*
         * RFC 5246 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;
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
        ProtocolVersion currentServerVersion = clientContext.getServerVersion();
        if (null == currentServerVersion)
        {
            clientContext.setServerVersion(server_version);
            state.client.notifyServerVersion(server_version);
        }
        else if (!currentServerVersion.equals(server_version))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
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
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length, clientHelloBody.length
            - cookiePos);

        return patched;
    }

    protected static class ClientHandshakeState
    {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        TlsSession tlsSession = null;
        SessionParameters sessionParameters = null;
        SessionParameters.Builder sessionParametersBuilder = null;
        int[] offeredCipherSuites = null;
        short[] offeredCompressionMethods = null;
        Hashtable clientExtensions = null;
        Hashtable serverExtensions = null;
        byte[] selectedSessionID = null;
        boolean resumedSession = false;
        boolean secure_renegotiation = false;
        boolean allowCertificateStatus = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateStatus certificateStatus = null;
        CertificateRequest certificateRequest = null;
        TlsCredentials clientCredentials = null;
    }
}
