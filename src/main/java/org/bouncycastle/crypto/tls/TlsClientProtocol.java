package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.util.Arrays;

public class TlsClientProtocol
    extends TlsProtocol
{

    protected TlsClient tlsClient = null;
    protected TlsClientContextImpl tlsClientContext = null;

    protected int[] offeredCipherSuites = null;
    protected short[] offeredCompressionMethods = null;
    protected Hashtable clientExtensions = null;

    protected int selectedCipherSuite;
    protected short selectedCompressionMethod;

    protected TlsKeyExchange keyExchange = null;
    protected TlsAuthentication authentication = null;
    protected CertificateRequest certificateRequest = null;

    private static SecureRandom createSecureRandom()
    {
        /*
         * We use our threaded seed generator to generate a good random seed. If the user has a
         * better random seed, he should use the constructor with a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        SecureRandom random = new SecureRandom();

        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        random.setSeed(tsg.generateSeed(20, true));

        return random;
    }

    public TlsClientProtocol(InputStream input, OutputStream output)
    {
        this(input, output, createSecureRandom());
    }

    public TlsClientProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        super(input, output, secureRandom);
    }

    /**
     * Initiates a TLS handshake in the role of client
     *
     * @param tlsClient
     * @throws IOException If handshake was not successful.
     */
    public void connect(TlsClient tlsClient)
        throws IOException
    {
        if (tlsClient == null)
        {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        }
        if (this.tlsClient != null)
        {
            throw new IllegalStateException("connect can only be called once");
        }

        this.tlsClient = tlsClient;

        this.securityParameters = new SecurityParameters();
        this.securityParameters.entity = ConnectionEnd.client;
        this.securityParameters.clientRandom = createRandomBlock(secureRandom);

        this.tlsClientContext = new TlsClientContextImpl(secureRandom, securityParameters);
        this.tlsClient.init(tlsClientContext);
        this.recordStream.init(tlsClientContext);

        sendClientHelloMessage();
        this.connection_state = CS_CLIENT_HELLO;

        completeHandshake();

        this.tlsClient.notifyHandshakeComplete();
    }

    protected AbstractTlsContext getContext()
    {
        return tlsClientContext;
    }

    protected TlsPeer getPeer()
    {
        return tlsClient;
    }

    protected void handleChangeCipherSpecMessage()
        throws IOException
    {

        switch (this.connection_state)
        {
        case CS_CLIENT_FINISHED:
        {
            if (this.expectSessionTicket)
            {
                /*
                 * RFC 5077 3.3. This message MUST be sent if the server included a SessionTicket
                 * extension in the ServerHello.
                 */
                this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
            }
            // NB: Fall through to next case label
        }
        case CS_SERVER_SESSION_TICKET:
            this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC;
            break;
        default:
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
    }

    protected void handleHandshakeMessage(short type, byte[] data)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(data);

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
                // Parse the Certificate message and send to cipher suite

                Certificate serverCertificate = Certificate.parse(buf);

                assertEmpty(buf);

                this.keyExchange.processServerCertificate(serverCertificate);

                this.authentication = tlsClient.getAuthentication();
                this.authentication.notifyServerCertificate(serverCertificate);

                break;
            }
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_CERTIFICATE;
            break;
        }
        case HandshakeType.finished:
            switch (this.connection_state)
            {
            case CS_SERVER_CHANGE_CIPHER_SPEC:
                processFinishedMessage(buf);
                this.connection_state = CS_SERVER_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        case HandshakeType.server_hello:
            switch (this.connection_state)
            {
            case CS_CLIENT_HELLO:
                receiveServerHelloMessage(buf);
                this.connection_state = CS_SERVER_HELLO;

                securityParameters.prfAlgorithm = getPRFAlgorithm(selectedCipherSuite);
                securityParameters.compressionAlgorithm = this.selectedCompressionMethod;

                /*
                 * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify
                 * verify_data_length has a verify_data_length equal to 12. This includes all
                 * existing cipher suites.
                 */
                securityParameters.verifyDataLength = 12;

                recordStream.notifyHelloComplete();

                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        case HandshakeType.supplemental_data:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
                handleSupplementalData(readSupplementalDataMessage(buf));
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.server_hello_done:
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO:
            {
                handleSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_SERVER_SUPPLEMENTAL_DATA:
            {

                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCredentials();
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label

            case CS_SERVER_KEY_EXCHANGE:
            case CS_CERTIFICATE_REQUEST:

                assertEmpty(buf);

                this.connection_state = CS_SERVER_HELLO_DONE;

                Vector clientSupplementalData = tlsClient.getClientSupplementalData();
                if (clientSupplementalData != null)
                {
                    sendSupplementalDataMessage(clientSupplementalData);
                }
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;

                TlsCredentials clientCreds = null;
                if (certificateRequest == null)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else
                {
                    clientCreds = this.authentication.getClientCredentials(certificateRequest);

                    if (clientCreds == null)
                    {
                        this.keyExchange.skipClientCredentials();

                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                        sendCertificateMessage(Certificate.EMPTY_CHAIN);
                    }
                    else
                    {
                        this.keyExchange.processClientCredentials(clientCreds);

                        sendCertificateMessage(clientCreds.getCertificate());
                    }
                }

                this.connection_state = CS_CLIENT_CERTIFICATE;

                /*
                 * Send the client key exchange message, depending on the key exchange we are using
                 * in our CipherSuite.
                 */
                sendClientKeyExchangeMessage();

                establishMasterSecret(getContext(), keyExchange);

                /*
                 * Initialize our cipher suite
                 */
                recordStream.setPendingConnectionState(tlsClient.getCompression(), tlsClient.getCipher());

                this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                if (clientCreds != null && clientCreds instanceof TlsSignerCredentials)
                {
                    /*
                     * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm
                     * prepended from TLS 1.2
                     */
                    TlsSignerCredentials signerCreds = (TlsSignerCredentials)clientCreds;
                    byte[] md5andsha1 = recordStream.getCurrentHash(null);
                    byte[] clientCertificateSignature = signerCreds.generateCertificateSignature(md5andsha1);
                    sendCertificateVerifyMessage(clientCertificateSignature);

                    this.connection_state = CS_CERTIFICATE_VERIFY;
                }

                sendChangeCipherSpecMessage();
                this.connection_state = CS_CLIENT_CHANGE_CIPHER_SPEC;

                sendFinishedMessage();
                this.connection_state = CS_CLIENT_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
            }
            break;
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

                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCredentials();
                this.authentication = null;

                // NB: Fall through to next case label
            }
            case CS_SERVER_CERTIFICATE:

                this.keyExchange.processServerKeyExchange(buf);

                assertEmpty(buf);
                break;

            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_KEY_EXCHANGE;
            break;
        }
        case HandshakeType.certificate_request:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_CERTIFICATE:

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label

            case CS_SERVER_KEY_EXCHANGE:
            {
                if (this.authentication == null)
                {
                    /*
                     * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
                     * to request client identification.
                     */
                    this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                }

                this.certificateRequest = CertificateRequest.parse(buf);

                assertEmpty(buf);

                this.keyExchange.validateCertificateRequest(this.certificateRequest);

                break;
            }
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_CERTIFICATE_REQUEST;
            break;
        }
        case HandshakeType.session_ticket:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_FINISHED:
                if (!this.expectSessionTicket)
                {
                    /*
                     * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
                     * SessionTicket extension in the ServerHello.
                     */
                    this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                }
                receiveNewSessionTicketMessage(buf);
                this.connection_state = CS_SERVER_SESSION_TICKET;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
        }
        case HandshakeType.hello_request:

            assertEmpty(buf);

            /*
             * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
             * client is currently negotiating a session. This message may be ignored by the client
             * if it does not wish to renegotiate a session, or the client may, if it wishes,
             * respond with a no_renegotiation alert.
             */
            if (this.connection_state == CS_SERVER_FINISHED)
            {
                String message = "Renegotiation not supported";
                raiseWarning(AlertDescription.no_renegotiation, message);
            }
            break;
        case HandshakeType.client_key_exchange:
        case HandshakeType.certificate_verify:
        case HandshakeType.client_hello:
        case HandshakeType.hello_verify_request:
        default:
            // We do not support this!
            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            break;
        }
    }

    protected void handleSupplementalData(Vector serverSupplementalData)
        throws IOException
    {

        this.tlsClient.processServerSupplementalData(serverSupplementalData);
        this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

        this.keyExchange = tlsClient.getKeyExchange();
        this.keyExchange.init(getContext());
    }

    protected void receiveNewSessionTicketMessage(ByteArrayInputStream buf)
        throws IOException
    {

        NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

        TlsProtocol.assertEmpty(buf);

        tlsClient.notifyNewSessionTicket(newSessionTicket);
    }

    protected void receiveServerHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (server_version.isDTLS())
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        // Check that this matches what the server is sending in the record layer
        if (!server_version.equals(recordStream.getReadVersion()))
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        ProtocolVersion client_version = getContext().getClientVersion();
        if (!server_version.isEqualOrEarlierVersionOf(client_version))
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        this.recordStream.setWriteVersion(server_version);
        getContext().setServerVersion(server_version);
        this.tlsClient.notifyServerVersion(server_version);

        /*
         * Read the server random
         */
        securityParameters.serverRandom = TlsUtils.readFully(32, buf);

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySessionID(sessionID);

        /*
         * Find out which CipherSuite the server has chosen and check that it was one of the offered
         * ones.
         */
        this.selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!arrayContains(offeredCipherSuites, this.selectedCipherSuite)
            || this.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || this.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySelectedCipherSuite(this.selectedCipherSuite);

        /*
         * Find out which CompressionMethod the server has chosen and check that it was one of the
         * offered ones.
         */
        short selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!arrayContains(offeredCompressionMethods, selectedCompressionMethod))
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        this.tlsClient.notifySelectedCompressionMethod(selectedCompressionMethod);

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
        Hashtable serverExtensions = readExtensions(buf);

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message.
         * 
         * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
         * Hello is always allowed.
         */
        if (serverExtensions != null)
        {
            Enumeration e = serverExtensions.keys();
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
                if (!extType.equals(EXT_RenegotiationInfo)
                    && (clientExtensions == null || clientExtensions.get(extType) == null))
                {
                    /*
                     * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless
                     * the same extension type appeared in the corresponding ClientHello. If a
                     * client receives an extension type in ServerHello that it did not request in
                     * the associated ClientHello, it MUST abort the handshake with an
                     * unsupported_extension fatal alert.
                     */
                    this.failWithError(AlertLevel.fatal, AlertDescription.unsupported_extension);
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
                byte[] renegExtValue = (byte[])serverExtensions.get(EXT_RenegotiationInfo);
                if (renegExtValue != null)
                {
                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    this.secure_renegotiation = true;

                    if (!Arrays.constantTimeAreEqual(renegExtValue, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                    {
                        this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                    }
                }
            }

            this.expectSessionTicket = serverExtensions.containsKey(EXT_SessionTicket);
        }

        tlsClient.notifySecureRenegotiation(this.secure_renegotiation);

        if (clientExtensions != null)
        {
            tlsClient.processServerExtensions(serverExtensions);
        }
    }

    protected void sendCertificateVerifyMessage(byte[] data)
        throws IOException
    {
        /*
         * Send signature of handshake messages so far to prove we are the owner of the cert See RFC
         * 2246 sections 4.7, 7.4.3 and 7.4.8
         */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.certificate_verify, bos);
        TlsUtils.writeUint24(data.length + 2, bos);
        TlsUtils.writeOpaque16(data, bos);
        byte[] message = bos.toByteArray();

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendClientHelloMessage()
        throws IOException
    {

        recordStream.setWriteVersion(this.tlsClient.getClientHelloRecordLayerVersion());

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.client_hello, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        ProtocolVersion client_version = this.tlsClient.getClientVersion();
        if (client_version.isDTLS())
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        getContext().setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(securityParameters.clientRandom);

        // Session id
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        /*
         * Cipher suites
         */
        this.offeredCipherSuites = this.tlsClient.getCipherSuites();

        // Integer -> byte[]
        this.clientExtensions = this.tlsClient.getClientExtensions();

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = clientExtensions == null || clientExtensions.get(EXT_RenegotiationInfo) == null;

            int count = offeredCipherSuites.length;
            if (noRenegExt)
            {
                // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ++count;
            }

            TlsUtils.writeUint16(2 * count, buf);
            TlsUtils.writeUint16Array(offeredCipherSuites, buf);

            if (noRenegExt)
            {
                TlsUtils.writeUint16(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, buf);
            }
        }

        // Compression methods
        this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();

        TlsUtils.writeUint8((short)offeredCompressionMethods.length, buf);
        TlsUtils.writeUint8Array(offeredCompressionMethods, buf);

        // Extensions
        if (clientExtensions != null)
        {
            writeExtensions(buf, clientExtensions);
        }

        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendClientKeyExchangeMessage()
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        TlsUtils.writeUint8(HandshakeType.client_key_exchange, bos);

        // Reserve space for length
        TlsUtils.writeUint24(0, bos);

        this.keyExchange.generateClientKeyExchange(bos);
        byte[] message = bos.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }
}
