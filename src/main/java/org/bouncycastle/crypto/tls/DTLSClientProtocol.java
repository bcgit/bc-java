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
        securityParameters.clientRandom = TlsProtocol.createRandomBlock(secureRandom);

        ClientHandshakeState state = new ClientHandshakeState();
        state.client = client;
        state.clientContext = new TlsClientContextImpl(secureRandom, securityParameters);
        client.init(state.clientContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.clientContext, client, ContentType.handshake);

        try
        {
            return clientHandshake(state, recordLayer);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected DTLSTransport clientHandshake(ClientHandshakeState state, DTLSRecordLayer recordLayer)
        throws IOException
    {

        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.clientContext, recordLayer);

        byte[] clientHelloBody = generateClientHello(state, state.client);
        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        {
            // NOTE: After receiving a record from the server, we discover the record layer version
            ProtocolVersion server_version = recordLayer.getDiscoveredPeerVersion();
            ProtocolVersion client_version = state.clientContext.getClientVersion();

            if (!server_version.isEqualOrEarlierVersionOf(client_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            state.clientContext.setServerVersion(server_version);
            state.client.notifyServerVersion(server_version);
        }

        while (serverMessage.getType() == HandshakeType.hello_verify_request)
        {
            byte[] cookie = parseHelloVerifyRequest(state.clientContext, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetHandshakeMessagesDigest();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() == HandshakeType.server_hello)
        {
            processServerHello(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        securityParameters.prfAlgorithm = TlsProtocol.getPRFAlgorithm(state.selectedCipherSuite);
        securityParameters.compressionAlgorithm = state.selectedCompressionMethod;

        /*
         * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. This includes all existing cipher suites.
         */
        securityParameters.verifyDataLength = 12;

        handshake.notifyHelloComplete();

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

        if (serverMessage.getType() == HandshakeType.certificate)
        {
            processServerCertificate(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        }
        else
        {
            // Okay, Certificate is optional
            state.keyExchange.skipServerCredentials();
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

        TlsProtocol.establishMasterSecret(state.clientContext, state.keyExchange);

        if (state.clientCredentials instanceof TlsSignerCredentials)
        {
            /*
             * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm prepended
             * from TLS 1.2
             */
            TlsSignerCredentials signerCredentials = (TlsSignerCredentials)state.clientCredentials;
            byte[] md5andsha1 = handshake.getCurrentHash();
            byte[] signature = signerCredentials.generateCertificateSignature(md5andsha1);
            byte[] certificateVerifyBody = generateCertificateVerify(state, signature);
            handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
        }

        recordLayer.initPendingEpoch(state.client.getCipher());

        // NOTE: Calculated exclusive of the Finished message itself
        byte[] clientVerifyData = TlsUtils.calculateVerifyData(state.clientContext, "client finished",
            handshake.getCurrentHash());
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
        byte[] expectedServerVerifyData = TlsUtils.calculateVerifyData(state.clientContext, "server finished",
            handshake.getCurrentHash());
        serverMessage = handshake.receiveMessage();

        if (serverMessage.getType() == HandshakeType.finished)
        {
            processFinished(serverMessage.getBody(), expectedServerVerifyData);
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        handshake.finish();

        state.client.notifyHandshakeComplete();

        return new DTLSTransport(recordLayer);
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, byte[] signature)
        throws IOException
    {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeOpaque16(signature, buf);
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

        state.clientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(state.clientContext.getSecurityParameters().getClientRandom());

        // Session id
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

        // Cookie
        TlsUtils.writeOpaque8(TlsUtils.EMPTY_BYTES, buf);

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
            boolean noRenegExt = state.clientExtensions == null
                || state.clientExtensions.get(TlsProtocol.EXT_RenegotiationInfo) == null;

            int count = state.offeredCipherSuites.length;
            if (noRenegExt)
            {
                // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ++count;
            }

            TlsUtils.writeUint16(2 * count, buf);
            TlsUtils.writeUint16Array(state.offeredCipherSuites, buf);

            if (noRenegExt)
            {
                TlsUtils.writeUint16(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, buf);
            }
        }

        // TODO Add support for compression
        // Compression methods
        // state.offeredCompressionMethods = client.getCompressionMethods();
        state.offeredCompressionMethods = new short[]{CompressionMethod._null};

        TlsUtils.writeUint8((short)state.offeredCompressionMethods.length, buf);
        TlsUtils.writeUint8Array(state.offeredCompressionMethods, buf);

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

        state.certificateRequest = CertificateRequest.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.validateCertificateRequest(state.certificateRequest);
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

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate serverCertificate = Certificate.parse(buf);

        TlsProtocol.assertEmpty(buf);

        state.keyExchange.processServerCertificate(serverCertificate);
        state.authentication = state.client.getAuthentication();
        state.authentication.notifyServerCertificate(serverCertificate);
    }

    protected void processServerHello(ClientHandshakeState state, byte[] body)
        throws IOException
    {

        SecurityParameters securityParameters = state.clientContext.getSecurityParameters();

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        // TODO Read RFCs for guidance on the expected record layer version number
        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (!server_version.equals(state.clientContext.getServerVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        securityParameters.serverRandom = TlsUtils.readFully(32, buf);

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySessionID(sessionID);

        state.selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!TlsProtocol.arrayContains(state.offeredCipherSuites, state.selectedCipherSuite)
            || state.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
            || state.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        validateSelectedCipherSuite(state.selectedCipherSuite, AlertDescription.illegal_parameter);

        state.client.notifySelectedCipherSuite(state.selectedCipherSuite);

        state.selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!TlsProtocol.arrayContains(state.offeredCompressionMethods, state.selectedCompressionMethod))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        state.client.notifySelectedCompressionMethod(state.selectedCompressionMethod);

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
        Hashtable serverExtensions = TlsProtocol.readExtensions(buf);

        /*
         * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
         * extended client hello message. However, see RFC 5746 exception below. We always include
         * the SCSV, so an Extended Server Hello is always allowed.
         */
        if (serverExtensions != null)
        {
            Enumeration e = serverExtensions.keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();

                /*
                 * RFC 5746 Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. TLS implementations
                 * MUST continue to comply with Section 7.4.1.4 for all other extensions.
                 */
                if (!extType.equals(TlsProtocol.EXT_RenegotiationInfo)
                    && (state.clientExtensions == null || state.clientExtensions.get(extType) == null))
                {
                    /*
                     * RFC 3546 2.3 Note that for all extension types (including those defined in
                     * future), the extension type MUST NOT appear in the extended server hello
                     * unless the same extension type appeared in the corresponding client hello.
                     * Thus clients MUST abort the handshake if they receive an extension type in
                     * the extended server hello that they did not request in the associated
                     * (extended) client hello.
                     */
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);
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
                byte[] renegExtValue = (byte[])serverExtensions.get(TlsProtocol.EXT_RenegotiationInfo);
                if (renegExtValue != null)
                {
                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    state.secure_renegotiation = true;

                    if (!Arrays.constantTimeAreEqual(renegExtValue,
                        TlsProtocol.createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            state.expectSessionTicket = serverExtensions.containsKey(TlsProtocol.EXT_SessionTicket);
        }

        state.client.notifySecureRenegotiation(state.secure_renegotiation);

        if (state.clientExtensions != null)
        {
            state.client.processServerExtensions(serverExtensions);
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

    protected static byte[] parseHelloVerifyRequest(TlsContext context, byte[] body)
        throws IOException
    {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (!server_version.equals(context.getServerVersion()))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        byte[] cookie = TlsUtils.readOpaque8(buf);

        // TODO RFC 4347 has the cookie length restricted to 32, but not in RFC 6347

        TlsProtocol.assertEmpty(buf);

        return cookie;
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
        TlsUtils.writeUint8((short)cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length, clientHelloBody.length
            - cookiePos);

        return patched;
    }

    protected static class ClientHandshakeState
    {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        int[] offeredCipherSuites = null;
        short[] offeredCompressionMethods = null;
        Hashtable clientExtensions = null;
        int selectedCipherSuite = -1;
        short selectedCompressionMethod = -1;
        boolean secure_renegotiation = false;
        boolean expectSessionTicket = false;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateRequest certificateRequest = null;
        TlsCredentials clientCredentials = null;
    }
}
