package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class DTLSProtocolHandler {

    private static final Integer EXT_RenegotiationInfo = Integers
        .valueOf(ExtensionType.renegotiation_info);

    private static final byte[] EMPTY_BYTES = new byte[0];

    private final SecureRandom secureRandom;

    public DTLSProtocolHandler(SecureRandom secureRandom) {

        if (secureRandom == null)
            throw new IllegalArgumentException("'secureRandom' cannot be null");

        this.secureRandom = secureRandom;
    }

    public DTLSTransport connect(TlsClient client, DatagramTransport transport) throws IOException {

        if (client == null)
            throw new IllegalArgumentException("'client' cannot be null");
        if (transport == null)
            throw new IllegalArgumentException("'transport' cannot be null");

        HandshakeState state = new HandshakeState();
        state.client = client;
        state.clientContext = createClientContext();

        client.init(state.clientContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.clientContext,
            ContentType.handshake);
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(recordLayer);

        byte[] clientHelloBody = generateClientHello(state, client);
        handshake.sendMessage(HandshakeType.client_hello, clientHelloBody);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        // NOTE: After receiving a record from the server, we discover the version it chose
        ProtocolVersion server_version = recordLayer.getDiscoveredServerVersion();
        ProtocolVersion client_version = state.clientContext.getClientVersion();

        if (server_version.getFullVersion() < client_version.getFullVersion()) {
            // TODO Alert
        }

        state.clientContext.setServerVersion(server_version);
        client.notifyServerVersion(server_version);

        if (serverMessage.getType() == HandshakeType.hello_verify_request) {
            byte[] cookie = parseHelloVerifyRequest(state.clientContext, serverMessage.getBody());
            byte[] patched = patchClientHelloWithCookie(clientHelloBody, cookie);

            handshake.resetHash();
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        } else {
            // Okay, HelloVerifyRequest is optional
        }

        if (serverMessage.getType() == HandshakeType.server_hello) {
            processServerHello(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        } else {
            // TODO Alert
        }

        if (serverMessage.getType() == HandshakeType.certificate) {
            processCertificate(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        } else {
            // Okay, Certificate is optional
            state.keyExchange.skipServerCertificate();
        }

        if (serverMessage.getType() == HandshakeType.server_key_exchange) {
            processServerKeyExchange(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        } else {
            // Okay, ServerKeyExchange is optional
            state.keyExchange.skipServerKeyExchange();
        }

        if (serverMessage.getType() == HandshakeType.certificate_request) {
            processCertificateRequest(state, serverMessage.getBody());
            serverMessage = handshake.receiveMessage();
        } else {
            // Okay, CertificateRequest is optional
        }

        if (serverMessage.getType() == HandshakeType.server_hello_done) {
            if (serverMessage.getBody().length != 0) {
                // TODO Alert
            }
        } else {
            // TODO Alert
        }

        if (state.certificateRequest != null) {
            state.clientCredentials = state.authentication
                .getClientCredentials(state.certificateRequest);

            Certificate clientCertificate = Certificate.EMPTY_CHAIN;
            if (state.clientCredentials != null) {
                clientCertificate = state.clientCredentials.getCertificate();
            }

            byte[] certificateBody = generateCertificate(clientCertificate);
            handshake.sendMessage(HandshakeType.certificate, certificateBody);
        }

        if (state.clientCredentials != null) {
            state.keyExchange.processClientCredentials(state.clientCredentials);
        } else {
            state.keyExchange.skipClientCredentials();
        }

        byte[] clientKeyExchangeBody = generateClientKeyExchange(state);
        handshake.sendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

        // Calculate the master_secret
        {
            byte[] pms = state.keyExchange.generatePremasterSecret();

            try {
                state.clientContext.getSecurityParameters().masterSecret = TlsUtils
                    .calculateMasterSecret(state.clientContext, pms);
            } finally {
                // TODO Is there a way to ensure the data is really overwritten?
                if (pms != null) {
                    Arrays.fill(pms, (byte) 0);
                }
            }
        }

        if (state.clientCredentials instanceof TlsSignerCredentials) {
            TlsSignerCredentials signerCredentials = (TlsSignerCredentials) state.clientCredentials;

            byte[] md5andsha1 = handshake.getCurrentHash();
            byte[] signature = signerCredentials.generateCertificateSignature(md5andsha1);

            byte[] certificateVerifyBody = generateCertificateVerify(state, signature);
            handshake.sendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
        }

        // TODO Change cipher state

        // TODO Send Finished message

        handshake.finish();

        // TODO Needs to be attached to the record layer using ContentType.application_data
        return new DTLSTransport(recordLayer);
    }

    private void assertEmpty(ByteArrayInputStream is) throws IOException {
        if (is.available() > 0) {
            // throw new TlsFatalAlert(AlertDescription.decode_error);
            // TODO ALert
        }
    }

    private TlsClientContextImpl createClientContext() {
        SecurityParameters securityParameters = new SecurityParameters();

        securityParameters.clientRandom = new byte[32];
        secureRandom.nextBytes(securityParameters.clientRandom);
        TlsUtils.writeGMTUnixTime(securityParameters.clientRandom, 0);

        return new TlsClientContextImpl(secureRandom, securityParameters);
    }

    private byte[] generateCertificate(Certificate clientCertificate) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        clientCertificate.encode(buf);
        return buf.toByteArray();
    }

    private byte[] generateCertificateVerify(HandshakeState state, byte[] signature)
        throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeOpaque16(signature, buf);
        return buf.toByteArray();
    }

    private byte[] generateClientHello(HandshakeState state, TlsClient client) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ProtocolVersion client_version = client.getClientVersion();
        if (!client_version.isDTLS()) {
            // TODO Alert
        }

        state.clientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(state.clientContext.getSecurityParameters().getClientRandom());

        // Length of Session id
        TlsUtils.writeUint8((short) 0, buf);

        // Length of cookie
        TlsUtils.writeUint8((short) 0, buf);

        /*
         * Cipher suites
         */
        state.offeredCipherSuites = client.getCipherSuites();

        for (int cipherSuite : state.offeredCipherSuites) {
            switch (cipherSuite) {
            case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
            case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
            case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
            case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
                // TODO Alert
                throw new IllegalStateException(
                    "Client offered an RC4 cipher suite: RC4 MUST NOT be used with DTLS");
            }
        }

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
                || state.clientExtensions.get(EXT_RenegotiationInfo) == null;

            int count = state.offeredCipherSuites.length;
            if (noRenegExt) {
                // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ++count;
            }

            TlsUtils.writeUint16(2 * count, buf);
            TlsUtils.writeUint16Array(state.offeredCipherSuites, buf);

            if (noRenegExt) {
                TlsUtils.writeUint16(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, buf);
            }
        }

        // Compression methods
        state.offeredCompressionMethods = client.getCompressionMethods();

        TlsUtils.writeUint8((short) state.offeredCompressionMethods.length, buf);
        TlsUtils.writeUint8Array(state.offeredCompressionMethods, buf);

        // Extensions
        if (state.clientExtensions != null) {
            ByteArrayOutputStream ext = new ByteArrayOutputStream();

            Enumeration keys = state.clientExtensions.keys();
            while (keys.hasMoreElements()) {
                Integer extType = (Integer) keys.nextElement();
                TlsProtocolHandler.writeExtension(ext, extType,
                    (byte[]) state.clientExtensions.get(extType));
            }

            TlsUtils.writeOpaque16(ext.toByteArray(), buf);
        }

        return buf.toByteArray();
    }

    private byte[] generateClientKeyExchange(HandshakeState state) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        state.keyExchange.generateClientKeyExchange(buf);
        return buf.toByteArray();
    }

    private byte[] parseHelloVerifyRequest(TlsClientContextImpl clientContext, byte[] body)
        throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (!server_version.equals(clientContext.getServerVersion())) {
            // TODO Alert
        }

        byte[] cookie = TlsUtils.readOpaque8(buf);

        assertEmpty(buf);

        if (cookie.length < 1 || cookie.length > 32) {
            // TODO Alert
        }

        return cookie;
    }

    private byte[] patchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie)
        throws IOException {

        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHelloBody, sessionIDPos);

        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;

        byte[] patched = new byte[clientHelloBody.length + cookie.length];
        System.arraycopy(clientHelloBody, 0, patched, 0, cookieLengthPos);
        TlsUtils.writeUint8((short) cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHelloBody, cookiePos, patched, cookiePos + cookie.length,
            clientHelloBody.length - cookiePos);

        return patched;
    }

    private void processCertificate(HandshakeState state, byte[] body) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        Certificate serverCertificate = Certificate.parse(buf);

        assertEmpty(buf);

        state.keyExchange.processServerCertificate(serverCertificate);
        state.authentication = state.client.getAuthentication();
        state.authentication.notifyServerCertificate(serverCertificate);
    }

    private void processCertificateRequest(HandshakeState state, byte[] body) throws IOException {

        if (state.authentication == null) {
            // TODO Alert
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        int numTypes = TlsUtils.readUint8(buf);
        short[] certificateTypes = new short[numTypes];
        for (int i = 0; i < numTypes; ++i) {
            certificateTypes[i] = TlsUtils.readUint8(buf);
        }

        byte[] authorities = TlsUtils.readOpaque16(buf);

        assertEmpty(buf);

        Vector authorityDNs = new Vector();

        ByteArrayInputStream bis = new ByteArrayInputStream(authorities);
        while (bis.available() > 0) {
            byte[] dnBytes = TlsUtils.readOpaque16(bis);
            authorityDNs.addElement(X500Name.getInstance(ASN1Primitive.fromByteArray(dnBytes)));
        }

        state.certificateRequest = new CertificateRequest(certificateTypes, authorityDNs);
        state.keyExchange.validateCertificateRequest(state.certificateRequest);
    }

    private void processServerHello(HandshakeState state, byte[] body) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        ProtocolVersion server_version = TlsUtils.readVersion(buf);
        if (!server_version.equals(state.clientContext.getServerVersion())) {
            // TODO Alert
        }

        byte[] server_random = new byte[32];
        TlsUtils.readFully(server_random, buf);
        state.clientContext.getSecurityParameters().serverRandom = server_random;

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32) {
            // TODO Alert
        }
        state.client.notifySessionID(sessionID);

        int selectedCipherSuite = TlsUtils.readUint16(buf);
        if (!TlsProtocolHandler.arrayContains(state.offeredCipherSuites, selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            // TODO Alert
        }
        state.client.notifySelectedCipherSuite(selectedCipherSuite);

        short selectedCompressionMethod = TlsUtils.readUint8(buf);
        if (!TlsProtocolHandler.arrayContains(state.offeredCompressionMethods,
            selectedCompressionMethod)) {
            // TODO Alert
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
        Hashtable serverExtensions = new Hashtable();

        if (buf.available() > 0) {
            // Process extensions from extended server hello
            byte[] extBytes = TlsUtils.readOpaque16(buf);

            ByteArrayInputStream ext = new ByteArrayInputStream(extBytes);
            while (ext.available() > 0) {
                Integer extType = Integers.valueOf(TlsUtils.readUint16(ext));
                byte[] extValue = TlsUtils.readOpaque16(ext);

                /*
                 * RFC 5746 Note that sending a "renegotiation_info" extension in response to a
                 * ClientHello containing only the SCSV is an explicit exception to the prohibition
                 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. TLS implementations
                 * MUST continue to comply with Section 7.4.1.4 for all other extensions.
                 */

                if (!extType.equals(EXT_RenegotiationInfo)
                    && state.clientExtensions.get(extType) == null) {
                    /*
                     * RFC 3546 2.3 Note that for all extension types (including those defined in
                     * future), the extension type MUST NOT appear in the extended server hello
                     * unless the same extension type appeared in the corresponding client hello.
                     * Thus clients MUST abort the handshake if they receive an extension type in
                     * the extended server hello that they did not request in the associated
                     * (extended) client hello.
                     */
                    // TODO Alert
                }

                if (serverExtensions.containsKey(extType)) {
                    /*
                     * RFC 3546 2.3 Also note that when multiple extensions of different types are
                     * present in the extended client hello or the extended server hello, the
                     * extensions may appear in any order. There MUST NOT be more than one extension
                     * of the same type.
                     */
                    // TODO Alert
                }

                serverExtensions.put(extType, extValue);
            }
        }

        assertEmpty(buf);

        /*
         * RFC 5746 3.4. When a ServerHello is received, the client MUST check if it includes the
         * "renegotiation_info" extension:
         */
        {
            boolean secure_negotiation = serverExtensions.containsKey(EXT_RenegotiationInfo);

            /*
             * If the extension is present, set the secure_renegotiation flag to TRUE. The client
             * MUST then verify that the length of the "renegotiated_connection" field is zero, and
             * if it is not, MUST abort the handshake (by sending a fatal handshake_failure alert).
             */
            if (secure_negotiation) {
                byte[] renegExtValue = (byte[]) serverExtensions.get(EXT_RenegotiationInfo);

                if (!Arrays.constantTimeAreEqual(renegExtValue,
                    TlsProtocolHandler.createRenegotiationInfo(EMPTY_BYTES))) {
                    // TODO Alert
                }
            }

            state.client.notifySecureRenegotiation(secure_negotiation);
        }

        if (state.clientExtensions != null) {
            state.client.processServerExtensions(serverExtensions);
        }

        state.keyExchange = state.client.getKeyExchange();
    }

    private void processServerKeyExchange(HandshakeState state, byte[] body) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        state.keyExchange.processServerKeyExchange(buf);

        assertEmpty(buf);
    }

    private static class HandshakeState {
        TlsClient client = null;
        TlsClientContextImpl clientContext = null;
        int[] offeredCipherSuites = null;
        Hashtable clientExtensions = null;
        short[] offeredCompressionMethods = null;
        TlsKeyExchange keyExchange = null;
        TlsAuthentication authentication = null;
        CertificateRequest certificateRequest = null;
        TlsCredentials clientCredentials = null;
    }
}
