package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;

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

        TlsClientContextImpl clientContext = createClientContext();

        client.init(clientContext);

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, clientContext,
            ContentType.handshake);
        DTLSReliableHandshake handshake = new DTLSReliableHandshake(recordLayer);

        byte[] clientHello = generateClientHello(clientContext, client);
        handshake.sendMessage(HandshakeType.client_hello, clientHello);

        DTLSReliableHandshake.Message serverMessage = handshake.receiveMessage();

        // NOTE: After receiving a record from the server, we discover the version it chose
        ProtocolVersion server_version = recordLayer.getDiscoveredServerVersion();
        if (server_version.getFullVersion() < clientContext.getClientVersion().getFullVersion()) {
            // TODO Alert
        }

        clientContext.setServerVersion(server_version);
        client.notifyServerVersion(server_version);

        if (serverMessage.getType() == HandshakeType.hello_verify_request) {

            byte[] cookie = parseHelloVerifyRequest(clientContext, serverMessage.getBody());

            byte[] patched = patchClientHelloWithCookie(clientHello, cookie);
            handshake.sendMessage(HandshakeType.client_hello, patched);

            serverMessage = handshake.receiveMessage();
        }

        if (serverMessage.getType() != HandshakeType.server_hello) {
            // TODO Alert
        }

        while (serverMessage.getType() != HandshakeType.server_hello_done) {

            // TODO Process serverMessage

            serverMessage = handshake.receiveMessage();
        }

        // TODO Lots more handshake messages...

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

    private byte[] generateClientHello(TlsClientContextImpl clientContext, TlsClient client)
        throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ProtocolVersion client_version = client.getClientVersion();
        if (!client_version.isDTLS()) {
            // TODO Alert
        }

        clientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(clientContext.getSecurityParameters().getClientRandom());

        // Length of Session id
        TlsUtils.writeUint8((short) 0, buf);

        // Length of cookie
        TlsUtils.writeUint8((short) 0, buf);

        /*
         * Cipher suites
         */
        int[] offeredCipherSuites = client.getCipherSuites();

        for (int cipherSuite : offeredCipherSuites) {
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
        Hashtable clientExtensions = client.getClientExtensions();

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = clientExtensions == null
                || clientExtensions.get(EXT_RenegotiationInfo) == null;

            int count = offeredCipherSuites.length;
            if (noRenegExt) {
                // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ++count;
            }

            TlsUtils.writeUint16(2 * count, buf);
            TlsUtils.writeUint16Array(offeredCipherSuites, buf);

            if (noRenegExt) {
                TlsUtils.writeUint16(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, buf);
            }
        }

        // Compression methods
        short[] offeredCompressionMethods = client.getCompressionMethods();

        TlsUtils.writeUint8((short) offeredCompressionMethods.length, buf);
        TlsUtils.writeUint8Array(offeredCompressionMethods, buf);

        // Extensions
        if (clientExtensions != null) {
            ByteArrayOutputStream ext = new ByteArrayOutputStream();

            Enumeration keys = clientExtensions.keys();
            while (keys.hasMoreElements()) {
                Integer extType = (Integer) keys.nextElement();
                TlsProtocolHandler.writeExtension(ext, extType,
                    (byte[]) clientExtensions.get(extType));
            }

            TlsUtils.writeOpaque16(ext.toByteArray(), buf);
        }

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

    private byte[] patchClientHelloWithCookie(byte[] clientHello, byte[] cookie) throws IOException {

        int sessionIDPos = 34;
        int sessionIDLength = TlsUtils.readUint8(clientHello, sessionIDPos);

        int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
        int cookiePos = cookieLengthPos + 1;

        byte[] patched = new byte[clientHello.length + cookie.length];
        System.arraycopy(clientHello, 0, patched, 0, cookieLengthPos);
        TlsUtils.writeUint8((short) cookie.length, patched, cookieLengthPos);
        System.arraycopy(cookie, 0, patched, cookiePos, cookie.length);
        System.arraycopy(clientHello, cookiePos, patched, cookiePos + cookie.length,
            clientHello.length - cookiePos);

        return patched;
    }
}
