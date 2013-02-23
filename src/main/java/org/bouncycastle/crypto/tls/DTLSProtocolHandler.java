package org.bouncycastle.crypto.tls;

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

        byte[] clientHello = generateClientHello(client, clientContext, EMPTY_BYTES);
        handshake.sendMessage(HandshakeType.client_hello, clientHello);

        DTLSReliableHandshake.Message serverHello = handshake.receiveMessage();
        if (serverHello.getType() == HandshakeType.hello_verify_request) {
            // TODO Actually, need to extract the cookie and add it here the second time
            handshake.sendMessage(HandshakeType.client_hello, clientHello);

            serverHello = handshake.receiveMessage();
        }

        if (serverHello.getType() != HandshakeType.server_hello) {
            // TODO Alert
        }

        return new DTLSTransport(transport);

        // if (client_version.isDTLS())
        // {
        // for (int cipherSuite : offeredCipherSuites)
        // {
        // switch (cipherSuite)
        // {
        // case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        // case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
        // case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
        // case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
        // case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
        // case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
        // throw new
        // IllegalStateException("Client offered an RC4 cipher suite: RC4 MUST NOT be used with DTLS");
        // }
        // }
        // }
    }

    private TlsClientContextImpl createClientContext() {
        SecurityParameters securityParameters = new SecurityParameters();

        securityParameters.clientRandom = new byte[32];
        secureRandom.nextBytes(securityParameters.clientRandom);
        TlsUtils.writeGMTUnixTime(securityParameters.clientRandom, 0);

        return new TlsClientContextImpl(secureRandom, securityParameters);
    }

    private byte[] generateClientHello(TlsClient client, TlsClientContextImpl clientContext,
        byte[] cookie) throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ProtocolVersion client_version = client.getClientVersion();
        clientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, buf);

        buf.write(clientContext.getSecurityParameters().getClientRandom());

        /*
         * Length of Session id
         */
        TlsUtils.writeUint8((short) 0, buf);

        if (cookie != null) {
            TlsUtils.writeUint8((short) cookie.length, buf);
            buf.write(cookie, 0, cookie.length);
        }

        /*
         * Cipher suites
         */
        int[] offeredCipherSuites = client.getCipherSuites();

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
}
