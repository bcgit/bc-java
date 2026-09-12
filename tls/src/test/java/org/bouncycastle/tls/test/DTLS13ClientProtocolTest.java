package org.bouncycastle.tls.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsFatalAlert;

import junit.framework.TestCase;

/**
 * Isolated coverage of the DTLS 1.3 client's ServerHello handling. There is no DTLS 1.3 server in the tree
 * yet, so these tests script a single ServerHello onto the wire and assert that the client enters the DTLS
 * 1.3 path and fails with a specific alert rather than hanging or silently taking the DTLS 1.2 path. A
 * complete DTLS 1.3 handshake is only exercised once the server half exists.
 */
public class DTLS13ClientProtocolTest
    extends TestCase
{
    private static final int MTU = 1500;

    /**
     * A ServerHello selecting a version later than DTLS 1.3 must be refused outright: this implementation
     * does not know its semantics, and processing it as DTLS 1.3 would be wrong.
     */
    public void testServerSelectsUnsupportedFutureVersion() throws Exception
    {
        // {0xFE, 0xFB} is one version later than DTLS 1.3 and is not implemented here
        short alertDescription = connectAndExpectFatalAlert(new byte[]{ (byte)0xFE, (byte)0xFB });

        assertEquals("alert for an unimplemented future version", AlertDescription.protocol_version,
            alertDescription);
    }

    /**
     * A DTLS 1.3 ServerHello with no "key_share" and no pre-shared key is illegal (RFC 8446 4.1.3/4.2.8).
     * Reaching that check at all proves the client routed the ServerHello into its DTLS 1.3 path: the DTLS
     * 1.2 path has no such requirement and would have gone on to look for a ServerKeyExchange.
     */
    public void testDTLSv13ServerHelloWithoutKeyShare() throws Exception
    {
        short alertDescription = connectAndExpectFatalAlert(new byte[]{ (byte)0xFE, (byte)0xFC });

        assertEquals("alert for a DTLS 1.3 ServerHello with no key_share", AlertDescription.illegal_parameter,
            alertDescription);
    }

    private short connectAndExpectFatalAlert(byte[] selectedVersion) throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null)
        {
            public int[] getCipherSuites()
            {
                return new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };
            }

            protected ProtocolVersion[] getSupportedVersions()
            {
                return ProtocolVersion.DTLSv13.only();
            }
        };

        // NOTE: Bounded so that a client which does not fail as expected ends the test instead of hanging
        client.setHandshakeTimeoutMillis(5000);

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();

        ScriptedServerHelloTransport transport = new ScriptedServerHelloTransport(
            createServerHelloRecord(selectedVersion));

        try
        {
            clientProtocol.connect(client, transport);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            assertTrue("server never received a ClientHello", transport.sawClientHello());

            return fatalAlert.getAlertDescription();
        }

        fail("expected the client to raise a fatal alert");
        return -1;
    }

    /**
     * A DTLS plaintext record (RFC 9147 4) carrying a single unfragmented ServerHello, selecting the given
     * version through the "supported_versions" extension.
     */
    private static byte[] createServerHelloRecord(byte[] selectedVersion) throws IOException
    {
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeUint16(extensions, ExtensionType.supported_versions);
        writeUint16(extensions, selectedVersion.length);
        extensions.write(selectedVersion, 0, selectedVersion.length);

        byte[] extensionsData = extensions.toByteArray();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // legacy_version
        body.write(0xFE);
        body.write(0xFD);
        // random: fixed, and deliberately not the HelloRetryRequest value of RFC 8446 4.1.3
        for (int i = 0; i < 32; ++i)
        {
            body.write(i);
        }
        // legacy_session_id_echo: the client offered none
        body.write(0);
        writeUint16(body, CipherSuite.TLS_AES_128_GCM_SHA256);
        // legacy_compression_method
        body.write(0);
        writeUint16(body, extensionsData.length);
        body.write(extensionsData, 0, extensionsData.length);

        byte[] bodyData = body.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(ContentType.handshake);
        // legacy_record_version
        record.write(0xFE);
        record.write(0xFD);
        // epoch
        writeUint16(record, 0);
        // sequence_number
        for (int i = 0; i < 6; ++i)
        {
            record.write(0);
        }
        writeUint16(record, 12 + bodyData.length);

        record.write(HandshakeType.server_hello);
        writeUint24(record, bodyData.length);
        // message_seq
        writeUint16(record, 0);
        // fragment_offset
        writeUint24(record, 0);
        // fragment_length
        writeUint24(record, bodyData.length);
        record.write(bodyData, 0, bodyData.length);

        return record.toByteArray();
    }

    private static void writeUint16(ByteArrayOutputStream buf, int i)
    {
        buf.write((i >>> 8) & 0xFF);
        buf.write(i & 0xFF);
    }

    private static void writeUint24(ByteArrayOutputStream buf, int i)
    {
        buf.write((i >>> 16) & 0xFF);
        buf.write((i >>> 8) & 0xFF);
        buf.write(i & 0xFF);
    }

    /**
     * Answers the first ClientHello with one prepared record and nothing thereafter.
     */
    private static class ScriptedServerHelloTransport
        implements DatagramTransport
    {
        private final byte[] serverHelloRecord;

        private boolean sawClientHello = false;
        private byte[] pending = null;

        ScriptedServerHelloTransport(byte[] serverHelloRecord)
        {
            this.serverHelloRecord = serverHelloRecord;
        }

        boolean sawClientHello()
        {
            return sawClientHello;
        }

        public int getReceiveLimit()
        {
            return MTU;
        }

        public int getSendLimit()
        {
            return MTU;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            // DTLS plaintext record header (13 bytes), then the DTLS handshake message header
            if (!sawClientHello && len > 13 && (buf[off] & 0xFF) == ContentType.handshake
                && (buf[off + 13] & 0xFF) == HandshakeType.client_hello)
            {
                this.sawClientHello = true;
                this.pending = serverHelloRecord;
            }
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            if (null == pending)
            {
                return -1;
            }

            byte[] record = pending;
            this.pending = null;

            if (record.length > len)
            {
                return -1;
            }

            System.arraycopy(record, 0, buf, off, record.length);
            return record.length;
        }

        public void close() throws IOException
        {
        }
    }
}
