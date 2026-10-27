package org.bouncycastle.tls.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.UDPTransport;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

/**
 * A manual-run DTLS 1.3 (RFC 9147) interoperability check of the BC server against an external DTLS 1.3
 * client, e.g. OpenSSL's "s_client -dtls1_3". It is not part of any test suite; it accepts one connection on
 * 127.0.0.1 and then exits. See {@link DTLS13InteropClient} for the other direction, the shared options and
 * the application data exchange: here the server sends "BC-SERVER-&lt;round&gt;-&lt;nonce&gt;." lines and expects
 * each one back reversed, which whatever drives the external client has to arrange.
 * <p>
 * The server is not placed behind {@link org.bouncycastle.tls.DTLSVerifier}: that front end implements only
 * the DTLS 1.2 HelloVerifyRequest exchange, and a DTLS 1.3 handshake cannot be reached through it. Instead the
 * first datagram received decides the peer the socket is connected to, and it and the rest of that peer's first
 * flight are handed to the handshake as the first datagrams the transport delivers.
 * </p>
 * <p>
 * Usage: DTLS13InteropServer [-port 4433] [-cert ecdsa|rsa_pss_256|ed25519|rsa[+ca]] [-suite ...]
 * [-groups ...] [-auth none|ecdsa|rsa_pss_256|ed25519|rsa] [-mtu 1500] [-loss 0] [-seed 1]
 * [-keyupdate none|update|update-requested] [-rounds 3] [-expect-updates &lt;sent&gt;:&lt;received&gt;]
 * </p>
 * <p>
 * -cert is the server credential (x509-server-*.pem; "rsa" is the rsa-sign pair). -groups are the groups the
 * server will select from, in the client's order of preference, so leaving out the group of the client's key
 * share forces a HelloRetryRequest. -auth other than "none" makes the server require a client certificate and
 * check that it is that credential's (x509-client-*.pem). The server prints "LISTENING &lt;port&gt;" once its socket
 * is bound, and its last line is "PASS" or "FAIL: &lt;reason&gt;", with exit status 0 or 1 to match.
 * </p>
 */
public class DTLS13InteropServer
{
    /** How long a gap in the client's first flight ends it. */
    private static final int INITIAL_FLIGHT_GAP_MILLIS = 300;

    public static void main(String[] args)
    {
        DTLS13InteropClient.startWatchdog();

        DTLS13InteropClient.Options options;
        try
        {
            options = DTLS13InteropClient.Options.parse(args, true);
        }
        catch (RuntimeException e)
        {
            DTLS13InteropClient.finish("bad arguments: " + e.getMessage());
            return;
        }

        String failure;
        try
        {
            failure = run(options);
        }
        catch (Throwable t)
        {
            t.printStackTrace(System.out);
            failure = "exception: " + t;
        }

        DTLS13InteropClient.finish(failure);
    }

    private static String run(final DTLS13InteropClient.Options options) throws Exception
    {
        System.out.println("CONFIG " + options + " cert=" + options.cert);

        final BcTlsCrypto crypto = new BcTlsCrypto();

        DatagramSocket socket = new DatagramSocket(options.port, InetAddress.getByName("127.0.0.1"));
        System.out.println("LISTENING " + options.port);
        System.out.flush();

        byte[] data = new byte[options.mtu];
        DatagramPacket packet = new DatagramPacket(data, data.length);
        socket.setSoTimeout(DTLS13InteropClient.WATCHDOG_MILLIS / 2);
        socket.receive(packet);

        InetAddress peerAddress = packet.getAddress();
        int peerPort = packet.getPort();
        System.out.println("First datagram (" + packet.getLength() + " bytes) from " + peerAddress.getHostAddress()
            + ":" + peerPort);

        /*
         * Connecting the socket discards whatever it has already queued (the JDK's DatagramChannel flushes on
         * connect), which loses the rest of a ClientHello that is fragmented over several datagrams. So the
         * remainder of the client's first flight is read before connecting, and replayed after.
         */
        Vector initialFlight = new Vector();
        initialFlight.addElement(Arrays.copyOfRange(data, 0, packet.getLength()));
        socket.setSoTimeout(INITIAL_FLIGHT_GAP_MILLIS);
        for (;;)
        {
            packet = new DatagramPacket(data, data.length);
            try
            {
                socket.receive(packet);
            }
            catch (SocketTimeoutException e)
            {
                break;
            }
            if (peerAddress.equals(packet.getAddress()) && peerPort == packet.getPort())
            {
                initialFlight.addElement(Arrays.copyOfRange(data, 0, packet.getLength()));
            }
        }
        System.out.println("Initial flight: " + initialFlight.size() + " datagram(s)");

        socket.connect(peerAddress, peerPort);

        DatagramTransport udp = new InitialFlightTransport(new UDPTransport(socket, options.mtu), initialFlight);
        DTLS13InteropClient.WireMonitor monitor = new DTLS13InteropClient.WireMonitor(udp, false);
        DatagramTransport transport = options.wrapLoss(monitor);

        final DTLS13InteropClient.Outcome outcome = new DTLS13InteropClient.Outcome();

        MockDTLSServer server = new MockDTLSServer(crypto)
        {
            protected ProtocolVersion[] getSupportedVersions()
            {
                return ProtocolVersion.DTLSv13.only();
            }

            protected int[] getSupportedCipherSuites()
            {
                return options.cipherSuite < 0 ? super.getSupportedCipherSuites() : new int[]{ options.cipherSuite };
            }

            public int[] getSupportedGroups() throws IOException
            {
                return null == options.groups ? super.getSupportedGroups() : options.groups;
            }

            public int getHandshakeTimeoutMillis()
            {
                return DTLS13InteropClient.STEP_MILLIS;
            }

            public TlsCredentials getCredentials() throws IOException
            {
                if (!TlsUtils.isTLSv13(context))
                {
                    return super.getCredentials();
                }

                return DTLS13InteropClient.loadSignerCredentials(context, true, options.cert,
                    context.getSecurityParametersHandshake().getClientSigAlgs());
            }

            public CertificateRequest getCertificateRequest() throws IOException
            {
                if (null == options.auth)
                {
                    return null;
                }

                outcome.certificateRequested = true;
                return super.getCertificateRequest();
            }

            public void notifyClientCertificate(Certificate clientCertificate) throws IOException
            {
                if (null == clientCertificate || clientCertificate.isEmpty())
                {
                    System.out.println("Client sent an empty Certificate");

                    // RFC 8446 4.4.2.4. The client declined, and this server requires a certificate.
                    throw new TlsFatalAlert(AlertDescription.certificate_required);
                }

                super.notifyClientCertificate(clientCertificate);

                String expected = "x509-client-" + DTLS13InteropClient.getEndEntityName(false, stripCA(options.auth))
                    + ".pem";
                if (!TlsTestUtils.areSameCertificate(context.getCrypto(), clientCertificate.getCertificateAt(0),
                    expected))
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate,
                        "the client certificate is not " + expected);
                }
                System.out.println("Client certificate matches " + expected);
            }

            public void notifyHandshakeComplete() throws IOException
            {
                super.notifyHandshakeComplete();

                outcome.record(context);
            }
        };

        long start = System.currentTimeMillis();
        DTLSTransport dtls = new DTLSServerProtocol().accept(server, transport);
        System.out.println("Handshake completed in " + (System.currentTimeMillis() - start) + " ms");

        String failure = outcome.check(monitor);
        if (null == failure)
        {
            failure = DTLS13InteropClient.runRounds(dtls, "SERVER", options, monitor);
        }

        dtls.close();

        return failure;
    }

    private static String stripCA(String name)
    {
        return name.endsWith("+ca") ? name.substring(0, name.length() - 3) : name;
    }

    /**
     * Delivers the datagrams that were read before the socket was connected ahead of anything the socket
     * receives afterwards, so that the handshake starts from the client's first ClientHello rather than waiting
     * for its retransmission.
     */
    static class InitialFlightTransport
        implements DatagramTransport
    {
        private final DatagramTransport transport;
        private final Vector pending;

        InitialFlightTransport(DatagramTransport transport, Vector initialFlight)
        {
            this.transport = transport;
            this.pending = initialFlight;
        }

        public int getReceiveLimit() throws IOException
        {
            return transport.getReceiveLimit();
        }

        public int getSendLimit() throws IOException
        {
            return transport.getSendLimit();
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            if (!pending.isEmpty())
            {
                byte[] datagram = (byte[])pending.elementAt(0);
                pending.removeElementAt(0);

                int length = Math.min(len, datagram.length);
                System.arraycopy(datagram, 0, buf, off, length);
                return length;
            }

            return transport.receive(buf, off, len, waitMillis);
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            transport.send(buf, off, len);
        }

        public void close() throws IOException
        {
            transport.close();
        }
    }
}
