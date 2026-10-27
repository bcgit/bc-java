package org.bouncycastle.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DTLS13KeyUpdateTestSupport;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.UDPTransport;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * A manual-run DTLS 1.3 (RFC 9147) interoperability check of the BC client against an external DTLS 1.3
 * server, e.g. OpenSSL's "s_server -dtls1_3". It is not part of any test suite and starts nothing itself: the
 * external server has to be running already. See {@link DTLS13InteropServer} for the other direction.
 * <p>
 * After the handshake the client runs a number of rounds (3 by default). In each it sends the line
 * "BC-CLIENT-&lt;round&gt;-&lt;nonce&gt;." and waits for the same line reversed to come back. OpenSSL's s_server
 * has a -rev option that would do the reversing, but it refuses it for DTLS, so whatever drives the server has
 * to read each line from its stdout and write the reversed line to its stdin. Anything else received (an
 * s_server driven through a pipe sends a stream of filler lines) is ignored. With a KeyUpdate mode set, the
 * client starts an RFC 9147 sec. 8 key update between the first and second rounds.
 * </p>
 * <p>
 * Usage: DTLS13InteropClient [-host 127.0.0.1] [-port 4433] [-suite TLS_AES_128_GCM_SHA256|default]
 * [-groups x25519:P-256|default] [-auth none|ecdsa|rsa_pss_256|ed25519|rsa[+ca]] [-mtu 1500] [-loss 0]
 * [-seed 1] [-keyupdate none|update|update-requested] [-rounds 3] [-expect-updates &lt;sent&gt;:&lt;received&gt;]
 * </p>
 * <p>
 * The first group of -groups is the one the client sends a key share for. -auth names the credential the
 * client answers a CertificateRequest with (the x509-client-*.pem files in bc-test-data; "+ca" appends the CA
 * certificate to the chain). -loss is a percentage applied in each direction through
 * {@link UnreliableDatagramTransport}, seeded with -seed. -expect-updates is the minimum number of key updates
 * (write-epoch advances after the first application epoch) that must be observed on the wire in each direction.
 * The last line printed is "PASS" or "FAIL: &lt;reason&gt;", and the exit status is 0 or 1 to match.
 * </p>
 */
public class DTLS13InteropClient
{
    /** The hard timeout on the handshake and on each round of the application data exchange. */
    static final int STEP_MILLIS = 20000;

    /** Kills a run that has stopped making progress, however that happened. */
    static final int WATCHDOG_MILLIS = 120000;

    public static void main(String[] args)
    {
        startWatchdog();

        Options options;
        try
        {
            options = Options.parse(args, false);
        }
        catch (RuntimeException e)
        {
            finish("bad arguments: " + e.getMessage());
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

        finish(failure);
    }

    private static String run(final Options options) throws Exception
    {
        System.out.println("CONFIG " + options);

        DatagramSocket socket = new DatagramSocket();
        socket.connect(InetAddress.getByName(options.host), options.port);

        DatagramTransport udp = new UDPTransport(socket, options.mtu);
        WireMonitor monitor = new WireMonitor(udp, true);
        DatagramTransport transport = options.wrapLoss(monitor);

        final Outcome outcome = new Outcome();

        MockDTLSClient client = new MockDTLSClient(null)
        {
            protected ProtocolVersion[] getSupportedVersions()
            {
                return ProtocolVersion.DTLSv13.only();
            }

            protected int[] getSupportedCipherSuites()
            {
                return options.cipherSuite < 0 ? super.getSupportedCipherSuites() : new int[]{ options.cipherSuite };
            }

            protected Vector getSupportedGroups(Vector namedGroupRoles)
            {
                if (null == options.groups)
                {
                    return super.getSupportedGroups(namedGroupRoles);
                }

                Vector groups = new Vector();
                for (int i = 0; i < options.groups.length; ++i)
                {
                    groups.addElement(Integers.valueOf(options.groups[i]));
                }
                return groups;
            }

            public Vector getEarlyKeyShareGroups()
            {
                if (null == options.groups)
                {
                    return super.getEarlyKeyShareGroups();
                }

                return TlsUtils.vectorOfOne(Integers.valueOf(options.groups[0]));
            }

            public TlsAuthentication getAuthentication() throws IOException
            {
                final TlsAuthentication authentication = super.getAuthentication();

                return new TlsAuthentication()
                {
                    public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
                    {
                        authentication.notifyServerCertificate(serverCertificate);
                    }

                    /*
                     * MockDTLSClient's own answer looks at the 'certificate_types' that a (D)TLS 1.3
                     * CertificateRequest no longer has, so the credentials are chosen here instead.
                     */
                    public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                        throws IOException
                    {
                        outcome.certificateRequested = true;
                        System.out.println("Server sent a CertificateRequest");

                        if (null == options.auth)
                        {
                            System.out.println("No client credential configured: sending an empty Certificate");
                            return null;
                        }

                        return loadSignerCredentials(context, false, options.auth,
                            certificateRequest.getSupportedSignatureAlgorithms());
                    }
                };
            }

            public void notifyHandshakeComplete() throws IOException
            {
                super.notifyHandshakeComplete();

                outcome.record(context);
            }
        };
        client.setHandshakeTimeoutMillis(STEP_MILLIS);

        long start = System.currentTimeMillis();
        DTLSTransport dtls = new DTLSClientProtocol().connect(client, transport);
        System.out.println("Handshake completed in " + (System.currentTimeMillis() - start) + " ms");

        String failure = outcome.check(monitor);
        if (null == failure)
        {
            failure = runRounds(dtls, "CLIENT", options, monitor);
        }

        dtls.close();

        return failure;
    }

    /**
     * The application data exchange both mains share: 'rounds' lines out, each answered by the same line
     * reversed, with the configured key update started between the first and second rounds. Returns null on
     * success or a reason for failure.
     */
    static String runRounds(DTLSTransport dtls, String role, Options options, WireMonitor monitor)
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        byte[] nonceBytes = new byte[4];
        random.nextBytes(nonceBytes);
        String nonce = Hex.toHexString(nonceBytes);

        /*
         * An application record that is lost is not retransmitted by DTLS, so a line that has not been answered
         * after this long is sent again. With no loss configured, the interval only has to clear the time the
         * driver takes to answer, including any KeyUpdate command it slots in first.
         */
        int resendMillis = options.loss > 0 ? 2000 : 6000;

        byte[] buf = new byte[dtls.getReceiveLimit()];

        for (int round = 1; round <= options.rounds; ++round)
        {
            if (round == 2 && !"none".equals(options.keyUpdate))
            {
                boolean requestUpdate = "update-requested".equals(options.keyUpdate);
                System.out.println("Sending KeyUpdate(" + (requestUpdate ? "update_requested" : "update_not_requested")
                    + ")");
                DTLS13KeyUpdateTestSupport.sendKeyUpdate(dtls, requestUpdate);
            }

            /*
             * The trailing '.' becomes the first character of the reversed line, so that a peer which takes
             * single-letter commands from its stdin (s_server and s_client do) never reads the answer as one.
             */
            String line = "BC-" + role + "-" + round + "-" + nonce + ".";
            String expected = new StringBuffer(line).reverse().toString();
            byte[] lineBytes = Strings.toUTF8ByteArray(line + "\n");

            StringBuffer received = new StringBuffer();
            long roundStart = System.currentTimeMillis();
            long deadline = roundStart + STEP_MILLIS;
            long nextSend = roundStart;
            int sends = 0;

            for (;;)
            {
                long now = System.currentTimeMillis();
                if (now >= deadline)
                {
                    return "round " + round + ": no reversed echo of '" + line + "' within " + STEP_MILLIS
                        + " ms (sent " + sends + " times)";
                }

                if (now >= nextSend)
                {
                    dtls.send(lineBytes, 0, lineBytes.length);
                    ++sends;
                    System.out.println((sends == 1 ? "Sent: " : "Re-sent: ") + line);
                    nextSend = now + resendMillis;
                }

                int waitMillis = (int)Math.max(1, Math.min(deadline, nextSend) - now);
                int length = dtls.receive(buf, 0, buf.length, waitMillis);
                if (length < 0)
                {
                    continue;
                }

                String text = Strings.fromUTF8ByteArray(buf, 0, length);
                received.append(text);

                String trimmed = text.trim();
                if (trimmed.length() > 0)
                {
                    System.out.println("Received: " + trimmed);
                }

                if (received.toString().indexOf(expected) >= 0)
                {
                    System.out.println("Round " + round + " OK in " + (System.currentTimeMillis() - roundStart)
                        + " ms");
                    break;
                }
            }
        }

        /*
         * Let a final ACK, or the peer's answer to a KeyUpdate, arrive before the wire is judged. Receiving is
         * what drives the record layer, so the time is spent in receive().
         */
        long settleEnd = System.currentTimeMillis() + 1000;
        for (;;)
        {
            long now = System.currentTimeMillis();
            if (now >= settleEnd)
            {
                break;
            }
            dtls.receive(buf, 0, buf.length, (int)Math.max(1, settleEnd - now));
        }

        System.out.println("WIRE " + monitor.summary());

        int minSent = options.expectSentUpdates, minReceived = options.expectReceivedUpdates;
        if ("update".equals(options.keyUpdate) || "update-requested".equals(options.keyUpdate))
        {
            minSent = Math.max(minSent, 1);
        }
        if ("update-requested".equals(options.keyUpdate))
        {
            minReceived = Math.max(minReceived, 1);
        }

        if (monitor.getUpdates(true) < minSent)
        {
            return "expected at least " + minSent + " key update(s) sent, saw " + monitor.getUpdates(true);
        }
        if (monitor.getUpdates(false) < minReceived)
        {
            return "expected at least " + minReceived + " key update(s) received, saw " + monitor.getUpdates(false);
        }

        return null;
    }

    static void finish(String failure)
    {
        System.out.flush();
        if (null == failure)
        {
            System.out.println("PASS");
            System.out.flush();
            System.exit(0);
        }
        else
        {
            System.out.println("FAIL: " + failure);
            System.out.flush();
            System.exit(1);
        }
    }

    static void startWatchdog()
    {
        Thread watchdog = new Thread()
        {
            public void run()
            {
                try
                {
                    Thread.sleep(WATCHDOG_MILLIS);
                }
                catch (InterruptedException e)
                {
                    return;
                }
                finish("watchdog: no result after " + WATCHDOG_MILLIS + " ms");
            }
        };
        watchdog.setDaemon(true);
        watchdog.start();
    }

    static String getCipherSuiteName(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_GCM_SHA256:
            return "TLS_AES_128_GCM_SHA256";
        case CipherSuite.TLS_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384";
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return "TLS_CHACHA20_POLY1305_SHA256";
        case CipherSuite.TLS_AES_128_CCM_SHA256:
            return "TLS_AES_128_CCM_SHA256";
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
            return "TLS_AES_128_CCM_8_SHA256";
        default:
            return "0x" + Integer.toHexString(cipherSuite);
        }
    }

    static int parseCipherSuite(String name)
    {
        int[] suites = new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
            CipherSuite.TLS_AES_128_CCM_8_SHA256 };
        for (int i = 0; i < suites.length; ++i)
        {
            if (getCipherSuiteName(suites[i]).equalsIgnoreCase(name))
            {
                return suites[i];
            }
        }
        throw new IllegalArgumentException("unknown cipher suite: " + name);
    }

    static int parseGroup(String name)
    {
        if (name.equalsIgnoreCase("x25519"))
        {
            return NamedGroup.x25519;
        }
        if (name.equalsIgnoreCase("x448"))
        {
            return NamedGroup.x448;
        }
        if (name.equalsIgnoreCase("P-256") || name.equalsIgnoreCase("secp256r1") || name.equalsIgnoreCase("prime256v1"))
        {
            return NamedGroup.secp256r1;
        }
        if (name.equalsIgnoreCase("P-384") || name.equalsIgnoreCase("secp384r1"))
        {
            return NamedGroup.secp384r1;
        }
        if (name.equalsIgnoreCase("P-521") || name.equalsIgnoreCase("secp521r1"))
        {
            return NamedGroup.secp521r1;
        }
        if (name.equalsIgnoreCase("ffdhe2048"))
        {
            return NamedGroup.ffdhe2048;
        }
        throw new IllegalArgumentException("unknown group: " + name);
    }

    /**
     * Loads one of the bc-test-data credentials by short name: "ecdsa" (P-256), "ed25519", "rsa_pss_256"
     * (an RSASSA-PSS key) or "rsa" (an rsaEncryption key, signing with rsa_pss_rsae_sha256), optionally with
     * "+ca" to send the CA certificate after the end-entity one.
     */
    static TlsCredentialedSigner loadSignerCredentials(TlsContext context, boolean forServer, String name,
        Vector peerSigAlgs) throws IOException
    {
        boolean withCA = name.endsWith("+ca");
        String alg = withCA ? name.substring(0, name.length() - 3) : name;

        int signatureScheme;
        if ("ecdsa".equals(alg))
        {
            signatureScheme = SignatureScheme.ecdsa_secp256r1_sha256;
        }
        else if ("ed25519".equals(alg))
        {
            signatureScheme = SignatureScheme.ed25519;
        }
        else if ("rsa_pss_256".equals(alg))
        {
            signatureScheme = SignatureScheme.rsa_pss_pss_sha256;
        }
        else if ("rsa".equals(alg))
        {
            signatureScheme = SignatureScheme.rsa_pss_rsae_sha256;
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "unknown credential: " + name);
        }

        SignatureAndHashAlgorithm sigAlg = SignatureScheme.getSignatureAndHashAlgorithm(signatureScheme);
        if (null != peerSigAlgs && !TlsUtils.containsSignatureAlgorithm(peerSigAlgs, sigAlg))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure,
                "the peer did not offer " + SignatureScheme.getName(signatureScheme));
        }

        String role = forServer ? "server" : "client";
        String eeName = getEndEntityName(forServer, alg);
        String eeCert = "x509-" + role + "-" + eeName + ".pem";
        String[] certs = withCA
            ?   new String[]{ eeCert, "x509-ca-" + alg + ".pem" }
            :   new String[]{ eeCert };

        System.out.println("Using credential " + certs[0] + (withCA ? " + " + certs[1] : "") + " with "
            + SignatureScheme.getName(signatureScheme));

        return TlsTestUtils.loadSignerCredentials(context, certs, "x509-" + role + "-key-" + eeName + ".pem", sigAlg);
    }

    static String getEndEntityName(boolean forServer, String alg)
    {
        return (forServer && "rsa".equals(alg)) ? "rsa-sign" : alg;
    }

    /**
     * What the handshake negotiated, as the BC peer saw it.
     */
    static class Outcome
    {
        ProtocolVersion version = null;
        int cipherSuite = -1;
        int negotiatedGroup = -1;
        boolean certificateRequested = false;
        int localCertChainLength = 0;
        int peerCertChainLength = -1;

        void record(TlsContext context)
        {
            SecurityParameters sp = context.getSecurityParametersConnection();
            version = sp.getNegotiatedVersion();
            cipherSuite = sp.getCipherSuite();
            negotiatedGroup = sp.getNegotiatedGroup();
            if (null != sp.getLocalCertificate())
            {
                localCertChainLength = sp.getLocalCertificate().getLength();
            }
            if (null != sp.getPeerCertificate())
            {
                peerCertChainLength = sp.getPeerCertificate().getLength();
            }
        }

        /**
         * Prints the summary line the write-up quotes, and returns a reason for failure if the handshake did not
         * produce DTLS 1.3.
         */
        String check(WireMonitor monitor)
        {
            System.out.println("NEGOTIATED version=" + version + " suite=" + getCipherSuiteName(cipherSuite)
                + " group=" + (negotiatedGroup < 0 ? "none" : NamedGroup.getName(negotiatedGroup))
                + " hrr=" + (monitor.getHelloRetryRequests() > 0 ? "yes" : "no")
                + " certificateRequest=" + (certificateRequested ? "yes" : "no")
                + " localCertChain=" + localCertChainLength + " peerCertChain=" + peerCertChainLength);

            if (!ProtocolVersion.DTLSv13.equals(version))
            {
                return "negotiated " + version + ", not DTLS 1.3";
            }
            return null;
        }
    }

    /**
     * The varying parameters of a run, shared by both mains.
     */
    static class Options
    {
        String host = "127.0.0.1";
        int port = 4433;
        int cipherSuite = -1;
        int[] groups = null;
        String auth = null;
        String cert = "ecdsa";
        int mtu = 1500;
        int loss = 0;
        long seed = 1;
        String keyUpdate = "none";
        int rounds = 3;
        int expectSentUpdates = 0;
        int expectReceivedUpdates = 0;

        static Options parse(String[] args, boolean forServer)
        {
            Options options = new Options();
            for (int i = 0; i < args.length; ++i)
            {
                String name = args[i];
                if (i + 1 >= args.length)
                {
                    throw new IllegalArgumentException("missing value for " + name);
                }
                String value = args[++i];

                if ("-host".equals(name))
                {
                    options.host = value;
                }
                else if ("-port".equals(name))
                {
                    options.port = Integer.parseInt(value);
                }
                else if ("-suite".equals(name))
                {
                    options.cipherSuite = "default".equals(value) ? -1 : parseCipherSuite(value);
                }
                else if ("-groups".equals(name))
                {
                    if ("default".equals(value))
                    {
                        options.groups = null;
                    }
                    else
                    {
                        String[] names = value.split(":");
                        options.groups = new int[names.length];
                        for (int j = 0; j < names.length; ++j)
                        {
                            options.groups[j] = parseGroup(names[j]);
                        }
                    }
                }
                else if ("-auth".equals(name))
                {
                    options.auth = "none".equals(value) ? null : value;
                }
                else if ("-cert".equals(name) && forServer)
                {
                    options.cert = value;
                }
                else if ("-mtu".equals(name))
                {
                    options.mtu = Integer.parseInt(value);
                }
                else if ("-loss".equals(name))
                {
                    options.loss = Integer.parseInt(value);
                }
                else if ("-seed".equals(name))
                {
                    options.seed = Long.parseLong(value);
                }
                else if ("-keyupdate".equals(name))
                {
                    if (!"none".equals(value) && !"update".equals(value) && !"update-requested".equals(value))
                    {
                        throw new IllegalArgumentException("unknown -keyupdate mode: " + value);
                    }
                    options.keyUpdate = value;
                }
                else if ("-rounds".equals(name))
                {
                    options.rounds = Integer.parseInt(value);
                }
                else if ("-expect-updates".equals(name))
                {
                    int colon = value.indexOf(':');
                    if (colon < 0)
                    {
                        throw new IllegalArgumentException("-expect-updates takes <sent>:<received>");
                    }
                    options.expectSentUpdates = Integer.parseInt(value.substring(0, colon));
                    options.expectReceivedUpdates = Integer.parseInt(value.substring(colon + 1));
                }
                else
                {
                    throw new IllegalArgumentException("unknown option: " + name);
                }
            }

            if (options.rounds < 2 && !"none".equals(options.keyUpdate))
            {
                throw new IllegalArgumentException("-keyupdate needs at least 2 rounds");
            }

            return options;
        }

        DatagramTransport wrapLoss(DatagramTransport transport)
        {
            if (loss <= 0)
            {
                return transport;
            }

            return new UnreliableDatagramTransport(transport, new Random(seed), loss, loss);
        }

        public String toString()
        {
            StringBuffer sb = new StringBuffer();
            sb.append("host=").append(host).append(" port=").append(port);
            sb.append(" suite=").append(cipherSuite < 0 ? "default" : getCipherSuiteName(cipherSuite));
            sb.append(" groups=");
            if (null == groups)
            {
                sb.append("default");
            }
            else
            {
                for (int i = 0; i < groups.length; ++i)
                {
                    sb.append(i == 0 ? "" : ":").append(NamedGroup.getName(groups[i]));
                }
            }
            sb.append(" auth=").append(null == auth ? "none" : auth);
            sb.append(" mtu=").append(mtu).append(" loss=").append(loss).append("% seed=").append(seed);
            sb.append(" keyupdate=").append(keyUpdate).append(" rounds=").append(rounds);
            sb.append(" expect-updates=").append(expectSentUpdates).append(':').append(expectReceivedUpdates);
            return sb.toString();
        }
    }

    /**
     * Watches the datagrams on the wire, below any simulated loss, for the facts a run is meant to exercise and
     * that the TlsClient / TlsServer callbacks do not report: whether a HelloRetryRequest was sent or received
     * (and what it carried), how many ClientHellos went past, and how the epochs of protected records advanced
     * in each direction. The epoch is read from the two low bits that the RFC 9147 sec. 4 unified header
     * carries, so a key update shows up as the next value modulo 4.
     */
    static class WireMonitor
        implements DatagramTransport
    {
        /** RFC 8446 4.1.3. The 'random' of a HelloRetryRequest. */
        private static final byte[] HELLO_RETRY_REQUEST_RANDOM = Hex.decodeStrict(
            "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

        private final DatagramTransport transport;
        private final boolean isClient;

        private int helloRetryRequests = 0;
        private String helloRetryRequestDetail = null;
        private int clientHelloSeqs = 0;
        private int clientHelloDatagrams = 0;

        // Index 0: records sent; index 1: records received
        private final int[] firstEpochBits = new int[]{ -1, -1 };
        private final int[] logicalEpoch = new int[]{ -1, -1 };
        private final StringBuffer[] epochTrail = new StringBuffer[]{ new StringBuffer(), new StringBuffer() };
        private final int[] datagrams = new int[2];

        WireMonitor(DatagramTransport transport, boolean isClient)
        {
            this.transport = transport;
            this.isClient = isClient;
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
            int length = transport.receive(buf, off, len, waitMillis);
            if (length >= 0)
            {
                inspect(buf, off, length, false);
            }
            return length;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            inspect(buf, off, len, true);
            transport.send(buf, off, len);
        }

        public void close() throws IOException
        {
            transport.close();
        }

        synchronized int getHelloRetryRequests()
        {
            return helloRetryRequests;
        }

        /**
         * The number of key updates seen in one direction: advances of the write epoch past 3, the first
         * application data epoch (RFC 9147 sec. 6.1).
         */
        synchronized int getUpdates(boolean sent)
        {
            int dir = sent ? 0 : 1;
            return Math.max(0, logicalEpoch[dir] - 3);
        }

        synchronized String summary()
        {
            StringBuffer sb = new StringBuffer();
            sb.append("datagramsSent=").append(datagrams[0]).append(" datagramsReceived=").append(datagrams[1]);
            sb.append(" clientHelloDatagrams=").append(clientHelloDatagrams);
            sb.append(" clientHelloMessageSeqs=").append(Integer.toBinaryString(clientHelloSeqs));
            sb.append(" helloRetryRequests=").append(helloRetryRequests);
            if (null != helloRetryRequestDetail)
            {
                sb.append(" [").append(helloRetryRequestDetail).append(']');
            }
            sb.append(" epochsSent=").append(epochTrail[0]).append(" epochsReceived=").append(epochTrail[1]);
            sb.append(" keyUpdatesSent=").append(getUpdates(true)).append(" keyUpdatesReceived=")
                .append(getUpdates(false));
            return sb.toString();
        }

        private synchronized void inspect(byte[] buf, int off, int len, boolean sent)
        {
            int dir = sent ? 0 : 1;
            ++datagrams[dir];

            try
            {
                int pos = 0;
                while (pos < len)
                {
                    int b0 = buf[off + pos] & 0xFF;
                    if ((b0 & 0xE0) == 0x20)
                    {
                        // RFC 9147 4. Unified header: 001CSLEE
                        noteEpochBits(dir, b0 & 0x03);
                        if ((b0 & 0x10) != 0 || (b0 & 0x04) == 0)
                        {
                            // A connection ID of unknown length, or no length field: the record runs to the end
                            break;
                        }
                        int headerLength = 1 + ((b0 & 0x08) != 0 ? 2 : 1);
                        if (pos + headerLength + 2 > len)
                        {
                            break;
                        }
                        int length = TlsUtils.readUint16(buf, off + pos + headerLength);
                        pos += headerLength + 2 + length;
                    }
                    else if (b0 >= 20 && b0 <= 26)
                    {
                        // DTLSPlaintext (RFC 9147 4): type(1) version(2) epoch(2) sequence(6) length(2)
                        if (pos + 13 > len)
                        {
                            break;
                        }
                        int epoch = TlsUtils.readUint16(buf, off + pos + 3);
                        int length = TlsUtils.readUint16(buf, off + pos + 11);
                        int available = Math.min(length, len - pos - 13);
                        if (b0 == 22 && epoch == 0)
                        {
                            inspectHandshake(buf, off + pos + 13, available, sent);
                        }
                        pos += 13 + length;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            catch (RuntimeException e)
            {
                System.out.println("WIRE: could not parse a " + len + "-byte datagram: " + e);
            }
        }

        private void noteEpochBits(int dir, int bits)
        {
            if (logicalEpoch[dir] < 0)
            {
                // The first protected record is at the handshake epoch 2, or for a late joiner 3
                logicalEpoch[dir] = 2 + ((bits - 2) & 3);
                firstEpochBits[dir] = bits;
                epochTrail[dir].append(logicalEpoch[dir]);
            }
            else if (bits == ((logicalEpoch[dir] + 1) & 3))
            {
                ++logicalEpoch[dir];
                epochTrail[dir].append(',').append(logicalEpoch[dir]);
            }
        }

        private void inspectHandshake(byte[] buf, int off, int len, boolean sent)
        {
            boolean sawClientHello = false;

            int pos = 0;
            while (pos + 12 <= len)
            {
                short msgType = TlsUtils.readUint8(buf, off + pos);
                int length = TlsUtils.readUint24(buf, off + pos + 1);
                int messageSeq = TlsUtils.readUint16(buf, off + pos + 4);
                int fragmentOffset = TlsUtils.readUint24(buf, off + pos + 6);
                int fragmentLength = TlsUtils.readUint24(buf, off + pos + 9);
                int body = off + pos + 12;
                int available = Math.min(fragmentLength, len - pos - 12);

                if (msgType == 1 && fragmentOffset == 0)
                {
                    sawClientHello = true;
                    if (messageSeq < 31)
                    {
                        clientHelloSeqs |= (1 << messageSeq);
                    }
                }
                else if (msgType == 2 && fragmentOffset == 0 && available >= 34
                    && Arrays.areEqual(HELLO_RETRY_REQUEST_RANDOM, Arrays.copyOfRange(buf, body + 2, body + 34)))
                {
                    ++helloRetryRequests;
                    if (fragmentLength == length && available == length)
                    {
                        helloRetryRequestDetail = describeHelloRetryRequest(buf, body, length);
                    }
                    System.out.println("WIRE: HelloRetryRequest " + (sent ? "sent" : "received") + ": "
                        + helloRetryRequestDetail);
                }

                pos += 12 + fragmentLength;
            }

            if (sawClientHello)
            {
                ++clientHelloDatagrams;
            }
        }

        private static String describeHelloRetryRequest(byte[] buf, int off, int len)
        {
            int end = off + len;
            int pos = off + 2 + 32;
            int sessionIdLength = TlsUtils.readUint8(buf, pos);
            pos += 1 + sessionIdLength;
            int cipherSuite = TlsUtils.readUint16(buf, pos);
            pos += 2 + 1;
            int extensionsLength = TlsUtils.readUint16(buf, pos);
            pos += 2;

            StringBuffer sb = new StringBuffer();
            sb.append("cipher_suite=").append(getCipherSuiteName(cipherSuite));
            sb.append(" legacy_session_id_echo=").append(sessionIdLength).append(" bytes");
            sb.append(" extensions:");

            int extensionsEnd = Math.min(end, pos + extensionsLength);
            while (pos + 4 <= extensionsEnd)
            {
                int type = TlsUtils.readUint16(buf, pos);
                int length = TlsUtils.readUint16(buf, pos + 2);
                int data = pos + 4;
                if (type == 43 && length == 2)
                {
                    sb.append(" supported_versions=0x").append(Integer.toHexString(TlsUtils.readUint16(buf, data)));
                }
                else if (type == 51 && length == 2)
                {
                    sb.append(" key_share(selected_group=")
                        .append(NamedGroup.getName(TlsUtils.readUint16(buf, data))).append(')');
                }
                else if (type == 44 && length >= 2)
                {
                    sb.append(" cookie(").append(TlsUtils.readUint16(buf, data)).append(" bytes)");
                }
                else
                {
                    sb.append(" type_").append(type).append('(').append(length).append(" bytes)");
                }
                pos = data + length;
            }
            return sb.toString();
        }
    }
}
