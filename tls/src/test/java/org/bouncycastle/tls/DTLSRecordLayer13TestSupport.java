package org.bouncycastle.tls;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

/**
 * Paired-record-layer test harness shared by {@link DTLSRecordLayer13Test} and other DTLS 1.3 record layer
 * tests: two {@link DTLSRecordLayer}s wired together over in-memory {@link Queue}s.
 */
class DTLSRecordLayer13TestSupport
{
    private static final SecureRandom RANDOM = new SecureRandom();
    static final int MTU = 1500;

    /** One direction of a loopback: datagrams appended by the sender, popped by the receiver. */
    static class Queue
    {
        final Vector datagrams = new Vector();

        synchronized void put(byte[] datagram)
        {
            datagrams.addElement(datagram);
            notifyAll();
        }

        synchronized byte[] take(int waitMillis) throws IOException
        {
            if (datagrams.isEmpty())
            {
                if (waitMillis <= 0)
                {
                    return null;
                }

                try
                {
                    wait(waitMillis);
                }
                catch (InterruptedException e)
                {
                    throw new IOException("interrupted");
                }
                if (datagrams.isEmpty())
                {
                    return null;
                }
            }
            byte[] d = (byte[])datagrams.elementAt(0);
            datagrams.removeElementAt(0);
            return d;
        }

        synchronized byte[] peekLast()
        {
            return (byte[])datagrams.elementAt(datagrams.size() - 1);
        }
    }

    static class QueueTransport
        implements DatagramTransport
    {
        final Queue in, out;

        QueueTransport(Queue in, Queue out)
        {
            this.in = in;
            this.out = out;
        }

        public int getReceiveLimit()
        {
            return MTU;
        }

        public int getSendLimit()
        {
            return MTU;
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            byte[] d = in.take(waitMillis);
            if (null == d)
            {
                return -1;
            }
            int n = Math.min(len, d.length);
            System.arraycopy(d, 0, buf, off, n);
            return n;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            out.put(Arrays.copyOfRange(buf, off, off + len));
        }

        public void close()
        {
        }
    }

    static class Side
    {
        final AbstractTlsContext context;
        final DTLSRecordLayer recordLayer;

        Side(AbstractTlsContext context, DTLSRecordLayer recordLayer)
        {
            this.context = context;
            this.recordLayer = recordLayer;
        }
    }

    Queue clientToServer, serverToClient;
    Side client, server;

    void setUpPair(int cipherSuite, int hash) throws IOException
    {
        setUpPair(cipherSuite, hash, null, null);
    }

    /**
     * As {@link #setUpPair(int, int)}, but each side's completed-handshake transition is driven with its own
     * {@link DTLSHandshakeRetransmit}, retaining the handshake epoch (RFC 9147 5.8.1) for that side instead of
     * dropping it. Pass null for a side that should complete the handshake with nothing retained, exactly as
     * {@link #setUpPair(int, int)} does for both sides.
     */
    void setUpPair(int cipherSuite, int hash, DTLSHandshakeRetransmit clientRetransmit,
        DTLSHandshakeRetransmit serverRetransmit) throws IOException
    {
        TlsCrypto crypto = new BcTlsCrypto();
        byte[] clientSecret = new byte[48];
        byte[] serverSecret = new byte[48];
        RANDOM.nextBytes(clientSecret);
        RANDOM.nextBytes(serverSecret);

        clientToServer = new Queue();
        serverToClient = new Queue();

        client = createSide(crypto, false, cipherSuite, hash, clientSecret, serverSecret,
            new QueueTransport(serverToClient, clientToServer), clientRetransmit);
        server = createSide(crypto, true, cipherSuite, hash, clientSecret, serverSecret,
            new QueueTransport(clientToServer, serverToClient), serverRetransmit);
    }

    private static Side createSide(TlsCrypto crypto, boolean isServer, int cipherSuite, int hash,
        byte[] clientSecret, byte[] serverSecret, DatagramTransport transport,
        DTLSHandshakeRetransmit retransmit) throws IOException
    {
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, isServer, cipherSuite, hash,
            clientSecret, serverSecret);

        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };

        DTLSRecordLayer recordLayer = new DTLSRecordLayer(context, peer, transport);
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv12);
        recordLayer.setReadVersion(ProtocolVersion.DTLSv12);

        // epoch 2: handshake keys
        recordLayer.initPendingEpoch(TlsUtils.initCipher(context));
        checkEquals(2, recordLayer.getPendingEpoch());
        recordLayer.enablePendingEpochRead();
        recordLayer.enablePendingEpochWrite();

        // epoch 3: application keys (same secrets are fine for a record layer test)
        recordLayer.initPendingEpoch(TlsUtils.initCipher(context));
        checkEquals(3, recordLayer.getPendingEpoch());
        recordLayer.enablePendingEpochWrite();
        recordLayer.enablePendingEpochRead();
        recordLayer.handshakeSuccessful(retransmit);

        checkEquals(3, recordLayer.getReadEpoch());

        return new Side(context, recordLayer);
    }

    /** A DTLS 1.2 record layer, built the way {@code testLegacyHeaderPlaintextStillAcceptedAtEpochZero} does. */
    DTLSRecordLayer setUpLegacyLayer() throws IOException
    {
        TlsCrypto crypto = new BcTlsCrypto();
        Queue c2s = new Queue();
        Queue s2c = new Queue();
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, true,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);
        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };
        DTLSRecordLayer serverLayer = new DTLSRecordLayer(context, peer, new QueueTransport(c2s, s2c));
        serverLayer.setReadVersion(ProtocolVersion.DTLSv12);
        return serverLayer;
    }

    private static void checkEquals(int expected, int actual)
    {
        if (expected != actual)
        {
            throw new IllegalStateException("expected " + expected + " but was " + actual);
        }
    }

    static byte[] receive(Side side, int waitMillis) throws IOException
    {
        byte[] buf = new byte[side.recordLayer.getReceiveLimit()];
        int n = side.recordLayer.receive(buf, 0, buf.length, waitMillis);
        return n < 0 ? null : Arrays.copyOf(buf, n);
    }
}
