package org.bouncycastle.tls.test;

import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsUtils;

/** This is a [Transport] wrapper which causes the first retransmission of the second flight of a server
 * handshake to be dropped. */
public class ServerHandshakeDropper extends FilteredDatagramTransport
{
    public ServerHandshakeDropper(DatagramTransport transport, boolean dropOnReceive)
    {
        super(transport,
            dropOnReceive ? new DropFirstServerFinalFlight() : ALWAYS_ALLOW,
            dropOnReceive ? ALWAYS_ALLOW : new DropFirstServerFinalFlight()
        );
    }

    /** This drops the first instance of DTLS packets that either begin with a ChangeCipherSpec, or handshake in
     * epoch 1.  This is the server's final flight of the handshake.  It will test whether the client properly
     * retransmits its second flight, and the server properly retransmits the dropped flight.
     */
    private static class DropFirstServerFinalFlight implements FilteredDatagramTransport.FilterPredicate {

        boolean sawChangeCipherSpec = false;
        boolean sawEpoch1Handshake = false;

        private boolean isChangeCipherSpec(byte[] buf, int off, int len)
        {
            short contentType = TlsUtils.readUint8(buf, off);
            return ContentType.change_cipher_spec == contentType;
        }

        private boolean isEpoch1Handshake(byte[] buf, int off, int len)
        {
            short contentType = TlsUtils.readUint8(buf, off);
            if (ContentType.handshake != contentType)
            {
                return false;
            }

            int epoch = TlsUtils.readUint16(buf, off + 3);
            return 1 == epoch;
        }

        public boolean allowPacket(byte[] buf, int off, int len)
        {
            if (!sawChangeCipherSpec && isChangeCipherSpec(buf, off, len))
            {
                sawChangeCipherSpec = true;
                return false;
            }
            if (!sawEpoch1Handshake && isEpoch1Handshake(buf, off, len)) {
                sawEpoch1Handshake = true;
                return false;
            }
            return true;
        }
    }
}
