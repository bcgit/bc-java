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

        private static final int RECORD_HEADER_LENGTH = FilteredDatagramTransport.RECORD_HEADER_LENGTH;

        boolean sawChangeCipherSpec = false;
        boolean sawEpoch1Handshake = false;

        private boolean isChangeCipherSpec(byte[] buf, int off)
        {
            short contentType = TlsUtils.readUint8(buf, off);
            return ContentType.change_cipher_spec == contentType;
        }

        private boolean isEpoch1Handshake(byte[] buf, int off)
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
            /*
             * A datagram may carry several records (the record layer now packs handshake flights), so every
             * record has to be examined; when each datagram held exactly one record, looking at the first was
             * the same thing.
             */
            boolean hasChangeCipherSpec = false;
            boolean hasEpoch1Handshake = false;

            int pos = off;
            int end = off + len;

            while (pos + RECORD_HEADER_LENGTH <= end)
            {
                int recordLength = TlsUtils.readUint16(buf, pos + 11);

                if (isChangeCipherSpec(buf, pos))
                {
                    hasChangeCipherSpec = true;
                }
                else if (isEpoch1Handshake(buf, pos))
                {
                    hasEpoch1Handshake = true;
                }

                if (recordLength > end - (pos + RECORD_HEADER_LENGTH))
                {
                    // NOTE: Malformed or truncated record - stop rather than read past the datagram
                    break;
                }
                pos += RECORD_HEADER_LENGTH + recordLength;
            }

            boolean drop = false;
            if (!sawChangeCipherSpec && hasChangeCipherSpec)
            {
                sawChangeCipherSpec = true;
                drop = true;
            }
            if (!sawEpoch1Handshake && hasEpoch1Handshake)
            {
                sawEpoch1Handshake = true;
                drop = true;
            }
            return !drop;
        }
    }
}
