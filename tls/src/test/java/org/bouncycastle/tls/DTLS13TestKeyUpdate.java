package org.bouncycastle.tls;

import java.io.IOException;

/**
 * Starts an RFC 9147 section 8 key update on a live {@link DTLSTransport}, for the end-to-end tests in
 * {@code org.bouncycastle.tls.test}, which cannot see the package-private machinery that owns one.
 * <p>
 * There is no application-facing "update my keys now" entry point on {@link DTLSTransport} - {@code
 * TlsProtocol} does not expose one for TLS either - so on a real connection a key update is started only by
 * the record layer's own sequence-number threshold or by a peer's {@code update_requested}. The threshold is
 * not usable from a test against a live peer: reaching it means jumping the write epoch's sequence number,
 * and RFC 9147 4.2.2 has the receiver reconstruct a sequence number as the value closest to the one it
 * expects, so a jump of 2^20 would be reconstructed as something near the peer's own count and the record
 * would fail to decrypt. This calls the sending state machine directly instead; everything from
 * {@code sendKeyUpdate} onwards - the derivation, the record on the wire, the acknowledgement gate, the
 * retransmit timer - is the production path.
 * </p>
 */
public class DTLS13TestKeyUpdate
{
    /**
     * @param requestUpdate whether to ask the peer for a key update in return (RFC 8446 4.6.3).
     */
    public static void sendKeyUpdate(DTLSTransport transport, boolean requestUpdate) throws IOException
    {
        short value = requestUpdate ? KeyUpdateRequest.update_requested : KeyUpdateRequest.update_not_requested;

        DTLS13PostHandshake postHandshake = transport.getRecordLayerForTest().getPostHandshake();
        if (null == postHandshake)
        {
            throw new IllegalStateException("no DTLS 1.3 post-handshake owner on this transport");
        }

        postHandshake.sendKeyUpdate(value);
    }
}
