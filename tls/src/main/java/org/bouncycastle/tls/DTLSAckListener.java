package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

/**
 * RFC 9147 7. Receives ACK records from the record layer. ACK is a content type rather than a handshake
 * message, so it does not reach the handshake through the normal message path.
 */
interface DTLSAckListener
{
    /**
     * @param recordNumbers the acknowledged {@link DTLSRecordNumber}s, in the order they appeared.
     */
    void receivedAck(Vector recordNumbers) throws IOException;
}
