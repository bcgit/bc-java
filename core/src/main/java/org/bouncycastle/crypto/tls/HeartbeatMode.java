package org.bouncycastle.crypto.tls;

/*
 * RFC 6520
 *
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class HeartbeatMode
{
    public static final short peer_allowed_to_send = 1;
    public static final short peer_not_allowed_to_send = 2;

    public static boolean isValid(short heartbeatMode)
    {
        return heartbeatMode >= peer_allowed_to_send && heartbeatMode <= peer_not_allowed_to_send;
    }
}
