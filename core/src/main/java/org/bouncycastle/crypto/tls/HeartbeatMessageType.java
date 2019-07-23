package org.bouncycastle.crypto.tls;

/*
 * RFC 6520 3.
 *
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class HeartbeatMessageType
{
    public static final short heartbeat_request = 1;
    public static final short heartbeat_response = 2;

    public static boolean isValid(short heartbeatMessageType)
    {
        return heartbeatMessageType >= heartbeat_request && heartbeatMessageType <= heartbeat_response;
    }
}
