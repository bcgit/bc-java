package org.bouncycastle.tls;

/*
 * RFC 6520
 */
public class HeartbeatMode
{
    public static final short peer_allowed_to_send = 1;
    public static final short peer_not_allowed_to_send = 2;

    public static String getName(short heartbeatMode)
    {
        switch (heartbeatMode)
        {
        case peer_allowed_to_send:
            return "peer_allowed_to_send";
        case peer_not_allowed_to_send:
            return "peer_not_allowed_to_send";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short heartbeatMode)
    {
        return getName(heartbeatMode) + "(" + heartbeatMode + ")";
    }

    public static boolean isValid(short heartbeatMode)
    {
        return heartbeatMode >= peer_allowed_to_send && heartbeatMode <= peer_not_allowed_to_send;
    }
}
