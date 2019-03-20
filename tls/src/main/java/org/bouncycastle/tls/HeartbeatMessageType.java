package org.bouncycastle.tls;

/*
 * RFC 6520 3.
 */
public class HeartbeatMessageType
{
    public static final short heartbeat_request = 1;
    public static final short heartbeat_response = 2;

    public static String getName(short heartbeatMessageType)
    {
        switch (heartbeatMessageType)
        {
        case heartbeat_request:
            return "heartbeat_request";
        case heartbeat_response:
            return "heartbeat_response";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short heartbeatMessageType)
    {
        return getName(heartbeatMessageType) + "(" + heartbeatMessageType + ")";
    }

    public static boolean isValid(short heartbeatMessageType)
    {
        return heartbeatMessageType >= heartbeat_request && heartbeatMessageType <= heartbeat_response;
    }
}
