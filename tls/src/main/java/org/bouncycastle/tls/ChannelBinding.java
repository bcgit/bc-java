package org.bouncycastle.tls;

/**
 * RFC 5056
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class ChannelBinding
{
    /*
     * RFC 5929
     */
    public static final int tls_server_end_point = 0;
    public static final int tls_unique = 1;
    public static final int tls_unique_for_telnet = 2;
}
