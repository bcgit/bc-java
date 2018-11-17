package org.bouncycastle.tls;

/**
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class RenegotiationPolicy
{
    public static final int DENY = 0;
    public static final int IGNORE = 1;
    public static final int ACCEPT = 2;
}
