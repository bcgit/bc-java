package org.bouncycastle.tls;

/**
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class NamedGroupRole
{
    public static final int dh = 1;
    public static final int ecdh = 2;
    public static final int ecdsa = 3;
}
