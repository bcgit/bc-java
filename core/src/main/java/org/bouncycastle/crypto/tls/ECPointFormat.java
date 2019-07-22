package org.bouncycastle.crypto.tls;

/**
 * RFC 4492 5.1.2
 *
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class ECPointFormat
{
    public static final short uncompressed = 0;
    public static final short ansiX962_compressed_prime = 1;
    public static final short ansiX962_compressed_char2 = 2;

    /*
     * reserved (248..255)
     */
}
