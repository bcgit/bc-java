package org.bouncycastle.crypto.tls;

/**
 * RFC 2246
 * 
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class PRFAlgorithm {

    public static final int tls_prf_sha256 = 0;

    /*
     * Implied by RFC 5288
     */
    public static final int tls_prf_sha384 = 1;
}
