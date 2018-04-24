package org.bouncycastle.tls;

/**
 * RFC 5246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class PRFAlgorithm
{
    /*
     * Placeholder to refer to the legacy TLS algorithm
     */
    public static final int tls_prf_legacy = 0;

    public static final int tls_prf_sha256 = 1;

    /*
     * Implied by RFC 5288
     */
    public static final int tls_prf_sha384 = 2;

    public static String getName(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case tls_prf_legacy:
            return "tls_prf_legacy";
        case tls_prf_sha256:
            return "tls_prf_sha256";
        case tls_prf_sha384:
            return "tls_prf_sha384";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(int prfAlgorithm)
    {
        return getName(prfAlgorithm) + "(" + prfAlgorithm + ")";
    }
}
