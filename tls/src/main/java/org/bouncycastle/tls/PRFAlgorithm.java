package org.bouncycastle.tls;

/**
 * RFC 5246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class PRFAlgorithm
{
    public static final int ssl_prf_legacy = 0;
    public static final int tls_prf_legacy = 1;
    public static final int tls_prf_sha256 = 2;
    public static final int tls_prf_sha384 = 3;
    public static final int tls13_hkdf_sha256 = 4;
    public static final int tls13_hkdf_sha384 = 5;

    public static String getName(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case ssl_prf_legacy:
            return "ssl_prf_legacy";
        case tls_prf_legacy:
            return "tls_prf_legacy";
        case tls_prf_sha256:
            return "tls_prf_sha256";
        case tls_prf_sha384:
            return "tls_prf_sha384";
        case tls13_hkdf_sha256:
            return "tls13_hkdf_sha256";
        case tls13_hkdf_sha384:
            return "tls13_hkdf_sha384";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(int prfAlgorithm)
    {
        return getName(prfAlgorithm) + "(" + prfAlgorithm + ")";
    }
}
