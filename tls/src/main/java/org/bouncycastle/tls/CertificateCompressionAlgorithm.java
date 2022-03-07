package org.bouncycastle.tls;

/**
 * RFC 8879
 */
public class CertificateCompressionAlgorithm
{
    public static final int zlib = 1;
    public static final int brotli = 2;
    public static final int zstd = 3;

    public static String getName(int certificateCompressionAlgorithm)
    {
        switch (certificateCompressionAlgorithm)
        {
        case zlib:
            return "zlib";
        case brotli:
            return "brotli";
        case zstd:
            return "zstd";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(int certificateCompressionAlgorithm)
    {
        return getName(certificateCompressionAlgorithm) + "(" + certificateCompressionAlgorithm + ")";
    }

    public static boolean isRecognized(int certificateCompressionAlgorithm)
    {
        switch (certificateCompressionAlgorithm)
        {
        case zlib:
        case brotli:
        case zstd:
            return true;
        default:
            return false;
        }
    }
}
