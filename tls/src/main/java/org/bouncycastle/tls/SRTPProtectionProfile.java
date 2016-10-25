package org.bouncycastle.tls;

public class SRTPProtectionProfile
{
    /*
     * RFC 5764 4.1.2.
     */
    public static final int SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001;
    public static final int SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002;
    public static final int SRTP_NULL_HMAC_SHA1_80 = 0x0005;
    public static final int SRTP_NULL_HMAC_SHA1_32 = 0x0006;

    /*
     * RFC 7714 14.2.
     */
    public static final int SRTP_AEAD_AES_128_GCM = 0x0007;
    public static final int SRTP_AEAD_AES_256_GCM = 0x0008;
}
