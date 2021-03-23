package org.bouncycastle.tls;

public class SignatureScheme
{
    /*
     * RFC 8446
     */

    public static final int rsa_pkcs1_sha1 = 0x0201;
    public static final int ecdsa_sha1 = 0x0203;

    public static final int rsa_pkcs1_sha256 = 0x0401;
    public static final int rsa_pkcs1_sha384 = 0x0501;
    public static final int rsa_pkcs1_sha512 = 0x0601;

    public static final int ecdsa_secp256r1_sha256 = 0x0403;
    public static final int ecdsa_secp384r1_sha384 = 0x0503;
    public static final int ecdsa_secp521r1_sha512 = 0x0603;

    public static final int rsa_pss_rsae_sha256 = 0x0804;
    public static final int rsa_pss_rsae_sha384 = 0x0805;
    public static final int rsa_pss_rsae_sha512 = 0x0806;

    public static final int ed25519 = 0x0807;
    public static final int ed448 = 0x0808;

    public static final int rsa_pss_pss_sha256 = 0x0809;
    public static final int rsa_pss_pss_sha384 = 0x080A;
    public static final int rsa_pss_pss_sha512 = 0x080B;

    /*
     * RFC 8734
     */

    public static final int ecdsa_brainpoolP256r1tls13_sha256 = 0x081A;
    public static final int ecdsa_brainpoolP384r1tls13_sha384 = 0x081B;
    public static final int ecdsa_brainpoolP512r1tls13_sha512 = 0x081C;

    /*
     * RFC 8998
     */

    public static final int sm2sig_sm3 = 0x0708;

    /*
     * RFC 8446 reserved for private use (0xFE00..0xFFFF)
     */

    public static String getName(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case rsa_pkcs1_sha1:
            return "rsa_pkcs1_sha1";
        case ecdsa_sha1:
            return "ecdsa_sha1";
        case rsa_pkcs1_sha256:
            return "rsa_pkcs1_sha256";
        case rsa_pkcs1_sha384:
            return "rsa_pkcs1_sha384";
        case rsa_pkcs1_sha512:
            return "rsa_pkcs1_sha512";
        case ecdsa_secp256r1_sha256:
            return "ecdsa_secp256r1_sha256";
        case ecdsa_secp384r1_sha384:
            return "ecdsa_secp384r1_sha384";
        case ecdsa_secp521r1_sha512:
            return "ecdsa_secp521r1_sha512";
        case rsa_pss_rsae_sha256:
            return "rsa_pss_rsae_sha256";
        case rsa_pss_rsae_sha384:
            return "rsa_pss_rsae_sha384";
        case rsa_pss_rsae_sha512:
            return "rsa_pss_rsae_sha512";
        case ed25519:
            return "ed25519";
        case ed448:
            return "ed448";
        case rsa_pss_pss_sha256:
            return "rsa_pss_pss_sha256";
        case rsa_pss_pss_sha384:
            return "rsa_pss_pss_sha384";
        case rsa_pss_pss_sha512:
            return "rsa_pss_pss_sha512";
        case ecdsa_brainpoolP256r1tls13_sha256:
            return "ecdsa_brainpoolP256r1tls13_sha256";
        case ecdsa_brainpoolP384r1tls13_sha384:
            return "ecdsa_brainpoolP384r1tls13_sha384";
        case ecdsa_brainpoolP512r1tls13_sha512:
            return "ecdsa_brainpoolP512r1tls13_sha512";
        case sm2sig_sm3:
            return "sm2sig_sm3";
        default:
            return "UNKNOWN";
        }
    }

    /**
     * For TLS 1.3+ usage, some signature schemes are constrained to use a particular
     * ({@link NamedGroup}. Not relevant for TLS 1.2 and below.
     */
    public static int getNamedGroup(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case ecdsa_brainpoolP256r1tls13_sha256:
            return NamedGroup.brainpoolP256r1tls13;
        case ecdsa_brainpoolP384r1tls13_sha384:
            return NamedGroup.brainpoolP384r1tls13;
        case ecdsa_brainpoolP512r1tls13_sha512:
            return NamedGroup.brainpoolP512r1tls13;
        case ecdsa_secp256r1_sha256:
            return NamedGroup.secp256r1;
        case ecdsa_secp384r1_sha384:
            return NamedGroup.secp384r1;
        case ecdsa_secp521r1_sha512:
            return NamedGroup.secp521r1;
        case sm2sig_sm3:
            return NamedGroup.curveSM2;
        default:
            return -1;
        }
    }

    public static short getIntrinsicHashAlgorithm(int signatureScheme)
    {
        // TODO[RFC 8998] sm2sig_sm3
        switch (signatureScheme)
        {
        case ecdsa_brainpoolP256r1tls13_sha256:
        case rsa_pss_pss_sha256:
        case rsa_pss_rsae_sha256:
            return HashAlgorithm.sha256;
        case ecdsa_brainpoolP384r1tls13_sha384:
        case rsa_pss_pss_sha384:
        case rsa_pss_rsae_sha384:
            return HashAlgorithm.sha384;
        case ecdsa_brainpoolP512r1tls13_sha512:
        case rsa_pss_pss_sha512:
        case rsa_pss_rsae_sha512:
            return HashAlgorithm.sha512;
        case ed25519:
        case ed448:
        default:
            return -1;
        }
    }

    /** @deprecated Use {@link #getIntrinsicHashAlgorithm(int)} instead. */
    public static short getRSAPSSHashAlgorithm(int signatureScheme)
    {
        return getIntrinsicHashAlgorithm(signatureScheme);
    }

    public static short getHashAlgorithm(int signatureScheme)
    {
        // TODO[RFC 8998] sm2sig_sm3
        return (short)((signatureScheme >>> 8) & 0xFF);
    }

    public static short getSignatureAlgorithm(int signatureScheme)
    {
        // TODO[RFC 8998] sm2sig_sm3
        return (short)(signatureScheme & 0xFF);
    }

    public static String getText(int signatureScheme)
    {
        return getName(signatureScheme) + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }

    public static boolean isPrivate(int signatureScheme)
    {
        return (signatureScheme >>> 9) == 0xFE; 
    }
}
