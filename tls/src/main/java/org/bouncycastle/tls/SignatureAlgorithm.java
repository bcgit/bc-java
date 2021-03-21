package org.bouncycastle.tls;

/**
 * RFC 5246 7.4.1.4.1 (in RFC 2246, there were no specific values assigned)
 */
public class SignatureAlgorithm
{
    public static final short anonymous = 0;
    public static final short rsa = 1;
    public static final short dsa = 2;
    public static final short ecdsa = 3;


    /*
     * RFC 8422
     */
    public static final short ed25519 = 7;
    public static final short ed448 = 8;

    /*
     * RFC 8446 (implied from SignatureScheme values)
     */
    public static final short rsa_pss_rsae_sha256 = 4;
    public static final short rsa_pss_rsae_sha384 = 5;
    public static final short rsa_pss_rsae_sha512 = 6;
    public static final short rsa_pss_pss_sha256 = 9;
    public static final short rsa_pss_pss_sha384 = 10;
    public static final short rsa_pss_pss_sha512 = 11;

    /*
     * RFC 8734 (implied from SignatureScheme values)
     */
    public static final short ecdsa_brainpoolP256r1tls13_sha256 = 26;
    public static final short ecdsa_brainpoolP384r1tls13_sha384 = 27;
    public static final short ecdsa_brainpoolP512r1tls13_sha512 = 28;


    /*
     * GMSSL GMT 0009-2012
     */
    public static final short sm2 = 200;


    public static short getClientCertificateType(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return ClientCertificateType.rsa_sign;

        case SignatureAlgorithm.dsa:
            return ClientCertificateType.dss_sign;

        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.ed25519:
        case SignatureAlgorithm.ed448:
        case SignatureAlgorithm.sm2:
            return ClientCertificateType.ecdsa_sign;

        // NOTE: Only valid from TLS 1.3, where ClientCertificateType is not used
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
        default:
            return -1;
        }
    }

    public static String getName(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case anonymous:
            return "anonymous";
        case rsa:
            return "rsa";
        case dsa:
            return "dsa";
        case ecdsa:
            return "ecdsa";
        case ed25519:
            return "ed25519";
        case ed448:
            return "ed448";
        case rsa_pss_rsae_sha256:
            return "rsa_pss_rsae_sha256";
        case rsa_pss_rsae_sha384:
            return "rsa_pss_rsae_sha384";
        case rsa_pss_rsae_sha512:
            return "rsa_pss_rsae_sha512";
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
        case sm2:
            return "sm2";
        default:
            return "UNKNOWN";
        }
    }

    public static short getIntrinsicHashAlgorithm(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
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
    public static short getRSAPSSHashAlgorithm(short signatureAlgorithm)
    {
        return getIntrinsicHashAlgorithm(signatureAlgorithm);
    }

    public static String getText(short signatureAlgorithm)
    {
        return getName(signatureAlgorithm) + "(" + signatureAlgorithm + ")";
    }

    /** deprecated Will be removed. */
    public static boolean hasIntrinsicHash(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case ed25519:
        case ed448:
        case rsa_pss_rsae_sha256:
        case rsa_pss_rsae_sha384:
        case rsa_pss_rsae_sha512:
        case rsa_pss_pss_sha256:
        case rsa_pss_pss_sha384:
        case rsa_pss_pss_sha512:
        case ecdsa_brainpoolP256r1tls13_sha256:
        case ecdsa_brainpoolP384r1tls13_sha384:
        case ecdsa_brainpoolP512r1tls13_sha512:
            return true;
        default:
            return false;
        }
    }

    public static boolean isRSAPSS(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case rsa_pss_rsae_sha256:
        case rsa_pss_pss_sha256:
        case rsa_pss_rsae_sha384:
        case rsa_pss_pss_sha384:
        case rsa_pss_rsae_sha512:
        case rsa_pss_pss_sha512:
            return true;
        default:
            return false;
        }
    }
}
