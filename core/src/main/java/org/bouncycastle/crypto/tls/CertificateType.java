package org.bouncycastle.crypto.tls;

/**
 * RFC 6091 
 *
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class CertificateType
{
    public static final short X509 = 0;
    public static final short OpenPGP = 1;
    
    /*
     * RFC 7250
     */
    public static final short RawPublicKey = 2;
}
