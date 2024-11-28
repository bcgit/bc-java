package org.bouncycastle.asn1.cryptlib;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CryptlibObjectIdentifiers
{
    public static final ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");

    public static final ASN1ObjectIdentifier ecc = cryptlib.branch("1").branch("5");

    /**
     * Curve25519Legacy for use with ECDH.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#ec-curves">
     * RFC9580 - ECC Curves for OpenPGP</a>
     */
    public static final ASN1ObjectIdentifier curvey25519 = ecc.branch("1");
}
