package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Base class for an ECDSA Public Key.
 * This type is used with {@link PublicKeyAlgorithmTags#ECDSA} and the curve is identified by providing an OID.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ec">
 *     OpenPGP - Algorithm-Specific Parts for ECDSA Keys</a>
 */
public class ECDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected ECDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
    }

    public ECDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public ECDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
        throws IOException
    {
        super(oid, encodedPoint);
    }

}
