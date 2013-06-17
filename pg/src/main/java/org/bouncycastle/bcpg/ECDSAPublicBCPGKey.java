package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;

/**
 * base class for an ECDSA Public Key.
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

    protected ECDSAPublicBCPGKey(
        ECPoint point,
        ASN1ObjectIdentifier oid)
    {
        super(point, oid);
    }

}
