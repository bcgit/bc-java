package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;

/**
 * base class for an ECDSA Public Key.
 */
public class ECDSAPublicBCPGKey
    extends ECPublicBCPGKey
{

    /**
     * @param in the stream to read the packet from.
     * @throws PGPException
     */
    protected ECDSAPublicBCPGKey(
        BCPGInputStream    in)
        throws IOException, PGPException
    {
        super(in, null);
    }

    protected ECDSAPublicBCPGKey(
        ECPoint                 point,
        ASN1ObjectIdentifier      oid)
    {
        super(point, oid);
    }

}
