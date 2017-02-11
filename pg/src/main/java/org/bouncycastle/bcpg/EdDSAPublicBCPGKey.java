package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;


/**
 * base class for an ECDSA Public Key.
 */
public class EdDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    private static final ASN1ObjectIdentifier OID_Ed25519 = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.15.1");

    /**
     * @param in the stream to read the packet from.
     */
    protected EdDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);

        if (!OID_Ed25519.equals(oid))
        {
            throw new IOException("Invalid curve oid for EdDSA key!");
        }
    }

    public EdDSAPublicBCPGKey(
           BigInteger encodedPoint)
        throws IOException
    {
        super(OID_Ed25519, encodedPoint);
    }

    public static EdDSAPublicBCPGKey fromEdDSAEncodedPoint(
            byte[] eddsaEncodedPoint)
        throws IOException
    {
        byte[] openpgpEncodedPoint = new byte[eddsaEncodedPoint.length + 1];
        openpgpEncodedPoint[0] = 0x40;
        System.arraycopy(eddsaEncodedPoint, 0, openpgpEncodedPoint, 1, eddsaEncodedPoint.length);
        return new EdDSAPublicBCPGKey(BigIntegers.fromUnsignedByteArray(openpgpEncodedPoint));
    }

    public byte[] getEdDSAEncodedPoint()
    {
        BigInteger encodedPoint = getEncodedPoint();
        byte[] pointData = BigIntegers.asUnsignedByteArray(encodedPoint);
        if (pointData[0] != 0x40)
        {
            throw new IllegalStateException("Invalid point format in EdDSA key!");
        }
        return Arrays.copyOfRange(pointData, 1, pointData.length);
    }

}
