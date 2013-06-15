package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;

/**
 * base class for an EC Public Key.
 */
public abstract class ECPublicBCPGKey
    extends BCPGObject implements BCPGKey
{
    ASN1ObjectIdentifier   oid;
    ECPoint              point;

    /**
     * @param in the stream to read the packet from.
     * @throws PGPException
     */
    protected ECPublicBCPGKey(
        BCPGInputStream        in,
        ASN1ObjectIdentifier  oid)
        throws IOException, PGPException
    {
        this.oid = oid != null ? oid : (ASN1ObjectIdentifier)ASN1Primitive.fromByteArray(readBytesOfEncodedLength(in));
    }

    protected ECPublicBCPGKey(
        ECPoint                  point,
        ASN1ObjectIdentifier       oid)
    {
        this.point = point;
        this.oid = oid;
    }

    protected ECPublicBCPGKey(
        BigInteger              encodedPoint,
        ASN1ObjectIdentifier             oid)
        throws PGPException
    {
        this.point = decodePoint(encodedPoint, oid);
        this.oid = oid;
    }

    /**
     *  return "PGP"
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getFormat()
     */
    public String getFormat()
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
     */
    public byte[] getEncoded()
    {
        try
        {
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            BCPGOutputStream         pgpOut = new BCPGOutputStream(bOut);

            pgpOut.writeObject(this);

            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        byte[] oid = this.oid.getEncoded();
        out.write(oid.length);
        out.write(oid);

        MPInteger point = new MPInteger(new BigInteger(1, this.point.getEncoded()));
        out.writeObject(point);
    }

    /**
     * @return point
     */
    public ECPoint getPoint()
    {
        return point;
    }

    /**
     * @return oid
     */
    public ASN1ObjectIdentifier getOid()
    {
        return oid;
    }

    protected static byte[] readBytesOfEncodedLength(
        BCPGInputStream in)
        throws PGPException, IOException
    {
        int length = in.read();
        if (length == 0 || length == 0xFF)
            throw new PGPException("future extensions not yet implemented.");

        byte[] buffer = new byte[length];
        in.readFully(buffer);
        return buffer;
    }

    private static ECPoint decodePoint(
        BigInteger             encodedPoint,
        ASN1ObjectIdentifier            oid)
        throws PGPException
    {
        X9ECParameters curve = ECNamedCurveTable.getByOID(oid);
        if (curve == null)
            throw new PGPException(oid.getId() + " does not match any known curve.");
        if (!(curve.getCurve() instanceof ECCurve.Fp))
            throw new PGPException("Only FPCurves are supported.");

        return curve.getCurve().decodePoint(encodedPoint.toByteArray());
    }

}
