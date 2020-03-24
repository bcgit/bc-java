package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.math.ec.ECPoint;

/**
 * base class for an EC Public Key.
 */
public abstract class ECPublicBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    ASN1ObjectIdentifier oid;
    BigInteger point;

    /**
     * @param in the stream to read the packet from.
     */
    protected ECPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        this.oid = ASN1ObjectIdentifier.getInstance(ASN1Primitive.fromByteArray(readBytesOfEncodedLength(in)));
        this.point = new MPInteger(in).getValue();
    }

    protected ECPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        this.point = new BigInteger(1, point.getEncoded(false));
        this.oid = oid;
    }

    protected ECPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        BigInteger encodedPoint)
    {
        this.point = encodedPoint;
        this.oid = oid;
    }

    /**
     * return "PGP"
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
            return super.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        byte[] oid = this.oid.getEncoded();
        out.write(oid, 1, oid.length - 1);

        MPInteger point = new MPInteger(this.point);
        out.writeObject(point);
    }

    /**
     * @return point
     */
    public BigInteger getEncodedPoint()
    {
        return point;
    }

    /**
     * @return oid
     */
    public ASN1ObjectIdentifier getCurveOID()
    {
        return oid;
    }

    protected static byte[] readBytesOfEncodedLength(
        BCPGInputStream in)
        throws IOException
    {
        int length = in.read();
        if (length < 0)
        {
            throw new IOException("unexpected end-of-stream");
        }
        if (length == 0 || length == 0xFF)
        {
            throw new IOException("future extensions not yet implemented");
        }
        if (length > 127)
        {
            throw new IOException("unsupported OID");
        }

        byte[] buffer = new byte[length + 2];
        in.readFully(buffer, 2, buffer.length - 2);
        buffer[0] = (byte)0x06;
        buffer[1] = (byte)length;

        return buffer;
    }
}
