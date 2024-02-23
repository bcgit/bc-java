package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.Arrays;

/**
 * Public/Secret BCPGKey which is encoded as an array of octets rather than an MPI.
 */
public abstract class OctetArrayBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    private final byte[] key;
    ASN1ObjectIdentifier oid;
    BigInteger point;

    //TODO remove this method
    OctetArrayBCPGKey(BCPGInputStream in)
        throws IOException
    {
        this.oid = ASN1ObjectIdentifier.getInstance(ASN1Primitive.fromByteArray(readBytesOfEncodedLength(in)));
        this.point = new MPInteger(in).getValue();
        key = point.toByteArray();
    }

    public BigInteger getEncodedPoint()
    {
        return point;
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

    OctetArrayBCPGKey(int length, BCPGInputStream in)
        throws IOException
    {
        key = new byte[length];
        in.readFully(key);
    }

    OctetArrayBCPGKey(int length, byte[] key)
    {
        if (key.length != length)
        {
            throw new IllegalArgumentException("unexpected key encoding length: expected " + length + " bytes, got " + key.length);
        }
        this.key = new byte[length];
        System.arraycopy(key, 0, this.key, 0, length);
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
     */
    @Override
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

    @Override
    public String getFormat()
    {
        return "PGP";
    }

    @Override
    public void encode(BCPGOutputStream out)
        throws IOException
    {
        out.write(key);
//        //TODO
//        byte[] oid = this.oid.getEncoded();
//        out.write(oid, 1, oid.length - 1);
//
//        MPInteger point = new MPInteger(this.point);
//        out.writeObject(point);
    }

    public byte[] getKey()
    {
        return Arrays.clone(key);
    }
}
