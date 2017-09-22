package com.github.gv2011.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

/**
 * @deprecated use BEROctetString
 */
@Deprecated
public class BERConstructedOctetString
    extends BEROctetString
{
    private static final int MAX_LENGTH = 1000;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private byte[] toBytes(
        final Vector  octs)
    {
        final ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        for (int i = 0; i != octs.size(); i++)
        {
            try
            {
                final DEROctetString  o = (DEROctetString)octs.elementAt(i);

                bOut.write(o.getOctets());
            }
            catch (final ClassCastException e)
            {
                throw new IllegalArgumentException(octs.elementAt(i).getClass().getName() + " found in input should only contain DEROctetString");
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("exception converting octets " + e.toString());
            }
        }

        return bOut.toByteArray();
    }

    private Vector  octs;

    /**
     * @param string the octets making up the octet string.
     */
    public BERConstructedOctetString(
        final byte[]  string)
    {
        super(string);
    }

    public BERConstructedOctetString(
        final Vector  octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    public BERConstructedOctetString(
        final ASN1Primitive  obj)
    {
        super(toByteArray(obj));
    }

    private static byte[] toByteArray(final ASN1Primitive obj)
    {
        return obj.getEncoded();
    }

    public BERConstructedOctetString(
        final ASN1Encodable  obj)
    {
        this(obj.toASN1Primitive());
    }

    @Override
    public byte[] getOctets()
    {
        return string;
    }

    /**
     * return the DER octets that make up this string.
     */
    @Override
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return octs.elements();
    }

    private Vector generateOcts()
    {
        final Vector vec = new Vector();
        for (int i = 0; i < string.length; i += MAX_LENGTH)
        {
            int end;

            if (i + MAX_LENGTH > string.length)
            {
                end = string.length;
            }
            else
            {
                end = i + MAX_LENGTH;
            }

            final byte[] nStr = new byte[end - i];

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(nStr));
         }

         return vec;
    }

    public static BEROctetString fromSequence(final ASN1Sequence seq)
    {
        final Vector      v = new Vector();
        final Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            v.addElement(e.nextElement());
        }

        return new BERConstructedOctetString(v);
    }
}
