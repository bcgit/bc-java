package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.util.Enumeration;
import java.util.Vector;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

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
    @SuppressWarnings("rawtypes")
    static private Bytes toBytes(
        final Vector  octs)
    {
      final BytesBuilder bOut = newBytesBuilder();

        for (int i = 0; i != octs.size(); i++)
        {
            try
            {
                final DEROctetString  o = (DEROctetString)octs.elementAt(i);

                o.getOctets().write(bOut);
            }
            catch (final ClassCastException e){
              throw new IllegalArgumentException(
                octs.elementAt(i).getClass().getName() + " found in input should only contain DEROctetString"
              );
            }
        }

        return bOut.build();
    }

    @SuppressWarnings("rawtypes")
    private Vector  octs;

    /**
     * @param string the octets making up the octet string.
     */
    public BERConstructedOctetString(final Bytes string){
        super(string);
    }

    @SuppressWarnings("rawtypes")
    public BERConstructedOctetString(
        final Vector  octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    public BERConstructedOctetString(final ASN1Primitive obj) {
        super(obj.getEncoded());
    }

    public BERConstructedOctetString(
        final ASN1Encodable  obj)
    {
        this(obj.toASN1Primitive());
    }


    /**
     * return the DER octets that make up this string.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return octs.elements();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Vector generateOcts()
    {
        final Vector vec = new Vector();
        for (int i = 0; i < string.size(); i += MAX_LENGTH)
        {
            int end;

            if (i + MAX_LENGTH > string.size())
            {
                end = string.size();
            }
            else
            {
                end = i + MAX_LENGTH;
            }

            final byte[] nStr = new byte[end - i];

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(newBytes(nStr)));
         }

         return vec;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
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
