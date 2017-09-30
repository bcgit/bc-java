package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.util.Enumeration;
import java.util.Vector;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

public class BEROctetString extends ASN1OctetString {

    private static final int MAX_LENGTH = 1000;

    private ASN1OctetString[] octs;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private Bytes toBytes(
        final ASN1OctetString[]  octs)
    {
      final BytesBuilder bOut = newBytesBuilder();

        for (int i = 0; i != octs.length; i++)
        {
            try
            {
                final DEROctetString o = (DEROctetString)octs[i];

                o.getOctets().write(bOut);
            }
            catch (final ClassCastException e)
            {
                throw new IllegalArgumentException(octs[i].getClass().getName() + " found in input should only contain DEROctetString");
            }
        }

        return bOut.build();
    }

    /**
     * @param string the octets making up the octet string.
     */
    public BEROctetString(
        final Bytes string)
    {
        super(string);
    }

    public BEROctetString(
        final ASN1OctetString[] octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    /**
     * return the DER octets that make up this string.
     */
    @SuppressWarnings("rawtypes")
    public Enumeration getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return new Enumeration()
        {
            int counter = 0;

            @Override
            public boolean hasMoreElements()
            {
                return counter < octs.length;
            }

            @Override
            public Object nextElement()
            {
                return octs[counter++];
            }
        };
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

    @Override
    boolean isConstructed()
    {
        return true;
    }

    @SuppressWarnings("rawtypes")
    @Override
    int encodedLength()
    {
        int length = 0;
        for (final Enumeration e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public void encode(
        final ASN1OutputStream out)
    {
        out.write(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);

        out.write(0x80);

        //
        // write out the octet array
        //
        for (final Enumeration e = getObjects(); e.hasMoreElements();)
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }

    @SuppressWarnings("rawtypes")
    static BEROctetString fromSequence(final ASN1Sequence seq)
    {
        final ASN1OctetString[]     v = new ASN1OctetString[seq.size()];
        final Enumeration e = seq.getObjects();
        int                   index = 0;

        while (e.hasMoreElements())
        {
            v[index++] = (ASN1OctetString)e.nextElement();
        }

        return new BEROctetString(v);
    }
}
