package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The length determinant (X.696 sec. 8.6) and the sequence-of quantity (sec. 17.2) are written
 * from a long directly rather than through a BigInteger; this pins the output to what the
 * BigInteger form produced, octet for octet, and to the decoder, across the octet-count boundaries.
 */
public class OERDeterminantTest
    extends TestCase
{
    private static final long[] COUNTS = { 0, 1, 2, 127, 128, 129, 255, 256, 257, 65535, 65536, 70000 };

    public void testLengthDeterminant()
        throws IOException
    {
        Element octets = OERDefinition.octets().build();
        for (int i = 0; i != COUNTS.length; i++)
        {
            int len = (int)COUNTS[i];
            byte[] content = new byte[len];
            Arrays.fill(content, (byte)0x5A);

            byte[] encoding = encode(new DEROctetString(content), octets);
            byte[] expected = Arrays.concatenate(determinant(len), content);
            assertTrue("length " + len, Arrays.areEqual(expected, encoding));

            DEROctetString decoded = (DEROctetString)OERInputStream.parse(encoding, octets);
            assertTrue("round trip " + len, Arrays.areEqual(content, decoded.getOctets()));
        }
    }

    public void testQuantity()
        throws IOException
    {
        Element seqOfBool = OERDefinition.seqof(OERDefinition.bool()).build();
        for (int i = 0; i != COUNTS.length; i++)
        {
            int count = (int)COUNTS[i];
            ASN1EncodableVector v = new ASN1EncodableVector(count);
            byte[] elements = new byte[count];
            for (int j = 0; j != count; j++)
            {
                v.add(ASN1Boolean.TRUE);
                elements[j] = (byte)0xFF;
            }

            byte[] encoding = encode(new DERSequence(v), seqOfBool);
            byte[] expected = Arrays.concatenate(quantity(count), elements);
            assertTrue("quantity " + count, Arrays.areEqual(expected, encoding));

            ASN1Sequence decoded = (ASN1Sequence)OERInputStream.parse(encoding, seqOfBool);
            assertEquals("round trip " + count, count, decoded.size());
        }
    }

    /** 8.6.4 / 8.6.5 as the BigInteger-based encoder wrote them. */
    private static byte[] determinant(long len)
    {
        if (len <= 127)
        {
            return new byte[]{ (byte)len };
        }
        byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(len));
        return Arrays.prepend(value, (byte)(0x80 | value.length));
    }

    /** 17.2 as the BigInteger-based encoder wrote it. */
    private static byte[] quantity(long count)
    {
        byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(count));
        return Arrays.prepend(value, (byte)value.length);
    }

    private static byte[] encode(ASN1Encodable value, Element schema)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OEROutputStream oerOut = new OEROutputStream(bOut);
        oerOut.write(value, schema);
        oerOut.flush();
        return bOut.toByteArray();
    }
}
