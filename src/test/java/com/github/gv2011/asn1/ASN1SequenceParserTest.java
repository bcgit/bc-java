package com.github.gv2011.asn1;

import static com.github.gv2011.testutil.Matchers.is;
import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import com.github.gv2011.asn1.ASN1Integer;
import com.github.gv2011.asn1.ASN1Null;
import com.github.gv2011.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.asn1.ASN1SequenceParser;
import com.github.gv2011.asn1.ASN1StreamParser;
import com.github.gv2011.asn1.BERSequenceGenerator;
import com.github.gv2011.asn1.DERSequenceGenerator;
import com.github.gv2011.asn1.util.encoders.Hex;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class ASN1SequenceParserTest
    extends TestCase
{
    private static final Bytes seqData = Hex.decode("3006020100060129");
    private static final Bytes nestedSeqData = Hex.decode("300b0201000601293003020101");
    private static final Bytes expTagSeqData = Hex.decode("a1083006020100060129");
    private static final Bytes implTagSeqData = Hex.decode("a106020100060129");
    private static final Bytes nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
    private static final Bytes nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");

    private static final Bytes berSeqData = Hex.decode("30800201000601290000");
    private static final Bytes berDERNestedSeqData = Hex.decode("308002010006012930030201010000");
    private static final Bytes berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
    private static final Bytes berExpTagSeqData = Hex.decode("a180308002010006012900000000");

    private static final Bytes berSeqWithDERNullData = Hex.decode("308005000201000601290000");

    public void testDERWriting()
        throws Exception
    {
       final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut);

       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

       seqGen.close();

       assertThat("basic DER writing test failed.", bOut.build(), is(seqData));
    }

    public void testNestedDERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);

       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

       final DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());

       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

       seqGen2.close();

       seqGen1.close();

       assertThat("nested DER writing test failed.", bOut.build(), is(nestedSeqData));
    }

    public void testDERExplicitTaggedSequenceWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, true);

       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

       seqGen.close();

       assertThat("explicit tag writing test failed.", bOut.build(), is(expTagSeqData));
    }

    public void testDERImplicitTaggedSequenceWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, false);

       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

       seqGen.close();

       assertThat("implicit tag writing test failed.", bOut.build(), is(implTagSeqData));
    }

    public void testNestedExplicitTagDERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);

       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

       final DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);

       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

       seqGen2.close();

       seqGen1.close();

       assertThat("nested explicit tagged DER writing test failed.", bOut.build(), is(nestedSeqExpTagData));
    }

    public void testNestedImplicitTagDERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);

       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

       final DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);

       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

       seqGen2.close();

       seqGen1.close();

       assertTrue("nested implicit tagged DER writing test failed.", Arrays.equals(nestedSeqImpTagData, bOut.toByteArray()));
       assertThat("nested explicit tagged DER writing test failed.", bOut.build(), is(nestedSeqExpTagData));
    }

    public void testBERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut);

       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

       seqGen.close();

       assertTrue("basic BER writing test failed.", Arrays.equals(berSeqData, bOut.toByteArray()));
    }

    public void testNestedBERDERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);

       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

       final DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());

       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

       seqGen2.close();

       seqGen1.close();

       assertTrue("nested BER/DER writing test failed.", Arrays.equals(berDERNestedSeqData, bOut.toByteArray()));
    }

    public void testNestedBERWriting()
        throws Exception
    {
      final BytesBuilder bOut = newBytesBuilder();
       final BERSequenceGenerator  seqGen1 = new BERSequenceGenerator(bOut);

       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

       final BERSequenceGenerator seqGen2 = new BERSequenceGenerator(seqGen1.getRawOutputStream());

       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

       seqGen2.close();

       seqGen1.close();

       assertTrue("nested BER writing test failed.", Arrays.equals(berNestedSeqData, bOut.toByteArray()));
    }

    public void testDERReading()
        throws Exception
    {
        final ASN1StreamParser aIn = new ASN1StreamParser(seqData);

        final ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 2, count);
    }

    private void testNestedReading(
        final Bytes data)
        throws Exception
    {
        final ASN1StreamParser aIn = new ASN1StreamParser(data);

        final ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            case 2:
                assertTrue(o instanceof ASN1SequenceParser);

                final ASN1SequenceParser s = (ASN1SequenceParser)o;

                // NB: Must exhaust the nested parser
                while (s.readObject() != null)
                {
                    // Nothing
                }

                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 3, count);
    }

    public void testNestedDERReading()
        throws Exception
    {
        testNestedReading(nestedSeqData);
    }

    public void testBERReading()
        throws Exception
    {
        final ASN1StreamParser aIn = new ASN1StreamParser(berSeqData);

        final ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 2, count);
    }

    public void testNestedBERDERReading()
        throws Exception
    {
        testNestedReading(berDERNestedSeqData);
    }

    public void testNestedBERReading()
        throws Exception
    {
        testNestedReading(berNestedSeqData);
    }

    public void testBERExplicitTaggedSequenceWriting()
        throws Exception
    {
       final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       final BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut, 1, true);

       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

       seqGen.close();

       assertTrue("explicit BER tag writing test failed.", Arrays.equals(berExpTagSeqData, bOut.toByteArray()));
    }

    public void testSequenceWithDERNullReading()
        throws Exception
    {
        testParseWithNull(berSeqWithDERNullData);
    }

    private void testParseWithNull(final Bytes data)
        throws IOException
    {
        final ASN1StreamParser aIn = new ASN1StreamParser(data);
        final ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Null);
                break;
            case 1:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 2:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 3, count);
    }

    public static Test suite()
    {
        return new TestSuite(ASN1SequenceParserTest.class);
    }
}
