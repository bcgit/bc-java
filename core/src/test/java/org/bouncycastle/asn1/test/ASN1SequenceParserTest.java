package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.util.encoders.Hex;

public class ASN1SequenceParserTest 
    extends TestCase 
{
    private static final byte[] seqData = Hex.decode("3006020100060129");
    private static final byte[] nestedSeqData = Hex.decode("300b0201000601293003020101");
    private static final byte[] expTagSeqData = Hex.decode("a1083006020100060129");
    private static final byte[] implTagSeqData = Hex.decode("a106020100060129");
    private static final byte[] nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
    private static final byte[] nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");
    
    private static final byte[] berSeqData = Hex.decode("30800201000601290000");
    private static final byte[] berDERNestedSeqData = Hex.decode("308002010006012930030201010000");
    private static final byte[] berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
    private static final byte[] berExpTagSeqData = Hex.decode("a180308002010006012900000000");

    private static final byte[] berSeqWithDERNullData = Hex.decode("308005000201000601290000");

    public void testDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("basic DER writing test failed.", Arrays.equals(seqData, bOut.toByteArray()));
    }
 
    public void testNestedDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested DER writing test failed.", Arrays.equals(nestedSeqData, bOut.toByteArray()));
    }

    public void testDERExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("explicit tag writing test failed.", Arrays.equals(expTagSeqData, bOut.toByteArray()));
    }
    
    public void testDERImplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, false);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("implicit tag writing test failed.", Arrays.equals(implTagSeqData, bOut.toByteArray()));
    }
    
    public void testNestedExplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested explicit tagged DER writing test failed.", Arrays.equals(nestedSeqExpTagData, bOut.toByteArray()));
    }
    
    public void testNestedImplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested implicit tagged DER writing test failed.", Arrays.equals(nestedSeqImpTagData, bOut.toByteArray()));
    }
    
    public void testBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();
       
       assertTrue("basic BER writing test failed.", Arrays.equals(berSeqData, bOut.toByteArray()));
    }

    public void testNestedBERDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER/DER writing test failed.", Arrays.equals(berDERNestedSeqData, bOut.toByteArray()));
    }
    
    public void testNestedBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       BERSequenceGenerator seqGen2 = new BERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER writing test failed.", Arrays.equals(berNestedSeqData, bOut.toByteArray()));
    }
    
    public void testDERReading()
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(seqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
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
        byte[] data)
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
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
                
                ASN1SequenceParser s = (ASN1SequenceParser)o;

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
        ASN1StreamParser aIn = new ASN1StreamParser(berSeqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
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
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut, 1, true);
       
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

    private void testParseWithNull(byte[] data)
        throws IOException
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
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
