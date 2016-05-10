package com.github.gv2011.bcasn.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1OctetStringParser;
import com.github.gv2011.bcasn.asn1.ASN1SequenceParser;
import com.github.gv2011.bcasn.asn1.ASN1StreamParser;
import com.github.gv2011.bcasn.asn1.BEROctetStringGenerator;
import com.github.gv2011.bcasn.asn1.BERSequenceGenerator;
import com.github.gv2011.bcasn.asn1.BERTags;
import com.github.gv2011.bcasn.asn1.DERSequenceGenerator;
import com.github.gv2011.bcasn.asn1.cms.CMSObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.cms.CompressedDataParser;
import com.github.gv2011.bcasn.asn1.cms.ContentInfoParser;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class OctetStringTest 
    extends TestCase 
{
    public void testReadingWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BEROctetStringGenerator octGen = new BEROctetStringGenerator(bOut);
       
       OutputStream out = octGen.getOctetOutputStream();
       
       out.write(new byte[] { 1, 2, 3, 4 });
       out.write(new byte[4]);
       
       out.close();
       
       ASN1StreamParser aIn = new ASN1StreamParser(bOut.toByteArray());
       
       ASN1OctetStringParser s = (ASN1OctetStringParser)aIn.readObject();
       
       InputStream in = s.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }

       assertEquals(8, count);
    }
    
    public void testReadingWritingZeroInLength()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BEROctetStringGenerator octGen = new BEROctetStringGenerator(bOut);
       
       OutputStream out = octGen.getOctetOutputStream();
       
       out.write(new byte[] { 1, 2, 3, 4 });
       out.write(new byte[512]);  // forces a zero to appear in length
       
       out.close();
       
       ASN1StreamParser aIn = new ASN1StreamParser(bOut.toByteArray());
       
       ASN1OctetStringParser s = (ASN1OctetStringParser)aIn.readObject();
       
       InputStream in = s.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }
    
       assertEquals(516, count);
    }
    
    public void testReadingWritingNested()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator sGen = new BERSequenceGenerator(bOut);
       BEROctetStringGenerator octGen = new BEROctetStringGenerator(sGen.getRawOutputStream());
       
       OutputStream out = octGen.getOctetOutputStream();
       
       BERSequenceGenerator inSGen = new BERSequenceGenerator(out);
       
       BEROctetStringGenerator inOctGen = new BEROctetStringGenerator(inSGen.getRawOutputStream());
       
       OutputStream inOut = inOctGen.getOctetOutputStream();
       
       inOut.write(new byte[] { 1, 2, 3, 4 });
       inOut.write(new byte[10]);
       
       inOut.close();
       
       inSGen.close();
       
       out.close();
       
       sGen.close();
       
       ASN1StreamParser aIn = new ASN1StreamParser(bOut.toByteArray());
       
       ASN1SequenceParser sq = (ASN1SequenceParser)aIn.readObject();
       
       ASN1OctetStringParser s = (ASN1OctetStringParser)sq.readObject();
       
       ASN1StreamParser aIn2 = new ASN1StreamParser(s.getOctetStream());
       
       ASN1SequenceParser sq2 = (ASN1SequenceParser)aIn2.readObject();
       
       ASN1OctetStringParser inS = (ASN1OctetStringParser)sq2.readObject();
       
       InputStream in = inS.getOctetStream();
       int         count = 0;
       
       while (in.read() >= 0)
       {
           count++;
       }
    
       assertEquals(14, count);
    }
    
    public void testNestedStructure()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        BERSequenceGenerator sGen = new BERSequenceGenerator(bOut);
        
        sGen.addObject(new ASN1ObjectIdentifier(CMSObjectIdentifiers.compressedData.getId()));
        
        BERSequenceGenerator cGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        cGen.addObject(new ASN1Integer(0));
        
        //
        // AlgorithmIdentifier
        //
        DERSequenceGenerator algGen = new DERSequenceGenerator(cGen.getRawOutputStream());
        
        algGen.addObject(new ASN1ObjectIdentifier("1.2"));

        algGen.close();
        
        //
        // Encapsulated ContentInfo
        //
        BERSequenceGenerator eiGen = new BERSequenceGenerator(cGen.getRawOutputStream());
        
        eiGen.addObject(new ASN1ObjectIdentifier("1.1"));
        
        BEROctetStringGenerator octGen = new BEROctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
        
        //
        // output containing zeroes
        //
        OutputStream out = octGen.getOctetOutputStream();
        
        out.write(new byte[] { 1, 2, 3, 4 });
        out.write(new byte[4]);
        out.write(new byte[20]);
        
        out.close();
        eiGen.close();
        cGen.close();
        sGen.close();
        
        //
        // reading back
        //
        ASN1StreamParser aIn = new ASN1StreamParser(bOut.toByteArray());

        ContentInfoParser cp = new ContentInfoParser((ASN1SequenceParser)aIn.readObject());
        
        CompressedDataParser comData = new CompressedDataParser((ASN1SequenceParser)cp.getContent(BERTags.SEQUENCE));
        ContentInfoParser     content = comData.getEncapContentInfo();

        ASN1OctetStringParser bytes = (ASN1OctetStringParser)content.getContent(BERTags.OCTET_STRING);

        InputStream in = bytes.getOctetStream();
        int         count = 0;
        
        while (in.read() >= 0)
        {
            count++;
        }

        assertEquals(28, count);
    }
    
    public static Test suite()
    {
        return new TestSuite(OctetStringTest.class);
    }
}
