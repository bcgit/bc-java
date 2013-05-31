package org.bouncycastle.asn1.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
import org.bouncycastle.asn1.cms.EnvelopedDataParser;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class ParseTest
    extends TestCase
{
    private static byte[] classCastTest = Base64.decode(
      "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");
    
    private static byte[] derExpTest = Base64.decode(
      "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"
    + "yv8TOTFCWnZEUTtVA9+2CpwfmuEjD2UQ4vxoM+o=");

    byte[] longTagged = Hex.decode("9f1f023330");
    
    public void testClassCast()
        throws IOException
    {
        parseEnveloped(classCastTest);
    }

    public void testDerExp()
        throws IOException
    {
        parseEnveloped(derExpTest);
    }
    
    public void testLongTag()
        throws IOException
    {
        ASN1StreamParser aIn = new ASN1StreamParser(longTagged);
        
        ASN1TaggedObjectParser tagged = (ASN1TaggedObjectParser)aIn.readObject();
        
        assertEquals(31, tagged.getTagNo());
    }
    
    private void parseEnveloped(byte[] data) throws IOException
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        
        ContentInfoParser cP = new ContentInfoParser((ASN1SequenceParser)aIn.readObject());
        
        EnvelopedDataParser eP = new EnvelopedDataParser((ASN1SequenceParser)cP.getContent(BERTags.SEQUENCE));
        
        eP.getRecipientInfos().toASN1Primitive(); // Must drain the parser!
        
        EncryptedContentInfoParser ecP = eP.getEncryptedContentInfo();
        
        ASN1OctetStringParser content = (ASN1OctetStringParser)ecP.getEncryptedContent(BERTags.OCTET_STRING);

        Streams.drain(content.getOctetStream());
    }
}
