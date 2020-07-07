package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.IDEACBCPar;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class MiscTest
    extends SimpleTest
{
    public void shouldFailOnExtraData()
        throws Exception
    {
        // basic construction
        DERBitString s1 = new DERBitString(new byte[0], 0);

        ASN1Primitive.fromByteArray(s1.getEncoded());

        ASN1Primitive.fromByteArray(new BERSequence(s1).getEncoded());

        try
        {
            ASN1Primitive obj = ASN1Primitive.fromByteArray(Arrays.concatenate(s1.getEncoded(), new byte[1]));
            fail("no exception");
        }
        catch (IOException e)
        {
            if (!"Extra data detected in stream".equals(e.getMessage()))
            {
                fail("wrong exception");
            }
        }
    }

    public void asn1IntegerTest()
        throws Exception
    {
        try
        {
            new ASN1Integer(new byte[] { 0, 0, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new ASN1Integer(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed integer".equals(e.getMessage()));
        }

        try
        {
            new ASN1Enumerated(new byte[] { 0, 0, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
        }

        try
        {
            new ASN1Enumerated(new byte[] {(byte)0xff, (byte)0x80, 0, 1});
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong exc", "malformed enumerated".equals(e.getMessage()));
        }
    }

    public void performTest()
        throws Exception
    {
        byte[]  testIv = { 1, 2, 3, 4, 5, 6, 7, 8 };
        
        ASN1Encodable[]     values = {
            new CAST5CBCParameters(testIv, 128), 
            new NetscapeCertType(NetscapeCertType.smime),    
            new VerisignCzagExtension(new DERIA5String("hello")),
            new IDEACBCPar(testIv),        
            new NetscapeRevocationURL(new DERIA5String("http://test"))
        };
        
        byte[] data = Base64.decode("MA4ECAECAwQFBgcIAgIAgAMCBSAWBWhlbGxvMAoECAECAwQFBgcIFgtodHRwOi8vdGVzdA==");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

        for (int i = 0; i != values.length; i++)
        {
            aOut.writeObject(values[i].toASN1Primitive());
        }

        if (!areEqual(bOut.toByteArray(), data))
        {
            fail("Failed data check");
        }

        ASN1InputStream aIn = new ASN1InputStream(data);

        for (int i = 0; i != values.length; i++)
        {
            ASN1Primitive o = aIn.readObject();
            if (!values[i].equals(o))
            {
                fail("Failed equality test for " + o);
            }

            if (o.hashCode() != values[i].hashCode())
            {
                fail("Failed hashCode test for " + o);
            }
        }

        shouldFailOnExtraData();
        asn1IntegerTest();
    }

    public String getName()
    {
        return "Misc";
    }

    public static void main(
        String[] args)
    {
        runTest(new MiscTest());
    }
}
