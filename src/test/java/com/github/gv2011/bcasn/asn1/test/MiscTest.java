package com.github.gv2011.bcasn.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1OutputStream;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.BERSequence;
import com.github.gv2011.bcasn.asn1.DERBitString;
import com.github.gv2011.bcasn.asn1.DERIA5String;
import com.github.gv2011.bcasn.asn1.misc.CAST5CBCParameters;
import com.github.gv2011.bcasn.asn1.misc.IDEACBCPar;
import com.github.gv2011.bcasn.asn1.misc.NetscapeCertType;
import com.github.gv2011.bcasn.asn1.misc.NetscapeRevocationURL;
import com.github.gv2011.bcasn.asn1.misc.VerisignCzagExtension;
import com.github.gv2011.bcasn.util.Arrays;
import com.github.gv2011.bcasn.util.encoders.Base64;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class MiscTest
    extends SimpleTest
{
    private boolean isSameAs(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        
        return true;
    }

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
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        for (int i = 0; i != values.length; i++)
        {
            aOut.writeObject(values[i]);
        }

        ASN1Primitive[] readValues = new ASN1Primitive[values.length];

        if (!isSameAs(bOut.toByteArray(), data))
        {
            fail("Failed data check");
        }

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

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
