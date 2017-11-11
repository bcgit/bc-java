package com.github.gv2011.asn1;

import static org.junit.Assert.*;

import org.junit.Ignore;
import org.junit.Test;

import com.github.gv2011.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.asn1.util.test.SimpleTest;
import com.github.gv2011.asn1.util.test.TestResult;
import com.github.gv2011.util.bytes.Bytes;

public class ObjectIdentifierTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "ObjectIdentifier";
    }

    @Override
    public void performTest() throws Exception{
        // exercise the object cache
        for (int i = 0; i < 1024; i++)
        {
            for (int j = 0; j != 17000; j++)
            {
                final Bytes encoded = new ASN1ObjectIdentifier("1.1." + i + "." + j).getEncoded();

                ASN1ObjectIdentifier.getInstance(encoded);
            }
        }
    }

    @Test
    @Ignore("Takes about 30s")
    public void test(){
        final ObjectIdentifierTest test = new ObjectIdentifierTest();
        final TestResult result = test.perform();
        assertTrue(result.isSuccessful());
    }
}
