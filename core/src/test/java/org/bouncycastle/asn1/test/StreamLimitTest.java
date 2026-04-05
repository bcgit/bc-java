package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.util.test.SimpleTest;

public class StreamLimitTest
    extends SimpleTest
{
    static final String MAX_LIMIT = "org.bouncycastle.asn1.max_limit";

    public void performTest()
        throws Exception
    {
        System.setProperty(MAX_LIMIT, "1024");

        MyASN1InputStream asn1In = new MyASN1InputStream();

        isEquals(1024, asn1In.getLimit());
        
        System.setProperty(MAX_LIMIT, "1024k");

        asn1In = new MyASN1InputStream();

        isEquals(1048576, asn1In.getLimit());

        System.setProperty(MAX_LIMIT, "1024m");

        asn1In = new MyASN1InputStream();

        isEquals(1073741824, asn1In.getLimit());

        System.setProperty(MAX_LIMIT, "1g");

        asn1In = new MyASN1InputStream();

        isEquals(1073741824, asn1In.getLimit());

        System.clearProperty(MAX_LIMIT)
    }

    public String getName()
    {
        return "StreamLimit";
    }

    public static void main(
        String[] args)
    {
        runTest(new StreamLimitTest());
    }

    private static class MyASN1InputStream
        extends ASN1InputStream
    {
        MyASN1InputStream()
        {
            super(new InputStream()
            {
                @Override
                public int read()
                    throws IOException
                {
                    return 0;
                }
            });
        }

        public int getLimit()
        {
            return super.getLimit();
        }
    }
}
