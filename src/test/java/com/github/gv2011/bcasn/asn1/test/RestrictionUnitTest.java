package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1String;
import com.github.gv2011.bcasn.asn1.isismtt.x509.Restriction;
import com.github.gv2011.bcasn.asn1.x500.DirectoryString;

public class RestrictionUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "Restriction";
    }

    public void performTest()
        throws Exception
    {
        DirectoryString res = new DirectoryString("test");
        Restriction restriction = new Restriction(res.getString());

        checkConstruction(restriction, res);

        try
        {
            Restriction.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        Restriction restriction,
        DirectoryString res)
        throws IOException
    {
        checkValues(restriction, res);

        restriction = Restriction.getInstance(restriction);

        checkValues(restriction, res);

        ASN1InputStream aIn = new ASN1InputStream(restriction.toASN1Primitive().getEncoded());

        ASN1String str = (ASN1String)aIn.readObject();

        restriction = Restriction.getInstance(str);

        checkValues(restriction, res);
    }

    private void checkValues(
        Restriction restriction,
        DirectoryString res)
    {
        checkMandatoryField("restriction", res, restriction.getRestriction());
    }

    public static void main(
        String[]    args)
    {
        runTest(new RestrictionUnitTest());
    }
}
