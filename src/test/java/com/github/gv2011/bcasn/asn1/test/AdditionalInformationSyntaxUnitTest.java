package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1String;
import com.github.gv2011.bcasn.asn1.isismtt.x509.AdditionalInformationSyntax;
import com.github.gv2011.bcasn.asn1.x500.DirectoryString;

public class AdditionalInformationSyntaxUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "AdditionalInformationSyntax";
    }

    public void performTest()
        throws Exception
    {
        AdditionalInformationSyntax syntax = new AdditionalInformationSyntax("hello world");

        checkConstruction(syntax, new DirectoryString("hello world"));

        try
        {
            AdditionalInformationSyntax.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        AdditionalInformationSyntax syntax,
        DirectoryString information)
        throws IOException
    {
        checkValues(syntax, information);

        syntax = AdditionalInformationSyntax.getInstance(syntax);

        checkValues(syntax, information);

        ASN1InputStream aIn = new ASN1InputStream(syntax.toASN1Primitive().getEncoded());

        ASN1String info = (ASN1String)aIn.readObject();

        syntax = AdditionalInformationSyntax.getInstance(info);

        checkValues(syntax, information);
    }

    private void checkValues(
        AdditionalInformationSyntax syntax,
        DirectoryString information)
    {
        checkMandatoryField("information", information, syntax.getInformation());
    }

    public static void main(
        String[]    args)
    {
        runTest(new AdditionalInformationSyntaxUnitTest());
    }
}
