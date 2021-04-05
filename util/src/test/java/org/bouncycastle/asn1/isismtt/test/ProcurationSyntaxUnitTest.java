package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.isismtt.x509.ProcurationSyntax;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

public class ProcurationSyntaxUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "ProcurationSyntax";
    }

    public void performTest()
        throws Exception
    {
        String country = "AU";
        DirectoryString  typeOfSubstitution = new DirectoryString("substitution");
        GeneralName thirdPerson = new GeneralName(new X500Name("CN=thirdPerson"));
        IssuerSerial certRef = new IssuerSerial(new GeneralNames(new GeneralName(new X500Name("CN=test"))), new ASN1Integer(1));

        ProcurationSyntax procuration = new ProcurationSyntax(country, typeOfSubstitution, thirdPerson);

        checkConstruction(procuration, country, typeOfSubstitution, thirdPerson, null);

        procuration = new ProcurationSyntax(country, typeOfSubstitution, certRef);

        checkConstruction(procuration, country, typeOfSubstitution, null, certRef);

        procuration = new ProcurationSyntax(null, typeOfSubstitution, certRef);

        checkConstruction(procuration, null, typeOfSubstitution, null, certRef);

        procuration = new ProcurationSyntax(country, null, certRef);

        checkConstruction(procuration, country, null, null, certRef);

        procuration = ProcurationSyntax.getInstance(null);

        if (procuration != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            ProcurationSyntax.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        ProcurationSyntax procuration,
        String country,
        DirectoryString  typeOfSubstitution,
        GeneralName thirdPerson,
        IssuerSerial certRef)
        throws IOException
    {
        checkValues(procuration, country, typeOfSubstitution, thirdPerson, certRef);

        procuration = ProcurationSyntax.getInstance(procuration);

        checkValues(procuration, country, typeOfSubstitution, thirdPerson, certRef);

        ASN1InputStream aIn = new ASN1InputStream(procuration.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        procuration = ProcurationSyntax.getInstance(seq);

        checkValues(procuration, country, typeOfSubstitution, thirdPerson, certRef);
    }

    private void checkValues(
        ProcurationSyntax procuration,
        String country,
        DirectoryString  typeOfSubstitution,
        GeneralName thirdPerson,
        IssuerSerial certRef)
    {
        checkOptionalField("country", country, procuration.getCountry());
        checkOptionalField("typeOfSubstitution", typeOfSubstitution, procuration.getTypeOfSubstitution());
        checkOptionalField("thirdPerson", thirdPerson, procuration.getThirdPerson());
        checkOptionalField("certRef", certRef, procuration.getCertRef());
    }

    public static void main(
        String[]    args)
    {
        runTest(new ProcurationSyntaxUnitTest());
    }
}
