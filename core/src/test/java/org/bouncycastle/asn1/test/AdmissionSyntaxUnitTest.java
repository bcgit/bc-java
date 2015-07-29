package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

public class AdmissionSyntaxUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "AdmissionSyntax";
    }

    public void performTest()
        throws Exception
    {
        GeneralName     name = new GeneralName(new X500Name("CN=hello world"));
        ASN1Sequence    admissions = new DERSequence(
                                        new Admissions(name,
                                          new NamingAuthority(new ASN1ObjectIdentifier("1.2.3"), "url", new DirectoryString("fred")),
                                          new ProfessionInfo[0]));
        AdmissionSyntax syntax = new AdmissionSyntax(name, admissions);

        checkConstruction(syntax, name, admissions);

        syntax = AdmissionSyntax.getInstance(null);

        if (syntax != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            AdmissionSyntax.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        AdmissionSyntax syntax,
        GeneralName     authority,
        ASN1Sequence    admissions)
        throws IOException
    {
        checkValues(syntax, authority, admissions);

        syntax = AdmissionSyntax.getInstance(syntax);

        checkValues(syntax, authority, admissions);

        ASN1InputStream aIn = new ASN1InputStream(syntax.toASN1Primitive().getEncoded());

        ASN1Sequence info = (ASN1Sequence)aIn.readObject();

        syntax = AdmissionSyntax.getInstance(info);

        checkValues(syntax, authority, admissions);
    }

    private void checkValues(
        AdmissionSyntax syntax,
        GeneralName     authority,
        ASN1Sequence    admissions)
    {
        checkMandatoryField("admissionAuthority", authority, syntax.getAdmissionAuthority());

        Admissions[] adm = syntax.getContentsOfAdmissions();

        if (adm.length != 1 || !adm[0].equals(admissions.getObjectAt(0)))
        {
            fail("admissions check failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new AdmissionSyntaxUnitTest());
    }
}
