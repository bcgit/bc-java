package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.isismtt.x509.Admissions;
import com.github.gv2011.bcasn.asn1.isismtt.x509.NamingAuthority;
import com.github.gv2011.bcasn.asn1.isismtt.x509.ProfessionInfo;
import com.github.gv2011.bcasn.asn1.x500.DirectoryString;
import com.github.gv2011.bcasn.asn1.x500.X500Name;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;

public class AdmissionsUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "Admissions";
    }

    public void performTest()
        throws Exception
    {
        GeneralName name = new GeneralName(new X500Name("CN=hello world"));
        NamingAuthority auth =  new NamingAuthority(new ASN1ObjectIdentifier("1.2.3"), "url", new DirectoryString("fred"));
        Admissions  admissions = new Admissions(name, auth, new ProfessionInfo[0]);

        checkConstruction(admissions, name, auth);

        admissions = Admissions.getInstance(null);

        if (admissions != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            Admissions.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        Admissions      admissions,
        GeneralName     name,
        NamingAuthority auth)
        throws IOException
    {
        checkValues(admissions, name, auth);

        admissions = Admissions.getInstance(admissions);

        checkValues(admissions, name, auth);

        ASN1InputStream aIn = new ASN1InputStream(admissions.toASN1Primitive().getEncoded());

        ASN1Sequence info = (ASN1Sequence)aIn.readObject();

        admissions = Admissions.getInstance(info);

        checkValues(admissions, name, auth);
    }

    private void checkValues(
        Admissions      admissions,
        GeneralName     name,
        NamingAuthority auth)
    {
        checkMandatoryField("admissionAuthority", name, admissions.getAdmissionAuthority());
        checkMandatoryField("namingAuthority", auth, admissions.getNamingAuthority());
    }

    public static void main(
        String[]    args)
    {
        runTest(new AdmissionsUnitTest());
    }
}
