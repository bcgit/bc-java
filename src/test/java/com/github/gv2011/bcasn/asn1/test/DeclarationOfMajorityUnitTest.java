package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1GeneralizedTime;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;
import com.github.gv2011.bcasn.asn1.isismtt.x509.DeclarationOfMajority;

public class DeclarationOfMajorityUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "DeclarationOfMajority";
    }

    public void performTest()
        throws Exception
    {
        ASN1GeneralizedTime dateOfBirth = new ASN1GeneralizedTime("20070315173729Z");
        DeclarationOfMajority decl = new DeclarationOfMajority(dateOfBirth);

        checkConstruction(decl, DeclarationOfMajority.dateOfBirth, dateOfBirth, -1);

        decl = new DeclarationOfMajority(6);

        checkConstruction(decl, DeclarationOfMajority.notYoungerThan, null, 6);

        decl = DeclarationOfMajority.getInstance(null);

        if (decl != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            DeclarationOfMajority.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        DeclarationOfMajority decl,
        int                   type,
        ASN1GeneralizedTime   dateOfBirth,
        int                   notYoungerThan)
        throws IOException
    {
        checkValues(decl, type, dateOfBirth, notYoungerThan);

        decl = DeclarationOfMajority.getInstance(decl);

        checkValues(decl, type, dateOfBirth, notYoungerThan);

        ASN1InputStream aIn = new ASN1InputStream(decl.toASN1Primitive().getEncoded());

        DERTaggedObject info = (DERTaggedObject)aIn.readObject();

        decl = DeclarationOfMajority.getInstance(info);

        checkValues(decl, type, dateOfBirth, notYoungerThan);
    }

    private void checkValues(
        DeclarationOfMajority decl,
        int                   type,
        ASN1GeneralizedTime   dateOfBirth,
        int                   notYoungerThan)
    {
        checkMandatoryField("type", type, decl.getType());
        checkOptionalField("dateOfBirth", dateOfBirth, decl.getDateOfBirth());
        if (notYoungerThan != -1 && notYoungerThan != decl.notYoungerThan())
        {
            fail("notYoungerThan mismatch");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DeclarationOfMajorityUnitTest());
    }
}
