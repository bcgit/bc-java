package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ess.OtherCertID;
import com.github.gv2011.bcasn.asn1.ess.OtherSigningCertificate;
import com.github.gv2011.bcasn.asn1.x509.AlgorithmIdentifier;

public class OtherSigningCertificateUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "OtherSigningCertificate";
    }

    public void performTest()
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.2.3"));
        byte[]              digest = new byte[20];
        OtherCertID         otherCertID = new OtherCertID(algId, digest);

        OtherSigningCertificate otherCert = new OtherSigningCertificate(otherCertID);

        checkConstruction(otherCert, otherCertID);

        otherCert = OtherSigningCertificate.getInstance(null);

        if (otherCert != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            OtherCertID.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        OtherSigningCertificate otherCert,
        OtherCertID otherCertID)
        throws IOException
    {
        checkValues(otherCert, otherCertID);

        otherCert = OtherSigningCertificate.getInstance(otherCert);

        checkValues(otherCert, otherCertID);

        ASN1InputStream aIn = new ASN1InputStream(otherCert.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        otherCert = OtherSigningCertificate.getInstance(seq);

        checkValues(otherCert, otherCertID);
    }

    private void checkValues(
        OtherSigningCertificate otherCert,
        OtherCertID otherCertID)
    {
        if (otherCert.getCerts().length != 1)
        {
            fail("getCerts() length wrong");
        }
        checkMandatoryField("getCerts()[0]", otherCertID, otherCert.getCerts()[0]);
    }

    public static void main(
        String[]    args)
    {
        runTest(new OtherSigningCertificateUnitTest());
    }
}
