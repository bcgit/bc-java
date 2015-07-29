package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

public class OtherCertIDUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "OtherCertID";
    }

    public void performTest()
        throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.2.3"));
        byte[]              digest = new byte[20];
        IssuerSerial        issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(new X500Name("CN=test"))), new ASN1Integer(1));

        OtherCertID certID = new OtherCertID(algId, digest);

        checkConstruction(certID, algId, digest, null);

        certID = new OtherCertID(algId, digest, issuerSerial);

        checkConstruction(certID, algId, digest, issuerSerial);

        certID = OtherCertID.getInstance(null);

        if (certID != null)
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
        OtherCertID certID,
        AlgorithmIdentifier algId,
        byte[] digest,
        IssuerSerial issuerSerial)
        throws IOException
    {
        checkValues(certID, algId, digest, issuerSerial);

        certID = OtherCertID.getInstance(certID);

        checkValues(certID, algId, digest, issuerSerial);

        ASN1InputStream aIn = new ASN1InputStream(certID.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        certID = OtherCertID.getInstance(seq);

        checkValues(certID, algId, digest, issuerSerial);
    }

    private void checkValues(
        OtherCertID certID,
        AlgorithmIdentifier algId,
        byte[] digest,
        IssuerSerial issuerSerial)
    {
        checkMandatoryField("algorithmHash", algId, certID.getAlgorithmHash());
        checkMandatoryField("certHash", digest, certID.getCertHash());

        checkOptionalField("issuerSerial", issuerSerial, certID.getIssuerSerial());
    }

    public static void main(
        String[]    args)
    {
        runTest(new OtherCertIDUnitTest());
    }
}
