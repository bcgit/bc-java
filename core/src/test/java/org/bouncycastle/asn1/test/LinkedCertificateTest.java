package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bc.LinkedCertificate;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class LinkedCertificateTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "LinkedCertificate";
    }

    public void performTest()
        throws Exception
    {
        DigestInfo digInfo = new DigestInfo(
                                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), new byte[32]);
        GeneralName certLocation = new GeneralName(GeneralName.uniformResourceIdentifier, "https://www.bouncycastle.org/certs");
        X500Name certIssuer = null;
        GeneralNames cACerts = null;

        LinkedCertificate linked = new LinkedCertificate(digInfo, certLocation);

        checkConstruction(linked, digInfo, certLocation, certIssuer, cACerts);

        certIssuer = new X500Name("CN=Test");
        cACerts = new GeneralNames(new GeneralName(new X500Name("CN=CA Test")));

        linked = new LinkedCertificate(digInfo, certLocation, certIssuer, cACerts);

        checkConstruction(linked, digInfo, certLocation, certIssuer, cACerts);

        linked = LinkedCertificate.getInstance(null);

        if (linked != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            LinkedCertificate.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        LinkedCertificate linked,
        DigestInfo digestInfo, GeneralName certLocation, X500Name certIssuer, GeneralNames caCerts)
        throws IOException
    {
        checkValues(linked, digestInfo, certLocation, certIssuer, caCerts);

        linked = LinkedCertificate.getInstance(linked);

        checkValues(linked, digestInfo, certLocation, certIssuer, caCerts);

        ASN1InputStream aIn = new ASN1InputStream(linked.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        linked = LinkedCertificate.getInstance(seq);

        checkValues(linked, digestInfo, certLocation, certIssuer, caCerts);
    }

    private void checkValues(
        LinkedCertificate linked,
        DigestInfo digestInfo, GeneralName certLocation, X500Name certIssuer, GeneralNames caCerts)
    {
        checkMandatoryField("digest", digestInfo, linked.getDigest());
        checkMandatoryField("certLocatin", certLocation, linked.getCertLocation());
        checkOptionalField("certIssuer", certIssuer, linked.getCertIssuer());
        checkOptionalField("caCerts", caCerts, linked.getCACerts());
    }

    public static void main(
        String[]    args)
    {
        runTest(new LinkedCertificateTest());
    }
}
