package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The X.509 extension types whose RFC 5280 syntax is SEQUENCE SIZE (1..MAX)
 * must reject an empty SEQUENCE on parse, matching AuthorityInformationAccess.
 */
public class EmptyExtensionSequenceTest
    extends SimpleTest
{
    private static final ASN1ObjectIdentifier anyPolicy = new ASN1ObjectIdentifier("2.5.29.32.0");

    public String getName()
    {
        return "EmptyExtensionSequence";
    }

    public void performTest()
        throws IOException
    {
        emptyRejected();
        nonEmptyParses();
    }

    private void emptyRejected()
    {
        DERSequence empty = new DERSequence();

        rejectEmpty("CertificatePolicies", new Parse()
        {
            public void parse() { CertificatePolicies.getInstance(empty); }
        });
        rejectEmpty("PolicyMappings", new Parse()
        {
            public void parse() { PolicyMappings.getInstance(empty); }
        });
        rejectEmpty("ExtendedKeyUsage", new Parse()
        {
            public void parse() { ExtendedKeyUsage.getInstance(empty); }
        });
        rejectEmpty("CRLDistPoint", new Parse()
        {
            public void parse() { CRLDistPoint.getInstance(empty); }
        });
        rejectEmpty("SubjectDirectoryAttributes", new Parse()
        {
            public void parse() { SubjectDirectoryAttributes.getInstance(empty); }
        });
        // already enforced before this change - guards the family stays consistent
        rejectEmpty("AuthorityInformationAccess", new Parse()
        {
            public void parse() { AuthorityInformationAccess.getInstance(empty); }
        });
    }

    private void rejectEmpty(String name, Parse p)
    {
        try
        {
            p.parse();
            fail("empty " + name + " accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message for " + name + ": " + e.getMessage(),
                e.getMessage().indexOf("sequence may not be empty") >= 0);
        }
    }

    private void nonEmptyParses()
    {
        // each built non-empty and re-parsed through the ASN1Sequence constructor
        CertificatePolicies.getInstance(
            new CertificatePolicies(new PolicyInformation(anyPolicy)).toASN1Primitive());

        PolicyMappings.getInstance(
            new PolicyMappings(CertPolicyId.getInstance(anyPolicy),
                CertPolicyId.getInstance(anyPolicy)).toASN1Primitive());

        ExtendedKeyUsage.getInstance(
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).toASN1Primitive());

        DistributionPoint dp = new DistributionPoint(
            new DistributionPointName(new GeneralNames(
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.example/c.crl"))),
            null, null);
        CRLDistPoint.getInstance(
            new CRLDistPoint(new DistributionPoint[]{ dp }).toASN1Primitive());

        AuthorityInformationAccess.getInstance(
            new AuthorityInformationAccess(AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ca.example/ca")).toASN1Primitive());

        Vector attrs = new Vector();
        attrs.addElement(new Attribute(new ASN1ObjectIdentifier("2.5.4.3"),
            new DERSet(new DERUTF8String("name"))));
        SubjectDirectoryAttributes.getInstance(
            new SubjectDirectoryAttributes(attrs).toASN1Primitive());
    }

    private interface Parse
    {
        void parse();
    }

    public static void main(String[] args)
    {
        runTest(new EmptyExtensionSequenceTest());
    }
}
