package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Several X.509 extension values are defined as SEQUENCE SIZE (1..MAX) by RFC 5280, so an empty
 * SEQUENCE is malformed and must be rejected with a clean IllegalArgumentException on the parse
 * path (matching the existing AuthorityInformationAccess / NameConstraints behaviour) rather than
 * being accepted and yielding a degenerate, empty extension. Relates to github #2331.
 */
public class EmptyExtensionSequenceTest
    extends SimpleTest
{
    public String getName()
    {
        return "EmptyExtensionSequenceTest";
    }

    public void performTest()
        throws Exception
    {
        // CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation (RFC 5280 sec. 4.2.1.4)
        rejectEmpty("CertificatePolicies", new Runnable()
        {
            public void run()
            {
                CertificatePolicies.getInstance(new DERSequence());
            }
        });

        // PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {...} (RFC 5280 sec. 4.2.1.5)
        rejectEmpty("PolicyMappings", new Runnable()
        {
            public void run()
            {
                PolicyMappings.getInstance(new DERSequence());
            }
        });

        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId (RFC 5280 sec. 4.2.1.12)
        rejectEmpty("ExtendedKeyUsage", new Runnable()
        {
            public void run()
            {
                ExtendedKeyUsage.getInstance(new DERSequence());
            }
        });

        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint (RFC 5280 sec. 4.2.1.13)
        rejectEmpty("CRLDistPoint", new Runnable()
        {
            public void run()
            {
                CRLDistPoint.getInstance(new DERSequence());
            }
        });

        // SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute (RFC 5280 sec. 4.2.1.8)
        rejectEmpty("SubjectDirectoryAttributes", new Runnable()
        {
            public void run()
            {
                SubjectDirectoryAttributes.getInstance(new DERSequence());
            }
        });

        // a valid, non-empty extension still round-trips through the parse path.
        ExtendedKeyUsage eku = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
        isTrue("ExtendedKeyUsage round-trip",
            ExtendedKeyUsage.getInstance(eku.toASN1Primitive()).hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));

        CertificatePolicies cp = new CertificatePolicies(
            new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32.0")));
        isTrue("CertificatePolicies round-trip",
            CertificatePolicies.getInstance(cp.toASN1Primitive()).getPolicyInformation().length == 1);
    }

    private void rejectEmpty(String name, Runnable parse)
    {
        try
        {
            parse.run();
            fail("empty " + name + " sequence accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("sequence may not be empty", e.getMessage());
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new EmptyExtensionSequenceTest());
    }
}
