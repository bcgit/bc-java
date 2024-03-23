package org.bouncycastle.asn1.misc.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.CRLSource;
import org.bouncycastle.asn1.cmp.CRLStatus;
import org.bouncycastle.asn1.cmp.CertReqTemplateContent;
import org.bouncycastle.asn1.cmp.DHBMParameter;
import org.bouncycastle.asn1.cmp.RootCaKeyUpdateContent;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * Basic sanity checking of classes added from
 * Certificate Management Protocol (CMP) Updates
 * draft-ietf-lamps-cmp-updates-16
 */
public class CMPUpdates16Test
    extends TestCase
{

    public void testCertReqTemplateContent()
        throws Exception
    {
        // Test assert sequence size

        try
        {
            CertReqTemplateContent.getInstance(new DERSequence());
            fail("expected fail for zero length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence size of 1 or 2", ilex.getMessage());
        }

        try
        {
            CertReqTemplateContent.getInstance(new DERSequence(new ASN1Encodable[]{
                DERNull.INSTANCE, DERNull.INSTANCE, DERNull.INSTANCE
            }));
            fail("expected fail on > 2 length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence size of 1 or 2", ilex.getMessage());
        }
    }

    public void testCRLSource()
        throws Exception
    {
        try
        {
            CRLSource.getInstance(new DERTaggedObject(3, DERNull.INSTANCE));
            fail("expected fail for unknown tag");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("unknown tag 3", ilex.getMessage());
        }

        // Check that both values are not set at construction

        try
        {
            new CRLSource(new DistributionPointName(1, DERNull.INSTANCE), new GeneralNames(new GeneralName(1, "")));
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("either dpn or issuer must be set", ilex.getMessage());
        }


    }

    public void testCertCRLStatus()
        throws Exception
    {
        // Test assert sequence size

        try
        {
            CRLStatus.getInstance(new DERSequence());
            fail("expected fail for zero length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence size of 1 or 2, got 0", ilex.getMessage());
        }

        try
        {
            CRLStatus.getInstance(new DERSequence(new ASN1Encodable[]{
                DERNull.INSTANCE, DERNull.INSTANCE, DERNull.INSTANCE
            }));
            fail("expected fail on > 2 length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence size of 1 or 2, got 3", ilex.getMessage());
        }
    }


    public void testDHBMParameter()
        throws Exception
    {
        // Test assert sequence size

        try
        {
            DHBMParameter.getInstance(new DERSequence());
            fail("expected fail for zero length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expecting sequence size of 2", ilex.getMessage());
        }

        try
        {
            DHBMParameter.getInstance(new DERSequence(new ASN1Encodable[]{
                DERNull.INSTANCE, DERNull.INSTANCE, DERNull.INSTANCE
            }));
            fail("expected fail on > 2 length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expecting sequence size of 2", ilex.getMessage());
        }
    }

    public void testRootCaKeyUpdateContent()
        throws Exception
    {
        try
        {
            RootCaKeyUpdateContent.getInstance(new DERSequence());
            fail("expected fail for zero length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence of 1 to 3 elements only", ilex.getMessage());
        }

        try
        {
            RootCaKeyUpdateContent.getInstance(new DERSequence(new ASN1Encodable[]{
                DERNull.INSTANCE, DERNull.INSTANCE, DERNull.INSTANCE, DERNull.INSTANCE
            }));
            fail("expected fail on > 2 length sequence");
        }
        catch (IllegalArgumentException ilex)
        {
            assertEquals("expected sequence of 1 to 3 elements only", ilex.getMessage());
        }
    }

}
