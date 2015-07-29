package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.util.test.SimpleTest;

public class IssuingDistributionPointUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "IssuingDistributionPoint";
    }

    public void performTest()
        throws Exception
    {
        DistributionPointName    name = new DistributionPointName(
                                              new GeneralNames(new GeneralName(new X500Name("cn=test"))));
        ReasonFlags reasonFlags = new ReasonFlags(ReasonFlags.cACompromise);

        checkPoint(6, name, true, true, reasonFlags, true, true);

        checkPoint(2, name, false, false, reasonFlags, false, false);

        checkPoint(0, null, false, false, null, false, false);

        try
        {
            IssuingDistributionPoint.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkPoint(
        int size,
        DistributionPointName distributionPoint,
        boolean onlyContainsUserCerts,
        boolean onlyContainsCACerts,
        ReasonFlags onlySomeReasons,
        boolean indirectCRL,
        boolean onlyContainsAttributeCerts)
        throws IOException
    {
        IssuingDistributionPoint point = new IssuingDistributionPoint(distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);

        checkValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);

        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(point.getEncoded()));

        if (seq.size() != size)
        {
            fail("size mismatch");
        }

        point = IssuingDistributionPoint.getInstance(seq);

        checkValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);
    }

    private void checkValues(IssuingDistributionPoint point, DistributionPointName distributionPoint, boolean onlyContainsUserCerts, boolean onlyContainsCACerts, ReasonFlags onlySomeReasons, boolean indirectCRL, boolean onlyContainsAttributeCerts)
    {
        if (point.onlyContainsUserCerts() != onlyContainsUserCerts)
        {
            fail("mismatch on onlyContainsUserCerts");
        }

        if (point.onlyContainsCACerts() != onlyContainsCACerts)
        {
            fail("mismatch on onlyContainsCACerts");
        }

        if (point.isIndirectCRL() != indirectCRL)
        {
            fail("mismatch on indirectCRL");
        }

        if (point.onlyContainsAttributeCerts() != onlyContainsAttributeCerts)
        {
            fail("mismatch on onlyContainsAttributeCerts");
        }

        if (!isEquiv(onlySomeReasons, point.getOnlySomeReasons()))
        {
            fail("mismatch on onlySomeReasons");
        }

        if (!isEquiv(distributionPoint, point.getDistributionPoint()))
        {
            fail("mismatch on distributionPoint");
        }
    }

    private boolean isEquiv(Object o1, Object o2)
    {
        if (o1 == null)
        {
            return o2 == null;
        }

        return o1.equals(o2);
    }

    public static void main(
        String[]    args)
    {
        runTest(new IssuingDistributionPointUnitTest());
    }
}