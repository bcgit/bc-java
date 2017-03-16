package org.bouncycastle.asn1.test;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.GetCRL;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.util.test.SimpleTest;

public class GetCRLTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new GetCRLTest());
    }

    public String getName()
    {
        return "GetCRLTest";
    }

    public void performTest()
        throws Exception
    {

        {
            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            builder.addRDN(BCStyle.C, "AU");
            X500Name name = new X500Name(builder.build().toString());

            GetCRL crl = new GetCRL(
                name,
                new GeneralName(GeneralName.rfc822Name, "/"),
                new ASN1GeneralizedTime(new Date()),
                new ReasonFlags(ReasonFlags.affiliationChanged)
            );

            byte[] b = crl.getEncoded();

            GetCRL crlResp = GetCRL.getInstance(b);

            isEquals("IssuerName", crl.getIssuerName(), crlResp.getIssuerName());
            isEquals("cRLName", crl.getcRLName(), crlResp.getcRLName());
            isEquals("time", crl.getTime(), crlResp.getTime());
            isEquals("reasons", crl.getReasons(), crlResp.getReasons());

            try
            {
                GetCRL.getInstance(new DERSequence(new ASN1Encodable[0]));
                fail("Must not accept sequence less than 1");
            }
            catch (Throwable t)
            {
                isEquals("", t.getClass(), IllegalArgumentException.class);
            }

            try
            {
                GetCRL.getInstance(new DERSequence(new ASN1Encodable[5]));
                fail("Must not accept sequence larger than 5");
            }
            catch (Throwable t)
            {
                isEquals("", t.getClass(), IllegalArgumentException.class);
            }
        }

        { // Permutate on options test all possible combinations.

            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            builder.addRDN(BCStyle.C, "AU");
            X500Name name = new X500Name(builder.build().toString());
            GeneralName generalName = null;
            ASN1GeneralizedTime generalizedTime = null;
            ReasonFlags flags = null;

            for (int t = 0; t < 8; t++)
            {
                if ((t & 1) == 1)
                {
                    generalName = new GeneralName(GeneralName.rfc822Name, "/");
                }
                if ((t & 2) == 2)
                {
                    generalizedTime = new ASN1GeneralizedTime(new Date());
                }

                if ((t & 4) == 4)
                {
                    flags = new ReasonFlags(ReasonFlags.affiliationChanged);
                }


                GetCRL crl = new GetCRL(
                    name,
                    generalName,
                    generalizedTime,
                    flags
                );

                byte[] b = crl.getEncoded();

                GetCRL crlResp = GetCRL.getInstance(b);

                isEquals("IssuerName", crl.getIssuerName(), crlResp.getIssuerName());
                isEquals("cRLName", crl.getcRLName(), crlResp.getcRLName());
                isEquals("time", crl.getTime(), crlResp.getTime());
                isEquals("reasons", crl.getReasons(), crlResp.getReasons());

            }
        }

    }
}
