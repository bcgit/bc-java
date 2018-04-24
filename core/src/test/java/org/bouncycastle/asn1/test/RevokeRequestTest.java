package org.bouncycastle.asn1.test;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.test.SimpleTest;


public class RevokeRequestTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new RevokeRequestTest());
    }

    public String getName()
    {
        return "RevokeRequestTest";
    }

    public void performTest()
        throws Exception
    {


        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.OU, "Bouncycastle");

        X500Name name = builder.build();

        for (int t = 0; t < 8; t++)
        {
            ASN1GeneralizedTime invalidityDate = null;
            ASN1OctetString passphrase = null;
            DERUTF8String comment = null;

            if ((t & 1) == 1)
            {
                invalidityDate = new ASN1GeneralizedTime(new Date());
            }
            if ((t & 2) == 2)
            {
                passphrase = new DEROctetString(Pack.longToBigEndian(System.currentTimeMillis()));
            }
            if ((t & 4) == 4)
            {
                comment = new DERUTF8String("T" + Long.toOctalString(System.currentTimeMillis()));
            }

            RevokeRequest rr = new RevokeRequest(
                name,
                new ASN1Integer(12L),
                CRLReason.getInstance(new ASN1Enumerated(CRLReason.certificateHold)),
                invalidityDate,
                passphrase,
                comment);
            byte[] b = rr.getEncoded();
            RevokeRequest rrResp = RevokeRequest.getInstance(b);

            isEquals("issuerName", rr.getName(), rrResp.getName());
            isEquals("serialNumber", rr.getSerialNumber(), rrResp.getSerialNumber());
            isEquals("reason", rr.getReason(), rrResp.getReason());
            isEquals("invalidityDate", rr.getInvalidityDate(), rrResp.getInvalidityDate());
            isTrue("passphrase", areEqual(rr.getPassPhrase(), rrResp.getPassPhrase()));
            isEquals("comment", rr.getComment(), rrResp.getComment());

        }

        try
        {
            RevokeRequest.getInstance(new DERSequence());
            fail("Sequence is less that 3");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
