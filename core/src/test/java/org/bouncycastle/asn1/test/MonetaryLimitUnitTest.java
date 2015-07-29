package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.isismtt.x509.MonetaryLimit;

public class MonetaryLimitUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "MonetaryLimit";
    }

    public void performTest()
        throws Exception
    {
        String currency = "AUD";
        int    amount = 1;
        int    exponent = 2;

        MonetaryLimit limit = new MonetaryLimit(currency, amount, exponent);

        checkConstruction(limit, currency, amount, exponent);

        limit = MonetaryLimit.getInstance(null);

        if (limit != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            MonetaryLimit.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        MonetaryLimit limit,
        String currency,
        int    amount,
        int    exponent)
        throws IOException
    {
        checkValues(limit, currency, amount, exponent);

        limit = MonetaryLimit.getInstance(limit);

        checkValues(limit, currency, amount, exponent);

        ASN1InputStream aIn = new ASN1InputStream(limit.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        limit = MonetaryLimit.getInstance(seq);

        checkValues(limit, currency, amount, exponent);
    }

    private void checkValues(
        MonetaryLimit limit,
        String currency,
        int    amount,
        int    exponent)
    {
        checkMandatoryField("currency", currency, limit.getCurrency());
        checkMandatoryField("amount", amount, limit.getAmount().intValue());
        checkMandatoryField("exponent", exponent, limit.getExponent().intValue());
    }

    public static void main(
        String[]    args)
    {
        runTest(new MonetaryLimitUnitTest());
    }
}
