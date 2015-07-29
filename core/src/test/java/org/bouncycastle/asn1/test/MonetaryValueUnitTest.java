package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.util.test.SimpleTest;

public class MonetaryValueUnitTest 
    extends SimpleTest
{
    private static final int TEST_AMOUNT = 100;
    private static final int ZERO_EXPONENT = 0;
    
    private static final String CURRENCY_CODE = "AUD";

    public String getName()
    {
        return "MonetaryValue";
    }

    public void performTest() 
        throws Exception
    {
        MonetaryValue mv = new MonetaryValue(new Iso4217CurrencyCode(CURRENCY_CODE), TEST_AMOUNT, ZERO_EXPONENT);

        checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);
        
        mv = MonetaryValue.getInstance(mv);
        
        checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        mv = MonetaryValue.getInstance(seq);
        
        checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);
        
        mv = MonetaryValue.getInstance(null);
        
        if (mv != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            MonetaryValue.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkValues(
        MonetaryValue mv,
        int           amount,
        int           exponent)
    {
        if (mv.getAmount().intValue() != amount)
        {
            fail("amounts don't match.");
        }
        
        if (mv.getExponent().intValue() != exponent)
        {
            fail("exponents don't match.");
        }
        
        Iso4217CurrencyCode cc = mv.getCurrency();
        
        if (!cc.getAlphabetic().equals(CURRENCY_CODE))
        {
            fail("currency code wrong");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new MonetaryValueUnitTest());
    }
}
