package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.util.test.SimpleTest;

public class Iso4217CurrencyCodeUnitTest 
    extends SimpleTest
{
    private static final String ALPHABETIC_CURRENCY_CODE = "AUD";
    private static final int    NUMERIC_CURRENCY_CODE = 1;

    public String getName()
    {
        return "Iso4217CurrencyCode";
    }

    public void performTest() 
        throws Exception
    {
        //
        // alphabetic
        //
        Iso4217CurrencyCode cc = new Iso4217CurrencyCode(ALPHABETIC_CURRENCY_CODE);

        checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);
        
        cc = Iso4217CurrencyCode.getInstance(cc);
        
        checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);
        
        ASN1Primitive obj = cc.toASN1Primitive();
        
        cc = Iso4217CurrencyCode.getInstance(obj);
        
        checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);
        
        //
        // numeric
        //
        cc = new Iso4217CurrencyCode(NUMERIC_CURRENCY_CODE);

        checkNumeric(cc, NUMERIC_CURRENCY_CODE);
        
        cc = Iso4217CurrencyCode.getInstance(cc);
        
        checkNumeric(cc, NUMERIC_CURRENCY_CODE);
        
        obj = cc.toASN1Primitive();
        
        cc = Iso4217CurrencyCode.getInstance(obj);
        
        checkNumeric(cc, NUMERIC_CURRENCY_CODE);
        
        cc = Iso4217CurrencyCode.getInstance(null);
        
        if (cc != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            Iso4217CurrencyCode.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new Iso4217CurrencyCode("ABCD");
            
            fail("constructor failed to detect out of range currencycode.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new Iso4217CurrencyCode(0);
            
            fail("constructor failed to detect out of range small numeric code.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new Iso4217CurrencyCode(1000);
            
            fail("constructor failed to detect out of range large numeric code.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkNumeric(
        Iso4217CurrencyCode cc,
        String              code)
    {
        if (!cc.isAlphabetic())
        {
            fail("non-alphabetic code found when one expected.");
        }
        
        if (!cc.getAlphabetic().equals(code))
        {
            fail("string codes don't match.");
        }
    }
    
    private void checkNumeric(
        Iso4217CurrencyCode cc,
        int                 code)
    {
        if (cc.isAlphabetic())
        {
            fail("alphabetic code found when one not expected.");
        }
        
        if (cc.getNumeric() != code)
        {
            fail("numeric codes don't match.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new Iso4217CurrencyCodeUnitTest());
    }
}
