package com.github.gv2011.bcasn.asn1.x509.qualified;

import com.github.gv2011.bcasn.asn1.ASN1Choice;
import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.DERPrintableString;

/**
 * The Iso4217CurrencyCode object.
 * <pre>
 * Iso4217CurrencyCode  ::=  CHOICE {
 *       alphabetic              PrintableString (SIZE 3), --Recommended
 *       numeric              INTEGER (1..999) }
 * -- Alphabetic or numeric currency code as defined in ISO 4217
 * -- It is recommended that the Alphabetic form is used
 * </pre>
 */
public class Iso4217CurrencyCode 
    extends ASN1Object
    implements ASN1Choice
{
    final int ALPHABETIC_MAXSIZE = 3;
    final int NUMERIC_MINSIZE = 1;
    final int NUMERIC_MAXSIZE = 999;
    
    ASN1Encodable obj;
    int          numeric;
    
    public static Iso4217CurrencyCode getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof Iso4217CurrencyCode)
        {
            return (Iso4217CurrencyCode)obj;
        }

        if (obj instanceof ASN1Integer)
        {
            ASN1Integer numericobj = ASN1Integer.getInstance(obj);
            int numeric = numericobj.getValue().intValue();  
            return new Iso4217CurrencyCode(numeric);            
        }
        else
        if (obj instanceof DERPrintableString)
        {
            DERPrintableString alphabetic = DERPrintableString.getInstance(obj);
            return new Iso4217CurrencyCode(alphabetic.getString());
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }
            
    public Iso4217CurrencyCode(
        int numeric)
    {
        if (numeric > NUMERIC_MAXSIZE || numeric < NUMERIC_MINSIZE)
        {
            throw new IllegalArgumentException("wrong size in numeric code : not in (" +NUMERIC_MINSIZE +".."+ NUMERIC_MAXSIZE +")");
        }
        obj = new ASN1Integer(numeric);
    }
    
    public Iso4217CurrencyCode(
        String alphabetic)
    {
        if (alphabetic.length() > ALPHABETIC_MAXSIZE)
        {
            throw new IllegalArgumentException("wrong size in alphabetic code : max size is " + ALPHABETIC_MAXSIZE);
        }
        obj = new DERPrintableString(alphabetic);
    }            

    public boolean isAlphabetic()
    {
        return obj instanceof DERPrintableString;
    }
    
    public String getAlphabetic()
    {
        return ((DERPrintableString)obj).getString();
    }
    
    public int getNumeric()
    {
        return ((ASN1Integer)obj).getValue().intValue();
    }
    
    public ASN1Primitive toASN1Primitive()
    {    
        return obj.toASN1Primitive();
    }
}
