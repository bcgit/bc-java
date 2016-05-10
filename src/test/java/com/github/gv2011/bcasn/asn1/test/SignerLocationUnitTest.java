package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;
import com.github.gv2011.bcasn.asn1.DERUTF8String;
import com.github.gv2011.bcasn.asn1.esf.SignerLocation;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class SignerLocationUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "SignerLocation";
    }

    public void performTest() 
        throws Exception
    {
        DERUTF8String countryName = new DERUTF8String("Australia");
        
        SignerLocation sl = new SignerLocation(countryName, null, null);

        checkConstruction(sl, countryName, null, null);

        DERUTF8String localityName = new DERUTF8String("Melbourne");
        
        sl = new SignerLocation(null, localityName, null);

        checkConstruction(sl, null, localityName, null);
        
        sl = new SignerLocation(countryName, localityName, null);

        checkConstruction(sl, countryName, localityName, null);
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(new DERUTF8String("line 1"));
        v.add(new DERUTF8String("line 2"));
        
        ASN1Sequence postalAddress = new DERSequence(v);
        
        sl = new SignerLocation(null, null, postalAddress);
        
        checkConstruction(sl, null, null, postalAddress);
        
        sl = new SignerLocation(countryName, null, postalAddress);
        
        checkConstruction(sl, countryName, null, postalAddress);
        
        sl = new SignerLocation(countryName, localityName, postalAddress);
        
        checkConstruction(sl, countryName, localityName, postalAddress);
        
        sl = SignerLocation.getInstance(null);
        
        if (sl != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            SignerLocation.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
      
        //
        // out of range postal address
        //
        v = new ASN1EncodableVector();
        
        v.add(new DERUTF8String("line 1"));
        v.add(new DERUTF8String("line 2"));
        v.add(new DERUTF8String("line 3"));
        v.add(new DERUTF8String("line 4"));
        v.add(new DERUTF8String("line 5"));
        v.add(new DERUTF8String("line 6"));
        v.add(new DERUTF8String("line 7"));
        
        postalAddress = new DERSequence(v);
        
        try
        {
            new SignerLocation(null, null, postalAddress);
            
            fail("constructor failed to detect bad postalAddress.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            SignerLocation.getInstance(new DERSequence(new DERTaggedObject(2, postalAddress)));
            
            fail("sequence constructor failed to detect bad postalAddress.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            SignerLocation.getInstance(new DERSequence(new DERTaggedObject(5, postalAddress)));
            
            fail("sequence constructor failed to detect bad tag.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        SignerLocation sl,
        DERUTF8String  countryName,
        DERUTF8String  localityName,
        ASN1Sequence   postalAddress) 
        throws IOException
    {
        checkValues(sl, countryName, localityName, postalAddress);
        
        sl = SignerLocation.getInstance(sl);
        
        checkValues(sl, countryName, localityName, postalAddress);
        
        ASN1InputStream aIn = new ASN1InputStream(sl.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        sl = SignerLocation.getInstance(seq);
        
        checkValues(sl, countryName, localityName, postalAddress);
    }
    
    private void checkValues(
        SignerLocation sl,
        DERUTF8String  countryName,
        DERUTF8String  localityName,
        ASN1Sequence   postalAddress)
    {
        if (countryName != null)
        {
            if (!countryName.equals(sl.getCountryName()))
            {
                fail("countryNames don't match.");
            }
        }
        else if (sl.getCountryName() != null)
        {
            fail("countryName found when none expected.");
        }
        
        if (localityName != null)
        {
            if (!localityName.equals(sl.getLocalityName()))
            {
                fail("localityNames don't match.");
            }
        }
        else if (sl.getLocalityName() != null)
        {
            fail("localityName found when none expected.");
        }
        
        if (postalAddress != null)
        {
            if (!postalAddress.equals(sl.getPostalAddress()))
            {
                fail("postalAddresses don't match.");
            }
        }
        else if (sl.getPostalAddress() != null)
        {
            fail("postalAddress found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new SignerLocationUnitTest());
    }
}
