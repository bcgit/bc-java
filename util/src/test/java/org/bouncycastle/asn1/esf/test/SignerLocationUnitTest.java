package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.util.test.SimpleTest;

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

        checkConstruction(sl, DirectoryString.getInstance(countryName), null, null);

        DERUTF8String localityName = new DERUTF8String("Melbourne");
        
        sl = new SignerLocation(null, localityName, null);

        checkConstruction(sl, null, DirectoryString.getInstance(localityName), null);
        
        sl = new SignerLocation(countryName, localityName, null);

        checkConstruction(sl, DirectoryString.getInstance(countryName), DirectoryString.getInstance(localityName), null);
        
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(new DERUTF8String("line 1"));
        v.add(new DERUTF8String("line 2"));
        
        ASN1Sequence postalAddress = new DERSequence(v);
        
        sl = new SignerLocation(null, null, postalAddress);
        
        checkConstruction(sl, null, null, postalAddress);
        
        sl = new SignerLocation(countryName, null, postalAddress);
        
        checkConstruction(sl, DirectoryString.getInstance(countryName), null, postalAddress);
        
        sl = new SignerLocation(countryName, localityName, postalAddress);
        
        checkConstruction(sl, DirectoryString.getInstance(countryName), DirectoryString.getInstance(localityName), postalAddress);
        
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
        DirectoryString  countryName,
        DirectoryString  localityName,
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
        DirectoryString countryName,
        DirectoryString  localityName,
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
