package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.Random;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.util.test.SimpleTest;

public class DataGroupHashUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "DataGroupHash";
    }

    private byte[] generateHash()
    {
        Random rand = new Random();
        byte[] bytes = new byte[20];
        
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)rand.nextInt();
        }
        
        return bytes;
    }
    
    public void performTest() 
        throws Exception
    {
        int dataGroupNumber = 1;       
        ASN1OctetString     dataHash = new DEROctetString(generateHash());
        DataGroupHash       dg = new DataGroupHash(dataGroupNumber, dataHash);

        checkConstruction(dg, dataGroupNumber, dataHash);

        try
        {
            DataGroupHash.getInstance(null);
        }
        catch (Exception e)
        {
            fail("getInstance() failed to handle null.");
        }

        try
        {
            DataGroupHash.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        DataGroupHash dg,
        int dataGroupNumber,        
        ASN1OctetString     dataGroupHashValue) 
        throws IOException
    {
        checkValues(dg, dataGroupNumber, dataGroupHashValue);

        dg = DataGroupHash.getInstance(dg);

        checkValues(dg, dataGroupNumber, dataGroupHashValue);

        ASN1InputStream aIn = new ASN1InputStream(dg.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        dg = DataGroupHash.getInstance(seq);

        checkValues(dg, dataGroupNumber, dataGroupHashValue);
    }

    private void checkValues(
        DataGroupHash dg,
        int dataGroupNumber,        
        ASN1OctetString     dataGroupHashValue)
    {
        if (dg.getDataGroupNumber() != dataGroupNumber)
        {
            fail("group number don't match.");
        }
        
        if (!dg.getDataGroupHashValue().equals(dataGroupHashValue))
        {
            fail("hash value don't match.");
        }         
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new DataGroupHashUnitTest());
    }
}
