package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.util.test.SimpleTest;

public class TypeOfBiometricDataUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "TypeOfBiometricData";
    }

    public void performTest() 
        throws Exception
    {
        //
        // predefined
        //
        checkPredefinedType(TypeOfBiometricData.PICTURE);
        
        checkPredefinedType(TypeOfBiometricData.HANDWRITTEN_SIGNATURE);
        
        //
        // non-predefined
        //
        ASN1ObjectIdentifier localType = new ASN1ObjectIdentifier("1.1");
        
        TypeOfBiometricData type = new TypeOfBiometricData(localType);

        checkNonPredefined(type, localType);
        
        type = TypeOfBiometricData.getInstance(type);
        
        checkNonPredefined(type, localType);
        
        ASN1Primitive obj = type.toASN1Primitive();
        
        type = TypeOfBiometricData.getInstance(obj);
        
        checkNonPredefined(type, localType);
        
        type = TypeOfBiometricData.getInstance(null);
        
        if (type != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            TypeOfBiometricData.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new TypeOfBiometricData(100);
            
            fail("constructor failed to detect bad predefined type.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        if (TypeOfBiometricData.PICTURE != 0)
        {
            fail("predefined picture should be 0");
        }
        
        if (TypeOfBiometricData.HANDWRITTEN_SIGNATURE != 1)
        {
            fail("predefined handwritten signature should be 1");
        }
    }

    private void checkPredefinedType(
        int predefinedType)
        throws IOException
    {
        TypeOfBiometricData type = new TypeOfBiometricData(predefinedType);

        checkPredefined(type, predefinedType);
        
        type = TypeOfBiometricData.getInstance(type);
        
        checkPredefined(type, predefinedType);
        
        ASN1InputStream aIn = new ASN1InputStream(type.toASN1Primitive().getEncoded());

        ASN1Primitive obj = aIn.readObject();

        type = TypeOfBiometricData.getInstance(obj);
        
        checkPredefined(type, predefinedType);
    }

    private void checkPredefined(
        TypeOfBiometricData type,
        int                 value)
    {
        if (!type.isPredefined())
        {
            fail("predefined type expected but not found.");
        }
        
        if (type.getPredefinedBiometricType() != value)
        {
            fail("predefined type does not match.");
        }
    }
    
    private void checkNonPredefined(
        TypeOfBiometricData type,
        ASN1ObjectIdentifier value)
    {
        if (type.isPredefined())
        {
            fail("predefined type found when not expected.");
        }
        
        if (!type.getBiometricDataOid().equals(value))
        {
            fail("data oid does not match.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new TypeOfBiometricDataUnitTest());
    }
}
