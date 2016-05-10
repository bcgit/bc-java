package com.github.gv2011.bcasn.asn1.test;

import java.io.ByteArrayInputStream;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.DERGeneralizedTime;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.cms.RecipientKeyIdentifier;
import com.github.gv2011.bcasn.asn1.smime.SMIMECapabilitiesAttribute;
import com.github.gv2011.bcasn.asn1.smime.SMIMECapability;
import com.github.gv2011.bcasn.asn1.smime.SMIMECapabilityVector;
import com.github.gv2011.bcasn.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import com.github.gv2011.bcasn.util.encoders.Base64;
import com.github.gv2011.bcasn.util.test.SimpleTestResult;
import com.github.gv2011.bcasn.util.test.Test;
import com.github.gv2011.bcasn.util.test.TestResult;

public class SMIMETest
    implements Test
{
    byte[] attrBytes = Base64.decode("MDQGCSqGSIb3DQEJDzEnMCUwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMAcGBSsOAwIH");
    byte[] prefBytes = Base64.decode("MCwGCyqGSIb3DQEJEAILMR2hGwQIAAAAAAAAAAAYDzIwMDcwMzE1MTczNzI5Wg==");

    private boolean isSameAs(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        
        return true;
    }
    
    public TestResult perform()
    {
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();
                
        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);
                
        SMIMECapabilitiesAttribute attr = new SMIMECapabilitiesAttribute(caps);
        
        SMIMEEncryptionKeyPreferenceAttribute   pref = new SMIMEEncryptionKeyPreferenceAttribute(
                                                  new RecipientKeyIdentifier(new DEROctetString(new byte[8]), new DERGeneralizedTime("20070315173729Z"), null));
        
        try
        {
            if (!isSameAs(attr.getEncoded(), attrBytes))
            {
                return new SimpleTestResult(false, getName() + ": Failed attr data check");
            }
            
            ByteArrayInputStream    bIn = new ByteArrayInputStream(attrBytes);
            ASN1InputStream         aIn = new ASN1InputStream(bIn);
            
            ASN1Primitive o = aIn.readObject();
            if (!attr.equals(o))
            {
                return new SimpleTestResult(false, getName() + ": Failed equality test for attr");
            }
            
            if (!isSameAs(pref.getEncoded(), prefBytes))
            {
                return new SimpleTestResult(false, getName() + ": Failed attr data check");
            }
            
            bIn = new ByteArrayInputStream(prefBytes);
            aIn = new ASN1InputStream(bIn);
            
            o = aIn.readObject();
            if (!pref.equals(o))
            {
                return new SimpleTestResult(false, getName() + ": Failed equality test for pref");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "SMIME";
    }

    public static void main(
        String[] args)
    {
        SMIMETest    test = new SMIMETest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
