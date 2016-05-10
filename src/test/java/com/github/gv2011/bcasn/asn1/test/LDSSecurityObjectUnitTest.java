package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;
import java.util.Random;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.icao.DataGroupHash;
import com.github.gv2011.bcasn.asn1.icao.LDSSecurityObject;
import com.github.gv2011.bcasn.asn1.icao.LDSVersionInfo;
import com.github.gv2011.bcasn.asn1.oiw.OIWObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.x509.AlgorithmIdentifier;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class LDSSecurityObjectUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "LDSSecurityObject";
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
        AlgorithmIdentifier  algoId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        DataGroupHash[] datas = new DataGroupHash[2];
      
        datas[0] = new DataGroupHash(1, new DEROctetString(generateHash()));
        datas[1] = new DataGroupHash(2, new DEROctetString(generateHash()));
        
        LDSSecurityObject so = new LDSSecurityObject(algoId, datas);

        checkConstruction(so, algoId, datas);

        LDSVersionInfo versionInfo = new LDSVersionInfo("Hello", "world");

        so = new LDSSecurityObject(algoId, datas, versionInfo);

        checkConstruction(so, algoId, datas, versionInfo);

        try
        {
            LDSSecurityObject.getInstance(null);
        }
        catch (Exception e)
        {
            fail("getInstance() failed to handle null.");
        }
        
        try
        {
            LDSSecurityObject.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            
            LDSSecurityObject.getInstance(new DERSequence(v));
            
            fail("constructor failed to detect empty sequence.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new LDSSecurityObject(algoId, new DataGroupHash[1]);
            
            fail("constructor failed to detect small DataGroupHash array.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            new LDSSecurityObject(algoId, new DataGroupHash[LDSSecurityObject.ub_DataGroups + 1]);
            
            fail("constructor failed to out of bounds DataGroupHash array.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        LDSSecurityObject so,
        AlgorithmIdentifier digestAlgorithmIdentifier, 
        DataGroupHash[]       datagroupHash) 
        throws IOException
    {
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, null);
        
        so = LDSSecurityObject.getInstance(so);
        
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, null);
        
        ASN1InputStream aIn = new ASN1InputStream(so.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        so = LDSSecurityObject.getInstance(seq);
        
        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, null);
    }

    private void checkConstruction(
        LDSSecurityObject   so,
        AlgorithmIdentifier digestAlgorithmIdentifier,
        DataGroupHash[]     datagroupHash,
        LDSVersionInfo      versionInfo)
        throws IOException
    {
        if (so.getVersion() != 1)
        {
            fail("version number not 1");
        }

        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, versionInfo);

        so = LDSSecurityObject.getInstance(so);

        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, versionInfo);

        ASN1InputStream aIn = new ASN1InputStream(so.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        so = LDSSecurityObject.getInstance(seq);

        checkStatement(so, digestAlgorithmIdentifier, datagroupHash, versionInfo);
    }

    private void checkStatement(
        LDSSecurityObject   so,
        AlgorithmIdentifier digestAlgorithmIdentifier, 
        DataGroupHash[]     datagroupHash,
        LDSVersionInfo      versionInfo)
    {
        if (digestAlgorithmIdentifier != null)
        {
            if (!so.getDigestAlgorithmIdentifier().equals(digestAlgorithmIdentifier))
            {
                fail("ids don't match.");
            }
        }
        else if (so.getDigestAlgorithmIdentifier() != null)
        {
            fail("digest algorithm Id found when none expected.");
        }
        
        if (datagroupHash != null)
        {
            DataGroupHash[] datas = so.getDatagroupHash();
            
            for (int i = 0; i != datas.length; i++)
            {
                if (!datagroupHash[i].equals(datas[i]))
                {
                    fail("name registration authorities don't match.");
                }
            }
        }
        else if (so.getDatagroupHash() != null)
        {
            fail("data hash groups found when none expected.");
        }

        if (versionInfo != null)
        {
            if (!versionInfo.equals(so.getVersionInfo()))
            {
                fail("versionInfo doesn't match");
            }
        }
        else if (so.getVersionInfo() != null)
        {
            fail("version info found when none expected.");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new LDSSecurityObjectUnitTest());
    }
}
