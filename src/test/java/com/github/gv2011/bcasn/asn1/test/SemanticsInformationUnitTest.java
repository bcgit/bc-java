package com.github.gv2011.bcasn.asn1.test;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.x500.X500Name;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;
import com.github.gv2011.bcasn.asn1.x509.qualified.SemanticsInformation;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class SemanticsInformationUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "SemanticsInformation";
    }

    public void performTest() 
        throws Exception
    {
        ASN1ObjectIdentifier statementId = new ASN1ObjectIdentifier("1.1");
        SemanticsInformation mv = new SemanticsInformation(statementId);

        checkConstruction(mv, statementId, null);
        
        GeneralName[] names = new GeneralName[2];
        
        names[0] = new GeneralName(GeneralName.rfc822Name, "test@test.org");
        names[1] = new GeneralName(new X500Name("cn=test"));
        
        mv = new SemanticsInformation(statementId, names);

        checkConstruction(mv, statementId, names);
        
        mv = new SemanticsInformation(names);

        checkConstruction(mv, null, names);
        
        mv = SemanticsInformation.getInstance(null);
        
        if (mv != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            SemanticsInformation.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        try
        {
            ASN1EncodableVector v = new ASN1EncodableVector();
            
            SemanticsInformation.getInstance(new DERSequence(v));
            
            fail("constructor failed to detect empty sequence.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        SemanticsInformation mv,
        ASN1ObjectIdentifier  semanticsIdentifier,
        GeneralName[]        names)
        throws Exception
    {
        checkStatement(mv, semanticsIdentifier, names);
        
        mv = SemanticsInformation.getInstance(mv);
        
        checkStatement(mv, semanticsIdentifier, names);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());
        
        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        mv = SemanticsInformation.getInstance(seq);
        
        checkStatement(mv, semanticsIdentifier, names);
    }

    private void checkStatement(
        SemanticsInformation si,
        ASN1ObjectIdentifier  id,
        GeneralName[]        names)
    {
        if (id != null)
        {
            if (!si.getSemanticsIdentifier().equals(id))
            {
                fail("ids don't match.");
            }
        }
        else if (si.getSemanticsIdentifier() != null)
        {
            fail("statementId found when none expected.");
        }
        
        if (names != null)
        {
            GeneralName[] siNames = si.getNameRegistrationAuthorities();
            
            for (int i = 0; i != siNames.length; i++)
            {
                if (!names[i].equals(siNames[i]))
                {
                    fail("name registration authorities don't match.");
                }
            }
        }
        else if (si.getNameRegistrationAuthorities() != null)
        {
            fail("name registration authorities found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new SemanticsInformationUnitTest());
    }
}
