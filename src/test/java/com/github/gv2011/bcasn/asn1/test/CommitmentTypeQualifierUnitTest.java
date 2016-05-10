package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.esf.CommitmentTypeIdentifier;
import com.github.gv2011.bcasn.asn1.esf.CommitmentTypeQualifier;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class CommitmentTypeQualifierUnitTest 
    extends SimpleTest
{
    public String getName()
    {
        return "CommitmentTypeQualifier";
    }

    public void performTest() 
        throws Exception
    {
        CommitmentTypeQualifier ctq = new CommitmentTypeQualifier(CommitmentTypeIdentifier.proofOfOrigin);
        
        checkConstruction(ctq, CommitmentTypeIdentifier.proofOfOrigin, null);
        
        ASN1Encodable info = new ASN1ObjectIdentifier("1.2");
        
        ctq = new CommitmentTypeQualifier(CommitmentTypeIdentifier.proofOfOrigin, info);

        checkConstruction(ctq, CommitmentTypeIdentifier.proofOfOrigin, info);
        
        ctq = CommitmentTypeQualifier.getInstance(null);
        
        if (ctq != null)
        {
            fail("null getInstance() failed.");
        }
        
        try
        {
            CommitmentTypeQualifier.getInstance(new Object());
            
            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
         CommitmentTypeQualifier mv,
         ASN1ObjectIdentifier commitmenttTypeId,
         ASN1Encodable qualifier) 
         throws IOException
    {
        checkStatement(mv, commitmenttTypeId, qualifier);
        
        mv = CommitmentTypeQualifier.getInstance(mv);
        
        checkStatement(mv, commitmenttTypeId, qualifier);
        
        ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
        
        mv = CommitmentTypeQualifier.getInstance(seq);
        
        checkStatement(mv, commitmenttTypeId, qualifier);
    }

    private void checkStatement(
        CommitmentTypeQualifier ctq,
        ASN1ObjectIdentifier     commitmentTypeId,
        ASN1Encodable           qualifier)
    {
        if (!ctq.getCommitmentTypeIdentifier().equals(commitmentTypeId))
        {
            fail("commitmentTypeIds don't match.");
        }
        
        if (qualifier != null)
        {
            if (!ctq.getQualifier().equals(qualifier))
            {
                fail("qualifiers don't match.");
            }
        }
        else if (ctq.getQualifier() != null)
        {
            fail("qualifier found when none expected.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new CommitmentTypeQualifierUnitTest());
    }
}
