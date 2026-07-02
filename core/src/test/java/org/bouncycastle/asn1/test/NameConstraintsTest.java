package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.util.test.SimpleTest;

public class NameConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "NameConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        // GeneralSubtree ::= SEQUENCE { base GeneralName, ... } - base is mandatory, so an empty
        // sequence is malformed and must be rejected with a clean IllegalArgumentException rather
        // than an unchecked ArrayIndexOutOfBoundsException escaping the parse path.
        try
        {
            GeneralSubtree.getInstance(new DERSequence());
            fail("empty GeneralSubtree accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("sequence may not be empty", e.getMessage());
        }

        // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10):
        // an empty permittedSubtrees [0] must be rejected.
        try
        {
            NameConstraints.getInstance(new DERSequence(new DERTaggedObject(false, 0, new DERSequence())));
            fail("empty permittedSubtrees accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("sequence may not be empty", e.getMessage());
        }

        // ... and likewise an empty excludedSubtrees [1].
        try
        {
            NameConstraints.getInstance(new DERSequence(new DERTaggedObject(false, 1, new DERSequence())));
            fail("empty excludedSubtrees accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("sequence may not be empty", e.getMessage());
        }

        // a valid non-empty NameConstraints still round-trips through the parse path.
        GeneralSubtree subtree = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "test.example.com"));
        NameConstraints nc = new NameConstraints(new GeneralSubtree[]{ subtree }, null);

        NameConstraints parsed = NameConstraints.getInstance(nc.toASN1Primitive());
        isTrue("permitted subtree count", parsed.getPermittedSubtrees().length == 1);
        isTrue("excluded subtrees absent", parsed.getExcludedSubtrees() == null);
    }

    public static void main(
        String[] args)
    {
        runTest(new NameConstraintsTest());
    }
}
