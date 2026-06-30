package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * Exercises the diagnostic message OEROutputStream emits when a required (explicit, non-optional)
 * sequence element is absent from the supplied ASN.1 value. The throw condition is unchanged; only
 * the message is enriched with the offending element's label (and the parent label when present).
 */
public class OEROutputStreamErrorTest
    extends SimpleTest
{
    private static final String LEGACY_MESSAGE =
        "absent sequence element that is required by oer definition";

    @Override
    public String getName()
    {
        return "OER OutputStream error message";
    }

    @Override
    public void performTest()
        throws Exception
    {
        absentRequiredElementNamesParentAndChild();
        absentRequiredElementNamesChildWhenParentUnlabelled();
        absentRequiredElementUnlabelledChildKeepsLegacyMessage();
    }

    /**
     * A labelled SEQUENCE with a labelled required child: the message identifies both as
     * {@code parent.child}.
     */
    private void absentRequiredElementNamesParentAndChild()
        throws Exception
    {
        Element def = OERDefinition.seq(
            OERDefinition.integer().label("requiredField")
        ).label("MySeq").build();

        DERSequence seq = new DERSequence(new ASN1Encodable[]{OEROptional.ABSENT});

        OEROutputStream oos = new OEROutputStream(new ByteArrayOutputStream());

        try
        {
            oos.write(seq, def);
            fail("expected IllegalStateException for absent required element");
        }
        catch (IllegalStateException e)
        {
            isEquals(
                "message names parent and child",
                LEGACY_MESSAGE + ": MySeq.requiredField",
                e.getMessage());
        }
    }

    /**
     * The required child is labelled but the parent SEQUENCE is not: the message identifies the
     * child only.
     */
    private void absentRequiredElementNamesChildWhenParentUnlabelled()
        throws Exception
    {
        Element def = OERDefinition.seq(
            OERDefinition.integer().label("requiredField")
        ).build();

        DERSequence seq = new DERSequence(new ASN1Encodable[]{OEROptional.ABSENT});

        OEROutputStream oos = new OEROutputStream(new ByteArrayOutputStream());

        try
        {
            oos.write(seq, def);
            fail("expected IllegalStateException for absent required element");
        }
        catch (IllegalStateException e)
        {
            isEquals(
                "message names child only",
                LEGACY_MESSAGE + ": requiredField",
                e.getMessage());
        }
    }

    /**
     * When the offending child has no label the message must remain byte-identical to the legacy
     * text, so existing callers / future substring matches are unaffected.
     */
    private void absentRequiredElementUnlabelledChildKeepsLegacyMessage()
        throws Exception
    {
        Element def = OERDefinition.seq(
            OERDefinition.integer()
        ).label("MySeq").build();

        DERSequence seq = new DERSequence(new ASN1Encodable[]{OEROptional.ABSENT});

        OEROutputStream oos = new OEROutputStream(new ByteArrayOutputStream());

        try
        {
            oos.write(seq, def);
            fail("expected IllegalStateException for absent required element");
        }
        catch (IllegalStateException e)
        {
            isEquals(
                "unlabelled child keeps legacy message verbatim",
                LEGACY_MESSAGE,
                e.getMessage());
        }
    }

    public static void main(String[] args)
    {
        OEROutputStreamErrorTest test = new OEROutputStreamErrorTest();
        TestResult result = test.perform();

        System.out.println(result);
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
