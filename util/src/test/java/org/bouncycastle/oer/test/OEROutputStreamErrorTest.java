package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;
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
        definedOptionalWrapperAtRequiredElementIsWritten();
    }

    /**
     * A required component wrapped in a defined OEROptional - the form the ITS classes' toASN1Primitive
     * produce - is present, and is written like the bare value. Only the undefined wrapper is absent.
     */
    private void definedOptionalWrapperAtRequiredElementIsWritten()
        throws Exception
    {
        Element def = OERDefinition.seq(
            OERDefinition.integer(0, 255).label("requiredField")
        ).build();

        ByteArrayOutputStream wrapped = new ByteArrayOutputStream();
        new OEROutputStream(wrapped).write(
            new DERSequence(new ASN1Encodable[]{OEROptional.getInstance(new ASN1Integer(7))}), def);

        ByteArrayOutputStream bare = new ByteArrayOutputStream();
        new OEROutputStream(bare).write(new DERSequence(new ASN1Encodable[]{new ASN1Integer(7)}), def);

        isTrue("defined wrapper encodes as the bare value", Arrays.areEqual(bare.toByteArray(), wrapped.toByteArray()));
        isTrue("encoding is the single octet 07", Arrays.areEqual(new byte[]{ 0x07 }, wrapped.toByteArray()));
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
