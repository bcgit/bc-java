package org.bouncycastle.oer.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDecoder;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OEROptional;

public class OERExtensionTest
    extends TestCase
{

    private static final OERDefinition.Builder defBuilder = OERDefinition.seq(
        OERDefinition.integer(0, 255),
        OERDefinition.extension(
            OERDefinition.optional(
                OERDefinition.utf8String(),
                OERDefinition.integer()
            )
        )
    );

    public void testWithoutExtensionValue()
        throws Exception
    {

        Element ele = defBuilder.build();

        // Only has the non extension part populated
        ASN1Encodable withOutExtension = new DERSequence(new ASN1Encodable[]{new ASN1Integer(1)});

        byte[] raw = OEREncoder.toByteArray(withOutExtension, ele);
        TestCase.assertTrue((raw[0] & 0x80) == 0); // Extension present bit must be zero

        ASN1Sequence result = ASN1Sequence.getInstance(OERDecoder.decode(raw, ele));
        TestCase.assertEquals(1, result.size());
    }


    public void testWithOneExtensionValue()
        throws Exception
    {

        Element ele = defBuilder.build();
        {
            // Only has the non extension part populated
            ASN1Encodable withOutExtension = new DERSequence(new ASN1Encodable[]{new ASN1Integer(1), new DERUTF8String("cats")});

            byte[] raw = OEREncoder.toByteArray(withOutExtension, ele);
            TestCase.assertTrue((raw[0] & 0x80) != 0); // Extension present bit must be zero

            ASN1Sequence result = ASN1Sequence.getInstance(OERDecoder.decode(raw, ele));
            TestCase.assertEquals(3, result.size());
        }
        //
        // Again but with the first extension value missing.
        //

        {
            ASN1Encodable withOutExtension = new DERSequence(new ASN1Encodable[]{new ASN1Integer(1), OEROptional.ABSENT, new ASN1Integer(10)});

            byte[] raw = OEREncoder.toByteArray(withOutExtension, ele);
            TestCase.assertTrue((raw[0] & 0x80) != 0); // Extension present bit must be zero

            ASN1Sequence result = ASN1Sequence.getInstance(OERDecoder.decode(raw, ele));
            TestCase.assertEquals(3, result.size());
            TestCase.assertEquals(10, ASN1Integer.getInstance(result.getObjectAt(2)).intValueExact());
        }

    }

    public void testSequenceWithUndefinedExtensions()
        throws IOException
    {

        // This test verifies that the reader will skip extensions it does not know about.
        // For example, the sending implementation is using a later version of a module
        // and while the earlier version indicated the possibility of extensions the later version has them
        // defined.

        // Reading version
        OERDefinition.Builder readBuilder = OERDefinition.seq(
            OERDefinition.seq(
                OERDefinition.utf8String(),
                OERDefinition.extension() // Possibility of an extension but not defined.
            ),
            OERDefinition.integer()
        );

        Element readElement = readBuilder.build();


        //
        // This is a later version of the above.
        //
        OERDefinition.Builder writeBuilder = OERDefinition.seq(
            OERDefinition.seq(
                OERDefinition.utf8String(),
                OERDefinition.extension(
                    OERDefinition.optional(OERDefinition.integer(), OERDefinition.utf8String()) // With defined extensions
                )
            ),
            OERDefinition.integer()
        );

        Element writeElement = writeBuilder.build();


        ASN1Encodable enc = new DERSequence(new ASN1Encodable[]{
            new DERSequence(new ASN1Encodable[]{
                new DERUTF8String("cats"),
                OEROptional.ABSENT, // this and the one below are actually extension values.
                new DERUTF8String("other")
            }),
            new ASN1Integer(10)
        });

        byte[] value = OEREncoder.toByteArray(enc, writeElement);

        // As we are reading it with an earlier version of the definition
        // we only expect to see [["cats"],10]

        ASN1Encodable dec = OERDecoder.decode(value, readElement);

        ASN1Sequence seq1 = ASN1Sequence.getInstance(dec);
        TestCase.assertEquals(2, seq1.size());
        TestCase.assertEquals(10, ASN1Integer.getInstance(seq1.getObjectAt(1)).intValueExact());

        ASN1Sequence seq2 = ASN1Sequence.getInstance(seq1.getObjectAt(0));
        TestCase.assertEquals(1, seq2.size());
        TestCase.assertEquals("cats", ASN1UTF8String.getInstance(seq2.getObjectAt(0)).getString());

    }


}
