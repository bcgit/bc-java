package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLGenerator;
import org.bouncycastle.asn1.DLOctetStringGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSequenceGenerator;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests that the streaming generators (BERSequenceGenerator, BEROctetStringGenerator,
 * DERSequenceGenerator) produce the same encodings as the equivalent in-memory objects,
 * for untagged, explicitly tagged and implicitly tagged (X.690 8.14.2 / 8.14.3) forms,
 * including tag numbers requiring the high-tag-number identifier format (X.690 8.1.2.4).
 */
public class ASN1GeneratorTest
    extends SimpleTest
{
    // spans the single-byte identifier limit (30) and multi-byte high-tag-number forms
    private static final int[] TAG_NOS = { 0, 1, 30, 31, 127, 128, 5000 };

    public String getName()
    {
        return "ASN1Generator";
    }

    public void performTest()
        throws Exception
    {
        byte[] content = new byte[2500];    // > 1000 to force octet string chunking
        for (int i = 0; i != content.length; i++)
        {
            content[i] = (byte)i;
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(4095));
        v.add(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));

        BERSequence berSeq = new BERSequence(v);
        DERSequence derSeq = new DERSequence(v);
        BEROctetString berOctets = new BEROctetString(content);

        // untagged baselines
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BERSequenceGenerator berSeqGen = new BERSequenceGenerator(bOut);
        addSequenceContents(berSeqGen);
        berSeqGen.close();
        isTrue("untagged BER seq", areEqual(berSeq.getEncoded(), bOut.toByteArray()));

        bOut = new ByteArrayOutputStream();
        DERSequenceGenerator derSeqGen = new DERSequenceGenerator(bOut);
        addSequenceContents(derSeqGen);
        derSeqGen.close();
        isTrue("untagged DER seq", areEqual(derSeq.getEncoded(ASN1Encoding.DER), bOut.toByteArray()));

        bOut = new ByteArrayOutputStream();
        BEROctetStringGenerator berOctGen = new BEROctetStringGenerator(bOut);
        writeOctetContents(berOctGen, content);
        isTrue("untagged BER octets", areEqual(berOctets.getEncoded(), bOut.toByteArray()));

        for (int i = 0; i != TAG_NOS.length; i++)
        {
            int tagNo = TAG_NOS[i];

            testTaggedBERSequence(tagNo, true, berSeq);
            testTaggedBERSequence(tagNo, false, berSeq);
            testTaggedDERSequence(tagNo, true, derSeq);
            testTaggedDERSequence(tagNo, false, derSeq);
            testTaggedBEROctetString(tagNo, true, content, berOctets);
            testTaggedBEROctetString(tagNo, false, content, berOctets);
        }

        testDLGenerators(content);
        testDLLengthArithmetic();
        testDLLengthEnforcement();
    }

    private void testDLGenerators(byte[] content)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(4095));
        v.add(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
        DLSequence dlSeq = new DLSequence(v);

        long seqBodyLength = new ASN1Integer(4095).getEncoded(ASN1Encoding.DL).length
            + new DEROctetString(new byte[]{ 1, 2, 3, 4 }).getEncoded(ASN1Encoding.DL).length;

        // untagged baselines against the in-memory encodings
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator dlSeqGen = new DLSequenceGenerator(bOut, seqBodyLength);
        dlSeqGen.addObject(new ASN1Integer(4095));
        dlSeqGen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
        dlSeqGen.close();
        isTrue("untagged DL seq", areEqual(dlSeq.getEncoded(ASN1Encoding.DL), bOut.toByteArray()));

        DEROctetString dlOctets = new DEROctetString(content);
        bOut = new ByteArrayOutputStream();
        DLOctetStringGenerator dlOctGen = new DLOctetStringGenerator(bOut, content.length);
        dlOctGen.getOctetOutputStream().write(content);
        dlOctGen.close();
        isTrue("untagged DL octets", areEqual(dlOctets.getEncoded(ASN1Encoding.DL), bOut.toByteArray()));

        for (int i = 0; i != TAG_NOS.length; i++)
        {
            int tagNo = TAG_NOS[i];

            // implicit tags: all tag numbers; explicit: single identifier octet only
            testTaggedDLSequence(tagNo, false, dlSeq, seqBodyLength);
            testTaggedDLOctetString(tagNo, false, content, dlOctets);
            if (tagNo <= 30)
            {
                testTaggedDLSequence(tagNo, true, dlSeq, seqBodyLength);
                testTaggedDLOctetString(tagNo, true, content, dlOctets);
            }
        }
    }

    private void testTaggedDLSequence(int tagNo, boolean isExplicit, DLSequence seq, long bodyLength)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, tagNo, isExplicit, bodyLength);
        gen.addObject(new ASN1Integer(4095));
        gen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
        gen.close();

        byte[] expected = new DLTaggedObject(isExplicit, tagNo, seq).getEncoded(ASN1Encoding.DL);
        isTrue("DL seq [" + tagNo + "] explicit=" + isExplicit, areEqual(expected, bOut.toByteArray()));

        checkSequenceRoundTrip(bOut.toByteArray(), tagNo, isExplicit, seq);
    }

    private void testTaggedDLOctetString(int tagNo, boolean isExplicit, byte[] content, DEROctetString octets)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLOctetStringGenerator gen = new DLOctetStringGenerator(bOut, tagNo, isExplicit, content.length);
        gen.getOctetOutputStream().write(content);
        gen.close();

        byte[] expected = new DLTaggedObject(isExplicit, tagNo, octets).getEncoded(ASN1Encoding.DL);
        isTrue("DL octets [" + tagNo + "] explicit=" + isExplicit, areEqual(expected, bOut.toByteArray()));

        ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());
        ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();
        isTrue("DL octets tagNo [" + tagNo + "]", tagNo == tagged.getTagNo());
        ASN1OctetString recovered = ASN1OctetString.getInstance(tagged, isExplicit);
        isTrue("DL octets content [" + tagNo + "] explicit=" + isExplicit, areEqual(content, recovered.getOctets()));
    }

    private void testDLLengthArithmetic()
        throws Exception
    {
        // short form boundary, long form 1..5 length octets
        long[] bodyLengths = { 0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFFL, 0x100000000L, 0x123456789AL };
        int[] expectedOctets = { 1, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6 };

        for (int i = 0; i != bodyLengths.length; i++)
        {
            isTrue("length octet count for " + bodyLengths[i],
                expectedOctets[i] == DLGenerator.getLengthOctetCount(bodyLengths[i]));
            isTrue("TLV length for " + bodyLengths[i],
                1 + expectedOctets[i] + bodyLengths[i] == DLGenerator.getDLEncodingLength(bodyLengths[i]));
        }

        // a header for a body larger than any Java array: 04 85 12 34 56 78 9A
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new DLOctetStringGenerator(bOut, 0x123456789AL);
        isTrue("beyond-array-size header", areEqual(
            new byte[]{ 0x04, (byte)0x85, 0x12, 0x34, 0x56, 0x78, (byte)0x9A }, bOut.toByteArray()));
    }

    private void testDLLengthEnforcement()
        throws Exception
    {
        // overrun fails on write
        DLOctetStringGenerator gen = new DLOctetStringGenerator(new ByteArrayOutputStream(), 4);
        gen.getOctetOutputStream().write(new byte[]{ 1, 2, 3 });
        try
        {
            gen.getOctetOutputStream().write(new byte[]{ 4, 5 });
            fail("overrun not detected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("more than the declared") >= 0);
        }

        // underrun fails on close
        gen = new DLOctetStringGenerator(new ByteArrayOutputStream(), 4);
        gen.getOctetOutputStream().write(new byte[]{ 1, 2, 3 });
        try
        {
            gen.close();
            fail("underrun not detected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("fewer octets written") >= 0);
        }

        // same checks on the sequence generator body
        DLSequenceGenerator seqGen = new DLSequenceGenerator(new ByteArrayOutputStream(), 3);
        try
        {
            seqGen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
            fail("sequence overrun not detected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("more than the declared") >= 0);
        }

        seqGen = new DLSequenceGenerator(new ByteArrayOutputStream(), 7);
        seqGen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
        try
        {
            seqGen.close();
            fail("sequence underrun not detected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("fewer octets written") >= 0);
        }

        // explicit tags above 30 are rejected up front
        try
        {
            new DLSequenceGenerator(new ByteArrayOutputStream(), 31, true, 4);
            fail("explicit high tag not rejected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("explicit tag numbers > 30") >= 0);
        }
    }

    private void addSequenceContents(BERSequenceGenerator gen)
        throws Exception
    {
        gen.addObject(new ASN1Integer(4095));
        gen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
    }

    private void addSequenceContents(DERSequenceGenerator gen)
        throws Exception
    {
        gen.addObject(new ASN1Integer(4095));
        gen.addObject(new DEROctetString(new byte[]{ 1, 2, 3, 4 }));
    }

    private void writeOctetContents(BEROctetStringGenerator gen, byte[] content)
        throws Exception
    {
        OutputStream octOut = gen.getOctetOutputStream();
        octOut.write(content);
        octOut.close();
    }

    private void testTaggedBERSequence(int tagNo, boolean isExplicit, BERSequence seq)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BERSequenceGenerator gen = new BERSequenceGenerator(bOut, tagNo, isExplicit);
        addSequenceContents(gen);
        gen.close();

        byte[] expected = new BERTaggedObject(isExplicit, tagNo, seq).getEncoded();
        isTrue("BER seq [" + tagNo + "] explicit=" + isExplicit, areEqual(expected, bOut.toByteArray()));

        checkSequenceRoundTrip(bOut.toByteArray(), tagNo, isExplicit, seq);
    }

    private void testTaggedDERSequence(int tagNo, boolean isExplicit, DERSequence seq)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DERSequenceGenerator gen = new DERSequenceGenerator(bOut, tagNo, isExplicit);
        addSequenceContents(gen);
        gen.close();

        byte[] expected = new DERTaggedObject(isExplicit, tagNo, seq).getEncoded(ASN1Encoding.DER);
        isTrue("DER seq [" + tagNo + "] explicit=" + isExplicit, areEqual(expected, bOut.toByteArray()));

        checkSequenceRoundTrip(bOut.toByteArray(), tagNo, isExplicit, seq);
    }

    private void testTaggedBEROctetString(int tagNo, boolean isExplicit, byte[] content, BEROctetString octets)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BEROctetStringGenerator gen = new BEROctetStringGenerator(bOut, tagNo, isExplicit);
        writeOctetContents(gen, content);

        byte[] expected = new BERTaggedObject(isExplicit, tagNo, octets).getEncoded();
        isTrue("BER octets [" + tagNo + "] explicit=" + isExplicit, areEqual(expected, bOut.toByteArray()));

        ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());
        ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();
        isTrue("octets tagNo [" + tagNo + "]", tagNo == tagged.getTagNo());
        ASN1OctetString recovered = ASN1OctetString.getInstance(tagged, isExplicit);
        isTrue("octets content [" + tagNo + "] explicit=" + isExplicit, areEqual(content, recovered.getOctets()));
    }

    private void checkSequenceRoundTrip(byte[] encoding, int tagNo, boolean isExplicit, ASN1Sequence expected)
        throws Exception
    {
        ASN1InputStream aIn = new ASN1InputStream(encoding);
        ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();
        isTrue("seq tagNo [" + tagNo + "]", tagNo == tagged.getTagNo());
        ASN1Sequence recovered = ASN1Sequence.getInstance(tagged, isExplicit);
        isTrue("seq content [" + tagNo + "] explicit=" + isExplicit, expected.equals(recovered));
    }

    public static void main(String[] args)
    {
        runTest(new ASN1GeneratorTest());
    }
}
