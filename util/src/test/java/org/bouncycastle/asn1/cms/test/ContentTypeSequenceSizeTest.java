package org.bouncycastle.asn1.cms.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedData;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Confirms the CMS content-type decoders SignedData, EnvelopedData, AuthenticatedData,
 * AuthEnvelopedData and EncryptedData reject a too-short SEQUENCE with IllegalArgumentException
 * rather than reading their mandatory fields past the end and leaking a NoSuchElementException /
 * ArrayIndexOutOfBoundsException - the sibling content types CompressedData and DigestedData
 * already guard their size the same way.
 */
public class ContentTypeSequenceSizeTest
    extends SimpleTest
{
    private static final ASN1ObjectIdentifier DATA = CMSObjectIdentifiers.data;
    private static final AlgorithmIdentifier ALG =
        new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2"));

    public String getName()
    {
        return "ContentTypeSequenceSizeTest";
    }

    public void performTest()
        throws Exception
    {
        // a minimal well-formed EncryptedContentInfo: contentType, contentEncryptionAlgorithm
        DERSequence encContentInfo = new DERSequence(new ASN1Encodable[]{ DATA, ALG });

        // well-formed instances still parse
        SignedData.getInstance(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet(), new ContentInfo(DATA, null), new DERSet() }));
        EnvelopedData.getInstance(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new DERSet(), encContentInfo }));
        EncryptedData.getInstance(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), encContentInfo }));
        AuthenticatedData.getInstance(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new DERSet(), ALG, new ContentInfo(DATA, null),
            new DEROctetString(new byte[]{ 1, 2, 3, 4 }) }));
        AuthEnvelopedData.getInstance(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new DERSet(new DERSequence()), encContentInfo,
            new DEROctetString(new byte[]{ 1, 2, 3, 4 }) }));

        // empty SEQUENCE is rejected by every content type
        expectReject("SignedData empty", new SignedDataParse(), new DERSequence());
        expectReject("EnvelopedData empty", new EnvelopedDataParse(), new DERSequence());
        expectReject("AuthenticatedData empty", new AuthenticatedDataParse(), new DERSequence());
        expectReject("AuthEnvelopedData empty", new AuthEnvelopedDataParse(), new DERSequence());
        expectReject("EncryptedData empty", new EncryptedDataParse(), new DERSequence());

        // one element short of the mandatory fields
        expectReject("SignedData short", new SignedDataParse(), new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(1), new DERSet() }));
        expectReject("EnvelopedData short", new EnvelopedDataParse(), new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new DERSet() }));
        expectReject("EncryptedData short", new EncryptedDataParse(), new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0) }));

        // a leading OPTIONAL field claimed but the mandatory fields then truncated - the case a
        // single top-of-sequence size check would miss
        expectReject("EnvelopedData originatorInfo truncated", new EnvelopedDataParse(),
            new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(0), new DERTaggedObject(false, 0, new DERSequence()), new DERSet() }));
        expectReject("AuthenticatedData originatorInfo truncated", new AuthenticatedDataParse(),
            new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(0), new DERTaggedObject(false, 0, new DERSequence()),
                new DERSet(), ALG }));
        expectReject("AuthEnvelopedData originatorInfo truncated", new AuthEnvelopedDataParse(),
            new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(0), new DERTaggedObject(false, 0, new DERSequence()),
                new DERSet(new DERSequence()), encContentInfo }));
    }

    private void expectReject(String label, Parse parse, DERSequence malformed)
    {
        try
        {
            parse.run(malformed);
            fail("malformed " + label + " not rejected");
        }
        catch (IllegalArgumentException e)
        {
            // expected - the getInstance contract, not a leaked
            // NoSuchElementException / ArrayIndexOutOfBoundsException
        }
    }

    private interface Parse
    {
        void run(ASN1Primitive seq);
    }

    private static class SignedDataParse implements Parse
    {
        public void run(ASN1Primitive seq) { SignedData.getInstance(seq); }
    }

    private static class EnvelopedDataParse implements Parse
    {
        public void run(ASN1Primitive seq) { EnvelopedData.getInstance(seq); }
    }

    private static class AuthenticatedDataParse implements Parse
    {
        public void run(ASN1Primitive seq) { AuthenticatedData.getInstance(seq); }
    }

    private static class AuthEnvelopedDataParse implements Parse
    {
        public void run(ASN1Primitive seq) { AuthEnvelopedData.getInstance(seq); }
    }

    private static class EncryptedDataParse implements Parse
    {
        public void run(ASN1Primitive seq) { EncryptedData.getInstance(seq); }
    }

    public static void main(String[] args)
    {
        runTest(new ContentTypeSequenceSizeTest());
    }
}
