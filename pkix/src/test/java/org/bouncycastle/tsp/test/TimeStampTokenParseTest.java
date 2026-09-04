package org.bouncycastle.tsp.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.BigIntegers;

/**
 * A well-formed RFC 3161 TimeStampResp whose embedded token is malformed - in its TSTInfo content
 * or in the number of SignerInfos carrying it - must be reported through the documented
 * {@code throws TSPException} of {@code TimeStampResponse}, not as an unchecked exception from the
 * internal ASN.1 parse.
 */
public class TimeStampTokenParseTest
    extends TestCase
{
    // empty SEQUENCE - fewer elements than TSTInfo's five mandatory fields
    public void testEmptySequenceTstInfo()
        throws Exception
    {
        checkRejected(new DERSequence().getEncoded());
    }

    // valid DER, wrong type - ASN1Sequence.getInstance rejects a non-SEQUENCE
    public void testNonSequenceTstInfo()
        throws Exception
    {
        checkRejected(new ASN1Integer(0).getEncoded());
    }

    // structurally broken DER - length octet promises more than is present
    public void testTruncatedTstInfo()
        throws Exception
    {
        checkRejected(new byte[]{ 0x30, 0x05, 0x02, 0x01 });
    }

    // RFC 3161 sec. 2.4.2 gives TSTInfo ten fields at most
    public void testOversizeTstInfo()
        throws Exception
    {
        ASN1Encodable[] elements = new ASN1Encodable[11];

        for (int i = 0; i != elements.length; i++)
        {
            elements[i] = new ASN1Integer(i);
        }

        checkRejected(new DERSequence(elements).getEncoded());
    }

    // RFC 3161 sec. 2.4.2: the token must carry exactly the TSA signature
    public void testNoSigners()
        throws Exception
    {
        checkRejected(wellFormedTstInfo(), new DERSet());
    }

    public void testMultipleSigners()
        throws Exception
    {
        checkRejected(wellFormedTstInfo(), new DERSet(new ASN1Encodable[]{ signerInfo(), signerInfo() }));
    }

    private void checkRejected(byte[] tstInfoContent)
        throws Exception
    {
        checkRejected(tstInfoContent, new DERSet(signerInfo()));
    }

    private void checkRejected(byte[] tstInfoContent, ASN1Set signerInfos)
        throws Exception
    {
        byte[] resp = makeResponse(tstInfoContent, signerInfos);

        try
        {
            new TimeStampResponse(resp);
            fail("malformed timestamp token accepted");
        }
        catch (TSPException e)
        {
            // expected - the parse failure is surfaced as the declared checked exception
        }
    }

    private static byte[] wellFormedTstInfo()
        throws Exception
    {
        return new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(1),
            PKCSObjectIdentifiers.id_ct_TSTInfo,
            new DERSequence(new ASN1Encodable[]{ sha256(), new DEROctetString(new byte[32]) }),
            new ASN1Integer(1),
            new ASN1GeneralizedTime("20260101000000Z") }).getEncoded();
    }

    private static AlgorithmIdentifier sha256()
    {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    }

    private static SignerInfo signerInfo()
    {
        SignerIdentifier sid = new SignerIdentifier(
            new IssuerAndSerialNumber(new X500Name("CN=Test TSA"), BigIntegers.ONE));

        return new SignerInfo(
            sid, sha256(), (ASN1Set)null,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            new DEROctetString(new byte[]{ 1, 2, 3, 4 }), (ASN1Set)null);
    }

    private static byte[] makeResponse(byte[] tstInfoContent, ASN1Set signerInfos)
        throws Exception
    {
        ContentInfo encapContentInfo = new ContentInfo(
            PKCSObjectIdentifiers.id_ct_TSTInfo, new DEROctetString(tstInfoContent));

        SignedData signedData = new SignedData(
            new DERSet(sha256()), encapContentInfo, null, null, signerInfos);

        ContentInfo token = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);

        TimeStampResp resp = new TimeStampResp(new PKIStatusInfo(PKIStatus.granted), token);

        return resp.getEncoded();
    }
}
