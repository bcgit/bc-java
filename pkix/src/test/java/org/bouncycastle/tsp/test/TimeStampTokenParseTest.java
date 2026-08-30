package org.bouncycastle.tsp.test;

import java.math.BigInteger;

import junit.framework.TestCase;
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

/**
 * A well-formed RFC 3161 TimeStampResp whose embedded token carries malformed TSTInfo content
 * must be reported through the documented {@code throws TSPException} of {@code TimeStampResponse},
 * not as an unchecked exception from the internal ASN.1 parse.
 */
public class TimeStampTokenParseTest
    extends TestCase
{
    // empty SEQUENCE - TSTInfo(ASN1Sequence) reads its fixed fields with no hasMoreElements guard
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

    private void checkRejected(byte[] tstInfoContent)
        throws Exception
    {
        byte[] resp = makeResponse(tstInfoContent);

        try
        {
            new TimeStampResponse(resp);
            fail("malformed TSTInfo accepted");
        }
        catch (TSPException e)
        {
            // expected - the parse failure is surfaced as the declared checked exception
        }
    }

    private static byte[] makeResponse(byte[] tstInfoContent)
        throws Exception
    {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

        ContentInfo encapContentInfo = new ContentInfo(
            PKCSObjectIdentifiers.id_ct_TSTInfo, new DEROctetString(tstInfoContent));

        SignerIdentifier sid = new SignerIdentifier(
            new IssuerAndSerialNumber(new X500Name("CN=Test TSA"), BigInteger.ONE));
        SignerInfo signerInfo = new SignerInfo(
            sid, sha256, (ASN1Set)null,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            new DEROctetString(new byte[]{ 1, 2, 3, 4 }), (ASN1Set)null);

        SignedData signedData = new SignedData(
            new DERSet(sha256), encapContentInfo, null, null, new DERSet(signerInfo));

        ContentInfo token = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);

        TimeStampResp resp = new TimeStampResp(new PKIStatusInfo(PKIStatus.granted), token);

        return resp.getEncoded();
    }
}
