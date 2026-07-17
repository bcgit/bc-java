package org.bouncycastle.tsp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import junit.framework.TestCase;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.cms.CMSTimeStampedData;

public class CMSTimeStampedDataTest
    extends TestCase
{

    CMSTimeStampedData cmsTimeStampedData = null;
    String fileInput = "FileDaFirmare.txt.tsd.der";
    String fileOutput = fileInput.substring(0, fileInput.indexOf(".tsd"));
    private byte[] baseData;

    protected void setUp()
        throws Exception
    {
        ByteArrayOutputStream origStream = new ByteArrayOutputStream();
        InputStream in = this.getClass().getResourceAsStream(fileInput);
        int ch;

        while ((ch = in.read()) >= 0)
        {
            origStream.write(ch);
        }

        origStream.close();

        this.baseData = origStream.toByteArray();

        cmsTimeStampedData = new CMSTimeStampedData(baseData);
    }

    protected void tearDown()
        throws Exception
    {
        cmsTimeStampedData = null;
    }

    public void testGetTimeStampTokens()
        throws Exception
    {
        TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
        assertEquals(3, tokens.length);
    }

    public void testValidateAllTokens()
        throws Exception
    {
        DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

        DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

        imprintCalculator.getOutputStream().write(cmsTimeStampedData.getContent());

        byte[] digest = imprintCalculator.getDigest();

        TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
        for (int i = 0; i < tokens.length; i++)
        {
            cmsTimeStampedData.validate(digestCalculatorProvider, digest, tokens[i]);
        }
    }

    public void testValidate()
        throws Exception
    {
        DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

        DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

        imprintCalculator.getOutputStream().write(cmsTimeStampedData.getContent());

        cmsTimeStampedData.validate(digestCalculatorProvider, imprintCalculator.getDigest());
    }

    public void testMalformedInputRejected()
        throws Exception
    {
        // (1) empty stream: ContentInfo.getInstance(readObject()) returns null on empty input and
        // initialize() then dereferences the null ContentInfo -> NPE. Must be a declared IOException.
        try
        {
            new CMSTimeStampedData(new byte[0]);
            fail("empty input should be rejected");
        }
        catch (java.io.IOException e)
        {
            // expected
        }

        // (2) a ContentInfo carrying the timestampedData OID but NO content (SEQUENCE { OID }):
        // TimeStampedData.getInstance(null) returns null, which would NPE in TimeStampDataUtil. This
        // second null path was previously masked only by a broad catch (RuntimeException).
        byte[] noContent = new org.bouncycastle.asn1.DERSequence(
            org.bouncycastle.asn1.cms.CMSObjectIdentifiers.timestampedData).getEncoded();
        try
        {
            new CMSTimeStampedData(noContent);
            fail("timestampedData content-info with no content should be rejected");
        }
        catch (java.io.IOException e)
        {
            // expected
        }
    }

}
