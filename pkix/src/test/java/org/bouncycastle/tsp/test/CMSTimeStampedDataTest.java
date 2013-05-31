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

}
