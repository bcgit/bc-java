package org.bouncycastle.crypto.test.cavp;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;
import java.util.regex.Matcher;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.TestFailedException;

public final class KDFCounterTests
    implements CAVPListener
{
    private PrintWriter out;

    public void receiveCAVPVectors(String name, Properties config,
                                   Properties vectors)
    {

        // always skip AFTER_FIXED, not included in SP 800-108
        if (config.getProperty("CTRLOCATION").matches("AFTER_FIXED"))
        {
            return;
        }

        // create Mac based PRF from PRF property, create the KDF
        final Mac prf = CAVPReader.createPRF(config);
        final KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(prf);


        Matcher matcherForR = CAVPReader.PATTERN_FOR_R.matcher(config.getProperty("RLEN"));
        if (!matcherForR.matches())
        {
            throw new IllegalStateException("RLEN value should always match");
        }
        final int r = Integer.parseInt(matcherForR.group(1));

        final int count = Integer.parseInt(vectors.getProperty("COUNT"));
        final int l = Integer.parseInt(vectors.getProperty("L"));
        final byte[] ki = Hex.decode(vectors.getProperty("KI"));
        final byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
        final KDFCounterParameters params = new KDFCounterParameters(ki, fixedInputData, r);
        gen.init(params);

        final byte[] koGenerated = new byte[l / 8];
        gen.generateBytes(koGenerated, 0, koGenerated.length);

        final byte[] koVectors = Hex.decode(vectors.getProperty("KO"));

        compareKO(name, config, count, koGenerated, koVectors);
    }

    private static void compareKO(
        String name, Properties config, int test, byte[] calculatedOKM, byte[] testOKM)
    {

        if (!Arrays.areEqual(calculatedOKM, testOKM))
        {
            throw new TestFailedException(new SimpleTestResult(
                false, name + " using " + config + " test " + test + " failed"));

        }
    }

    public void receiveCommentLine(String commentLine)
    {
        //                out.println("# " + commentLine);
    }

    public void receiveStart(String name)
    {
        // do nothing
    }

    public void receiveEnd()
    {
        out.println(" *** *** *** ");
    }

    public void setup()
    {
        try
        {
            out = new PrintWriter(new FileWriter("KDFCTR.gen"));
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public void tearDown()
    {
        out.close();
    }
}