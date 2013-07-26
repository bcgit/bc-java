package org.bouncycastle.crypto.test.cavp;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.TestFailedException;

public final class KDFFeedbackNoCounterTests
    implements CAVPListener
{
    private PrintWriter out;

    public void receiveCAVPVectors(String name, Properties config,
                                   Properties vectors)
    {


        // create Mac based PRF from PRF property, create the KDF
        final Mac prf = CAVPReader.createPRF(config);
        final KDFFeedbackBytesGenerator gen = new KDFFeedbackBytesGenerator(prf);

        final int count = Integer.parseInt(vectors.getProperty("COUNT"));
        final int l = Integer.parseInt(vectors.getProperty("L"));
        final byte[] ki = Hex.decode(vectors.getProperty("KI"));
        final byte[] iv = Hex.decode(vectors.getProperty("IV"));
        final byte[] fixedInputData = Hex.decode(vectors.getProperty("FixedInputData"));
        final KDFFeedbackParameters params = KDFFeedbackParameters.createWithoutCounter(ki, iv, fixedInputData);
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
            out = new PrintWriter(new FileWriter("KDFFeedbackNoCounter.gen"));
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