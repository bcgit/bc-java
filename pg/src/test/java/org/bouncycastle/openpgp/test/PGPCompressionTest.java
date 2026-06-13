package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.io.StreamOverflowException;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPCompressionTest 
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        testCompression(new byte[0]);
        testCompression("hello world!".getBytes());

        SecureRandom random = new SecureRandom();
        byte[] randomData = new byte[1000000];
        random.nextBytes(randomData);

        testCompression(randomData);

        testDecompressionLimit();

        //
        // new style - using stream close
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        OutputStream out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

        out.write("hello world! !dlrow olleh".getBytes());

        out.close();

        validateData(bOut.toByteArray());

        try
        {
            out.close();
            cPacket.close();
        }
        catch (Exception e)
        {
            fail("Redundant close() should be ignored");
        }

        //
        // new style - using generator close
        //
        bOut = new ByteArrayOutputStream();
        cPacket = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        out = cPacket.open(new UncloseableOutputStream(bOut), new byte[4]);

        out.write("hello world! !dlrow olleh".getBytes());

        cPacket.close();

        validateData(bOut.toByteArray());

        try
        {
            out.close();
            cPacket.close();
        }
        catch (Exception e)
        {
            fail("Redundant close() should be ignored");
        }
    }

    private void validateData(byte[] data)
        throws IOException, PGPException
    {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(data);
        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
        InputStream pIn = c1.getDataStream();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = pIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        if (!areEqual(bOut.toByteArray(), "hello world! !dlrow olleh".getBytes()))
        {
            fail("compression test failed");
        }
    }

    private void testCompression(byte[] data)
        throws IOException, PGPException
    {
        testCompression(data, PGPCompressedData.UNCOMPRESSED);
        testCompression(data, PGPCompressedData.ZIP);
        testCompression(data, PGPCompressedData.ZLIB);
        testCompression(data, PGPCompressedData.BZIP2);
    }

    private void testCompression(byte[] data, int type)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(type);

        OutputStream out = cPacket.open(new UncloseableOutputStream(bOut));

        out.write(data);

        out.close();

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(bOut.toByteArray());
        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
        InputStream pIn = c1.getDataStream();

        bOut.reset();

        int ch;
        while ((ch = pIn.read()) >= 0)
        {
            bOut.write(ch);
        }

        if (!areEqual(bOut.toByteArray(), data))
        {
            fail("compression test failed");
        }
    }

    private void testDecompressionLimit()
        throws IOException, PGPException
    {
        byte[] data = new byte[64 * 1024];
        new SecureRandom().nextBytes(data);

        testDecompressionLimit(data, PGPCompressedData.UNCOMPRESSED);
        testDecompressionLimit(data, PGPCompressedData.ZIP);
        testDecompressionLimit(data, PGPCompressedData.ZLIB);
        testDecompressionLimit(data, PGPCompressedData.BZIP2);
    }

    private void testDecompressionLimit(byte[] data, int type)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cPacket = new PGPCompressedDataGenerator(type);
        OutputStream out = cPacket.open(new UncloseableOutputStream(bOut));
        out.write(data);
        out.close();
        byte[] packet = bOut.toByteArray();

        // a limit at least the size of the data lets the full content through
        PGPCompressedData c1 = (PGPCompressedData)new JcaPGPObjectFactory(packet).nextObject();
        if (!areEqual(Streams.readAll(c1.getDataStream(data.length)), data))
        {
            fail("limit >= data should round-trip for type " + type);
        }

        // a limit one short of the data fails with StreamOverflowException
        PGPCompressedData c2 = (PGPCompressedData)new JcaPGPObjectFactory(packet).nextObject();
        InputStream limited = c2.getDataStream(data.length - 1);
        try
        {
            Streams.readAll(limited);
            fail("decompressed data limit not enforced for type " + type);
        }
        catch (StreamOverflowException e)
        {
            // expected
        }

        // a negative limit is equivalent to the unbounded getDataStream()
        PGPCompressedData c3 = (PGPCompressedData)new JcaPGPObjectFactory(packet).nextObject();
        if (!areEqual(Streams.readAll(c3.getDataStream(-1)), data))
        {
            fail("negative limit should be unbounded for type " + type);
        }
    }

    public String getName()
    {
        return "PGPCompressionTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPCompressionTest());
    }
}
