package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPPacketTest
    extends SimpleTest
{
    private static int MAX = 32000;
    
    private void readBackTest(
        PGPLiteralDataGenerator generator)
        throws IOException
    {
        Random                  rand = new Random();
        byte[]                  buf = new byte[MAX];
        
        rand.nextBytes(buf);
        
        for (int i = 1; i <= 200; i++)
        {
            bufferTest(generator, buf, i);
        }
        
        bufferTest(generator, buf, 8382);
        bufferTest(generator, buf, 8383);
        bufferTest(generator, buf, 8384);
        bufferTest(generator, buf, 8385);
        
        for (int i = 200; i < MAX; i += 100)
        {
            bufferTest(generator, buf, i);
        }
    }

    private void bufferTest(
        PGPLiteralDataGenerator generator, 
        byte[] buf, 
        int i)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = generator.open(
            new UncloseableOutputStream(bOut),
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            i,
            new Date());

        out.write(buf, 0, i);
        
        generator.close();
        
        JcaPGPObjectFactory        fact = new JcaPGPObjectFactory(bOut.toByteArray());
        PGPLiteralData          data = (PGPLiteralData)fact.nextObject();
        InputStream             in = data.getInputStream();

        for (int count = 0; count != i; count++)
        {
            if (in.read() != (buf[count] & 0xff))
            {
                fail("failed readback test - length = " + i);
            }
        }
    }

    private void iteratorTest()
        throws IOException
    {
        int packets = 5, packetsRead = 0;
        int packetLength = 50, totalLength = packets * packetLength;
        ByteArrayOutputStream msg = new ByteArrayOutputStream();

        byte[] src = new byte[totalLength];
        byte[] dst = new byte[totalLength];
        // deterministic content, so tests will fail with exact same error
        for (int i = 0; i < totalLength; i++)
        {
            src[i] = (byte) (i - 1);
        }

        // read from src into n literal data packets
        for (int i = 0; i < packets; i++)
        {
            PGPLiteralDataGenerator generator = new PGPLiteralDataGenerator();
            OutputStream out = generator.open(
                new UncloseableOutputStream(msg),
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                packetLength,
                new Date());
            out.write(src, packetLength * i, packetLength);
            generator.close();
        }

        // write to dst from n literal data packets
        JcaPGPObjectFactory fact = new JcaPGPObjectFactory(msg.toByteArray());
        Iterator iterator = fact.iterator();
        while (iterator.hasNext())
        {
            PGPLiteralData data = (PGPLiteralData)iterator.next();
            InputStream in = data.getInputStream();

            int bytesRead = in.read(dst, packetsRead * packetLength, packetLength);
            if (bytesRead != packetLength)
            {
                fail("not enough bytes read in iterator test: " + bytesRead);
            }

            int moreRead = in.read();
            if (moreRead != -1)
            {
                fail("too many bytes read in iterator test");
            }

            packetsRead++;
        }

        // verify n packets read
        if (packetsRead != packets)
        {
            fail("wrong number of packets read in iterator test: " + packetsRead);
        }

        // verify passed content correct
        for (int i = 0; i < totalLength; i++)
        {
            if (src[i] != dst[i])
            {
                fail("wrong content in iterator test");
            }
        }
    }

    public void performTest()
        throws IOException
    {
        PGPLiteralDataGenerator oldGenerator = new PGPLiteralDataGenerator(true);

        readBackTest(oldGenerator);
        
        PGPLiteralDataGenerator newGenerator = new PGPLiteralDataGenerator(false);
        
        readBackTest(newGenerator);

        iteratorTest();
    }

    public String getName()
    {
        return "PGPPacketTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPPacketTest());
    }
}
