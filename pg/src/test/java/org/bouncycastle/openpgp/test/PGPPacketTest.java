package org.bouncycastle.openpgp.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.Random;

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
        
        PGPObjectFactory        fact = new PGPObjectFactory(bOut.toByteArray());
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
    
    public void performTest()
        throws IOException
    {
        PGPLiteralDataGenerator oldGenerator = new PGPLiteralDataGenerator(true);

        readBackTest(oldGenerator);
        
        PGPLiteralDataGenerator newGenerator = new PGPLiteralDataGenerator(false);
        
        readBackTest(newGenerator);
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
