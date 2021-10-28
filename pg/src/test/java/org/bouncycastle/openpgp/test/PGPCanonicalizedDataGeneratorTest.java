package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPCanonicalizedDataGeneratorTest
    extends SimpleTest
{
    public String getName()
    {
        return "PGPCanonicalizedDataGeneratorTest";
    }

    public void performTest()
        throws Exception
    {
        String uData = "Now is the time for all good men\nTo come to the aid of the party\n";
        String mData = "Now is the time for all good men\rTo come to the aid of the party\r";

        String cData = "Now is the time for all good men\r\nTo come to the aid of the party\r\n";

        checkConversion(uData, cData);
        checkConversion(mData, cData);
        checkConversion(cData, cData);

        checkIndefiniteConversion(uData, cData);
        checkIndefiniteConversion(mData, cData);
        checkIndefiniteConversion(cData, cData);

        checkBackingConversion(uData, cData);
        checkBackingConversion(mData, cData);
        checkBackingConversion(cData, cData);

        checkBinaryConversion(uData, cData);
        checkBinaryConversion(mData, cData);
        checkBinaryConversion(cData, cData);
    }

    private void checkConversion(String data, String cData)
        throws IOException
    {
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, new Date());

        out.write(Strings.toByteArray(data));

        out.close();

        PGPLiteralData lData = new PGPLiteralData(bOut.toByteArray());

        isEquals(cData, Strings.fromByteArray(Streams.readAll(lData.getDataStream())));
    }

    private void checkIndefiniteConversion(String data, String cData)
        throws IOException
    {
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, new Date(), new byte[16]);

        out.write(Strings.toByteArray(data));

        out.close();

        PGPLiteralData lData = new PGPLiteralData(bOut.toByteArray());

        isEquals(cData, Strings.fromByteArray(Streams.readAll(lData.getDataStream())));
    }

    private void checkBackingConversion(String data, String cData)
        throws IOException
    {
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        File bcFile = File.createTempFile("bcpgp", ".back");
        OutputStream out = canGen.open(bOut, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, new Date(), bcFile);

        out.write(Strings.toByteArray(data));

        out.close();

        PGPLiteralData lData = new PGPLiteralData(bOut.toByteArray());

        isEquals(cData, Strings.fromByteArray(Streams.readAll(lData.getDataStream())));

        bcFile.delete();
    }

    private void checkBinaryConversion(String data, String cData)
        throws IOException
    {
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date());

        out.write(Strings.toByteArray(data));

        out.close();

        PGPLiteralData lData = new PGPLiteralData(bOut.toByteArray());

        isEquals(data, Strings.fromByteArray(Streams.readAll(lData.getDataStream())));
    }

    public static void main(
        String[] args)
    {
        runTest(new PGPCanonicalizedDataGeneratorTest());
    }
}
