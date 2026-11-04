package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Properties;
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

        // a bare CR is not a line ending and is written unaltered (github #2553)
        String[][] cases = {
            { uData, cData },
            { mData, mData },
            { cData, cData },
            { "a\ra", "a\ra" },
            { "a\r", "a\r" },
            { "\r", "\r" },
            { "a\na", "a\r\na" },
            { "a\r\ra\n", "a\r\ra\r\n" },
            { "\r\n\n\r", "\r\n\r\n\r" },
            { "a\n\rb", "a\r\n\rb" },
            { "", "" } };

        for (int i = 0; i != cases.length; i++)
        {
            checkConversion(cases[i][0], cases[i][1]);
            checkIndefiniteConversion(cases[i][0], cases[i][1]);
            checkBackingConversion(cases[i][0], cases[i][1]);
            checkBytewiseConversion(cases[i][0], cases[i][1]);
        }

        // CR LF split across write() calls is one line ending, CR then something else stays bare
        checkSplitConversion(new String[]{ "a\r", "\na" }, "a\r\na");
        checkSplitConversion(new String[]{ "a\r", "a" }, "a\ra");
        checkSplitConversion(new String[]{ "a", "\na" }, "a\r\na");
        checkSplitConversion(new String[]{ "a\r", "\r", "\n" }, "a\r\r\n");

        checkTextSignatureRoundTrip("a\ra\n");
        checkTextSignatureRoundTrip("a\r");
        checkTextSignatureRoundTrip("a\r\nb\nc\rd");

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

    private void checkBytewiseConversion(String data, String cData)
        throws IOException
    {
        byte[] bytes = Strings.toByteArray(data);
        String[] chunks = new String[bytes.length];
        for (int i = 0; i != bytes.length; i++)
        {
            chunks[i] = data.substring(i, i + 1);
        }
        checkSplitConversion(chunks, cData);
    }

    private void checkSplitConversion(String[] chunks, String cData)
        throws IOException
    {
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.UTF8, PGPLiteralData.CONSOLE, new Date(), new byte[16]);

        for (int i = 0; i != chunks.length; i++)
        {
            byte[] chunk = Strings.toByteArray(chunks[i]);
            if (chunk.length == 1)
            {
                out.write(chunk[0]);
            }
            else
            {
                out.write(chunk);
            }
        }

        out.close();

        PGPLiteralData lData = new PGPLiteralData(bOut.toByteArray());

        isEquals(cData, Strings.fromByteArray(Streams.readAll(lData.getDataStream())));
    }

    /*
     * A text signature made over the caller's data must verify over the literal data the
     * generator writes for it - the receiver only ever sees the latter. Checked with the legacy
     * verification fallback disabled, so only the current canonical form is in play.
     */
    private void checkTextSignatureRoundTrip(String data)
        throws Exception
    {
        PGPSecretKey alice = OpenPGPTestKeys.readPGPSecretKeyRing(OpenPGPTestKeys.ALICE_KEY).getSecretKey();
        PGPPublicKey pubKey = alice.getPublicKey();
        byte[] bytes = Strings.toByteArray(data);

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(pubKey.getAlgorithm(), HashAlgorithmTags.SHA512), pubKey);
        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, alice.extractPrivateKey(null));
        sGen.update(bytes);
        PGPSignature sig = sGen.generate();

        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = canGen.open(bOut, PGPLiteralData.UTF8, PGPLiteralData.CONSOLE, new Date());
        out.write(bytes);
        out.close();

        byte[] literal = Streams.readAll(new PGPLiteralData(bOut.toByteArray()).getDataStream());

        Properties.setThreadOverride(Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR, false);
        try
        {
            sig.init(new BcPGPContentVerifierBuilderProvider(), pubKey);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.OPENPGP_TEXT_SIG_ALLOW_LEGACY_CR);
        }
        sig.update(literal);

        isTrue("text signature over written literal data", sig.verify());
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
