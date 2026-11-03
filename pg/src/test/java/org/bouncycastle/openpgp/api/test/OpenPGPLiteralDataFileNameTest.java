package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * The file name in a literal data packet is advisory, need not be UTF-8, and is read before any integrity check
 * on the message, so a damaged ciphertext hands the reader arbitrary bytes there. Decoding it used to throw an
 * IllegalArgumentException from PGPLiteralData.getFileName(), which the high-level message reader calls on every
 * message, so such a message could not be read at all (github #2549).
 */
public class OpenPGPLiteralDataFileNameTest
    extends AbstractPacketTest
{
    private static final byte[] CONTENT = Strings.toByteArray("Hello, World!\n");

    // "café.txt" in ISO-8859-1: 0xE9 starts a three-byte UTF-8 sequence that never arrives
    private static final byte[] LATIN1_NAME = new byte[]{ 'c', 'a', 'f', (byte)0xE9, '.', 't', 'x', 't' };

    @Override
    public String getName()
    {
        return "OpenPGPLiteralDataFileNameTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        validUTF8NameUnchanged();
        lowLevelNonUTF8Name();
        highLevelNonUTF8Name();
        signerUserIDNonUTF8();
    }

    private void validUTF8NameUnchanged()
        throws Exception
    {
        // the compatibility assertion: a valid name decodes exactly as before
        String name = "café 中文.txt";
        PGPLiteralData literalData = parse(literalDataMessage(Strings.toUTF8ByteArray(name)));

        isEquals("valid UTF-8 file name should decode unchanged", name, literalData.getFileName());
    }

    private void lowLevelNonUTF8Name()
        throws Exception
    {
        PGPLiteralData literalData = parse(literalDataMessage(LATIN1_NAME));

        isEquals("malformed sequence should decode as U+FFFD", "caf�.txt", literalData.getFileName());
        isTrue("raw file name should be the exact bytes", Arrays.areEqual(LATIN1_NAME, literalData.getRawFileName()));
        isTrue("content should still be readable", Arrays.areEqual(CONTENT, readAll(literalData.getInputStream())));
    }

    private void highLevelNonUTF8Name()
        throws Exception
    {
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        OpenPGPMessageInputStream in = processor.process(new ByteArrayInputStream(literalDataMessage(LATIN1_NAME)));

        isTrue("content should be readable through the high-level API", Arrays.areEqual(CONTENT, readAll(in)));
        isEquals("high-level result should carry the decoded file name", "caf�.txt",
            in.getResult().getFilename());
    }

    private void signerUserIDNonUTF8()
    {
        SignerUserID signerUserID = new SignerUserID(false, false, LATIN1_NAME);

        isEquals("malformed signer user ID should decode as U+FFFD", "caf�.txt", signerUserID.getID());
        isTrue("raw signer user ID should be the exact bytes", Arrays.areEqual(LATIN1_NAME, signerUserID.getRawID()));

        isEquals("valid signer user ID should decode unchanged", "Alice <alice@example.com>",
            new SignerUserID(false, "Alice <alice@example.com>").getID());
    }

    private static PGPLiteralData parse(byte[] message)
        throws Exception
    {
        PGPObjectFactory factory = new PGPObjectFactory(message, new BcKeyFingerprintCalculator());
        return (PGPLiteralData)factory.nextObject();
    }

    /**
     * A new-format literal data packet built by hand, since PGPLiteralDataGenerator only takes the name as a String.
     */
    private static byte[] literalDataMessage(byte[] fileName)
    {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(PGPLiteralData.BINARY);
        body.write(fileName.length);
        body.write(fileName, 0, fileName.length);
        body.write(0x5f);    // modification time 0x5f000000
        body.write(0);
        body.write(0);
        body.write(0);
        body.write(CONTENT, 0, CONTENT.length);

        byte[] b = body.toByteArray();
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        packet.write(0xC0 | 11);    // new format, tag 11 (literal data)
        packet.write(b.length);     // one-octet length, body is under 192 bytes
        packet.write(b, 0, b.length);
        return packet.toByteArray();
    }

    private static byte[] readAll(InputStream in)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] buf = new byte[256];
        int n;
        while ((n = in.read(buf)) >= 0)
        {
            bOut.write(buf, 0, n);
        }
        in.close();
        return bOut.toByteArray();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPLiteralDataFileNameTest());
    }
}
