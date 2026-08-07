package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.zip.Deflater;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.util.io.StreamOverflowException;

/**
 * A compressed data packet declares no decompressed length, so a small packet can expand into an
 * arbitrarily large amount of data. {@link PGPCompressedData} has always offered a bounded
 * {@code getDataStream(long)} for this, but the high-level
 * {@link OpenPGPMessageProcessor} / {@link OpenPGPMessageInputStream} path called the unbounded
 * overload unconditionally and {@link OpenPGPPolicy} carried no property a caller could set to
 * change that - so on the documented entry point there was no way to bound it at all. The policy
 * now carries the limit, defaulting to unbounded exactly as the low-level pair does, so that
 * setting one stays the application's decision.
 * {@link OpenPGPMessageInputStream#MAX_RECURSION} bounds how many compression layers may nest,
 * which is a different limit.
 */
public class OpenPGPDecompressionLimitTest
    extends AbstractPacketTest
{
    // enough to overrun the limits below many times over while staying quick to build
    private static final long PAYLOAD_SIZE = 8L * 1024 * 1024;

    @Override
    public String getName()
    {
        return "OpenPGPDecompressionLimitTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        highLevelApiBoundsDecompressedSize();
        policyCanRaiseTheBound();
        negativeLimitRestoresUnboundedReads();
        defaultPolicyIsUnbounded();
    }

    private void highLevelApiBoundsDecompressedSize()
        throws Exception
    {
        byte[] message = compressedMessage(PAYLOAD_SIZE);

        isTrue("bomb should compress to far less than it expands to", message.length < PAYLOAD_SIZE / 100);

        long limit = 64 * 1024;

        try
        {
            drain(process(message, limit));
            fail("high-level message processing should stop at the configured decompressed size");
        }
        catch (StreamOverflowException e)
        {
            // expected - the decompression itself was stopped, not merely counted
        }
    }

    private void policyCanRaiseTheBound()
        throws Exception
    {
        // the same message that fails at 64KiB reads through when the policy allows for it
        byte[] message = compressedMessage(PAYLOAD_SIZE);

        isEquals("payload should be fully readable when the policy permits it",
            PAYLOAD_SIZE, drain(process(message, PAYLOAD_SIZE * 2)));
    }

    private void negativeLimitRestoresUnboundedReads()
        throws Exception
    {
        byte[] message = compressedMessage(PAYLOAD_SIZE);

        isEquals("a negative limit should remove the bound",
            PAYLOAD_SIZE, drain(process(message, -1)));
    }

    private void defaultPolicyIsUnbounded()
        throws Exception
    {
        // The compatibility assertion. Like PGPCompressedData.getDataStream(), the default is
        // unbounded - setting a limit is the application's decision, since no single value suits
        // every caller. A message that overruns the limits used above therefore still reads
        // through a default-configured processor.
        byte[] message = compressedMessage(PAYLOAD_SIZE);

        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();

        isEquals("the default policy should not bound decompressed size",
            PAYLOAD_SIZE, drain(processor.process(new ByteArrayInputStream(message))));

        isTrue("default policy should report no decompressed-size limit",
            new OpenPGPDefaultPolicy().getMaximumDecompressedDataSize() < 0);
    }

    private OpenPGPMessageInputStream process(byte[] message, final long limit)
        throws Exception
    {
        OpenPGPPolicy policy = new OpenPGPDefaultPolicy().setMaximumDecompressedDataSize(limit);

        OpenPGPMessageProcessor processor =
            new OpenPGPMessageProcessor(OpenPGPImplementation.getInstance(), policy);

        return processor.process(new ByteArrayInputStream(message));
    }

    private long drain(InputStream in)
        throws Exception
    {
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) >= 0)
        {
            total += n;
        }
        in.close();
        return total;
    }

    private byte[] compressedMessage(long payloadSize)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator cGen =
            new PGPCompressedDataGenerator(PGPCompressedData.ZIP, Deflater.BEST_COMPRESSION);
        OutputStream cOut = cGen.open(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(cOut, PGPLiteralData.BINARY, "bomb.bin", payloadSize, new Date());

        byte[] zeroChunk = new byte[64 * 1024];
        long written = 0;
        while (written < payloadSize)
        {
            int toWrite = (int)Math.min(zeroChunk.length, payloadSize - written);
            lOut.write(zeroChunk, 0, toWrite);
            written += toWrite;
        }

        lOut.close();
        cOut.close();

        return bOut.toByteArray();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPDecompressionLimitTest());
    }
}
