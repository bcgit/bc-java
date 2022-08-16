package org.bouncycastle.crypto.fpe;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@Fork(1)
@Warmup(iterations = 5)
@Measurement(iterations = 5)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode({Mode.AverageTime})
// Run a performance benchmark with JMH https://www.baeldung.com/java-microbenchmark-harness
// The benchmark measure the avg time it takes to encrypt 100 plain texts
// The benchmark has parameters:
// - plainTextDigits: the number of digits (in the alphabet defined by 'radix') in the plain text
// - radix: the radix to use
// 100 plain texts are randomly generated (with fixed seed) during benchmark setup. Each benchmark invocation
// encrypt the 100 texts.
public class SP80038GMicroBenchmark
{

    private static final Random RANDOM = new Random(123);
    private static final int NUMBER_OF_TEXTS = 100;

    public static void main(String[] args) throws RunnerException
    {
        new Runner(new OptionsBuilder()
                .jvmArgs("-Xmx4096m", "-Xms4096m")
                .build()).run();
    }

    @Benchmark
    public void encrypt(State state, Blackhole blackhole)
    {
        for (int i = 0; i < NUMBER_OF_TEXTS; i++)
        {
            byte[] plainText = state.plainTexts.get(i);
            blackhole.consume(state.encEngine.processBlock(plainText, 0, plainText.length, state.encs.get(i), 0));
        }
    }

    @org.openjdk.jmh.annotations.State(Scope.Benchmark)
    public static class State
    {

        @Param({"5", "20", "50", "100"})
        private String plainTextDigits;
        @Param({"127", "1024", "3011"})
        private String radix;
        private FPEEngine encEngine;
        private List<byte[]> plainTexts;
        private List<byte[]> encs;
        private final byte[] key = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        private final byte[] tweak = Hex.decode("39383736353433323130");

        @Setup(Level.Trial)
        public void setUp()
        {
            int numberOfDigits = Integer.parseInt(plainTextDigits);
            int r = Integer.parseInt(radix);
            plainTexts = generateTexts(numberOfDigits, r);
            encEngine = new FPEFF1Engine();
            encEngine.init(true, new FPEParameters(new KeyParameter(key), r, tweak));
            encs = generateBuffersForOutput(numberOfDigits, r);
        }

        private List<byte[]> generateBuffersForOutput(int numberOfDigits, int radix)
        {
            ArrayList<byte[]> outs = new ArrayList<byte[]>();
            for (int i = 0; i < NUMBER_OF_TEXTS; i++)
            {
                outs.add(radix <= 256 ? new byte[numberOfDigits] : new byte[numberOfDigits * 2]);
            }
            return outs;
        }

        private List<byte[]> generateTexts(int numberOfDigits, int radix)
        {
            List<byte[]> res = new ArrayList<byte[]>();
            for (int i = 0; i < NUMBER_OF_TEXTS; i++)
            {
                res.add(generateText(numberOfDigits, radix));
            }
            return res;
        }

        private byte[] generateText(int numberOfDigits, int radix)
        {
            if (radix <= 256)
            {
                byte[] bytes = new byte[numberOfDigits];
                for (int i = 0; i < bytes.length; i++)
                {
                    bytes[i] = (byte) RANDOM.nextInt(radix);
                }
                return bytes;
            } else
            {
                byte[] bytes = new byte[numberOfDigits * 2];
                for (int i = 0; i < numberOfDigits; i++)
                {
                    int v = RANDOM.nextInt(radix);
                    bytes[i * 2] = (byte) (v >>> 8);
                    bytes[(i * 2) + 1] = (byte) (v);
                }
                return bytes;
            }
        }
    }
}
