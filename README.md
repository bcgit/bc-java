bc-java
=======

Bouncy Castle Java Distribution (Mirror)


implementation of org.bouncycastle.crypto.util.Pack using sun.misc.Unsafe for the bit packing

c.b.b.BitpackBenchmark.int_big_endian_BC            thrpt        50 420776590.853  5220912.983    ops/s
c.b.b.BitpackBenchmark.int_big_endian_UNSAFE        thrpt        50 584328042.702  6204675.094    ops/s
c.b.b.BitpackBenchmark.int_little_endian_BC         thrpt        50 414145920.999  2039601.760    ops/s
c.b.b.BitpackBenchmark.int_little_endian_UNSAFE     thrpt        50 566896814.581  9367267.811    ops/s
c.b.b.BitpackBenchmark.long_big_endian_BC           thrpt        50 221806956.179  2572464.388    ops/s
c.b.b.BitpackBenchmark.long_big_endian_UNSAFE       thrpt        50 513907043.514  2208120.558    ops/s
c.b.b.BitpackBenchmark.long_little_endian_BC        thrpt        50 222062509.695  2979629.774    ops/s
c.b.b.BitpackBenchmark.long_little_endian_UNSAFE    thrpt        50 569441920.581 11614150.590    ops/s


Microbenchmark:

package com.bobymicroby.bitpacktest;

import org.openjdk.jmh.annotations.*;

import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * Created by Borislav Ivanov
 * Date: 7/7/14
 * Time: 2:17 PM
 */

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)

public class BitpackBenchmark {

    @State(Scope.Thread)
    public static class ThreadState {


        private static final int n = 10000;

        private static int[] ints = new int[n];

        private static long[] longs = new long[n];

        private static final Random r = new Random();

        static {
            Arrays.fill(ints, 0, n, r.nextInt()
            );

            Arrays.fill(longs, 0, n, r.nextLong()
            );

        }

        int iCounter = 0;

        public int nextInt() {
            if (iCounter == n) {
                iCounter = 0;
            }
            return ints[iCounter++];
        }


        int lCounter = 0;

        public long nextLong() {
            if (lCounter == n) {
                lCounter = 0;
            }
            return longs[lCounter++];
        }


    }

    @Benchmark
    public int int_big_endian_BC(ThreadState state) {


        return PackBouncyCastle.bigEndianToInt(PackBouncyCastle.intToBigEndian(state.nextInt()), 0);


    }

    @Benchmark
    public int int_big_endian_UNSAFE(ThreadState state) {

        return PackUnsafe.littleEndianToInt(PackUnsafe.intToLittleEndian(state.nextInt()), 0);
    }

    @Benchmark
    public int int_little_endian_UNSAFE(ThreadState state) {

        return PackUnsafe.littleEndianToInt(PackUnsafe.intToLittleEndian(state.nextInt()), 0);
    }


    @Benchmark
    public int int_little_endian_BC(ThreadState state) {

        return PackBouncyCastle.bigEndianToInt(PackBouncyCastle.intToBigEndian(state.nextInt()), 0);
    }


    @Benchmark
    public long long_big_endian_UNSAFE(ThreadState state) {

        return PackUnsafe.bigEndianToLong(PackUnsafe.longToBigEndian(state.nextLong()), 0);
    }

    @Benchmark
    public long long_big_endian_BC(ThreadState state) {

        return PackBouncyCastle.bigEndianToLong(PackBouncyCastle.longToBigEndian(state.nextLong()), 0);
    }


    @Benchmark
    public long long_little_endian_UNSAFE(ThreadState state) {

        return PackUnsafe.littleEndianToLong(PackUnsafe.longToLittleEndian(state.nextLong()), 0);
    }

    @Benchmark
    public long long_little_endian_BC(ThreadState state) {

        return PackBouncyCastle.littleEndianToLong(PackBouncyCastle.longToLittleEndian(state.nextLong()), 0);
    }


}
