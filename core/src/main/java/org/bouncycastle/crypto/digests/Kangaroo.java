package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

/**
 * Kangaroo.
 */
public final class Kangaroo
{
    /**
     * Default digest length.
     */
    private static final int DIGESTLEN = 32;

    /**
     * KangarooTwelve.
     */
    public static class KangarooTwelve
        extends KangarooBase
    {
        /**
         * Constructor.
         */
        public KangarooTwelve()
        {
            this(DIGESTLEN, CryptoServicePurpose.ANY);
        }

        /**
         * Constructor.
         *
         * @param pLength the digest length
         */
        public KangarooTwelve(final int pLength, CryptoServicePurpose purpose)
        {
            super(128, 12, pLength, purpose);
        }

        public KangarooTwelve(CryptoServicePurpose purpose)
        {
            this(DIGESTLEN, purpose);
        }

        public String getAlgorithmName()
        {
            return "KangarooTwelve";
        }
    }

    /**
     * MarsupilamiFourteen.
     */
    public static class MarsupilamiFourteen
        extends KangarooBase
    {
        /**
         * Constructor.
         */
        public MarsupilamiFourteen()
        {
            this(DIGESTLEN, CryptoServicePurpose.ANY);
        }

        /**
         * Constructor.
         *
         * @param pLength the digest length
         */
        public MarsupilamiFourteen(final int pLength, CryptoServicePurpose purpose)
        {
            super(256, 14, pLength, purpose);
        }
        public MarsupilamiFourteen(CryptoServicePurpose purpose)
        {
            this(DIGESTLEN, purpose);
        }

        public String getAlgorithmName()
        {
            return "MarsupilamiFourteen";
        }
    }

    /**
     * Kangaroo Parameters.
     */
    public static class KangarooParameters
        implements CipherParameters
    {
        /**
         * The personalisation.
         */
        private byte[] thePersonal;

        /**
         * Obtain the personalisation.
         *
         * @return the personalisation
         */
        public byte[] getPersonalisation()
        {
            return Arrays.clone(thePersonal);
        }

        /**
         * Parameter Builder.
         */
        public static class Builder
        {
            /**
             * The personalisation.
             */
            private byte[] thePersonal;

            /**
             * Set the personalisation.
             *
             * @param pPersonal the personalisation
             * @return the Builder
             */
            public Builder setPersonalisation(final byte[] pPersonal)
            {
                thePersonal = Arrays.clone(pPersonal);
                return this;
            }

            /**
             * Build the parameters.
             *
             * @return the parameters
             */
            public KangarooParameters build()
            {
                /* Create params */
                final KangarooParameters myParams = new KangarooParameters();

                /* Record personalisation */
                if (thePersonal != null)
                {
                    myParams.thePersonal = thePersonal;
                }

                /* Return the parameters */
                return myParams;
            }
        }
    }

    /**
     * The Kangaroo Base.
     */
    abstract static class KangarooBase
        implements ExtendedDigest, Xof
    {
        /**
         * Block Size.
         */
        private static final int BLKSIZE = 8192;

        /**
         * Single marker.
         */
        private static final byte[] SINGLE = new byte[]{7};

        /**
         * Intermediate marker.
         */
        private static final byte[] INTERMEDIATE = new byte[]{0xb};

        /**
         * Final marker.
         */
        private static final byte[] FINAL = new byte[]{-1, -1, 6};

        /**
         * First marker.
         */
        private static final byte[] FIRST = new byte[]{3, 0, 0, 0, 0, 0, 0, 0};

        /**
         * The single byte buffer.
         */
        private final byte[] singleByte = new byte[1];

        /**
         * The Tree Sponge.
         */
        private final KangarooSponge theTree;

        /**
         * The Leaf Sponge.
         */
        private final KangarooSponge theLeaf;

        /**
         * The chain length.
         */
        private final int theChainLen;

        /**
         * The personalisation.
         */
        private byte[] thePersonal;

        /**
         * Are we squeezing?.
         */
        private boolean squeezing;

        /**
         * The current node.
         */
        private int theCurrNode;

        /**
         * The data processed in the current node.
         */
        private int theProcessed;

        private final CryptoServicePurpose purpose;

        /**
         * Constructor.
         *
         * @param pStrength the strength
         * @param pRounds   the rounds.
         * @param pLength   the digest length
         */
        KangarooBase(final int pStrength,
                     final int pRounds,
                     final int pLength,
                     CryptoServicePurpose purpose)
        {
            /* Create underlying digests */
            theTree = new KangarooSponge(pStrength, pRounds);
            theLeaf = new KangarooSponge(pStrength, pRounds);
            theChainLen = pStrength >> 2;

            /* Build personalisation */
            buildPersonal(null);
            this.purpose = purpose;

            CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, pStrength, purpose));

        }

        /**
         * Constructor.
         *
         * @param pPersonal the personalisation
         */
        private void buildPersonal(final byte[] pPersonal)
        {
            /* Build personalisation */
            final int myLen = pPersonal == null ? 0 : pPersonal.length;
            final byte[] myEnc = lengthEncode(myLen);
            thePersonal = pPersonal == null
                ? new byte[myLen + myEnc.length]
                : Arrays.copyOf(pPersonal, myLen + myEnc.length);
            System.arraycopy(myEnc, 0, thePersonal, myLen, myEnc.length);
        }

        public int getByteLength()
        {
            return theTree.theRateBytes;
        }

        public int getDigestSize()
        {
            return theChainLen >> 1;
        }

        /**
         * Initialise the digest.
         *
         * @param pParams the parameters
         */
        public void init(final KangarooParameters pParams)
        {
            /* Build the new personalisation */
            buildPersonal(pParams.getPersonalisation());

            /* Reset everything */
            reset();
        }

        public void update(final byte pIn)
        {
            singleByte[0] = pIn;
            update(singleByte, 0, 1);
        }

        public void update(final byte[] pIn,
                           final int pInOff,
                           final int pLen)
        {
            processData(pIn, pInOff, pLen);
        }

        public int doFinal(final byte[] pOut,
                           final int pOutOffset)
        {
            /* finalise the digest */
            return doFinal(pOut, pOutOffset, getDigestSize());
        }

        public int doFinal(final byte[] pOut,
                           final int pOutOffset,
                           final int pOutLen)
        {
            /* Check that we are not already outputting */
            if (squeezing)
            {
                throw new IllegalStateException("Already outputting");
            }

            /* Build the required output */
            final int length = doOutput(pOut, pOutOffset, pOutLen);

            /* reset the underlying digest and return the length */
            reset();
            return length;
        }

        public int doOutput(final byte[] pOut,
                            final int pOutOffset,
                            final int pOutLen)
        {
            /* If we are not currently squeezing, switch to squeezing */
            if (!squeezing)
            {
                switchToSqueezing();
            }

            /* Reject if length is invalid */
            if (pOutLen < 0)
            {
                throw new IllegalArgumentException("Invalid output length");
            }

            /* Squeeze out the data and return the length */
            theTree.squeeze(pOut, pOutOffset, pOutLen);
            return pOutLen;
        }

        /**
         * Process data.
         *
         * @param pIn       the input buffer
         * @param pInOffSet the starting offset in the input buffer
         * @param pLen      the length of data to process
         */
        private void processData(final byte[] pIn,
                                 final int pInOffSet,
                                 final int pLen)
        {
            /* Check validity */
            if (squeezing)
            {
                throw new IllegalStateException("attempt to absorb while squeezing");
            }

            /* Determine current sponge */
            final KangarooSponge mySponge = theCurrNode == 0 ? theTree : theLeaf;

            /* Determine space in current block */
            final int mySpace = BLKSIZE - theProcessed;

            /* If all data can be processed by the current sponge*/
            if (mySpace >= pLen)
            {
                /* Absorb and return */
                mySponge.absorb(pIn, pInOffSet, pLen);
                theProcessed += pLen;
                return;
            }

            /* Absorb as much as possible into current sponge */
            if (mySpace > 0)
            {
                mySponge.absorb(pIn, pInOffSet, mySpace);
                theProcessed += mySpace;
            }

            /* Loop while we have data remaining */
            int myProcessed = mySpace;
            while (myProcessed < pLen)
            {
                /* Switch Leaf if the current sponge is full */
                if (theProcessed == BLKSIZE)
                {
                    switchLeaf(true);
                }

                /* Process next block */
                final int myDataLen = Math.min(pLen - myProcessed, BLKSIZE);
                theLeaf.absorb(pIn, pInOffSet + myProcessed, myDataLen);
                theProcessed += myDataLen;
                myProcessed += myDataLen;
            }
        }

        public void reset()
        {
            theTree.initSponge();
            theLeaf.initSponge();
            theCurrNode = 0;
            theProcessed = 0;
            squeezing = false;
        }

        /**
         * Complete Leaf.
         *
         * @param pMoreToCome is there more data to come? true/false
         */
        private void switchLeaf(final boolean pMoreToCome)
        {
            /* If we are the first node */
            if (theCurrNode == 0)
            {
                /* Absorb the padding */
                theTree.absorb(FIRST, 0, FIRST.length);

                /* else intermediate node */
            }
            else
            {
                /* Absorb intermediate node marker */
                theLeaf.absorb(INTERMEDIATE, 0, INTERMEDIATE.length);

                /* Complete the node */
                final byte[] myHash = new byte[theChainLen];
                theLeaf.squeeze(myHash, 0, theChainLen);
                theTree.absorb(myHash, 0, theChainLen);

                /* Re-init the leaf */
                theLeaf.initSponge();
            }

            /* Switch to next node */
            if (pMoreToCome)
            {
                theCurrNode++;
            }
            theProcessed = 0;
        }

        /**
         * Switch to squeezing.
         */
        private void switchToSqueezing()
        {
            /* Absorb the personalisation */
            processData(thePersonal, 0, thePersonal.length);

            /* Complete the absorption */
            if (theCurrNode == 0)
            {
                switchSingle();
            }
            else
            {
                switchFinal();
            }
        }

        /**
         * Switch single node to squeezing.
         */
        private void switchSingle()
        {
            /* Absorb single node marker */
            theTree.absorb(SINGLE, 0, 1);

            /* Switch to squeezing */
            theTree.padAndSwitchToSqueezingPhase();
        }

        /**
         * Switch multiple node to squeezing.
         */
        private void switchFinal()
        {
            /* Complete the current leaf */
            switchLeaf(false);

            /* Absorb length */
            final byte[] myLength = lengthEncode(theCurrNode);
            theTree.absorb(myLength, 0, myLength.length);

            /* Absorb final node marker */
            theTree.absorb(FINAL, 0, FINAL.length);

            /* Switch to squeezing */
            theTree.padAndSwitchToSqueezingPhase();
        }

        /**
         * right Encode a length.
         *
         * @param strLen the length to encode
         * @return the encoded length
         */
        private static byte[] lengthEncode(final long strLen)
        {
            /* Calculate # of bytes required to hold length */
            byte n = 0;
            long v = strLen;
            if (v != 0)
            {
                n = 1;
                while ((v >>= Bytes.SIZE) != 0)
                {
                    n++;
                }
            }

            /* Allocate byte array and store length */
            final byte[] b = new byte[n + 1];
            b[n] = n;

            /* Encode the length */
            for (int i = 0; i < n; i++)
            {
                b[i] = (byte)(strLen >> (Bytes.SIZE * (n - i - 1)));
            }

            /* Return the encoded length */
            return b;
        }
    }

    /**
     * The Kangaroo Sponge.
     */
    private static class KangarooSponge
    {
        /**
         * The round constants.
         */
        private static long[] KeccakRoundConstants = new long[]{0x0000000000000001L, 0x0000000000008082L,
            0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L,
            0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L,
            0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L,
            0x0000000080000001L, 0x8000000080008008L};

        /**
         * The number of rounds.
         */
        private final int theRounds;

        /**
         * The rateBytes.
         */
        private final int theRateBytes;

        /**
         * The state.
         */
        private final long[] theState = new long[25];

        /**
         * The queue.
         */
        private final byte[] theQueue;

        /**
         * The numnber of bytes in the queue.
         */
        private int bytesInQueue;

        /**
         * Are we squeezing?
         */
        private boolean squeezing;

        /**
         * Constructor.
         *
         * @param pStrength the strength
         * @param pRounds   the rounds.
         */
        KangarooSponge(final int pStrength,
                       final int pRounds)
        {
            theRateBytes = (1600 - (pStrength << 1)) >> 3;
            theRounds = pRounds;
            theQueue = new byte[theRateBytes];
            initSponge();
        }

        /**
         * Initialise the sponge.
         */
        private void initSponge()
        {
            Arrays.fill(theState, 0L);
            Arrays.fill(theQueue, (byte)0);
            bytesInQueue = 0;
            squeezing = false;
        }

        /**
         * Absorb data into sponge.
         *
         * @param data the data buffer
         * @param off  the starting offset in the buffer.
         * @param len  the length of data to absorb
         */
        private void absorb(final byte[] data,
                            final int off,
                            final int len)
        {
            /* Sanity checks */
            if (squeezing)
            {
                throw new IllegalStateException("attempt to absorb while squeezing");
            }

            int count = 0;
            while (count < len)
            {
                if (bytesInQueue == 0 && count <= (len - theRateBytes))
                {
                    do
                    {
                        KangarooAbsorb(data, off + count);
                        count += theRateBytes;
                    }
                    while (count <= (len - theRateBytes));

                }
                else
                {
                    final int partialBlock = Math.min(theRateBytes - bytesInQueue, len - count);
                    System.arraycopy(data, off + count, theQueue, bytesInQueue, partialBlock);

                    bytesInQueue += partialBlock;
                    count += partialBlock;

                    if (bytesInQueue == theRateBytes)
                    {
                        KangarooAbsorb(theQueue, 0);
                        bytesInQueue = 0;
                    }
                }
            }
        }

        /**
         * Handle padding.
         */
        private void padAndSwitchToSqueezingPhase()
        {
            /* Fill any remaining space in queue with zeroes */
            for (int i = bytesInQueue; i < theRateBytes; i++)
            {
                theQueue[i] = 0;
            }
            theQueue[theRateBytes - 1] ^= 0x80;
            KangarooAbsorb(theQueue, 0);

            KangarooExtract();
            bytesInQueue = theRateBytes;
            squeezing = true;
        }

        /**
         * Squeeze data out.
         *
         * @param output       the output buffer
         * @param offset       the offset in the output buffer
         * @param outputLength the output length
         */
        private void squeeze(final byte[] output,
                             final int offset,
                             final int outputLength)
        {
            if (!squeezing)
            {
                padAndSwitchToSqueezingPhase();
            }

            int i = 0;
            while (i < outputLength)
            {
                if (bytesInQueue == 0)
                {
                    KangarooPermutation();
                    KangarooExtract();
                    bytesInQueue = theRateBytes;
                }
                int partialBlock = Math.min(bytesInQueue, outputLength - i);
                System.arraycopy(theQueue, theRateBytes - bytesInQueue, output, offset + i, partialBlock);
                bytesInQueue -= partialBlock;
                i += partialBlock;
            }
        }

        /**
         * Absorb a block of data.
         *
         * @param data the data to absorb
         * @param off  the starting offset in the data
         */
        private void KangarooAbsorb(final byte[] data,
                                    final int off)
        {
            final int count = theRateBytes >> 3;
            int offSet = off;
            for (int i = 0; i < count; ++i)
            {
                theState[i] ^= Pack.littleEndianToLong(data, offSet);
                offSet += 8;
            }

            KangarooPermutation();
        }

        /**
         * Extract a block of data to the queue.
         */
        private void KangarooExtract()
        {
            Pack.longToLittleEndian(theState, 0, theRateBytes >> 3, theQueue, 0);
        }

        /**
         * Permutation (KP).
         */
        private void KangarooPermutation()
        {
            long[] A = theState;

            long a00 = A[0], a01 = A[1], a02 = A[2], a03 = A[3], a04 = A[4];
            long a05 = A[5], a06 = A[6], a07 = A[7], a08 = A[8], a09 = A[9];
            long a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
            long a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
            long a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];

            int myBase = KeccakRoundConstants.length - theRounds;
            for (int i = 0; i < theRounds; i++)
            {
                // theta
                long c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
                long c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
                long c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
                long c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
                long c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

                long d1 = (c1 << 1 | c1 >>> -1) ^ c4;
                long d2 = (c2 << 1 | c2 >>> -1) ^ c0;
                long d3 = (c3 << 1 | c3 >>> -1) ^ c1;
                long d4 = (c4 << 1 | c4 >>> -1) ^ c2;
                long d0 = (c0 << 1 | c0 >>> -1) ^ c3;

                a00 ^= d1;
                a05 ^= d1;
                a10 ^= d1;
                a15 ^= d1;
                a20 ^= d1;
                a01 ^= d2;
                a06 ^= d2;
                a11 ^= d2;
                a16 ^= d2;
                a21 ^= d2;
                a02 ^= d3;
                a07 ^= d3;
                a12 ^= d3;
                a17 ^= d3;
                a22 ^= d3;
                a03 ^= d4;
                a08 ^= d4;
                a13 ^= d4;
                a18 ^= d4;
                a23 ^= d4;
                a04 ^= d0;
                a09 ^= d0;
                a14 ^= d0;
                a19 ^= d0;
                a24 ^= d0;

                // rho/pi
                c1 = a01 << 1 | a01 >>> 63;
                a01 = a06 << 44 | a06 >>> 20;
                a06 = a09 << 20 | a09 >>> 44;
                a09 = a22 << 61 | a22 >>> 3;
                a22 = a14 << 39 | a14 >>> 25;
                a14 = a20 << 18 | a20 >>> 46;
                a20 = a02 << 62 | a02 >>> 2;
                a02 = a12 << 43 | a12 >>> 21;
                a12 = a13 << 25 | a13 >>> 39;
                a13 = a19 << 8 | a19 >>> 56;
                a19 = a23 << 56 | a23 >>> 8;
                a23 = a15 << 41 | a15 >>> 23;
                a15 = a04 << 27 | a04 >>> 37;
                a04 = a24 << 14 | a24 >>> 50;
                a24 = a21 << 2 | a21 >>> 62;
                a21 = a08 << 55 | a08 >>> 9;
                a08 = a16 << 45 | a16 >>> 19;
                a16 = a05 << 36 | a05 >>> 28;
                a05 = a03 << 28 | a03 >>> 36;
                a03 = a18 << 21 | a18 >>> 43;
                a18 = a17 << 15 | a17 >>> 49;
                a17 = a11 << 10 | a11 >>> 54;
                a11 = a07 << 6 | a07 >>> 58;
                a07 = a10 << 3 | a10 >>> 61;
                a10 = c1;

                // chi
                c0 = a00 ^ (~a01 & a02);
                c1 = a01 ^ (~a02 & a03);
                a02 ^= ~a03 & a04;
                a03 ^= ~a04 & a00;
                a04 ^= ~a00 & a01;
                a00 = c0;
                a01 = c1;

                c0 = a05 ^ (~a06 & a07);
                c1 = a06 ^ (~a07 & a08);
                a07 ^= ~a08 & a09;
                a08 ^= ~a09 & a05;
                a09 ^= ~a05 & a06;
                a05 = c0;
                a06 = c1;

                c0 = a10 ^ (~a11 & a12);
                c1 = a11 ^ (~a12 & a13);
                a12 ^= ~a13 & a14;
                a13 ^= ~a14 & a10;
                a14 ^= ~a10 & a11;
                a10 = c0;
                a11 = c1;

                c0 = a15 ^ (~a16 & a17);
                c1 = a16 ^ (~a17 & a18);
                a17 ^= ~a18 & a19;
                a18 ^= ~a19 & a15;
                a19 ^= ~a15 & a16;
                a15 = c0;
                a16 = c1;

                c0 = a20 ^ (~a21 & a22);
                c1 = a21 ^ (~a22 & a23);
                a22 ^= ~a23 & a24;
                a23 ^= ~a24 & a20;
                a24 ^= ~a20 & a21;
                a20 = c0;
                a21 = c1;

                // iota
                a00 ^= KeccakRoundConstants[myBase + i];
            }

            A[0] = a00;
            A[1] = a01;
            A[2] = a02;
            A[3] = a03;
            A[4] = a04;
            A[5] = a05;
            A[6] = a06;
            A[7] = a07;
            A[8] = a08;
            A[9] = a09;
            A[10] = a10;
            A[11] = a11;
            A[12] = a12;
            A[13] = a13;
            A[14] = a14;
            A[15] = a15;
            A[16] = a16;
            A[17] = a17;
            A[18] = a18;
            A[19] = a19;
            A[20] = a20;
            A[21] = a21;
            A[22] = a22;
            A[23] = a23;
            A[24] = a24;
        }
    }
}
