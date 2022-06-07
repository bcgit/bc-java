/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This package is based on the work done by Keiron Liddle, Aftex Software
 * <keiron@aftexsw.com> to whom the Ant project is very grateful for his
 * great code.
 */
package org.bouncycastle.apache.bzip2;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * An input stream that decompresses from the BZip2 format (with the file
 * header chars) to be read as any other stream.
 *
 * @author <a href="mailto:keiron@aftexsw.com">Keiron Liddle</a>
 *
 * <b>NB:</b> note this class has been modified to read the leading BZ from the
 * start of the BZIP2 stream to make it compatible with other PGP programs.
 */
public class CBZip2InputStream
    extends InputStream
    implements BZip2Constants
{
    /*
      index of the last char in the block, so
      the block size == last + 1.
    */
    private int last;

    /*
      index in zptr[] of original string after sorting.
    */
    private int origPtr;

    /*
      always: in the range 0 .. 9.
      The current block size is 100000 * this number.
    */
    private int blockSize100k;

    private int bsBuff;
    private int bsLive;
    private final CRC blockCRC = new CRC();

    private int nInUse;

    private byte[] seqToUnseq = new byte[256];

    private byte[] selectors = new byte[MAX_SELECTORS];

    private int[] tt;
    private byte[] ll8;

    /*
      freq table collected to save a pass over the data
      during decompression.
    */
    private int[] unzftab = new int[256];

    private int[][] limit = new int[N_GROUPS][MAX_CODE_LEN + 1];
    private int[][] base = new int[N_GROUPS][MAX_CODE_LEN + 1];
    private int[][] perm = new int[N_GROUPS][MAX_ALPHA_SIZE];
    private int[] minLens = new int[N_GROUPS];

    private InputStream bsStream;

    private boolean streamEnd = false;

    private int currentByte = -1;

    private static final int RAND_PART_B_STATE = 1;
    private static final int RAND_PART_C_STATE = 2;
    private static final int NO_RAND_PART_B_STATE = 3;
    private static final int NO_RAND_PART_C_STATE = 4;

    private int currentState = 0;

    private int expectedBlockCRC, expectedStreamCRC, streamCRC;

    int i2, count, chPrev, ch2;
    int i, tPos;
    int rNToGo = 0;
    int rTPos = 0;
    int j2;
    int z;

    public CBZip2InputStream(InputStream zStream)
        throws IOException
    {
        ll8 = null;
        tt = null;
        bsStream = zStream;
        bsLive = 0;
        bsBuff = 0;

        int magic1 = bsStream.read();
        int magic2 = bsStream.read();
        int version = bsStream.read();
        int level = bsStream.read();
        if (level < 0)
        {
            throw new EOFException();
        }

        if (magic1 != 'B' | magic2 != 'Z' | version != 'h' | level < '1' | level > '9')
        {
            throw new IOException("Invalid stream header");
        }

        blockSize100k = level - '0';

        int n = baseBlockSize * blockSize100k;
        ll8 = new byte[n];
        tt = new int[n];

        streamCRC = 0;

        beginBlock();
    }

    public int read()
        throws IOException
    {
        if (streamEnd)
        {
            return -1;
        }

        int result = currentByte;
        switch (currentState)
        {
        case RAND_PART_B_STATE:
            setupRandPartB();
            break;
        case RAND_PART_C_STATE:
            setupRandPartC();
            break;
        case NO_RAND_PART_B_STATE:
            setupNoRandPartB();
            break;
        case NO_RAND_PART_C_STATE:
            setupNoRandPartC();
            break;
        default:
            throw new IllegalStateException();
        }
        return result;
    }

    private void beginBlock()
        throws IOException
    {
        long magic48 = bsGetLong48();
        if (magic48 != 0x314159265359L)
        {
            if (magic48 != 0x177245385090L)
            {
                throw new IOException("Block header error");
            }

            expectedStreamCRC = bsGetInt32();
            if (expectedStreamCRC != streamCRC)
            {
                throw new IOException("Stream CRC error");
            }

            bsFinishedWithStream();
            streamEnd = true;
            return;
        }

        expectedBlockCRC = bsGetInt32();

        boolean blockRandomised = bsGetBit() == 1;

        getAndMoveToFrontDecode();

        blockCRC.initialise();

        int[] cftab = new int[257];
        {
            cftab[0] = 0;
            int accum = 0;
            for (i = 0; i < 256; ++i)
            {
                accum += unzftab[i];
                cftab[i + 1] = accum;
            }
            if (accum != (last + 1))
            {
                throw new IllegalStateException();
            }
        }

        for (i = 0; i <= last; i++)
        {
            int ch = ll8[i] & 0xFF;
            tt[cftab[ch]++] = i;
        }

        tPos = tt[origPtr];

        count = 0;
        i2 = 0;
        ch2 = 256;   /* not a char and not EOF */

        if (blockRandomised)
        {
            rNToGo = 0;
            rTPos = 0;
            setupRandPartA();
        }
        else
        {
            setupNoRandPartA();
        }
    }

    private void endBlock()
        throws IOException
    {
        int blockFinalCRC = blockCRC.getFinal();
        if (expectedBlockCRC != blockFinalCRC)
        {
            throw new IOException("Block CRC error");
        }

        streamCRC = Integers.rotateLeft(streamCRC, 1) ^ blockFinalCRC;
    }

    private void bsFinishedWithStream()
    {
        try
        {
            if (this.bsStream != null)
            {
                if (this.bsStream != System.in)
                {
                    this.bsStream.close();
                    this.bsStream = null;
                }
            }
        }
        catch (IOException ioe)
        {
            //ignore
        }
    }

    private int bsGetBit()
        throws IOException
    {
        if (bsLive == 0)
        {
            bsBuff = requireByte();
            bsLive = 7;
            return bsBuff >>> 7;
        }

        --bsLive;

        return (bsBuff >>> bsLive) & 1;
    }

    private int bsGetBits(int n)
        throws IOException
    {
//        assert 1 <= n && n <= 24;

        while (bsLive < n)
        {
            bsBuff = (bsBuff << 8) | requireByte();
            bsLive += 8;
        }

        bsLive -= n;

        return (bsBuff >>> bsLive) & ((1 << n) - 1);
    }

    private int bsGetBitsSmall(int n)
        throws IOException
    {
//        assert 1 <= n && n <= 8;

        if (bsLive < n)
        {
            bsBuff = (bsBuff << 8) | requireByte();
            bsLive += 8;
        }

        bsLive -= n;

        return (bsBuff >>> bsLive) & ((1 << n) - 1);
    }

    private int bsGetInt32()
        throws IOException
    {
        int u = bsGetBits(16) << 16;
        return u | bsGetBits(16); 
    }

    private long bsGetLong48()
        throws IOException
    {
        long u = (long)bsGetBits(24) << 24;
        return u | (long)bsGetBits(24);
    }

    private void hbCreateDecodeTables(int[] limit, int[] base, int[] perm, byte[] length, int minLen, int maxLen,
        int alphaSize)
    {
        Arrays.fill(base, 0);
        Arrays.fill(limit, 0);

        int pp = 0, baseVal = 0;
        for (int i = minLen; i <= maxLen; i++)
        {
            for (int j = 0; j < alphaSize; j++)
            {
                if ((length[j] & 0xFF) == i)
                {
                    perm[pp++] = j;
                }
            }
            base[i] = baseVal;
            limit[i] = baseVal + pp;
            baseVal += baseVal + pp;
        }
    }

    private int recvDecodingTables()
        throws IOException
    {
        int i, j;

        nInUse = 0;

        /* Receive the mapping table */
        int inUse16 = bsGetBits(16);

        for (i = 0; i < 16; ++i)
        {
            if ((inUse16 & (0x8000 >>> i)) != 0)
            {
                int inUse = bsGetBits(16);

                int i16 = i * 16;
                for (j = 0; j < 16; ++j)
                {
                    if ((inUse & (0x8000 >>> j)) != 0)
                    {
                        seqToUnseq[nInUse++] = (byte)(i16 + j);
                    }
                }
            }
        }

        if (nInUse < 1)
        {
            throw new IllegalStateException();
        }

        int alphaSize = nInUse + 2;

        /* Now the selectors */
        int nGroups = bsGetBitsSmall(3);
        if (nGroups < 2 || nGroups > N_GROUPS)
        {
            throw new IllegalStateException();
        }

        int nSelectors = bsGetBits(15);
        if (nSelectors < 1)
        {
            throw new IllegalStateException();
        }

        int mtfGroups = 0x00543210;
        for (i = 0; i < nSelectors; i++)
        {
            int mtfSelector = 0;
            while (bsGetBit() == 1)
            {
                if (++mtfSelector >= nGroups)
                {
                    throw new IllegalStateException();
                }
            }

            // Ignore declared selectors in excess of the maximum usable number
            if (i >= MAX_SELECTORS)
            {
                continue;
            }

            // Undo the MTF values for the selector.
            switch (mtfSelector)
            {
            case 0:
                break;
            case 1:
                mtfGroups = (mtfGroups >>>  4) & 0x00000F | (mtfGroups << 4) & 0x0000F0 | mtfGroups & 0xFFFF00;
                break;
            case 2:
                mtfGroups = (mtfGroups >>>  8) & 0x00000F | (mtfGroups << 4) & 0x000FF0 | mtfGroups & 0xFFF000;
                break;
            case 3:
                mtfGroups = (mtfGroups >>> 12) & 0x00000F | (mtfGroups << 4) & 0x00FFF0 | mtfGroups & 0xFF0000;
                break;
            case 4:
                mtfGroups = (mtfGroups >>> 16) & 0x00000F | (mtfGroups << 4) & 0x0FFFF0 | mtfGroups & 0xF00000;
                break;
            case 5:
                mtfGroups = (mtfGroups >>> 20) & 0x00000F | (mtfGroups << 4) & 0xFFFFF0;
                break;
            default:
                throw new IllegalStateException();
            }

            selectors[i] = (byte)(mtfGroups & 0xF);
        }

        byte[] len_t = new byte[alphaSize];

        /* Now the coding tables */
        for (int t = 0; t < nGroups; t++)
        {
            int maxLen = 0, minLen = 32;
            int curr = bsGetBitsSmall(5);
            if ((curr < 1) | (curr > MAX_CODE_LEN))
            {
                throw new IllegalStateException();
            }

            for (i = 0; i < alphaSize; i++)
            {
                int markerBit = bsGetBit();
                while (markerBit != 0)
                {
                    int nextTwoBits = bsGetBitsSmall(2);
                    curr += 1 - (nextTwoBits & 2);
                    if ((curr < 1) | (curr > MAX_CODE_LEN))
                    {
                        throw new IllegalStateException();
                    }
                    markerBit = nextTwoBits & 1;
                }

                len_t[i] = (byte)curr;
                maxLen = Math.max(maxLen, curr);
                minLen = Math.min(minLen, curr);
            }

            /* Create the Huffman decoding tables */
            hbCreateDecodeTables(limit[t], base[t], perm[t], len_t, minLen, maxLen, alphaSize);
            minLens[t] = minLen;
        }

        return nSelectors;
    }

    private void getAndMoveToFrontDecode()
        throws IOException
    {
        int i, j, nextSym;

        int limitLast = baseBlockSize * blockSize100k;

        origPtr = bsGetBits(24);
        if (origPtr > 10 + limitLast)
        {
            throw new IllegalStateException();
        }

        int nSelectors = recvDecodingTables();

        int alphaSize = nInUse + 2;
        int EOB = nInUse + 1;

        /*
          Setting up the unzftab entries here is not strictly
          necessary, but it does save having to do it later
          in a separate pass, and so saves a block's worth of
          cache misses.
        */
        for (i = 0; i <= 255; i++)
        {
            unzftab[i] = 0;
        }

        byte[] yy = new byte[nInUse];
        for (i = 0; i < nInUse; ++i)
        {
            yy[i] = seqToUnseq[i];
        }

        last = -1;

        int groupNo = 0;
        int groupPos = G_SIZE - 1;
        int groupSel = selectors[groupNo] & 0xFF;
        int groupMinLen = minLens[groupSel];
        int[] groupLimits = limit[groupSel];
        int[] groupPerm = perm[groupSel];
        int[] groupBase = base[groupSel];

        {
            int zn = groupMinLen;
            int zvec = bsGetBits(groupMinLen);
            while (zvec >= groupLimits[zn])
            {
                if (++zn > MAX_CODE_LEN)
                {
                    throw new IllegalStateException();
                }
                zvec = (zvec << 1) | bsGetBit();
            }
            int permIndex = zvec - groupBase[zn];
            if (permIndex >= alphaSize)
            {
                throw new IllegalStateException();
            }
            nextSym = groupPerm[permIndex];
        }

        while (nextSym != EOB)
        {
//            if (nextSym == RUNA || nextSym == RUNB)
            if (nextSym <= RUNB)
            {
                int n = 1, s = 0;
                do
                {
                    if (n > 1024*1024)
                    {
                        throw new IllegalStateException();
                    }

                    s += n << nextSym;
                    n <<= 1;
                    {
                        if (groupPos == 0)
                        {
                            if (++groupNo >= nSelectors)
                            {
                                throw new IllegalStateException();
                            }
                            groupPos = G_SIZE;
                            groupSel = selectors[groupNo] & 0xFF;
                            groupMinLen = minLens[groupSel];
                            groupLimits = limit[groupSel];
                            groupPerm = perm[groupSel];
                            groupBase = base[groupSel];
                        }
                        groupPos--;

                        int zn = groupMinLen;
                        int zvec = bsGetBits(groupMinLen);
                        while (zvec >= groupLimits[zn])
                        {
                            if (++zn > MAX_CODE_LEN)
                            {
                                throw new IllegalStateException();
                            }
                            zvec = (zvec << 1) | bsGetBit();
                        }
                        int permIndex = zvec - groupBase[zn];
                        if (permIndex >= alphaSize)
                        {
                            throw new IllegalStateException();
                        }
                        nextSym = groupPerm[permIndex];
                    }
                }
//                while (nextSym == RUNA || nextSym == RUNB);
                while (nextSym <= RUNB);

                byte ch = yy[0];
                unzftab[ch & 0xFF] += s;

                if (last >= limitLast - s)
                {
                    throw new IllegalStateException("Block overrun");
                }

                while (--s >= 0)
                {
                    ll8[++last] = ch;
                }
                continue;
            }
            else
            {
                if (++last >= limitLast)
                {
                    throw new IllegalStateException("Block overrun");
                }

                byte tmp = yy[nextSym - 1];
                unzftab[tmp & 0xFF]++;
                ll8[last] = tmp;

                /*
                 * This loop is hammered during decompression, hence avoid native method call
                 * overhead of System.arraycopy for very small ranges to copy.
                 */
                if (nextSym <= 16)
                {
                    for (j = nextSym - 1; j > 0; --j)
                    {
                        yy[j] = yy[j - 1];
                    }
                }
                else
                {
                    System.arraycopy(yy, 0, yy, 1, nextSym - 1);
                }

                yy[0] = tmp;

                {
                    if (groupPos == 0)
                    {
                        if (++groupNo >= nSelectors)
                        {
                            throw new IllegalStateException();
                        }
                        groupPos = G_SIZE;
                        groupSel = selectors[groupNo] & 0xFF;
                        groupMinLen = minLens[groupSel];
                        groupLimits = limit[groupSel];
                        groupPerm = perm[groupSel];
                        groupBase = base[groupSel];
                    }
                    groupPos--;

                    int zn = groupMinLen;
                    int zvec = bsGetBits(groupMinLen);
                    while (zvec >= groupLimits[zn])
                    {
                        if (++zn > MAX_CODE_LEN)
                        {
                            throw new IllegalStateException();
                        }
                        zvec = (zvec << 1) | bsGetBit();
                    }
                    int permIndex = zvec - groupBase[zn];
                    if (permIndex >= alphaSize)
                    {
                        throw new IllegalStateException();
                    }
                    nextSym = groupPerm[permIndex];
                }
                continue;
            }
        }

        if (origPtr > last)
        {
            throw new IllegalStateException();
        }

        // Check unzftab entries are in range.
        {
            int nblock = last + 1;
            int check = 0;

            for (i = 0; i <= 255; i++)
            {
                int t = unzftab[i];
                check |= t;
                check |= nblock - t;
            }
            if (check < 0)
            {
                throw new IllegalStateException();
            }
        }
    }

    private int requireByte()
        throws IOException
    {
        int b = bsStream.read();
        if (b < 0)
        {
            throw new EOFException();
        }
        return b & 0xFF;
    }

    private void setupRandPartA()
        throws IOException
    {
        if (i2 <= last)
        {
            chPrev = ch2;
            ch2 = ll8[tPos] & 0xFF;
            tPos = tt[tPos];
            if (rNToGo == 0)
            {
                rNToGo = CBZip2OutputStream.R_NUMS[rTPos++];
                rTPos &= 0x1FF;
            }
            rNToGo--;
            ch2 ^= rNToGo == 1 ? 1 : 0;
            i2++;

            currentByte = ch2;
            currentState = RAND_PART_B_STATE;
            blockCRC.update(ch2);
        }
        else
        {
            endBlock();
            beginBlock();
        }
    }

    private void setupNoRandPartA()
        throws IOException
    {
        if (i2 <= last)
        {
            chPrev = ch2;
            ch2 = ll8[tPos] & 0xFF;
            tPos = tt[tPos];
            i2++;

            currentByte = ch2;
            currentState = NO_RAND_PART_B_STATE;
            blockCRC.update(ch2);
        }
        else
        {
            endBlock();
            beginBlock();
        }
    }

    private void setupRandPartB()
        throws IOException
    {
        if (ch2 != chPrev)
        {
            count = 1;
            setupRandPartA();
        }
        else if (++count < 4)
        {
            setupRandPartA();
        }
        else
        {
            z = ll8[tPos] & 0xFF;
            tPos = tt[tPos];
            if (rNToGo == 0)
            {
                rNToGo = CBZip2OutputStream.R_NUMS[rTPos++];
                rTPos &= 0x1FF;
            }
            rNToGo--;
            z ^= rNToGo == 1 ? 1 : 0;
            j2 = 0;
            currentState = RAND_PART_C_STATE;
            setupRandPartC();
        }
    }

    private void setupNoRandPartB()
        throws IOException
    {
        if (ch2 != chPrev)
        {
            count = 1;
            setupNoRandPartA();
        }
        else if (++count < 4)
        {
            setupNoRandPartA();
        }
        else
        {
            z = ll8[tPos] & 0xFF;
            tPos = tt[tPos];
            currentState = NO_RAND_PART_C_STATE;
            j2 = 0;
            setupNoRandPartC();
        }
    }

    private void setupRandPartC()
        throws IOException
    {
        if (j2 < z)
        {
            currentByte = ch2;
            blockCRC.update(ch2);
            j2++;
        }
        else
        {
            i2++;
            count = 0;
            setupRandPartA();
        }
    }

    private void setupNoRandPartC()
        throws IOException
    {
        if (j2 < z)
        {
            currentByte = ch2;
            blockCRC.update(ch2);
            j2++;
        }
        else
        {
            i2++;
            count = 0;
            setupNoRandPartA();
        }
    }
}
