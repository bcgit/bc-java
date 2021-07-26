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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Vector;

/**
 * An output stream that compresses into the BZip2 format (with the file
 * header chars) into another stream.
 *
 * @author <a href="mailto:keiron@aftexsw.com">Keiron Liddle</a>
 * <p>
 * TODO:    Update to BZip2 1.0.1
 * <b>NB:</b> note this class has been modified to add a leading BZ to the
 * start of the BZIP2 stream to make it compatible with other PGP programs.
 */
public class CBZip2OutputStream
    extends OutputStream
    implements BZip2Constants
{
    protected static final int SETMASK = 1 << 21;
    protected static final int CLEARMASK = ~SETMASK;
    protected static final int GREATER_ICOST = 15;
    protected static final int LESSER_ICOST = 0;
    protected static final int SMALL_THRESH = 20;
    protected static final int DEPTH_THRESH = 10;

    private boolean finished;

    private static void panic()
    {
        throw new IllegalStateException();
    }

    private void makeMaps()
    {
        int i;
        nInUse = 0;
        for (i = 0; i < 256; i++)
        {
            if (inUse[i])
            {
                seqToUnseq[nInUse] = (char)i;
                unseqToSeq[i] = (char)nInUse;
                nInUse++;
            }
        }
    }

    protected static void hbMakeCodeLengths(byte[] len, int[] freq,
                                            int alphaSize, int maxLen)
    {
        /*
          Nodes and heap entries run from 1.  Entry 0
          for both the heap and nodes is a sentinel.
        */
        int nNodes, nHeap, n1, n2, i, j, k;
        boolean tooLong;

        int[] heap = new int[MAX_ALPHA_SIZE + 2];
        int[] weight = new int[MAX_ALPHA_SIZE * 2];
        int[] parent = new int[MAX_ALPHA_SIZE * 2];

        for (i = 0; i < alphaSize; i++)
        {
            weight[i + 1] = (freq[i] == 0 ? 1 : freq[i]) << 8;
        }

        while (true)
        {
            nNodes = alphaSize;
            nHeap = 0;

            heap[0] = 0;
            weight[0] = 0;
            parent[0] = -2;

            for (i = 1; i <= alphaSize; i++)
            {
                parent[i] = -1;
                nHeap++;
                heap[nHeap] = i;
                {
                    int zz, tmp;
                    zz = nHeap;
                    tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]])
                    {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }
            }
            if (!(nHeap < (MAX_ALPHA_SIZE + 2)))
            {
                panic();
            }

            while (nHeap > 1)
            {
                n1 = heap[1];
                heap[1] = heap[nHeap];
                nHeap--;
                {
                    int zz = 0, yy = 0, tmp = 0;
                    zz = 1;
                    tmp = heap[zz];
                    while (true)
                    {
                        yy = zz << 1;
                        if (yy > nHeap)
                        {
                            break;
                        }
                        if (yy < nHeap
                            && weight[heap[yy + 1]] < weight[heap[yy]])
                        {
                            yy++;
                        }
                        if (weight[tmp] < weight[heap[yy]])
                        {
                            break;
                        }
                        heap[zz] = heap[yy];
                        zz = yy;
                    }
                    heap[zz] = tmp;
                }
                n2 = heap[1];
                heap[1] = heap[nHeap];
                nHeap--;
                {
                    int zz = 0, yy = 0, tmp = 0;
                    zz = 1;
                    tmp = heap[zz];
                    while (true)
                    {
                        yy = zz << 1;
                        if (yy > nHeap)
                        {
                            break;
                        }
                        if (yy < nHeap
                            && weight[heap[yy + 1]] < weight[heap[yy]])
                        {
                            yy++;
                        }
                        if (weight[tmp] < weight[heap[yy]])
                        {
                            break;
                        }
                        heap[zz] = heap[yy];
                        zz = yy;
                    }
                    heap[zz] = tmp;
                }
                nNodes++;
                parent[n1] = parent[n2] = nNodes;

                weight[nNodes] = ((weight[n1] & 0xffffff00)
                    + (weight[n2] & 0xffffff00))
                    | (1 + (((weight[n1] & 0x000000ff) >
                    (weight[n2] & 0x000000ff)) ?
                    (weight[n1] & 0x000000ff) :
                    (weight[n2] & 0x000000ff)));

                parent[nNodes] = -1;
                nHeap++;
                heap[nHeap] = nNodes;
                {
                    int zz = 0, tmp = 0;
                    zz = nHeap;
                    tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]])
                    {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }
            }
            if (!(nNodes < (MAX_ALPHA_SIZE * 2)))
            {
                panic();
            }

            tooLong = false;
            for (i = 1; i <= alphaSize; i++)
            {
                j = 0;
                k = i;
                while (parent[k] >= 0)
                {
                    k = parent[k];
                    j++;
                }
                len[i - 1] = (byte)j;
                if (j > maxLen)
                {
                    tooLong = true;
                }
            }

            if (!tooLong)
            {
                break;
            }

            for (i = 1; i < alphaSize; i++)
            {
                j = weight[i] >> 8;
                j = 1 + (j / 2);
                weight[i] = j << 8;
            }
        }
    }

    /*
     * number of characters in the block
     */
    int count;

    /*
      index in zptr[] of original string after sorting.
    */
    int origPtr;

    /*
      always: in the range 0 .. 9.
      The current block size is 100000 * this number.
    */
    int blockSize100k;

    boolean blockRandomised;

    int bsBuff;
    int bsLive;
    CRC mCrc = new CRC();

    private boolean[] inUse = new boolean[256];
    private int nInUse;

    private char[] seqToUnseq = new char[256];
    private char[] unseqToSeq = new char[256];

    private char[] selector = new char[MAX_SELECTORS];
    private char[] selectorMtf = new char[MAX_SELECTORS];

    private byte[] blockBytes;
    private short[] quadrantShorts;
    private int[] zptr;
    private int[] szptr;
    private int[] ftab;

    private int nMTF;

    private int[] mtfFreq = new int[MAX_ALPHA_SIZE];

    /*
     * Used when sorting.  If too many long comparisons
     * happen, we stop sorting, randomise the block
     * slightly, and try again.
     */
    private int workFactor;
    private int workDone;
    private int workLimit;
    private boolean firstAttempt;

    private int currentByte = -1;
    private int runLength = 0;

    public CBZip2OutputStream(OutputStream outStream)
        throws IOException
    {
        this(outStream, 9);
    }

    public CBZip2OutputStream(OutputStream outStream, int blockSize)
        throws IOException
    {
        blockBytes = null;
        quadrantShorts = null;
        zptr = null;
        ftab = null;

        outStream.write('B');
        outStream.write('Z');

        bsSetStream(outStream);

        workFactor = 50;
        if (blockSize > 9)
        {
            blockSize = 9;
        }
        if (blockSize < 1)
        {
            blockSize = 1;
        }
        blockSize100k = blockSize;

        /* 20 is just a paranoia constant */
        allowableBlockSize = baseBlockSize * blockSize100k - 20;

        allocateCompressStructures();
        initialize();
        initBlock();
    }

    /**
     * modified by Oliver Merkel, 010128
     */
    public void write(int bv)
        throws IOException
    {
        int b = bv & 0xFF;
        if (currentByte == b)
        {
            runLength++;
            if (runLength > 254)
            {
                writeRun();
                currentByte = -1;
                runLength = 0;
            }
        }
        else if (currentByte == -1)
        {
            currentByte = b;
            runLength++;
        }
        else
        {
            writeRun();
            runLength = 1;
            currentByte = b;
        }
    }

    private void writeRun()
        throws IOException
    {
        if (count > allowableBlockSize)
        {
            endBlock();
            initBlock();
        }

        inUse[currentByte] = true;

        for (int i = 0; i < runLength; i++)
        {
            mCrc.updateCRC(currentByte);
        }

        switch (runLength)
        {
        case 1:
            blockBytes[++count] = (byte)currentByte;
            break;
        case 2:
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            break;
        case 3:
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            break;
        default:
            inUse[runLength - 4] = true;
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)currentByte;
            blockBytes[++count] = (byte)(runLength - 4);
            break;
        }
    }

    boolean closed = false;

    protected void finalize()
        throws Throwable
    {
        close();
        super.finalize();
    }

    public void close()
        throws IOException
    {
        if (closed)
        {
            return;
        }

        finish();

        closed = true;
        super.close();
        bsStream.close();
    }

    public void finish()
        throws IOException
    {
        if (finished)
        {
            return;
        }

        if (runLength > 0)
        {
            writeRun();
        }
        currentByte = -1;
        if (count > 0)
        {
            endBlock();
        }
        endCompression();
        finished = true;
        flush();
    }

    public void flush()
        throws IOException
    {
        super.flush();
        bsStream.flush();
    }

    private int blockCRC, combinedCRC;
    private final int allowableBlockSize;

    private void initialize()
        throws IOException
    {
        /* Write `magic' bytes h indicating file-format == huffmanised,
           followed by a digit indicating blockSize100k.
        */
        bsPutUChar('h');
        bsPutUChar('0' + blockSize100k);

        combinedCRC = 0;
    }

    private void initBlock()
    {
        mCrc.initialiseCRC();
        count = 0;

        for (int i = 0; i < 256; i++)
        {
            inUse[i] = false;
        }
    }

    private void endBlock()
        throws IOException
    {
        blockCRC = mCrc.getFinalCRC();
        combinedCRC = (combinedCRC << 1) | (combinedCRC >>> 31);
        combinedCRC ^= blockCRC;

        /* sort the block and establish posn of original string */
        doReversibleTransformation();

        /*
          A 6-byte block header, the value chosen arbitrarily
          as 0x314159265359 :-).  A 32 bit value does not really
          give a strong enough guarantee that the value will not
          appear by chance in the compressed datastream.  Worst-case
          probability of this event, for a 900k block, is about
          2.0e-3 for 32 bits, 1.0e-5 for 40 bits and 4.0e-8 for 48 bits.
          For a compressed file of size 100Gb -- about 100000 blocks --
          only a 48-bit marker will do.  NB: normal compression/
          decompression do *not* rely on these statistical properties.
          They are only important when trying to recover blocks from
          damaged files.
        */
        bsPutUChar(0x31);
        bsPutUChar(0x41);
        bsPutUChar(0x59);
        bsPutUChar(0x26);
        bsPutUChar(0x53);
        bsPutUChar(0x59);

        /* Now the block's CRC, so it is in a known place. */
        bsPutint(blockCRC);

        /* Now a single bit indicating randomisation. */
        bsW(1, blockRandomised ? 1 : 0);

        /* Finally, block's contents proper. */
        moveToFrontCodeAndSend();
    }

    private void endCompression()
        throws IOException
    {
        /*
          Now another magic 48-bit number, 0x177245385090, to
          indicate the end of the last block.  (sqrt(pi), if
          you want to know.  I did want to use e, but it contains
          too much repetition -- 27 18 28 18 28 46 -- for me
          to feel statistically comfortable.  Call me paranoid.)
        */
        bsPutUChar(0x17);
        bsPutUChar(0x72);
        bsPutUChar(0x45);
        bsPutUChar(0x38);
        bsPutUChar(0x50);
        bsPutUChar(0x90);

        bsPutint(combinedCRC);

        bsFinishedWithStream();
    }

    private void hbAssignCodes(int[] code, byte[] length, int minLen,
                               int maxLen, int alphaSize)
    {
        int vec = 0;
        for (int n = minLen; n <= maxLen; n++)
        {
            for (int i = 0; i < alphaSize; i++)
            {
                if ((length[i] & 0xFF) == n)
                {
                    code[i] = vec;
                    vec++;
                }
            }
            vec <<= 1;
        }
    }

    private void bsSetStream(OutputStream f)
    {
        bsStream = f;
        bsLive = 0;
        bsBuff = 0;
    }

    private void bsFinishedWithStream()
        throws IOException
    {
        while (bsLive > 0)
        {
            bsStream.write(bsBuff >> 24); // write 8-bit
            bsBuff <<= 8;
            bsLive -= 8;
        }
    }

    private void bsW(int n, int v)
        throws IOException
    {
        while (bsLive >= 8)
        {
            bsStream.write(bsBuff >> 24); // write 8-bit
            bsBuff <<= 8;
            bsLive -= 8;
        }
        bsBuff |= (v << (32 - bsLive - n));
        bsLive += n;
    }

    private void bsPutUChar(int c)
        throws IOException
    {
        bsW(8, c);
    }

    private void bsPutint(int u)
        throws IOException
    {
        bsW(8, (u >> 24) & 0xff);
        bsW(8, (u >> 16) & 0xff);
        bsW(8, (u >> 8) & 0xff);
        bsW(8, u & 0xff);
    }

    private void bsPutIntVS(int numBits, int c)
        throws IOException
    {
        bsW(numBits, c);
    }

    private void sendMTFValues()
        throws IOException
    {
        byte[][] len = new byte[N_GROUPS][MAX_ALPHA_SIZE];

        int v, t, i, j, gs, ge, bt, bc, iter;
        int nSelectors = 0, alphaSize, minLen, maxLen, selCtr;
        int nGroups;

        alphaSize = nInUse + 2;
        for (t = 0; t < N_GROUPS; t++)
        {
            byte[] len_t = len[t];
            for (v = 0; v < alphaSize; v++)
            {
                len_t[v] = GREATER_ICOST;
            }
        }

        /* Decide how many coding tables to use */
        if (nMTF <= 0)
        {
            panic();
        }

        if (nMTF < 200)
        {
            nGroups = 2;
        }
        else if (nMTF < 600)
        {
            nGroups = 3;
        }
        else if (nMTF < 1200)
        {
            nGroups = 4;
        }
        else if (nMTF < 2400)
        {
            nGroups = 5;
        }
        else
        {
            nGroups = 6;
        }

        /* Generate an initial set of coding tables */
        {
            int nPart, remF, tFreq, aFreq;

            nPart = nGroups;
            remF = nMTF;
            gs = 0;
            while (nPart > 0)
            {
                tFreq = remF / nPart;
                ge = gs - 1;
                aFreq = 0;
                while (aFreq < tFreq && ge < alphaSize - 1)
                {
                    ge++;
                    aFreq += mtfFreq[ge];
                }

                if (ge > gs && nPart != nGroups && nPart != 1
                    && ((nGroups - nPart) % 2 == 1))
                {
                    aFreq -= mtfFreq[ge];
                    ge--;
                }

                byte[] len_np = len[nPart - 1];
                for (v = 0; v < alphaSize; v++)
                {
                    if (v >= gs && v <= ge)
                    {
                        len_np[v] = LESSER_ICOST;
                    }
                    else
                    {
                        len_np[v] = GREATER_ICOST;
                    }
                }

                nPart--;
                gs = ge + 1;
                remF -= aFreq;
            }
        }

        int[][] rfreq = new int[N_GROUPS][MAX_ALPHA_SIZE];
        int[] fave = new int[N_GROUPS];
        short[] cost = new short[N_GROUPS];
        byte[] len_0 = len[0];
        byte[] len_1 = len[1];
        byte[] len_2 = len[2];
        byte[] len_3 = len[3];
        byte[] len_4 = len[4];
        byte[] len_5 = len[5];

        /*
          Iterate up to N_ITERS times to improve the tables.
        */
        for (iter = 0; iter < N_ITERS; iter++)
        {
            for (t = 0; t < nGroups; t++)
            {
                fave[t] = 0;
                int[] rfreq_t = rfreq[t];
                for (v = 0; v < alphaSize; v++)
                {
                    rfreq_t[v] = 0;
                }
            }

            nSelectors = 0;
            gs = 0;
            while (gs < nMTF)
            {
                /* Set group start & end marks. */

                /*
                 * Calculate the cost of this group as coded by each of the coding tables.
                 */

                ge = Math.min(gs + G_SIZE - 1, nMTF - 1);

                if (nGroups == 6)
                {
                    short cost0 = 0, cost1 = 0, cost2 = 0, cost3 = 0, cost4 = 0, cost5 = 0;

                    for (i = gs; i <= ge; i++)
                    {
                        int icv = szptr[i];
                        cost0 += len_0[icv] & 0xFF;
                        cost1 += len_1[icv] & 0xFF;
                        cost2 += len_2[icv] & 0xFF;
                        cost3 += len_3[icv] & 0xFF;
                        cost4 += len_4[icv] & 0xFF;
                        cost5 += len_5[icv] & 0xFF;
                    }

                    cost[0] = cost0;
                    cost[1] = cost1;
                    cost[2] = cost2;
                    cost[3] = cost3;
                    cost[4] = cost4;
                    cost[5] = cost5;
                }
                else
                {
                    for (t = 0; t < nGroups; t++)
                    {
                        cost[t] = 0;
                    }

                    for (i = gs; i <= ge; i++)
                    {
                        int icv = szptr[i];
                        for (t = 0; t < nGroups; t++)
                        {
                            cost[t] += len[t][icv] & 0xFF;
                        }
                    }
                }

                /*
                  Find the coding table which is best for this group,
                  and record its identity in the selector table.
                */
                bc = 999999999;
                bt = -1;
                for (t = 0; t < nGroups; t++)
                {
                    if (cost[t] < bc)
                    {
                        bc = cost[t];
                        bt = t;
                    }
                }
                fave[bt]++;
                selector[nSelectors] = (char)bt;
                nSelectors++;

                /*
                  Increment the symbol frequencies for the selected table.
                */
                int[] rfreq_bt = rfreq[bt];
                for (i = gs; i <= ge; i++)
                {
                    rfreq_bt[szptr[i]]++;
                }

                gs = ge + 1;
            }

            /*
              Recompute the tables based on the accumulated frequencies.
            */
            for (t = 0; t < nGroups; t++)
            {
                hbMakeCodeLengths(len[t], rfreq[t], alphaSize, 20);
            }
        }

        rfreq = null;
        fave = null;
        cost = null;

        if (!(nGroups < 8))
        {
            panic();
        }
        if (!(nSelectors < 32768 && nSelectors <= (2 + (900000 / G_SIZE))))
        {
            panic();
        }


        /* Compute MTF values for the selectors. */
        {
            char[] pos = new char[N_GROUPS];
            char ll_i, tmp2, tmp;
            for (i = 0; i < nGroups; i++)
            {
                pos[i] = (char)i;
            }
            for (i = 0; i < nSelectors; i++)
            {
                ll_i = selector[i];
                j = 0;
                tmp = pos[j];
                while (ll_i != tmp)
                {
                    j++;
                    tmp2 = tmp;
                    tmp = pos[j];
                    pos[j] = tmp2;
                }
                pos[0] = tmp;
                selectorMtf[i] = (char)j;
            }
        }

        int[][] code = new int[N_GROUPS][MAX_ALPHA_SIZE];

        /* Assign actual codes for the tables. */
        for (t = 0; t < nGroups; t++)
        {
            minLen = 32;
            maxLen = 0;
            byte[] len_t = len[t];
            for (i = 0; i < alphaSize; i++)
            {
                int lti = len_t[i] & 0xFF;
                if (lti > maxLen)
                {
                    maxLen = lti;
                }
                if (lti < minLen)
                {
                    minLen = lti;
                }
            }
            if (maxLen > 20)
            {
                panic();
            }
            if (minLen < 1)
            {
                panic();
            }
            hbAssignCodes(code[t], len[t], minLen, maxLen, alphaSize);
        }

        /* Transmit the mapping table. */
        {
            boolean[] inUse16 = new boolean[16];
            for (i = 0; i < 16; i++)
            {
                inUse16[i] = false;
                int i16 = i * 16;
                for (j = 0; j < 16; j++)
                {
                    if (inUse[i16 + j])
                    {
                        inUse16[i] = true;
                        break;
                    }
                }
            }

            for (i = 0; i < 16; i++)
            {
                bsW(1, inUse16[i] ? 1 : 0);
            }

            for (i = 0; i < 16; i++)
            {
                if (inUse16[i])
                {
                    int i16 = i * 16;
                    for (j = 0; j < 16; j++)
                    {
                        bsW(1, inUse[i16 + j] ? 1 : 0);
                    }
                }
            }
        }

        /* Now the selectors. */
        bsW(3, nGroups);
        bsW(15, nSelectors);
        for (i = 0; i < nSelectors; i++)
        {
            int count = selectorMtf[i];
//            for (j = 0; j < count; j++)
//            {
//                bsW(1, 1);
//            }
//            bsW(1, 0);
            while (count >= 24)
            {
                bsW(24, 0xFFFFFF);
                count -= 24;
            }
            bsW(count + 1, (1 << (count + 1)) - 2);
        }

        /* Now the coding tables. */

        for (t = 0; t < nGroups; t++)
        {
            byte[] len_t = len[t];
            int curr = len_t[0] & 0xFF;
            bsW(5, curr);
            for (i = 0; i < alphaSize; i++)
            {
                int lti = len_t[i] & 0xFF;
                while (curr < lti)
                {
                    bsW(2, 2);
                    curr++; /* 10 */
                }
                while (curr > lti)
                {
                    bsW(2, 3);
                    curr--; /* 11 */
                }
                bsW(1, 0);
            }
        }

        /* And finally, the block data proper */
        selCtr = 0;
        gs = 0;
        while (gs < nMTF)
        {
            ge = Math.min(gs + G_SIZE - 1, nMTF - 1);

            int selector_selCtr = selector[selCtr];
            byte[] len_selCtr = len[selector_selCtr];
            int[] code_selCtr = code[selector_selCtr];

            for (i = gs; i <= ge; i++)
            {
                int sfmap_i = szptr[i];
                bsW(len_selCtr[sfmap_i] & 0xFF, code_selCtr[sfmap_i]);
            }

            gs = ge + 1;
            selCtr++;
        }
        if (!(selCtr == nSelectors))
        {
            panic();
        }
    }

    private void moveToFrontCodeAndSend()
        throws IOException
    {
        bsPutIntVS(24, origPtr);
        generateMTFValues();
        sendMTFValues();
    }

    private OutputStream bsStream;

    private void simpleSort(int lo, int hi, int d)
    {
        int i, j, h, bigN, hp;
        int v;

        bigN = hi - lo + 1;
        if (bigN < 2)
        {
            return;
        }

        hp = 0;
        while (incs[hp] < bigN)
        {
            hp++;
        }
        hp--;

        for (; hp >= 0; hp--)
        {
            h = incs[hp];

            i = lo + h;
            while (true)
            {
                /* copy 1 */
                if (i > hi)
                {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullGtU(zptr[j - h] + d, v + d))
                {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1))
                    {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                /* copy 2 */
                if (i > hi)
                {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullGtU(zptr[j - h] + d, v + d))
                {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1))
                    {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                /* copy 3 */
                if (i > hi)
                {
                    break;
                }
                v = zptr[i];
                j = i;
                while (fullGtU(zptr[j - h] + d, v + d))
                {
                    zptr[j] = zptr[j - h];
                    j = j - h;
                    if (j <= (lo + h - 1))
                    {
                        break;
                    }
                }
                zptr[j] = v;
                i++;

                if (workDone > workLimit && firstAttempt)
                {
                    return;
                }
            }
        }
    }

    private void vswap(int p1, int p2, int n)
    {
        while (--n >= 0)
        {
            int t1 = zptr[p1], t2 = zptr[p2];
            zptr[p1++] = t2;
            zptr[p2++] = t1;
        }
    }

    private int med3(int a, int b, int c)
    {
        return a > b
            ? (c < b ? b : c > a ? a : c)
            : (c < a ? a : c > b ? b : c);
    }

    private static class StackElem
    {
        int ll;
        int hh;
        int dd;
    }

    private static void pushStackElem(Vector stack, int stackCount, int ll, int hh, int dd)
    {
        StackElem stackElem;
        if (stackCount < stack.size())
        {
            stackElem = (StackElem)stack.elementAt(stackCount);
        }
        else
        {
            stackElem = new StackElem();
            stack.addElement(stackElem);
        }

        stackElem.ll = ll;
        stackElem.hh = hh;
        stackElem.dd = dd;
    }

    private void qSort3(int loSt, int hiSt, int dSt)
    {
        int unLo, unHi, ltLo, gtHi, n, m;

        Vector stack = new Vector();
        int stackCount = 0;
        StackElem stackElem;

        int lo = loSt;
        int hi = hiSt;
        int d = dSt;

        for (;;)
        {
            if (hi - lo < SMALL_THRESH || d > DEPTH_THRESH)
            {
                simpleSort(lo, hi, d);
                if (stackCount < 1 || (workDone > workLimit && firstAttempt))
                {
                    return;
                }
                stackElem = (StackElem)stack.elementAt(--stackCount);
                lo = stackElem.ll;
                hi = stackElem.hh;
                d = stackElem.dd;
                continue;
            }

            int d1 = d + 1;
            int med = med3(
                blockBytes[zptr[lo] + d1] & 0xFF,
                blockBytes[zptr[hi] + d1] & 0xFF,
                blockBytes[zptr[(lo + hi) >>> 1] + d1] & 0xFF);

            unLo = ltLo = lo;
            unHi = gtHi = hi;

            while (true)
            {
                while (unLo <= unHi)
                {
                    int zUnLo = zptr[unLo];
                    n = (blockBytes[zUnLo + d1] & 0xFF) - med;
                    if (n > 0)
                    {
                        break;
                    }
                    if (n == 0)
                    {
                        zptr[unLo] = zptr[ltLo];
                        zptr[ltLo++] = zUnLo;
                    }
                    unLo++;
                }
                while (unLo <= unHi)
                {
                    int zUnHi = zptr[unHi];
                    n = (blockBytes[zUnHi + d1] & 0xFF) - med;
                    if (n < 0)
                    {
                        break;
                    }
                    if (n == 0)
                    {
                        zptr[unHi] = zptr[gtHi];
                        zptr[gtHi--] = zUnHi;
                    }
                    unHi--;
                }
                if (unLo > unHi)
                {
                    break;
                }
                int temp = zptr[unLo];
                zptr[unLo++] = zptr[unHi];
                zptr[unHi--] = temp;
            }

            if (gtHi < ltLo)
            {
                d = d1;
                continue;
            }

            n = Math.min(ltLo - lo, unLo - ltLo);
            vswap(lo, unLo - n, n);

            m = Math.min(hi - gtHi, gtHi - unHi);
            vswap(unLo, hi - m + 1, m);

            n = lo + (unLo - ltLo);
            m = hi - (gtHi - unHi);

            pushStackElem(stack, stackCount++, lo, n - 1, d);
            pushStackElem(stack, stackCount++, n, m, d1);

            lo = m + 1;
        }
    }

    private void mainSort()
    {
        int i, j, ss, sb;
        int[] runningOrder = new int[256];
        int[] copy = new int[256];
        boolean[] bigDone = new boolean[256];
        int c1, c2;

        /*
          In the various block-sized structures, live data runs
          from 0 to last+NUM_OVERSHOOT_BYTES inclusive.  First,
          set up the overshoot area for block.
        */
        for (i = 0; i < NUM_OVERSHOOT_BYTES; i++)
        {
            blockBytes[count + i + 1] = blockBytes[(i % count) + 1];
        }
        for (i = 0; i <= count + NUM_OVERSHOOT_BYTES; i++)
        {
            quadrantShorts[i] = 0;
        }

        blockBytes[0] = blockBytes[count];

        if (count <= 4000)
        {
            /*
              Use simpleSort(), since the full sorting mechanism
              has quite a large constant overhead.
            */
            for (i = 0; i < count; i++)
            {
                zptr[i] = i;
            }
            firstAttempt = false;
            workDone = workLimit = 0;
            simpleSort(0, count - 1, 0);
        }
        else
        {
            for (i = 0; i <= 255; i++)
            {
                bigDone[i] = false;
            }

            for (i = 0; i <= 65536; i++)
            {
                ftab[i] = 0;
            }

            c1 = blockBytes[0] & 0xFF;
            for (i = 0; i < count; i++)
            {
                c2 = blockBytes[i + 1] & 0xFF;
                ftab[(c1 << 8) + c2]++;
                c1 = c2;
            }

            for (i = 1; i <= 65536; i++)
            {
                ftab[i] += ftab[i - 1];
            }

            c1 = blockBytes[1] & 0xFF;
            for (i = 0; i < (count - 1); i++)
            {
                c2 = blockBytes[i + 2] & 0xFF;
                j = (c1 << 8) + c2;
                c1 = c2;
                ftab[j]--;
                zptr[ftab[j]] = i;
            }

            j = ((blockBytes[count] & 0xFF) << 8) + (blockBytes[1] & 0xFF);
            ftab[j]--;
            zptr[ftab[j]] = count - 1;

            /*
              Now ftab contains the first loc of every small bucket.
              Calculate the running order, from smallest to largest
              big bucket.
            */

            for (i = 0; i <= 255; i++)
            {
                runningOrder[i] = i;
            }

            {
                int vv;
                int h = 1;
                do
                {
                    h = 3 * h + 1;
                }
                while (h <= 256);
                do
                {
                    h = h / 3;
                    for (i = h; i <= 255; i++)
                    {
                        vv = runningOrder[i];
                        j = i;
                        while ((ftab[((runningOrder[j - h]) + 1) << 8]
                            - ftab[(runningOrder[j - h]) << 8]) >
                            (ftab[((vv) + 1) << 8] - ftab[(vv) << 8]))
                        {
                            runningOrder[j] = runningOrder[j - h];
                            j = j - h;
                            if (j <= (h - 1))
                            {
                                break;
                            }
                        }
                        runningOrder[j] = vv;
                    }
                }
                while (h != 1);
            }

            /*
              The main sorting loop.
            */
            for (i = 0; i <= 255; i++)
            {
                /*
                  Process big buckets, starting with the least full.
                */
                ss = runningOrder[i];

                /*
                  Complete the big bucket [ss] by quicksorting
                  any unsorted small buckets [ss, j].  Hopefully
                  previous pointer-scanning phases have already
                  completed many of the small buckets [ss, j], so
                  we don't have to sort them at all.
                */
                for (j = 0; j <= 255; j++)
                {
                    sb = (ss << 8) + j;
                    if (!((ftab[sb] & SETMASK) == SETMASK))
                    {
                        int lo = ftab[sb] & CLEARMASK;
                        int hi = (ftab[sb + 1] & CLEARMASK) - 1;
                        if (hi > lo)
                        {
                            qSort3(lo, hi, 2);
                            if (workDone > workLimit && firstAttempt)
                            {
                                return;
                            }
                        }
                        ftab[sb] |= SETMASK;
                    }
                }

                /*
                  The ss big bucket is now done.  Record this fact,
                  and update the quadrant descriptors.  Remember to
                  update quadrants in the overshoot area too, if
                  necessary.  The "if (i < 255)" test merely skips
                  this updating for the last bucket processed, since
                  updating for the last bucket is pointless.
                */
                bigDone[ss] = true;

                if (i < 255)
                {
                    int bbStart = ftab[ss << 8] & CLEARMASK;
                    int bbSize = (ftab[(ss + 1) << 8] & CLEARMASK) - bbStart;
                    int shifts = 0;

                    while ((bbSize >> shifts) > 65534)
                    {
                        shifts++;
                    }

                    for (j = 0; j < bbSize; j++)
                    {
                        int a2update = zptr[bbStart + j] + 1;
                        short qVal = (short)(j >> shifts);
                        quadrantShorts[a2update] = qVal;
                        if (a2update <= NUM_OVERSHOOT_BYTES)
                        {
                            quadrantShorts[a2update + count] = qVal;
                        }
                    }

                    if (!(((bbSize - 1) >> shifts) <= 65535))
                    {
                        panic();
                    }
                }

                /*
                  Now scan this big bucket so as to synthesise the
                  sorted order for small buckets [t, ss] for all t != ss.
                */
                for (j = 0; j <= 255; j++)
                {
                    copy[j] = ftab[(j << 8) + ss] & CLEARMASK;
                }

                for (j = ftab[ss << 8] & CLEARMASK;
                     j < (ftab[(ss + 1) << 8] & CLEARMASK); j++)
                {
                    c1 = blockBytes[zptr[j]] & 0xFF;
                    if (!bigDone[c1])
                    {
                        zptr[copy[c1]] = (zptr[j] == 0 ? count : zptr[j]) - 1;
                        copy[c1]++;
                    }
                }

                for (j = 0; j <= 255; j++)
                {
                    ftab[(j << 8) + ss] |= SETMASK;
                }
            }
        }
    }

    private void randomiseBlock()
    {
        int i;
        int rNToGo = 0;
        int rTPos = 0;
        for (i = 0; i < 256; i++)
        {
            inUse[i] = false;
        }

        for (i = 0; i < count; i++)
        {
            if (rNToGo == 0)
            {
                rNToGo = (char)rNums[rTPos];
                rTPos++;
                if (rTPos == 512)
                {
                    rTPos = 0;
                }
            }
            rNToGo--;
            blockBytes[i + 1] ^= (rNToGo == 1) ? 1 : 0;

            inUse[blockBytes[i + 1] & 0xFF] = true;
        }
    }

    private void doReversibleTransformation()
    {
        workLimit = workFactor * (count - 1);
        workDone = 0;
        blockRandomised = false;
        firstAttempt = true;

        mainSort();

        if (workDone > workLimit && firstAttempt)
        {
            randomiseBlock();
            workLimit = workDone = 0;
            blockRandomised = true;
            firstAttempt = false;
            mainSort();
        }

        origPtr = -1;
        for (int i = 0; i < count; i++)
        {
            if (zptr[i] == 0)
            {
                origPtr = i;
                break;
            }
        }

        if (origPtr == -1)
        {
            panic();
        }
    }

    private boolean fullGtU(int i1, int i2)
    {
        int c1, c2;

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        c1 = blockBytes[++i1] & 0xFF;
        c2 = blockBytes[++i2] & 0xFF;
        if (c1 != c2)
        {
            return c1 > c2;
        }

        int k = count;
        int s1, s2;

        do
        {
            c1 = blockBytes[++i1] & 0xFF;
            c2 = blockBytes[++i2] & 0xFF;
            if (c1 != c2)
            {
                return c1 > c2;
            }
            s1 = quadrantShorts[i1] & 0xFFFF;
            s2 = quadrantShorts[i2] & 0xFFFF;
            if (s1 != s2)
            {
                return s1 > s2;
            }

            c1 = blockBytes[++i1] & 0xFF;
            c2 = blockBytes[++i2] & 0xFF;
            if (c1 != c2)
            {
                return c1 > c2;
            }
            s1 = quadrantShorts[i1] & 0xFFFF;
            s2 = quadrantShorts[i2] & 0xFFFF;
            if (s1 != s2)
            {
                return s1 > s2;
            }

            c1 = blockBytes[++i1] & 0xFF;
            c2 = blockBytes[++i2] & 0xFF;
            if (c1 != c2)
            {
                return c1 > c2;
            }
            s1 = quadrantShorts[i1] & 0xFFFF;
            s2 = quadrantShorts[i2] & 0xFFFF;
            if (s1 != s2)
            {
                return s1 > s2;
            }

            c1 = blockBytes[++i1] & 0xFF;
            c2 = blockBytes[++i2] & 0xFF;
            if (c1 != c2)
            {
                return c1 > c2;
            }
            s1 = quadrantShorts[i1] & 0xFFFF;
            s2 = quadrantShorts[i2] & 0xFFFF;
            if (s1 != s2)
            {
                return s1 > s2;
            }

            if (i1 >= count)
            {
                i1 -= count;
            }
            if (i2 >= count)
            {
                i2 -= count;
            }

            k -= 4;
            workDone++;
        }
        while (k >= 0);

        return false;
    }

    /*
      Knuth's increments seem to work better
      than Incerpi-Sedgewick here.  Possibly
      because the number of elems to sort is
      usually small, typically <= 20.
    */
    private int[] incs = {1, 4, 13, 40, 121, 364, 1093, 3280,
        9841, 29524, 88573, 265720,
        797161, 2391484};

    private void allocateCompressStructures()
    {
        int n = baseBlockSize * blockSize100k;
        blockBytes = new byte[(n + 1 + NUM_OVERSHOOT_BYTES)];
        quadrantShorts = new short[(n + 1 + NUM_OVERSHOOT_BYTES)];
        zptr = new int[n];
        ftab = new int[65537];

        /*
          The back end needs a place to store the MTF values
          whilst it calculates the coding tables.  We could
          put them in the zptr array.  However, these values
          will fit in a short, so we overlay szptr at the
          start of zptr, in the hope of reducing the number
          of cache misses induced by the multiple traversals
          of the MTF values when calculating coding tables.
          Seems to improve compression speed by about 1%.
        */
        // NOTE: We can't "overlay" in Java, so we just share zptr
        szptr = zptr;
    }

    private void generateMTFValues()
    {
        char[] yy = new char[256];
        int i, j;
        char tmp;
        char tmp2;
        int zPend;
        int wr;
        int EOB;

        makeMaps();
        EOB = nInUse + 1;

        for (i = 0; i <= EOB; i++)
        {
            mtfFreq[i] = 0;
        }

        wr = 0;
        zPend = 0;
        for (i = 0; i < nInUse; i++)
        {
            yy[i] = (char)i;
        }

        for (i = 0; i < count; i++)
        {
            char ll_i;

            ll_i = unseqToSeq[blockBytes[zptr[i]] & 0xFF];

            j = 0;
            tmp = yy[j];
            while (ll_i != tmp)
            {
                j++;
                tmp2 = tmp;
                tmp = yy[j];
                yy[j] = tmp2;
            }
            yy[0] = tmp;

            if (j == 0)
            {
                zPend++;
            }
            else
            {
                if (zPend > 0)
                {
                    zPend--;
                    while (true)
                    {
                        switch (zPend % 2)
                        {
                        case 0:
                            szptr[wr++] = RUNA;
                            mtfFreq[RUNA]++;
                            break;
                        case 1:
                            szptr[wr++] = RUNB;
                            mtfFreq[RUNB]++;
                            break;
                        }
                        if (zPend < 2)
                        {
                            break;
                        }
                        zPend = (zPend - 2) / 2;
                    }
                    zPend = 0;
                }
                szptr[wr++] = j + 1;
                mtfFreq[j + 1]++;
            }
        }

        if (zPend > 0)
        {
            zPend--;
            while (true)
            {
                switch (zPend % 2)
                {
                case 0:
                    szptr[wr++] = RUNA;
                    mtfFreq[RUNA]++;
                    break;
                case 1:
                    szptr[wr++] = RUNB;
                    mtfFreq[RUNB]++;
                    break;
                }
                if (zPend < 2)
                {
                    break;
                }
                zPend = (zPend - 2) / 2;
            }
        }

        szptr[wr++] = EOB;
        mtfFreq[EOB]++;

        nMTF = wr;
    }
}
