package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

public abstract class SerpentEngineBase
    implements BlockCipher
{
    protected static final int BLOCK_SIZE = 16;

    static final int ROUNDS = 32;
    static final int PHI = 0x9E3779B9;       // (sqrt(5) - 1) * 2**31

    protected boolean encrypting;
    protected int[] wKey;

    protected int X0, X1, X2, X3;    // registers

    SerpentEngineBase()
    {

    }

    /**
     * initialise a Serpent cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params     the parameters required to set up the cipher.
     * @throws IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean encrypting,
        CipherParameters params)
    {
        if (params instanceof KeyParameter)
        {
            this.encrypting = encrypting;
            this.wKey = makeWorkingKey(((KeyParameter)params).getKey());
            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to " + getAlgorithmName() + " init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "Serpent";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    /**
     * Process one block of input from the array in and write it to
     * the out array.
     *
     * @param in     the array containing the input data.
     * @param inOff  offset into the in array the data starts at.
     * @param out    the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @return the number of bytes processed and produced.
     * @throws DataLengthException if there isn't enough data in in, or
     * space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    public final int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (wKey == null)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (encrypting)
        {
            encryptBlock(in, inOff, out, outOff);
        }
        else
        {
            decryptBlock(in, inOff, out, outOff);
        }

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    protected static int rotateLeft(
        int     x,
        int     bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    protected static int rotateRight(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }

    /**
     * The sboxes below are based on the work of Brian Gladman and
     * Sam Simpson, whose original notice appears below.
     * <p>
     * For further details see:
     *      http://fp.gladman.plus.com/cryptography_technology/serpent/
     */

    /* Partially optimised Serpent S Box boolean functions derived  */
    /* using a recursive descent analyser but without a full search */
    /* of all subtrees. This set of S boxes is the result of work    */
    /* by Sam Simpson and Brian Gladman using the spare time on a    */
    /* cluster of high capacity servers to search for S boxes with    */
    /* this customised search engine. There are now an average of    */
    /* 15.375 terms    per S box.                                        */
    /*                                                              */
    /* Copyright:   Dr B. R Gladman (gladman@seven77.demon.co.uk)   */
    /*                and Sam Simpson (s.simpson@mia.co.uk)            */
    /*              17th December 1998                                */
    /*                                                              */
    /* We hereby give permission for information in this file to be */
    /* used freely subject only to acknowledgement of its origin.    */

    /**
     * S0 - { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 } - 15 terms.
     */
    protected final void sb0(int a, int b, int c, int d)
    {
        int    t1 = a ^ d;
        int    t3 = c ^ t1;
        int    t4 = b ^ t3;
        X3 = (a & d) ^ t4;
        int    t7 = a ^ (b & t1);
        X2 = t4 ^ (c | t7);
        int    t12 = X3 & (t3 ^ t7);
        X1 = (~t3) ^ t12;
        X0 = t12 ^ (~t7);
    }

    /**
     * InvSO - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
     */
    protected final void ib0(int a, int b, int c, int d)
    {
        int    t1 = ~a;
        int    t2 = a ^ b;
        int    t4 = d ^ (t1 | t2);
        int    t5 = c ^ t4;
        X2 = t2 ^ t5;
        int    t8 = t1 ^ (d & t2);
        X1 = t4 ^ (X2 & t8);
        X3 = (a & t4) ^ (t5 | X1);
        X0 = X3 ^ (t5 ^ t8);
    }

    /**
     * S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms.
     */
    protected final void sb1(int a, int b, int c, int d)
    {
        int    t2 = b ^ (~a);
        int    t5 = c ^ (a | t2);
        X2 = d ^ t5;
        int    t7 = b ^ (d | t2);
        int    t8 = t2 ^ X2;
        X3 = t8 ^ (t5 & t7);
        int    t11 = t5 ^ t7;
        X1 = X3 ^ t11;
        X0 = t5 ^ (t8 & t11);
    }

    /**
     * InvS1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps.
     */
    protected final void ib1(int a, int b, int c, int d)
    {
        int    t1 = b ^ d;
        int    t3 = a ^ (b & t1);
        int    t4 = t1 ^ t3;
        X3 = c ^ t4;
        int    t7 = b ^ (t1 & t3);
        int    t8 = X3 | t7;
        X1 = t3 ^ t8;
        int    t10 = ~X1;
        int    t11 = X3 ^ t7;
        X0 = t10 ^ t11;
        X2 = t4 ^ (t10 | t11);
    }

    /**
     * S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms.
     */
    protected final void sb2(int a, int b, int c, int d)
    {
        int    t1 = ~a;
        int    t2 = b ^ d;
        int    t3 = c & t1;
        X0 = t2 ^ t3;
        int    t5 = c ^ t1;
        int    t6 = c ^ X0;
        int    t7 = b & t6;
        X3 = t5 ^ t7;
        X2 = a ^ ((d | t7) & (X0 | t5));
        X1 = (t2 ^ X3) ^ (X2 ^ (d | t1));
    }

    /**
     * InvS2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps.
     */
    protected final void ib2(int a, int b, int c, int d)
    {
        int    t1 = b ^ d;
        int    t2 = ~t1;
        int    t3 = a ^ c;
        int    t4 = c ^ t1;
        int    t5 = b & t4;
        X0 = t3 ^ t5;
        int    t7 = a | t2;
        int    t8 = d ^ t7;
        int    t9 = t3 | t8;
        X3 = t1 ^ t9;
        int    t11 = ~t4;
        int    t12 = X0 | X3;
        X1 = t11 ^ t12;
        X2 = (d & t11) ^ (t3 ^ t12);
    }

    /**
     * S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms.
     */
    protected final void sb3(int a, int b, int c, int d)
    {
        int    t1 = a ^ b;
        int    t2 = a & c;
        int    t3 = a | d;
        int    t4 = c ^ d;
        int    t5 = t1 & t3;
        int    t6 = t2 | t5;
        X2 = t4 ^ t6;
        int    t8 = b ^ t3;
        int    t9 = t6 ^ t8;
        int    t10 = t4 & t9;
        X0 = t1 ^ t10;
        int    t12 = X2 & X0;
        X1 = t9 ^ t12;
        X3 = (b | d) ^ (t4 ^ t12);
    }

    /**
     * InvS3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
     */
    protected final void ib3(int a, int b, int c, int d)
    {
        int    t1 = a | b;
        int    t2 = b ^ c;
        int    t3 = b & t2;
        int    t4 = a ^ t3;
        int    t5 = c ^ t4;
        int    t6 = d | t4;
        X0 = t2 ^ t6;
        int    t8 = t2 | t6;
        int    t9 = d ^ t8;
        X2 = t5 ^ t9;
        int    t11 = t1 ^ t9;
        int    t12 = X0 & t11;
        X3 = t4 ^ t12;
        X1 = X3 ^ (X0 ^ t11);
    }

    /**
     * S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms.
     */
    protected final void sb4(int a, int b, int c, int d)
    {
        int    t1 = a ^ d;
        int    t2 = d & t1;
        int    t3 = c ^ t2;
        int    t4 = b | t3;
        X3 = t1 ^ t4;
        int    t6 = ~b;
        int    t7 = t1 | t6;
        X0 = t3 ^ t7;
        int    t9 = a & X0;
        int    t10 = t1 ^ t6;
        int    t11 = t4 & t10;
        X2 = t9 ^ t11;
        X1 = (a ^ t3) ^ (t10 & X2);
    }

    /**
     * InvS4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms.
     */
    protected final void ib4(int a, int b, int c, int d)
    {
        int    t1 = c | d;
        int    t2 = a & t1;
        int    t3 = b ^ t2;
        int    t4 = a & t3;
        int    t5 = c ^ t4;
        X1 = d ^ t5;
        int    t7 = ~a;
        int    t8 = t5 & X1;
        X3 = t3 ^ t8;
        int    t10 = X1 | t7;
        int    t11 = d ^ t10;
        X0 = X3 ^ t11;
        X2 = (t3 & t11) ^ (X1 ^ t7);
    }

    /**
     * S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms.
     */
    protected final void sb5(int a, int b, int c, int d)
    {
        int    t1 = ~a;
        int    t2 = a ^ b;
        int    t3 = a ^ d;
        int    t4 = c ^ t1;
        int    t5 = t2 | t3;
        X0 = t4 ^ t5;
        int    t7 = d & X0;
        int    t8 = t2 ^ X0;
        X1 = t7 ^ t8;
        int    t10 = t1 | X0;
        int    t11 = t2 | t7;
        int    t12 = t3 ^ t10;
        X2 = t11 ^ t12;
        X3 = (b ^ t7) ^ (X1 & t12);
    }

    /**
     * InvS5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms.
     */
    protected final void ib5(int a, int b, int c, int d)
    {
        int    t1 = ~c;
        int    t2 = b & t1;
        int    t3 = d ^ t2;
        int    t4 = a & t3;
        int    t5 = b ^ t1;
        X3 = t4 ^ t5;
        int    t7 = b | X3;
        int    t8 = a & t7;
        X1 = t3 ^ t8;
        int    t10 = a | d;
        int    t11 = t1 ^ t7;
        X0 = t10 ^ t11;
        X2 = (b & t10) ^ (t4 | (a ^ c));
    }

    /**
     * S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms.
     */
    protected final void sb6(int a, int b, int c, int d)
    {
        int    t1 = ~a;
        int    t2 = a ^ d;
        int    t3 = b ^ t2;
        int    t4 = t1 | t2;
        int    t5 = c ^ t4;
        X1 = b ^ t5;
        int    t7 = t2 | X1;
        int    t8 = d ^ t7;
        int    t9 = t5 & t8;
        X2 = t3 ^ t9;
        int    t11 = t5 ^ t8;
        X0 = X2 ^ t11;
        X3 = (~t5) ^ (t3 & t11);
    }

    /**
     * InvS6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms.
     */
    protected final void ib6(int a, int b, int c, int d)
    {
        int    t1 = ~a;
        int    t2 = a ^ b;
        int    t3 = c ^ t2;
        int    t4 = c | t1;
        int    t5 = d ^ t4;
        X1 = t3 ^ t5;
        int    t7 = t3 & t5;
        int    t8 = t2 ^ t7;
        int    t9 = b | t8;
        X3 = t5 ^ t9;
        int    t11 = b | X3;
        X0 = t8 ^ t11;
        X2 = (d & t1) ^ (t3 ^ t11);
    }

    /**
     * S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms.
     */
    protected final void sb7(int a, int b, int c, int d)
    {
        int    t1 = b ^ c;
        int    t2 = c & t1;
        int    t3 = d ^ t2;
        int    t4 = a ^ t3;
        int    t5 = d | t1;
        int    t6 = t4 & t5;
        X1 = b ^ t6;
        int    t8 = t3 | X1;
        int    t9 = a & t4;
        X3 = t1 ^ t9;
        int    t11 = t4 ^ t8;
        int    t12 = X3 & t11;
        X2 = t3 ^ t12;
        X0 = (~t11) ^ (X3 & X2);
    }

    /**
     * InvS7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms.
     */
    protected final void ib7(int a, int b, int c, int d)
    {
        int t3 = c | (a & b);
        int    t4 = d & (a | b);
        X3 = t3 ^ t4;
        int    t6 = ~d;
        int    t7 = b ^ t4;
        int    t9 = t7 | (X3 ^ t6);
        X1 = a ^ t9;
        X0 = (c ^ t7) ^ (d | X1);
        X2 = (t3 ^ X1) ^ (X0 ^ (a & X3));
    }

    /**
     * Apply the linear transformation to the register set.
     */
    protected final void LT()
    {
        int x0  = rotateLeft(X0, 13);
        int x2  = rotateLeft(X2, 3);
        int x1  = X1 ^ x0 ^ x2 ;
        int x3  = X3 ^ x2 ^ x0 << 3;

        X1  = rotateLeft(x1, 1);
        X3  = rotateLeft(x3, 7);
        X0  = rotateLeft(x0 ^ X1 ^ X3, 5);
        X2  = rotateLeft(x2 ^ X3 ^ (X1 << 7), 22);
    }

    /**
     * Apply the inverse of the linear transformation to the register set.
     */
    protected final void inverseLT()
    {
        int x2 = rotateRight(X2, 22) ^ X3 ^ (X1 << 7);
        int x0 = rotateRight(X0, 5) ^ X1 ^ X3;
        int x3 = rotateRight(X3, 7);
        int x1 = rotateRight(X1, 1);
        X3 = x3 ^ x2 ^ x0 << 3;
        X1 = x1 ^ x0 ^ x2;
        X2 = rotateRight(x2, 3);
        X0 = rotateRight(x0, 13);
    }

    protected abstract int[] makeWorkingKey(byte[] key);

    protected abstract void encryptBlock(byte[] input, int inOff, byte[] output, int outOff);

    protected abstract void decryptBlock(byte[] input, int inOff, byte[] output, int outOff);
}
