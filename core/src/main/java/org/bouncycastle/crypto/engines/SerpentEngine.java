package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Pack;

/**
 * Serpent is a 128-bit 32-round block cipher with variable key lengths,
 * including 128, 192 and 256 bit keys conjectured to be at least as
 * secure as three-key triple-DES.
 * <p>
 * Serpent was designed by Ross Anderson, Eli Biham and Lars Knudsen as a
 * candidate algorithm for the NIST AES Quest.
 * <p>
 * For full details see <a href="https://www.cl.cam.ac.uk/~rja14/serpent.html">The Serpent home page</a>
 */
public final class SerpentEngine
    extends SerpentEngineBase
{
    /**
     * Expand a user-supplied key material into a session key.
     *
     * @param key  The user-key bytes (multiples of 4) to use.
     * @exception IllegalArgumentException
     */
    protected int[] makeWorkingKey(
        byte[] key)
    throws  IllegalArgumentException
    {
        //
        // pad key to 256 bits
        //
        int[]   kPad = new int[16];
        int     off = 0;
        int     length = 0;

        for (off = 0; (off + 4) < key.length; off += 4)
        {
            kPad[length++] = Pack.littleEndianToInt(key, off);
        }

        if (off % 4 == 0)
        {
            kPad[length++] = Pack.littleEndianToInt(key, off);
            if (length < 8)
            {
                kPad[length] = 1;
            }
        }
        else
        {
            throw new IllegalArgumentException("key must be a multiple of 4 bytes");
        }

        //
        // expand the padded key up to 33 x 128 bits of key material
        //
        int     amount = (ROUNDS + 1) * 4;
        int[]   w = new int[amount];

        //
        // compute w0 to w7 from w-8 to w-1
        //
        for (int i = 8; i < 16; i++)
        {
            kPad[i] = rotateLeft(kPad[i - 8] ^ kPad[i - 5] ^ kPad[i - 3] ^ kPad[i - 1] ^ PHI ^ (i - 8), 11);
        }

        System.arraycopy(kPad, 8, w, 0, 8);

        //
        // compute w8 to w136
        //
        for (int i = 8; i < amount; i++)
        {
            w[i] = rotateLeft(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i, 11);
        }

        //
        // create the working keys by processing w with the Sbox and IP
        //
        int[] X = new int[4];
        
        sb3(X, w[0], w[1], w[2], w[3]);
        w[0] = X[0]; w[1] = X[1]; w[2] = X[2]; w[3] = X[3]; 
        sb2(X, w[4], w[5], w[6], w[7]);
        w[4] = X[0]; w[5] = X[1]; w[6] = X[2]; w[7] = X[3]; 
        sb1(X, w[8], w[9], w[10], w[11]);
        w[8] = X[0]; w[9] = X[1]; w[10] = X[2]; w[11] = X[3]; 
        sb0(X, w[12], w[13], w[14], w[15]);
        w[12] = X[0]; w[13] = X[1]; w[14] = X[2]; w[15] = X[3]; 
        sb7(X, w[16], w[17], w[18], w[19]);
        w[16] = X[0]; w[17] = X[1]; w[18] = X[2]; w[19] = X[3]; 
        sb6(X, w[20], w[21], w[22], w[23]);
        w[20] = X[0]; w[21] = X[1]; w[22] = X[2]; w[23] = X[3]; 
        sb5(X, w[24], w[25], w[26], w[27]);
        w[24] = X[0]; w[25] = X[1]; w[26] = X[2]; w[27] = X[3]; 
        sb4(X, w[28], w[29], w[30], w[31]);
        w[28] = X[0]; w[29] = X[1]; w[30] = X[2]; w[31] = X[3]; 
        sb3(X, w[32], w[33], w[34], w[35]);
        w[32] = X[0]; w[33] = X[1]; w[34] = X[2]; w[35] = X[3]; 
        sb2(X, w[36], w[37], w[38], w[39]);
        w[36] = X[0]; w[37] = X[1]; w[38] = X[2]; w[39] = X[3]; 
        sb1(X, w[40], w[41], w[42], w[43]);
        w[40] = X[0]; w[41] = X[1]; w[42] = X[2]; w[43] = X[3]; 
        sb0(X, w[44], w[45], w[46], w[47]);
        w[44] = X[0]; w[45] = X[1]; w[46] = X[2]; w[47] = X[3]; 
        sb7(X, w[48], w[49], w[50], w[51]);
        w[48] = X[0]; w[49] = X[1]; w[50] = X[2]; w[51] = X[3]; 
        sb6(X, w[52], w[53], w[54], w[55]);
        w[52] = X[0]; w[53] = X[1]; w[54] = X[2]; w[55] = X[3]; 
        sb5(X, w[56], w[57], w[58], w[59]);
        w[56] = X[0]; w[57] = X[1]; w[58] = X[2]; w[59] = X[3]; 
        sb4(X, w[60], w[61], w[62], w[63]);
        w[60] = X[0]; w[61] = X[1]; w[62] = X[2]; w[63] = X[3]; 
        sb3(X, w[64], w[65], w[66], w[67]);
        w[64] = X[0]; w[65] = X[1]; w[66] = X[2]; w[67] = X[3]; 
        sb2(X, w[68], w[69], w[70], w[71]);
        w[68] = X[0]; w[69] = X[1]; w[70] = X[2]; w[71] = X[3]; 
        sb1(X, w[72], w[73], w[74], w[75]);
        w[72] = X[0]; w[73] = X[1]; w[74] = X[2]; w[75] = X[3]; 
        sb0(X, w[76], w[77], w[78], w[79]);
        w[76] = X[0]; w[77] = X[1]; w[78] = X[2]; w[79] = X[3]; 
        sb7(X, w[80], w[81], w[82], w[83]);
        w[80] = X[0]; w[81] = X[1]; w[82] = X[2]; w[83] = X[3]; 
        sb6(X, w[84], w[85], w[86], w[87]);
        w[84] = X[0]; w[85] = X[1]; w[86] = X[2]; w[87] = X[3]; 
        sb5(X, w[88], w[89], w[90], w[91]);
        w[88] = X[0]; w[89] = X[1]; w[90] = X[2]; w[91] = X[3]; 
        sb4(X, w[92], w[93], w[94], w[95]);
        w[92] = X[0]; w[93] = X[1]; w[94] = X[2]; w[95] = X[3]; 
        sb3(X, w[96], w[97], w[98], w[99]);
        w[96] = X[0]; w[97] = X[1]; w[98] = X[2]; w[99] = X[3]; 
        sb2(X, w[100], w[101], w[102], w[103]);
        w[100] = X[0]; w[101] = X[1]; w[102] = X[2]; w[103] = X[3]; 
        sb1(X, w[104], w[105], w[106], w[107]);
        w[104] = X[0]; w[105] = X[1]; w[106] = X[2]; w[107] = X[3]; 
        sb0(X, w[108], w[109], w[110], w[111]);
        w[108] = X[0]; w[109] = X[1]; w[110] = X[2]; w[111] = X[3]; 
        sb7(X, w[112], w[113], w[114], w[115]);
        w[112] = X[0]; w[113] = X[1]; w[114] = X[2]; w[115] = X[3]; 
        sb6(X, w[116], w[117], w[118], w[119]);
        w[116] = X[0]; w[117] = X[1]; w[118] = X[2]; w[119] = X[3]; 
        sb5(X, w[120], w[121], w[122], w[123]);
        w[120] = X[0]; w[121] = X[1]; w[122] = X[2]; w[123] = X[3]; 
        sb4(X, w[124], w[125], w[126], w[127]);
        w[124] = X[0]; w[125] = X[1]; w[126] = X[2]; w[127] = X[3]; 
        sb3(X, w[128], w[129], w[130], w[131]);
        w[128] = X[0]; w[129] = X[1]; w[130] = X[2]; w[131] = X[3]; 

        return w;
    }

    /**
     * Encrypt one block of plaintext.
     *
     * @param input the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param output the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     */
    protected void encryptBlock(
        byte[]  input,
        int     inOff,
        byte[]  output,
        int     outOff)
    {    
        int[] X = new int[4];
        
        X[0] = Pack.littleEndianToInt(input, inOff);
        X[1] = Pack.littleEndianToInt(input, inOff + 4);
        X[2] = Pack.littleEndianToInt(input, inOff + 8);
        X[3] = Pack.littleEndianToInt(input, inOff + 12);

        sb0(X, wKey[0] ^ X[0], wKey[1] ^ X[1], wKey[2] ^ X[2], wKey[3] ^ X[3]); LT(X);
        sb1(X, wKey[4] ^ X[0], wKey[5] ^ X[1], wKey[6] ^ X[2], wKey[7] ^ X[3]); LT(X);
        sb2(X, wKey[8] ^ X[0], wKey[9] ^ X[1], wKey[10] ^ X[2], wKey[11] ^ X[3]); LT(X);
        sb3(X, wKey[12] ^ X[0], wKey[13] ^ X[1], wKey[14] ^ X[2], wKey[15] ^ X[3]); LT(X);
        sb4(X, wKey[16] ^ X[0], wKey[17] ^ X[1], wKey[18] ^ X[2], wKey[19] ^ X[3]); LT(X);
        sb5(X, wKey[20] ^ X[0], wKey[21] ^ X[1], wKey[22] ^ X[2], wKey[23] ^ X[3]); LT(X);
        sb6(X, wKey[24] ^ X[0], wKey[25] ^ X[1], wKey[26] ^ X[2], wKey[27] ^ X[3]); LT(X);
        sb7(X, wKey[28] ^ X[0], wKey[29] ^ X[1], wKey[30] ^ X[2], wKey[31] ^ X[3]); LT(X);
        sb0(X, wKey[32] ^ X[0], wKey[33] ^ X[1], wKey[34] ^ X[2], wKey[35] ^ X[3]); LT(X);
        sb1(X, wKey[36] ^ X[0], wKey[37] ^ X[1], wKey[38] ^ X[2], wKey[39] ^ X[3]); LT(X);
        sb2(X, wKey[40] ^ X[0], wKey[41] ^ X[1], wKey[42] ^ X[2], wKey[43] ^ X[3]); LT(X);
        sb3(X, wKey[44] ^ X[0], wKey[45] ^ X[1], wKey[46] ^ X[2], wKey[47] ^ X[3]); LT(X);
        sb4(X, wKey[48] ^ X[0], wKey[49] ^ X[1], wKey[50] ^ X[2], wKey[51] ^ X[3]); LT(X);
        sb5(X, wKey[52] ^ X[0], wKey[53] ^ X[1], wKey[54] ^ X[2], wKey[55] ^ X[3]); LT(X);
        sb6(X, wKey[56] ^ X[0], wKey[57] ^ X[1], wKey[58] ^ X[2], wKey[59] ^ X[3]); LT(X);
        sb7(X, wKey[60] ^ X[0], wKey[61] ^ X[1], wKey[62] ^ X[2], wKey[63] ^ X[3]); LT(X);
        sb0(X, wKey[64] ^ X[0], wKey[65] ^ X[1], wKey[66] ^ X[2], wKey[67] ^ X[3]); LT(X);
        sb1(X, wKey[68] ^ X[0], wKey[69] ^ X[1], wKey[70] ^ X[2], wKey[71] ^ X[3]); LT(X);
        sb2(X, wKey[72] ^ X[0], wKey[73] ^ X[1], wKey[74] ^ X[2], wKey[75] ^ X[3]); LT(X);
        sb3(X, wKey[76] ^ X[0], wKey[77] ^ X[1], wKey[78] ^ X[2], wKey[79] ^ X[3]); LT(X);
        sb4(X, wKey[80] ^ X[0], wKey[81] ^ X[1], wKey[82] ^ X[2], wKey[83] ^ X[3]); LT(X);
        sb5(X, wKey[84] ^ X[0], wKey[85] ^ X[1], wKey[86] ^ X[2], wKey[87] ^ X[3]); LT(X);
        sb6(X, wKey[88] ^ X[0], wKey[89] ^ X[1], wKey[90] ^ X[2], wKey[91] ^ X[3]); LT(X);
        sb7(X, wKey[92] ^ X[0], wKey[93] ^ X[1], wKey[94] ^ X[2], wKey[95] ^ X[3]); LT(X);
        sb0(X, wKey[96] ^ X[0], wKey[97] ^ X[1], wKey[98] ^ X[2], wKey[99] ^ X[3]); LT(X);
        sb1(X, wKey[100] ^ X[0], wKey[101] ^ X[1], wKey[102] ^ X[2], wKey[103] ^ X[3]); LT(X);
        sb2(X, wKey[104] ^ X[0], wKey[105] ^ X[1], wKey[106] ^ X[2], wKey[107] ^ X[3]); LT(X);
        sb3(X, wKey[108] ^ X[0], wKey[109] ^ X[1], wKey[110] ^ X[2], wKey[111] ^ X[3]); LT(X);
        sb4(X, wKey[112] ^ X[0], wKey[113] ^ X[1], wKey[114] ^ X[2], wKey[115] ^ X[3]); LT(X);
        sb5(X, wKey[116] ^ X[0], wKey[117] ^ X[1], wKey[118] ^ X[2], wKey[119] ^ X[3]); LT(X);
        sb6(X, wKey[120] ^ X[0], wKey[121] ^ X[1], wKey[122] ^ X[2], wKey[123] ^ X[3]); LT(X);
        sb7(X, wKey[124] ^ X[0], wKey[125] ^ X[1], wKey[126] ^ X[2], wKey[127] ^ X[3]);

        Pack.intToLittleEndian(wKey[128] ^ X[0], output, outOff);
        Pack.intToLittleEndian(wKey[129] ^ X[1], output, outOff + 4);
        Pack.intToLittleEndian(wKey[130] ^ X[2], output, outOff + 8);
        Pack.intToLittleEndian(wKey[131] ^ X[3], output, outOff + 12);
    }

    /**
     * Decrypt one block of ciphertext.
     *
     * @param input the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param output the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     */
    protected void decryptBlock(
        byte[]  input,
        int     inOff,
        byte[]  output,
        int     outOff)
    {
        int[] X = new int[4];
        
        X[0] = wKey[128] ^ Pack.littleEndianToInt(input, inOff);
        X[1] = wKey[129] ^ Pack.littleEndianToInt(input, inOff + 4);
        X[2] = wKey[130] ^ Pack.littleEndianToInt(input, inOff + 8);
        X[3] = wKey[131] ^ Pack.littleEndianToInt(input, inOff + 12);

        ib7(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[124]; X[1] ^= wKey[125]; X[2] ^= wKey[126]; X[3] ^= wKey[127];
        inverseLT(X); ib6(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[120]; X[1] ^= wKey[121]; X[2] ^= wKey[122]; X[3] ^= wKey[123];
        inverseLT(X); ib5(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[116]; X[1] ^= wKey[117]; X[2] ^= wKey[118]; X[3] ^= wKey[119];
        inverseLT(X); ib4(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[112]; X[1] ^= wKey[113]; X[2] ^= wKey[114]; X[3] ^= wKey[115];
        inverseLT(X); ib3(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[108]; X[1] ^= wKey[109]; X[2] ^= wKey[110]; X[3] ^= wKey[111];
        inverseLT(X); ib2(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[104]; X[1] ^= wKey[105]; X[2] ^= wKey[106]; X[3] ^= wKey[107];
        inverseLT(X); ib1(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[100]; X[1] ^= wKey[101]; X[2] ^= wKey[102]; X[3] ^= wKey[103];
        inverseLT(X); ib0(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[96]; X[1] ^= wKey[97]; X[2] ^= wKey[98]; X[3] ^= wKey[99];
        inverseLT(X); ib7(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[92]; X[1] ^= wKey[93]; X[2] ^= wKey[94]; X[3] ^= wKey[95];
        inverseLT(X); ib6(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[88]; X[1] ^= wKey[89]; X[2] ^= wKey[90]; X[3] ^= wKey[91];
        inverseLT(X); ib5(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[84]; X[1] ^= wKey[85]; X[2] ^= wKey[86]; X[3] ^= wKey[87];
        inverseLT(X); ib4(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[80]; X[1] ^= wKey[81]; X[2] ^= wKey[82]; X[3] ^= wKey[83];
        inverseLT(X); ib3(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[76]; X[1] ^= wKey[77]; X[2] ^= wKey[78]; X[3] ^= wKey[79];
        inverseLT(X); ib2(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[72]; X[1] ^= wKey[73]; X[2] ^= wKey[74]; X[3] ^= wKey[75];
        inverseLT(X); ib1(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[68]; X[1] ^= wKey[69]; X[2] ^= wKey[70]; X[3] ^= wKey[71];
        inverseLT(X); ib0(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[64]; X[1] ^= wKey[65]; X[2] ^= wKey[66]; X[3] ^= wKey[67];
        inverseLT(X); ib7(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[60]; X[1] ^= wKey[61]; X[2] ^= wKey[62]; X[3] ^= wKey[63];
        inverseLT(X); ib6(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[56]; X[1] ^= wKey[57]; X[2] ^= wKey[58]; X[3] ^= wKey[59];
        inverseLT(X); ib5(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[52]; X[1] ^= wKey[53]; X[2] ^= wKey[54]; X[3] ^= wKey[55];
        inverseLT(X); ib4(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[48]; X[1] ^= wKey[49]; X[2] ^= wKey[50]; X[3] ^= wKey[51];
        inverseLT(X); ib3(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[44]; X[1] ^= wKey[45]; X[2] ^= wKey[46]; X[3] ^= wKey[47];
        inverseLT(X); ib2(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[40]; X[1] ^= wKey[41]; X[2] ^= wKey[42]; X[3] ^= wKey[43];
        inverseLT(X); ib1(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[36]; X[1] ^= wKey[37]; X[2] ^= wKey[38]; X[3] ^= wKey[39];
        inverseLT(X); ib0(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[32]; X[1] ^= wKey[33]; X[2] ^= wKey[34]; X[3] ^= wKey[35];
        inverseLT(X); ib7(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[28]; X[1] ^= wKey[29]; X[2] ^= wKey[30]; X[3] ^= wKey[31];
        inverseLT(X); ib6(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[24]; X[1] ^= wKey[25]; X[2] ^= wKey[26]; X[3] ^= wKey[27];
        inverseLT(X); ib5(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[20]; X[1] ^= wKey[21]; X[2] ^= wKey[22]; X[3] ^= wKey[23];
        inverseLT(X); ib4(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[16]; X[1] ^= wKey[17]; X[2] ^= wKey[18]; X[3] ^= wKey[19];
        inverseLT(X); ib3(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[12]; X[1] ^= wKey[13]; X[2] ^= wKey[14]; X[3] ^= wKey[15];
        inverseLT(X); ib2(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[8]; X[1] ^= wKey[9]; X[2] ^= wKey[10]; X[3] ^= wKey[11];
        inverseLT(X); ib1(X, X[0], X[1], X[2], X[3]);
        X[0] ^= wKey[4]; X[1] ^= wKey[5]; X[2] ^= wKey[6]; X[3] ^= wKey[7];
        inverseLT(X); ib0(X, X[0], X[1], X[2], X[3]);

        Pack.intToLittleEndian(X[0] ^ wKey[0], output, outOff);
        Pack.intToLittleEndian(X[1] ^ wKey[1], output, outOff + 4);
        Pack.intToLittleEndian(X[2] ^ wKey[2], output, outOff + 8);
        Pack.intToLittleEndian(X[3] ^ wKey[3], output, outOff + 12);
    }
}
