package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;

/**
 * ExpandEquations (spec algorithm 2). For each i in [0, m-1] derives
 * a per-equation seed via XOF1, then runs the deterministic PRG with
 * salt = 0, execution index 0, to draw the n(n+1)/2 + n field elements
 * forming the i-th lower-triangular matrix A_i and bias vector b_i.
 *
 * <p>Output: <code>aHat</code> contains the m matrices stored row-major,
 * lower-triangular, with row j of A_i taking n positions (last n-j-1 set
 * to zero). For K = GF(256) each element is one byte (aHat length is
 * m*n*n). For K = GF(256^2) each element is two bytes (length m*n*n*2).
 */
final class MQOMExpand
{
    private final MQOMParameters params;
    private final MQOMSymmetric sym;
    private final int n;
    private final int m;
    private final int extBytesPerElt;

    /* Scratch — sized at construction, reused across expand() calls. */
    private final byte[] scratchStream;   // nbEq
    private final byte[] scratchSeedEq;   // seedSize
    private final byte[] scratchPrgSalt;  // saltSize (zero)
    private final byte[] scratchI16;      // 2

    MQOMExpand(MQOMSymmetric sym)
    {
        this.params = sym.getParameters();
        this.sym = sym;
        this.n = params.getMqN();
        this.m = params.getMqM() / params.getMu();
        this.extBytesPerElt = params.getExtFieldLog2() / 8;

        int nfEq = n + (n * (n + 1) / 2);
        this.scratchStream = new byte[nfEq * extBytesPerElt];
        this.scratchSeedEq = new byte[params.getSeedSize()];
        this.scratchPrgSalt = new byte[params.getSaltSize()];
        this.scratchI16 = new byte[2];
    }

    void expand(byte[] mseedEq, byte[] aHat, byte[] bHat)
    {
        int nbEq = scratchStream.length;
        byte[] stream = scratchStream;
        byte[] seedEq = scratchSeedEq;
        byte[] prgSalt = scratchPrgSalt;
        byte[] i16 = scratchI16;

        int rowStride = n * extBytesPerElt;

        for (int i = 0; i < m; i++)
        {
            i16[0] = (byte)(i & 0xFF);
            i16[1] = (byte)((i >>> 8) & 0xFF);
            SHAKEDigest xof = sym.newXof();
            sym.xofUpdateTag(xof, 1);
            xof.update(mseedEq, 0, 2 * params.getSeedSize());
            xof.update(i16, 0, 2);
            sym.xofSqueeze(xof, seedEq, 0, params.getSeedSize());

            sym.prg(prgSalt, 0, seedEq, 0, nbEq, stream, 0);

            int k = 0;
            int matBase = i * n * rowStride;
            for (int j = 0; j < n; j++)
            {
                int rowLen = (j + 1) * extBytesPerElt;
                int rowOff = matBase + j * rowStride;
                System.arraycopy(stream, k, aHat, rowOff, rowLen);
                for (int t = rowLen; t < rowStride; t++)
                {
                    aHat[rowOff + t] = 0;
                }
                k += rowLen;
            }
            int bBase = i * rowStride;
            System.arraycopy(stream, k, bHat, bBase, rowStride);
        }
    }
}
