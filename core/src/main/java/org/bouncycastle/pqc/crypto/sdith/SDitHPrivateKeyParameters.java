package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * SDitH private key, in the same expanded form that the reference KAT files
 * write out (sdith_full_key_t).
 * <p>
 * Layout:
 * <pre>
 *   H_a_seed (seedSize)  ||  y (m-k)  ||  s_A (k)  ||  q_poly (d * w/d)  ||  p_poly (d * w/d)
 * </pre>
 * The {@code mSeed} is held alongside the expanded key whenever it is known
 * (after keygen); when reconstructed from a flat encoded blob we have only the
 * expanded data and {@link #getSeed()} returns {@code null}.
 */
public class SDitHPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final SDitHParameters parameters;
    private final byte[] mSeed;
    private final byte[] hASeed;
    private final byte[] y;
    private final byte[] sA;
    private final byte[] qPoly;
    private final byte[] pPoly;

    public SDitHPrivateKeyParameters(SDitHParameters parameters,
                                     byte[] mSeed,
                                     byte[] hASeed, byte[] y,
                                     byte[] sA, byte[] qPoly, byte[] pPoly)
    {
        super(true);
        int k = parameters.getK();
        int ySize = parameters.getYSize();
        int qpSize = parameters.getD() * parameters.getWd();
        if (hASeed.length != parameters.getSeedSize() || y.length != ySize)
        {
            throw new IllegalArgumentException("compressed pubkey component length mismatch");
        }
        if (sA.length != k || qPoly.length != qpSize || pPoly.length != qpSize)
        {
            throw new IllegalArgumentException("private payload length mismatch");
        }
        this.parameters = parameters;
        this.mSeed = Arrays.clone(mSeed);
        this.hASeed = Arrays.clone(hASeed);
        this.y = Arrays.clone(y);
        this.sA = Arrays.clone(sA);
        this.qPoly = Arrays.clone(qPoly);
        this.pPoly = Arrays.clone(pPoly);
    }

    public SDitHPrivateKeyParameters(SDitHParameters parameters, byte[] encoded)
    {
        super(true);
        int seedSize = parameters.getSeedSize();
        int ySize = parameters.getYSize();
        int k = parameters.getK();
        int d = parameters.getD();
        int wd = parameters.getWd();
        int qpSize = d * wd;
        int expected = seedSize + ySize + k + qpSize + qpSize;
        if (encoded.length != expected)
        {
            throw new IllegalArgumentException("encoded length mismatch: expected " + expected + ", got " + encoded.length);
        }
        int off = 0;
        this.parameters = parameters;
        this.mSeed = null;
        this.hASeed = Arrays.copyOfRange(encoded, off, off + seedSize); off += seedSize;
        this.y = Arrays.copyOfRange(encoded, off, off + ySize); off += ySize;
        this.sA = Arrays.copyOfRange(encoded, off, off + k); off += k;
        // Hypercube reference packs all q chunks then all p chunks (matches the
        // C struct's row-major sdith_full_key_t layout).
        // Threshold reference packs (q[0] || p[0] || q[1] || p[1] || ...) per
        // chunk (matches serialize_instance_solution in witness.c).
        if (parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD)
        {
            this.qPoly = new byte[qpSize];
            this.pPoly = new byte[qpSize];
            for (int chunk = 0; chunk < d; ++chunk)
            {
                System.arraycopy(encoded, off, this.qPoly, chunk * wd, wd); off += wd;
                System.arraycopy(encoded, off, this.pPoly, chunk * wd, wd); off += wd;
            }
        }
        else
        {
            this.qPoly = Arrays.copyOfRange(encoded, off, off + qpSize); off += qpSize;
            this.pPoly = Arrays.copyOfRange(encoded, off, off + qpSize);
        }
    }

    public SDitHParameters getParameters()
    {
        return parameters;
    }

    public byte[] getEncoded()
    {
        if (parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD)
        {
            int d = parameters.getD();
            int wd = parameters.getWd();
            byte[][] parts = new byte[3 + 2 * d][];
            parts[0] = hASeed;
            parts[1] = y;
            parts[2] = sA;
            int idx = 3;
            for (int chunk = 0; chunk < d; ++chunk)
            {
                parts[idx++] = Arrays.copyOfRange(qPoly, chunk * wd, (chunk + 1) * wd);
                parts[idx++] = Arrays.copyOfRange(pPoly, chunk * wd, (chunk + 1) * wd);
            }
            return Arrays.concatenate(parts);
        }
        return Arrays.concatenate(new byte[][] { hASeed, y, sA, qPoly, pPoly });
    }

    public byte[] getSeed()
    {
        return Arrays.clone(mSeed);
    }

    public byte[] getHASeed()
    {
        return Arrays.clone(hASeed);
    }

    public byte[] getY()
    {
        return Arrays.clone(y);
    }

    public byte[] getSA()
    {
        return Arrays.clone(sA);
    }

    public byte[] getQPoly()
    {
        return Arrays.clone(qPoly);
    }

    public byte[] getPPoly()
    {
        return Arrays.clone(pPoly);
    }

    public SDitHPublicKeyParameters getPublicKeyParameters()
    {
        return new SDitHPublicKeyParameters(parameters, hASeed, y);
    }
}
