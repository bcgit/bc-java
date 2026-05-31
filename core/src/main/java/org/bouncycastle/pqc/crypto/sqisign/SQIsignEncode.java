package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-independent SQIsign byte encoding / decoding. Java mirror of
 * {@code encode_verification.c} and {@code encode_signature.c}.
 *
 * <p>Driven from {@link SQIsignEncodeLvl1}, {@link SQIsignEncodeLvl3},
 * {@link SQIsignEncodeLvl5}, each of which supplies a level-specific
 * {@link Params} bundle (field instance + byte sizes + level-specific
 * MaxOrd/QuatAlg references + the {@code fromHint} callback).</p>
 */
final class SQIsignEncode
{
    private SQIsignEncode()
    {
    }

    /** Step-4 dispatch: deterministic 2-power basis from a hint byte. */
    interface FromHint
    {
        int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint);
    }

    /** Level-specific config bundle. Immutable. */
    static final class Params
    {
        final GfField field;
        final int fpEncodedBytes;
        final int fp2EncodedBytes;
        final int torsion2PowerBytes;
        final int publicKeyBytes;
        final int secretKeyBytes;
        final int signatureBytes;
        final int responseMatEntryBytes;
        final int challCoeffBytes;
        final int torsionEvenPower;
        final QuatLattice maxordO0;
        final QuatAlg quatalgPinfty;
        final FromHint fromHint;

        Params(GfField field,
               int fpEncodedBytes, int torsion2PowerBytes,
               int publicKeyBytes, int secretKeyBytes,
               int signatureBytes,
               int responseMatEntryBytes, int challCoeffBytes,
               int torsionEvenPower,
               QuatLattice maxordO0, QuatAlg quatalgPinfty,
               FromHint fromHint)
        {
            this.field = field;
            this.fpEncodedBytes = fpEncodedBytes;
            this.fp2EncodedBytes = 2 * fpEncodedBytes;
            this.torsion2PowerBytes = torsion2PowerBytes;
            this.publicKeyBytes = publicKeyBytes;
            this.secretKeyBytes = secretKeyBytes;
            this.signatureBytes = signatureBytes;
            this.responseMatEntryBytes = responseMatEntryBytes;
            this.challCoeffBytes = challCoeffBytes;
            this.torsionEvenPower = torsionEvenPower;
            this.maxordO0 = maxordO0;
            this.quatalgPinfty = quatalgPinfty;
            this.fromHint = fromHint;
        }
    }

    // ------------------------------------------------------------------
    // ibz <-> bytes (level-independent)
    // ------------------------------------------------------------------

    static void ibzToBytes(byte[] dst, int off, Ibz x, int nbytes, boolean sgn)
    {
        BigInteger v = x.v;
        if (v.signum() < 0)
        {
            if (!sgn)
            {
                throw new IllegalArgumentException("ibzToBytes: negative value, sgn=false");
            }
            v = BigInteger.ONE.shiftLeft(8 * nbytes).add(v);
        }
        for (int i = 0; i < nbytes; i++)
        {
            dst[off + i] = (byte)(v.intValue() & 0xFF);
            v = v.shiftRight(8);
        }
    }

    static Ibz ibzFromBytes(byte[] src, int off, int nbytes, boolean sgn)
    {
        BigInteger v = BigInteger.ZERO;
        for (int i = nbytes - 1; i >= 0; i--)
        {
            v = v.shiftLeft(8).or(BigInteger.valueOf(src[off + i] & 0xFFL));
        }
        if (sgn && (src[off + nbytes - 1] & 0x80) != 0)
        {
            v = v.subtract(BigInteger.ONE.shiftLeft(8 * nbytes));
        }
        return new Ibz(v);
    }

    // ------------------------------------------------------------------
    // fp2 / projective encoding
    // ------------------------------------------------------------------

    static void fp2ToBytes(Params p, byte[] dst, int off, Fp2 x)
    {
        p.field.fp2Encode(dst, off, x);
    }

    static int fp2FromBytes(Params p, Fp2 x, byte[] src, int off)
    {
        return p.field.fp2Decode(x, src, off);
    }

    static void projToBytes(Params p, byte[] dst, int off, Fp2 x, Fp2 z)
    {
        if (Fp2.isZero(z) != 0)
        {
            throw new IllegalArgumentException("projToBytes: z is zero");
        }
        Fp2 tmp = z.copy();
        p.field.fp2Inv(tmp);
        p.field.fp2Mul(tmp, x, tmp);
        fp2ToBytes(p, dst, off, tmp);
    }

    static int projFromBytes(Params p, Fp2 x, Fp2 z, byte[] src, int off)
    {
        int ret = fp2FromBytes(p, x, src, off);
        Fp2.setOne(z);
        return ret;
    }

    // ------------------------------------------------------------------
    // public key
    // ------------------------------------------------------------------

    static byte[] publicKeyToBytes(Params p, SQIsignPublicKeyData pk)
    {
        byte[] out = new byte[p.publicKeyBytes];
        writePublicKey(p, pk, out, 0);
        return out;
    }

    /** Write a public-key encoding directly into {@code out} at {@code off}. */
    static void writePublicKey(Params p, SQIsignPublicKeyData pk, byte[] out, int off)
    {
        projToBytes(p, out, off, pk.curve.A, pk.curve.C);
        out[off + p.fp2EncodedBytes] = (byte)(pk.hintPk & 0xFF);
    }

    static SQIsignPublicKeyData publicKeyFromBytes(Params p, byte[] enc, int off)
    {
        SQIsignPublicKeyData pk = new SQIsignPublicKeyData();
        pk.curve.field = p.field;
        Fp2.setZero(pk.curve.A);
        Fp2.setZero(pk.curve.C);
        projFromBytes(p, pk.curve.A, pk.curve.C, enc, off);
        pk.curve.isA24ComputedAndNormalized = false;
        pk.hintPk = enc[off + p.fp2EncodedBytes] & 0xFF;
        return pk;
    }

    // ------------------------------------------------------------------
    // secret key
    // ------------------------------------------------------------------

    static byte[] secretKeyToBytes(Params p, SQIsignSecretKeyData sk, SQIsignPublicKeyData pk,
                                   QuatAlg algebra)
    {
        byte[] out = new byte[p.secretKeyBytes];
        // Write the pk header directly into the sk buffer — no intermediate
        // allocation, no arraycopy.
        writePublicKey(p, pk, out, 0);

        int off = p.publicKeyBytes;
        ibzToBytes(out, off, sk.secretIdeal.norm, p.fpEncodedBytes, false);
        off += p.fpEncodedBytes;

        QuatAlg.Elem gen = new QuatAlg.Elem();
        int ok = QuatLeftIdeal.generator(gen, sk.secretIdeal, algebra);
        if (ok != 1)
        {
            throw new IllegalStateException("secretKeyToBytes: no generator found");
        }
        for (int i = 0; i < 4; i++)
        {
            ibzToBytes(out, off, gen.coord[i], p.fpEncodedBytes, true);
            off += p.fpEncodedBytes;
        }

        ibzToBytes(out, off, sk.matBAcanToBA0Two[0][0], p.torsion2PowerBytes, false);
        off += p.torsion2PowerBytes;
        ibzToBytes(out, off, sk.matBAcanToBA0Two[0][1], p.torsion2PowerBytes, false);
        off += p.torsion2PowerBytes;
        ibzToBytes(out, off, sk.matBAcanToBA0Two[1][0], p.torsion2PowerBytes, false);
        off += p.torsion2PowerBytes;
        ibzToBytes(out, off, sk.matBAcanToBA0Two[1][1], p.torsion2PowerBytes, false);
        off += p.torsion2PowerBytes;

        if (off != p.secretKeyBytes)
        {
            throw new IllegalStateException(
                "secretKeyToBytes: length mismatch " + off + " vs " + p.secretKeyBytes);
        }
        return out;
    }

    static SQIsignSecretKeyData secretKeyFromBytesFull(Params p, byte[] enc, int off,
                                                      SQIsignPublicKeyData pkOut)
    {
        SQIsignPublicKeyData pk = publicKeyFromBytes(p, enc, off);
        EcCurve.copy(pkOut.curve, pk.curve);
        pkOut.hintPk = pk.hintPk;

        SQIsignSecretKeyData sk = new SQIsignSecretKeyData();
        EcCurve.copy(sk.curve, pk.curve);
        sk.curve.field = p.field;

        int q = off + p.publicKeyBytes;
        Ibz norm = ibzFromBytes(enc, q, p.fpEncodedBytes, false);
        q += p.fpEncodedBytes;

        QuatAlg.Elem gen = new QuatAlg.Elem();
        for (int i = 0; i < 4; i++)
        {
            gen.coord[i].v = ibzFromBytes(enc, q, p.fpEncodedBytes, true).v;
            q += p.fpEncodedBytes;
        }
        Ibz.set(gen.denom, 1);

        QuatLeftIdeal.create(sk.secretIdeal, gen, norm, p.maxordO0, p.quatalgPinfty);

        sk.matBAcanToBA0Two[0][0].v = ibzFromBytes(enc, q, p.torsion2PowerBytes, false).v;
        q += p.torsion2PowerBytes;
        sk.matBAcanToBA0Two[0][1].v = ibzFromBytes(enc, q, p.torsion2PowerBytes, false).v;
        q += p.torsion2PowerBytes;
        sk.matBAcanToBA0Two[1][0].v = ibzFromBytes(enc, q, p.torsion2PowerBytes, false).v;
        q += p.torsion2PowerBytes;
        sk.matBAcanToBA0Two[1][1].v = ibzFromBytes(enc, q, p.torsion2PowerBytes, false).v;

        p.fromHint.fromHint(sk.canonicalBasis, sk.curve, p.torsionEvenPower, pk.hintPk);

        return sk;
    }

    // ------------------------------------------------------------------
    // signature
    // ------------------------------------------------------------------

    static void encodeLE(byte[] dst, int off, BigInteger value, int numBytes)
    {
        byte[] raw = value.signum() < 0
            ? value.add(BigInteger.ONE.shiftLeft(numBytes * 8)).toByteArray()
            : value.toByteArray();
        int rawOff = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int rawLen = raw.length - rawOff;
        if (rawLen > numBytes)
        {
            rawOff += rawLen - numBytes;
            rawLen = numBytes;
        }
        for (int i = 0; i < rawLen; i++)
        {
            dst[off + i] = raw[rawOff + rawLen - 1 - i];
        }
        for (int i = rawLen; i < numBytes; i++)
        {
            dst[off + i] = 0;
        }
    }

    static BigInteger decodeLE(byte[] src, int off, int numBytes)
    {
        byte[] be = new byte[numBytes + 1];
        be[0] = 0;
        for (int i = 0; i < numBytes; i++)
        {
            be[1 + i] = src[off + numBytes - 1 - i];
        }
        return new BigInteger(be);
    }

    static byte[] signatureToBytes(Params p, SQIsignSignature sig)
    {
        byte[] out = new byte[p.signatureBytes];
        int off = 0;

        fp2ToBytes(p, out, off, sig.eAuxA);
        off += p.fp2EncodedBytes;

        out[off++] = (byte)(sig.backtracking & 0xFF);
        out[off++] = (byte)(sig.twoRespLength & 0xFF);

        encodeLE(out, off, sig.matBchallCanToBChall[0][0], p.responseMatEntryBytes);
        off += p.responseMatEntryBytes;
        encodeLE(out, off, sig.matBchallCanToBChall[0][1], p.responseMatEntryBytes);
        off += p.responseMatEntryBytes;
        encodeLE(out, off, sig.matBchallCanToBChall[1][0], p.responseMatEntryBytes);
        off += p.responseMatEntryBytes;
        encodeLE(out, off, sig.matBchallCanToBChall[1][1], p.responseMatEntryBytes);
        off += p.responseMatEntryBytes;

        encodeLE(out, off, sig.challCoeff, p.challCoeffBytes);
        off += p.challCoeffBytes;

        out[off++] = (byte)(sig.hintAux & 0xFF);
        out[off++] = (byte)(sig.hintChall & 0xFF);

        if (off != p.signatureBytes)
        {
            throw new IllegalStateException(
                "signatureToBytes: length mismatch " + off + " vs " + p.signatureBytes);
        }
        return out;
    }

    /**
     * Populate a pre-allocated {@link SQIsignSignature} (typically a level-
     * specific subclass) from a byte buffer. Lets each level wrapper create
     * the right subclass and forward.
     */
    static void signatureFromBytes(Params p, SQIsignSignature sig, byte[] enc, int off)
    {
        if (enc.length - off < p.signatureBytes)
        {
            throw new IllegalArgumentException(
                "signatureFromBytes: input too short, expected at least "
                    + p.signatureBytes + " bytes from offset " + off);
        }
        int q = off;

        fp2FromBytes(p, sig.eAuxA, enc, q);
        q += p.fp2EncodedBytes;

        sig.backtracking = enc[q++] & 0xFF;
        sig.twoRespLength = enc[q++] & 0xFF;

        sig.matBchallCanToBChall[0][0] = decodeLE(enc, q, p.responseMatEntryBytes);
        q += p.responseMatEntryBytes;
        sig.matBchallCanToBChall[0][1] = decodeLE(enc, q, p.responseMatEntryBytes);
        q += p.responseMatEntryBytes;
        sig.matBchallCanToBChall[1][0] = decodeLE(enc, q, p.responseMatEntryBytes);
        q += p.responseMatEntryBytes;
        sig.matBchallCanToBChall[1][1] = decodeLE(enc, q, p.responseMatEntryBytes);
        q += p.responseMatEntryBytes;

        sig.challCoeff = decodeLE(enc, q, p.challCoeffBytes);
        q += p.challCoeffBytes;

        sig.hintAux = enc[q++] & 0xFF;
        sig.hintChall = enc[q] & 0xFF;
    }
}
