package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class MLDSAEngine
{
    private final SecureRandom random;
    final SHAKEDigest shake256Digest = new SHAKEDigest(256);

    public final static int DilithiumN = 256;
    public final static int DilithiumQ = 8380417;
    public final static int DilithiumQinv = 58728449; // q^(-1) mod 2^32
    public final static int DilithiumD = 13;
    //public final static int DilithiumRootOfUnity = 1753;
    public final static int SeedBytes = 32;
    public final static int CrhBytes = 64;
    public final static int RndBytes = 32;
    public final static int TrBytes = 64;

    public final static int DilithiumPolyT1PackedBytes = 320;
    public final static int DilithiumPolyT0PackedBytes = 416;

    private final int DilithiumPolyVecHPackedBytes;

    private final int DilithiumPolyZPackedBytes;
    private final int DilithiumPolyW1PackedBytes;
    private final int DilithiumPolyEtaPackedBytes;

    private final int DilithiumK;
    private final int DilithiumL;
    private final int DilithiumEta;
    private final int DilithiumTau;
    private final int DilithiumBeta;
    private final int DilithiumGamma1;
    private final int DilithiumGamma2;
    private final int DilithiumOmega;
    private final int DilithiumCTilde;

    private final int CryptoPublicKeyBytes;
//    private final int CryptoSecretKeyBytes;
    private final int CryptoBytes;

    private final int PolyUniformGamma1NBlocks;

    private final Symmetric symmetric;

    protected Symmetric GetSymmetric()
    {
        return symmetric;
    }

//    int getDilithiumPolyVecHPackedBytes()
//    {
//        return DilithiumPolyVecHPackedBytes;
//    }

    int getDilithiumPolyZPackedBytes()
    {
        return DilithiumPolyZPackedBytes;
    }

    int getDilithiumPolyW1PackedBytes()
    {
        return DilithiumPolyW1PackedBytes;
    }

    int getDilithiumPolyEtaPackedBytes()
    {
        return DilithiumPolyEtaPackedBytes;
    }

//    int getDilithiumMode()
//    {
//        return DilithiumMode;
//    }

    int getDilithiumK()
    {
        return DilithiumK;
    }

    int getDilithiumL()
    {
        return DilithiumL;
    }

    int getDilithiumEta()
    {
        return DilithiumEta;
    }

    int getDilithiumTau()
    {
        return DilithiumTau;
    }

    int getDilithiumBeta()
    {
        return DilithiumBeta;
    }

    int getDilithiumGamma1()
    {
        return DilithiumGamma1;
    }

    int getDilithiumGamma2()
    {
        return DilithiumGamma2;
    }

    int getDilithiumOmega()
    {
        return DilithiumOmega;
    }

    int getDilithiumCTilde()
    {
        return DilithiumCTilde;
    }

    int getCryptoPublicKeyBytes()
    {
        return CryptoPublicKeyBytes;
    }

//    int getCryptoSecretKeyBytes()
//    {
//        return CryptoSecretKeyBytes;
//    }
//
//    int getCryptoBytes()
//    {
//        return CryptoBytes;
//    }

    int getPolyUniformGamma1NBlocks()
    {
        return this.PolyUniformGamma1NBlocks;
    }

    MLDSAEngine(int mode, SecureRandom random)
    {
        switch (mode)
        {
        case 2:
            this.DilithiumK = 4;
            this.DilithiumL = 4;
            this.DilithiumEta = 2;
            this.DilithiumTau = 39;
            this.DilithiumBeta = 78;
            this.DilithiumGamma1 = (1 << 17);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 88);
            this.DilithiumOmega = 80;
            this.DilithiumPolyZPackedBytes = 576;
            this.DilithiumPolyW1PackedBytes = 192;
            this.DilithiumPolyEtaPackedBytes = 96;
            this.DilithiumCTilde = 32;
            break;
        case 3:
            this.DilithiumK = 6;
            this.DilithiumL = 5;
            this.DilithiumEta = 4;
            this.DilithiumTau = 49;
            this.DilithiumBeta = 196;
            this.DilithiumGamma1 = (1 << 19);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 32);
            this.DilithiumOmega = 55;
            this.DilithiumPolyZPackedBytes = 640;
            this.DilithiumPolyW1PackedBytes = 128;
            this.DilithiumPolyEtaPackedBytes = 128;
            this.DilithiumCTilde = 48;
            break;
        case 5:
            this.DilithiumK = 8;
            this.DilithiumL = 7;
            this.DilithiumEta = 2;
            this.DilithiumTau = 60;
            this.DilithiumBeta = 120;
            this.DilithiumGamma1 = (1 << 19);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 32);
            this.DilithiumOmega = 75;
            this.DilithiumPolyZPackedBytes = 640;
            this.DilithiumPolyW1PackedBytes = 128;
            this.DilithiumPolyEtaPackedBytes = 96;
            this.DilithiumCTilde = 64;
            break;
        default:
            throw new IllegalArgumentException("The mode " + mode + "is not supported by Crystals Dilithium!");
        }

        this.symmetric = new Symmetric.ShakeSymmetric();

        this.random = random;
        this.DilithiumPolyVecHPackedBytes = this.DilithiumOmega + this.DilithiumK;
        this.CryptoPublicKeyBytes = SeedBytes + this.DilithiumK * DilithiumPolyT1PackedBytes;
//        this.CryptoSecretKeyBytes =
//            (
//                2 * SeedBytes
//                    + TrBytes
//                    + DilithiumL * this.DilithiumPolyEtaPackedBytes
//                    + DilithiumK * this.DilithiumPolyEtaPackedBytes
//                    + DilithiumK * DilithiumPolyT0PackedBytes
//            );
        this.CryptoBytes = DilithiumCTilde + DilithiumL * this.DilithiumPolyZPackedBytes + this.DilithiumPolyVecHPackedBytes;

        if (this.DilithiumGamma1 == (1 << 17))
        {
            this.PolyUniformGamma1NBlocks = ((576 + symmetric.stream256BlockBytes - 1) / symmetric.stream256BlockBytes);
        }
        else if (this.DilithiumGamma1 == (1 << 19))
        {
            this.PolyUniformGamma1NBlocks = ((640 + symmetric.stream256BlockBytes - 1) / symmetric.stream256BlockBytes);
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
    }

    //Internal functions are deterministic. No randomness is sampled inside them
    byte[][] generateKeyPairInternal(byte[] seed)
    {
        byte[] buf = new byte[2 * SeedBytes + CrhBytes];
        byte[] tr = new byte[TrBytes];

        byte[] rho = new byte[SeedBytes],
            rhoPrime = new byte[CrhBytes],
            key = new byte[SeedBytes];

        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        PolyVecL s1 = new PolyVecL(this), s1hat;
        PolyVecK s2 = new PolyVecK(this), t1 = new PolyVecK(this), t0 = new PolyVecK(this);


        shake256Digest.update(seed, 0, SeedBytes);

        //Domain separation
        shake256Digest.update((byte)DilithiumK);
        shake256Digest.update((byte)DilithiumL);

        shake256Digest.doFinal(buf, 0, 2 * SeedBytes + CrhBytes);
        // System.out.print("buf = ");
        // Helper.printByteArray(buf);

        System.arraycopy(buf, 0, rho, 0, SeedBytes);
        System.arraycopy(buf, SeedBytes, rhoPrime, 0, CrhBytes);
        System.arraycopy(buf, SeedBytes + CrhBytes, key, 0, SeedBytes);
        // System.out.println("key = ");
        // Helper.printByteArray(key);

        aMatrix.expandMatrix(rho);
        // System.out.print(aMatrix.toString("aMatrix"));

        // System.out.println("rhoPrime = ");
        // Helper.printByteArray(rhoPrime);
        s1.uniformEta(rhoPrime, (short)0);
        // System.out.println(s1.toString("s1"));

        s2.uniformEta(rhoPrime, (short)DilithiumL);

        s1hat = new PolyVecL(this);

        s1.copyTo(s1hat);
        s1hat.polyVecNtt();

        // System.out.println(s1hat.toString("s1hat"));

        aMatrix.pointwiseMontgomery(t1, s1hat);
        // System.out.println(t1.toString("t1"));

        t1.reduce();
        t1.invNttToMont();

        t1.addPolyVecK(s2);
        // System.out.println(s2.toString("s2"));
        // System.out.println(t1.toString("t1"));
        t1.conditionalAddQ();
        t1.power2Round(t0);

        // System.out.println(t1.toString("t1"));
        // System.out.println(t0.toString("t0"));


        byte[] encT1 = Packing.packPublicKey(t1, this);
        // System.out.println("pk engine = ");
        // Helper.printByteArray(pk);

        shake256Digest.update(rho, 0, rho.length);
        shake256Digest.update(encT1, 0, encT1.length);
        shake256Digest.doFinal(tr, 0, TrBytes);

        byte[][] sk = Packing.packSecretKey(rho, tr, key, t0, s1, s2, this);

        return new byte[][]{sk[0], sk[1], sk[2], sk[3], sk[4], sk[5], encT1, seed};
    }

    byte[] deriveT1(byte[] rho, byte[] key, byte[] tr, byte[] s1Enc, byte[] s2Enc, byte[] t0Enc)
    {
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        PolyVecL s1 = new PolyVecL(this), s1hat;
        PolyVecK s2 = new PolyVecK(this), t1 = new PolyVecK(this), t0 = new PolyVecK(this);

        Packing.unpackSecretKey(t0, s1, s2, t0Enc, s1Enc, s2Enc, this);

        // System.out.print("rho = ");
        // Helper.printByteArray(rho);

        // System.out.println("key = ");
        // Helper.printByteArray(key);

        aMatrix.expandMatrix(rho);
        // System.out.print(aMatrix.toString("aMatrix"));

        s1hat = new PolyVecL(this);

        s1.copyTo(s1hat);
        s1hat.polyVecNtt();

        // System.out.println(s1hat.toString("s1hat"));

        aMatrix.pointwiseMontgomery(t1, s1hat);
        // System.out.println(t1.toString("t1"));

        t1.reduce();
        t1.invNttToMont();

        t1.addPolyVecK(s2);
        // System.out.println(s2.toString("s2"));
        // System.out.println(t1.toString("t1"));
        t1.conditionalAddQ();
        t1.power2Round(t0);

        // System.out.println(t1.toString("t1"));
        // System.out.println(t0.toString("t0"));

        byte[] encT1 = Packing.packPublicKey(t1, this);
        // System.out.println("enc t1 = ");
        // Helper.printByteArray(encT1);
        return encT1;
    }

    SHAKEDigest getShake256Digest()
    {
        return new SHAKEDigest(shake256Digest);
    }

    void initSign(byte[] tr, boolean isPreHash, byte[] ctx)
    {
        shake256Digest.update(tr, 0, TrBytes);
        absorbCtx(isPreHash, ctx);
    }

    void initVerify(byte[] rho, byte[] encT1, boolean isPreHash, byte[] ctx)
    {
        byte[] mu = new byte[TrBytes];

        shake256Digest.update(rho, 0, rho.length);
        shake256Digest.update(encT1, 0, encT1.length);
        shake256Digest.doFinal(mu, 0, TrBytes);

        shake256Digest.update(mu, 0, TrBytes);
        absorbCtx(isPreHash, ctx);
    }

    void absorbCtx(boolean isPreHash, byte[] ctx)
    {
        if (ctx != null)
        {
            shake256Digest.update(isPreHash ? (byte)1 : (byte)0);
            shake256Digest.update((byte)ctx.length);
            shake256Digest.update(ctx, 0, ctx.length);
        }
    }

    byte[] signInternal(byte[] msg, int msglen, byte[] rho, byte[] key, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc, byte[] rnd)
    {
        SHAKEDigest shake256 = new SHAKEDigest(shake256Digest);

        shake256.update(msg, 0, msglen);

        return generateSignature(generateMu(shake256), shake256, rho, key, t0Enc, s1Enc, s2Enc, rnd);
    }

    byte[] generateMu(SHAKEDigest shake256Digest)
    {
        byte[] mu = new byte[CrhBytes];

        shake256Digest.doFinal(mu, 0, CrhBytes);
        return mu;
    }

    byte[] generateSignature(byte[] mu, SHAKEDigest shake256Digest, byte[] rho, byte[] key, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc, byte[] rnd)
    {
        byte[] outSig = new byte[CryptoBytes];
        byte[] rhoPrime = new byte[CrhBytes];
        short nonce = 0;
        PolyVecL s1 = new PolyVecL(this), y = new PolyVecL(this), z = new PolyVecL(this);
        PolyVecK t0 = new PolyVecK(this), s2 = new PolyVecK(this), w1 = new PolyVecK(this), w0 = new PolyVecK(this), h = new PolyVecK(this);
        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        Packing.unpackSecretKey(t0, s1, s2, t0Enc, s1Enc, s2Enc, this);

        byte[] keyMu = Arrays.copyOf(key, SeedBytes + RndBytes + CrhBytes);
        System.arraycopy(rnd, 0, keyMu, SeedBytes, RndBytes);
        System.arraycopy(mu, 0, keyMu, SeedBytes + RndBytes, CrhBytes);
        shake256Digest.update(keyMu, 0, SeedBytes + RndBytes + CrhBytes);
        shake256Digest.doFinal(rhoPrime, 0, CrhBytes);

        aMatrix.expandMatrix(rho);

        s1.polyVecNtt();
        s2.polyVecNtt();

        t0.polyVecNtt();

        int count = 0;
        while (count < 1000)
        {
            count++;
            // Sample intermediate vector
            y.uniformGamma1(rhoPrime, nonce++);

            y.copyTo(z);
            z.polyVecNtt();

            // Matrix-vector multiplication
            aMatrix.pointwiseMontgomery(w1, z);
            w1.reduce();
            w1.invNttToMont();

            // Decompose w and call the random oracle
            w1.conditionalAddQ();
            w1.decompose(w0);

            w1.packW1(this, outSig, 0);

            shake256Digest.update(mu, 0, CrhBytes);
            shake256Digest.update(outSig, 0, DilithiumK * DilithiumPolyW1PackedBytes);
            shake256Digest.doFinal(outSig, 0, DilithiumCTilde);

            cp.challenge(outSig, 0, DilithiumCTilde);
            cp.polyNtt();

            // Compute z, reject if it reveals secret
            z.pointwisePolyMontgomery(cp, s1);
            z.invNttToMont();
            z.addPolyVecL(y);
            z.reduce();
            if (z.checkNorm(DilithiumGamma1 - DilithiumBeta))
            {
                continue;
            }

            h.pointwisePolyMontgomery(cp, s2);
            h.invNttToMont();
            w0.subtract(h);
            w0.reduce();
            if (w0.checkNorm(DilithiumGamma2 - DilithiumBeta))
            {
                continue;
            }

            h.pointwisePolyMontgomery(cp, t0);
            h.invNttToMont();
            h.reduce();
            if (h.checkNorm(DilithiumGamma2))
            {
                continue;
            }

            w0.addPolyVecK(h);
            w0.conditionalAddQ();
            int n = h.makeHint(w0, w1);
            if (n > DilithiumOmega)
            {
                continue;
            }

            Packing.packSignature(outSig, z, h, this);
            return outSig;
        }

        // TODO[pqc] Shouldn't this throw an exception here (or in caller)?
        return null;
    }

    boolean verifyInternalMu(byte[] providedMu)
    {
        byte[] mu = new byte[CrhBytes];

        shake256Digest.doFinal(mu, 0);

        return Arrays.constantTimeAreEqual(mu, providedMu);
    }

    boolean verifyInternalMuSignature(byte[] mu, byte[] sig, int siglen, SHAKEDigest shake256Digest, byte[] rho, byte[] encT1)
    {
        byte[] buf = new byte[Math.max(CrhBytes + DilithiumK * DilithiumPolyW1PackedBytes, DilithiumCTilde)];

        // Mu
        System.arraycopy(mu, 0, buf, 0, mu.length);

        return doVerifyInternal(buf, sig, siglen, shake256Digest, rho, encT1);
    }

    boolean verifyInternal(byte[] sig, int siglen, SHAKEDigest shake256Digest, byte[] rho, byte[] encT1)
    {
        byte[] buf = new byte[Math.max(CrhBytes + DilithiumK * DilithiumPolyW1PackedBytes, DilithiumCTilde)];

        // Mu
        shake256Digest.doFinal(buf, 0);

        return doVerifyInternal(buf, sig, siglen, shake256Digest, rho, encT1);
    }

    private boolean doVerifyInternal(byte[] buf, byte[] sig, int siglen, SHAKEDigest shake256Digest, byte[] rho, byte[] encT1)
    {
        if (siglen != CryptoBytes)
        {
            return false;
        }

        PolyVecK h = new PolyVecK(this);
        PolyVecL z = new PolyVecL(this);

        if (!Packing.unpackSignature(z, h, sig, this))
        {
            return false;
        }

        if (z.checkNorm(getDilithiumGamma1() - getDilithiumBeta()))
        {
            return false;
        }

        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);
        PolyVecK t1 = new PolyVecK(this), w1 = new PolyVecK(this);

        t1 = Packing.unpackPublicKey(t1, encT1, this);

        // Matrix-vector multiplication; compute Az - c2^dt1
        cp.challenge(sig, 0, DilithiumCTilde);

        aMatrix.expandMatrix(rho);

        z.polyVecNtt();
        aMatrix.pointwiseMontgomery(w1, z);

        cp.polyNtt();

        t1.shiftLeft();
        t1.polyVecNtt();
        t1.pointwisePolyMontgomery(cp, t1);

        w1.subtract(t1);
        w1.reduce();
        w1.invNttToMont();

        w1.conditionalAddQ();
        w1.useHint(w1, h);

        w1.packW1(this, buf, CrhBytes);

        shake256Digest.update(buf, 0, CrhBytes + DilithiumK * DilithiumPolyW1PackedBytes);
        shake256Digest.doFinal(buf, 0, DilithiumCTilde);

        return Arrays.constantTimeAreEqual(DilithiumCTilde, sig, 0, buf, 0);
    }

    byte[][] generateKeyPair()
    {
        byte[] seedBuf = new byte[SeedBytes];
        random.nextBytes(seedBuf);
        return generateKeyPairInternal(seedBuf);
    }
}
