package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class DilithiumEngine
{
    private final SecureRandom random;

    private final SHAKEDigest shake128Digest = new SHAKEDigest(128);
    private final SHAKEDigest shake256Digest = new SHAKEDigest(256);

    public final static int DilithiumN = 256;
    public final static int DilithiumQ = 8380417;
    public final static int DilithiumQinv = 58728449; // q^(-1) mod 2^32
    public final static int DilithiumD = 13;
    public final static int DilithiumRootOfUnity = 1753;
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

    private final int DilithiumMode;

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
    private final int CryptoSecretKeyBytes;
    private final int CryptoBytes;

    private final int PolyUniformGamma1NBlocks;

    private final Symmetric symmetric;

    protected Symmetric GetSymmetric()
    {
        return symmetric;
    }

    int getDilithiumPolyVecHPackedBytes()
    {
        return DilithiumPolyVecHPackedBytes;
    }

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

    int getDilithiumMode()
    {
        return DilithiumMode;
    }

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

    int getCryptoSecretKeyBytes()
    {
        return CryptoSecretKeyBytes;
    }

    int getCryptoBytes()
    {
        return CryptoBytes;
    }

    int getPolyUniformGamma1NBlocks()
    {
        return this.PolyUniformGamma1NBlocks;
    }

    SHAKEDigest getShake256Digest()
    {
        return this.shake256Digest;
    }

    SHAKEDigest getShake128Digest()
    {
        return this.shake128Digest;
    }

    DilithiumEngine(int mode, SecureRandom random, boolean usingAes)
    {
        this.DilithiumMode = mode;
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

        if(usingAes)
        {
            symmetric = new Symmetric.AesSymmetric();
        }
        else
        {
            symmetric = new Symmetric.ShakeSymmetric();
        }


        this.random = random;
        this.DilithiumPolyVecHPackedBytes = this.DilithiumOmega + this.DilithiumK;
        this.CryptoPublicKeyBytes = SeedBytes + this.DilithiumK * DilithiumPolyT1PackedBytes;
        this.CryptoSecretKeyBytes =
            (
                3 * SeedBytes
                    + DilithiumL * this.DilithiumPolyEtaPackedBytes
                    + DilithiumK * this.DilithiumPolyEtaPackedBytes
                    + DilithiumK * DilithiumPolyT0PackedBytes
            );
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

    public byte[][] generateKeyPair()
    {
        byte[] seedBuf = new byte[SeedBytes];
        byte[] buf = new byte[2 * SeedBytes + CrhBytes];
        byte[] tr = new byte[TrBytes];

        byte[] rho = new byte[SeedBytes],
            rhoPrime = new byte[CrhBytes],
            key = new byte[SeedBytes];

        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        PolyVecL s1 = new PolyVecL(this), s1hat;
        PolyVecK s2 = new PolyVecK(this), t1 = new PolyVecK(this), t0 = new PolyVecK(this);

        random.nextBytes(seedBuf);

        shake256Digest.update(seedBuf, 0, SeedBytes);

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

        s1.copyPolyVecL(s1hat);
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
        
        return new byte[][]{ sk[0], sk[1], sk[2], sk[3], sk[4], sk[5], encT1};
    }

    public byte[] signSignature(byte[] msg, int msglen, byte[] rho, byte[] key, byte[] tr, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc)
    {
        int n;
        byte[] outSig = new byte[CryptoBytes + msglen];
        byte[] mu = new byte[CrhBytes], rhoPrime = new byte[CrhBytes];
        short nonce = 0;
        PolyVecL s1 = new PolyVecL(this), y = new PolyVecL(this), z = new PolyVecL(this);
        PolyVecK t0 = new PolyVecK(this), s2 = new PolyVecK(this), w1 = new PolyVecK(this), w0 = new PolyVecK(this), h = new PolyVecK(this);
        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        Packing.unpackSecretKey(t0, s1, s2, t0Enc, s1Enc, s2Enc, this);

        this.shake256Digest.update(tr, 0, TrBytes);
        this.shake256Digest.update(msg, 0, msglen);
        this.shake256Digest.doFinal(mu, 0, CrhBytes);

        byte[] rnd = new byte[RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

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

            y.copyPolyVecL(z);
            z.polyVecNtt();

            // Matrix-vector multiplication
            aMatrix.pointwiseMontgomery(w1, z);
            w1.reduce();
            w1.invNttToMont();

            // Decompose w and call the random oracle
            w1.conditionalAddQ();
            w1.decompose(w0);

            System.arraycopy(w1.packW1(), 0, outSig, 0, DilithiumK * DilithiumPolyW1PackedBytes);

            shake256Digest.update(mu, 0, CrhBytes);
            shake256Digest.update(outSig, 0, DilithiumK * DilithiumPolyW1PackedBytes);
            shake256Digest.doFinal(outSig, 0, DilithiumCTilde);

            cp.challenge(Arrays.copyOfRange(outSig, 0, SeedBytes));  // uses only the first SeedBytes bytes of sig
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
            n = h.makeHint(w0, w1);
            if (n > DilithiumOmega)
            {
                continue;
            }

            return Packing.packSignature(outSig, z, h, this);
        }

        return null;
    }

    public byte[] sign(byte[] msg, int mlen, byte[] rho, byte[] key, byte[] tr, byte[] t0, byte[] s1, byte[] s2)
    {
        return signSignature(msg, mlen, rho, key, tr, t0, s1, s2);
    }

    public boolean signVerify(byte[] sig, int siglen, byte[] msg, int msglen, byte[] rho, byte[] encT1)
    {
        byte[] buf,
            mu = new byte[CrhBytes],
            c,
            c2 = new byte[DilithiumCTilde];
        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);
        PolyVecL z = new PolyVecL(this);
        PolyVecK t1 = new PolyVecK(this), w1 = new PolyVecK(this), h = new PolyVecK(this);

        if (siglen != CryptoBytes)
        {
            return false;
        }

        // System.out.println("publickey = ");
        // Helper.printByteArray(publicKey);

        t1 = Packing.unpackPublicKey(t1, encT1, this);

        // System.out.println(t1.toString("t1"));

        // System.out.println("rho = ");
        // Helper.printByteArray(rho);

        if (!Packing.unpackSignature(z, h, sig, this))
        {
            return false;
        }
        c = Arrays.copyOfRange(sig, 0, DilithiumCTilde);

        // System.out.println(z.toString("z"));
        // System.out.println(h.toString("h"));

        if (z.checkNorm(getDilithiumGamma1() - getDilithiumBeta()))
        {
            return false;
        }

        // Compute crh(crh(rho, t1), msg)
        shake256Digest.update(rho, 0, rho.length);
        shake256Digest.update(encT1, 0, encT1.length);
        shake256Digest.doFinal(mu, 0, TrBytes);
        // System.out.println("mu before = ");
        // Helper.printByteArray(mu);

        shake256Digest.update(mu, 0, TrBytes);
        shake256Digest.update(msg, 0, msglen);
        shake256Digest.doFinal(mu, 0);

        // System.out.println("mu after = ");
        // Helper.printByteArray(mu);

        // Matrix-vector multiplication; compute Az - c2^dt1
        cp.challenge(Arrays.copyOfRange(c, 0, SeedBytes));  // use only first SeedBytes of c.
        // System.out.println("cp = ");
        // System.out.println(cp.toString());

        aMatrix.expandMatrix(rho);
        // System.out.println(aMatrix.toString("aMatrix = "));


        z.polyVecNtt();
        aMatrix.pointwiseMontgomery(w1, z);

        cp.polyNtt();
        // System.out.println("cp = ");
        // System.out.println(cp.toString());

        t1.shiftLeft();
        t1.polyVecNtt();
        t1.pointwisePolyMontgomery(cp, t1);

        // System.out.println(t1.toString("t1"));

        w1.subtract(t1);
        w1.reduce();
        w1.invNttToMont();

        // System.out.println(w1.toString("w1 before caddq"));

        // Reconstruct w1
        w1.conditionalAddQ();
        // System.out.println(w1.toString("w1 before hint"));
        w1.useHint(w1, h);
        // System.out.println(w1.toString("w1"));

        buf = w1.packW1();

        // System.out.println("buf = ");
        // Helper.printByteArray(buf);

        // System.out.println("mu = ");
        // Helper.printByteArray(mu);

        SHAKEDigest shakeDigest256 = new SHAKEDigest(256);
        shakeDigest256.update(mu, 0, CrhBytes);
        shakeDigest256.update(buf, 0, DilithiumK * DilithiumPolyW1PackedBytes);
        shakeDigest256.doFinal(c2, 0, DilithiumCTilde);

        // System.out.println("c = ");
        // Helper.printByteArray(c);

        // System.out.println("c2 = ");
        // Helper.printByteArray(c2);


        for (int i = 0; i < DilithiumCTilde; ++i)
        {
            if (c[i] != c2[i])
            {
                return false;
            }
        }
        return true;
    }

    public boolean signOpen(byte[] msg, byte[] signedMsg, int signedMsglen, byte[] rho, byte[] t1)
    {
        return signVerify(signedMsg, signedMsglen, msg, msg.length, rho, t1);
    }
}
