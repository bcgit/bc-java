package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

public class NTRULPRimeKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final NTRULPRimePrivateKeyParameters privateKey;

    public NTRULPRimeKEMExtractor(NTRULPRimePrivateKeyParameters privateKey)
    {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        NTRULPRimeParameters params = privateKey.getParameters();

        int p = params.getP();
        int q = params.getQ();
        int w = params.getW();
        int roundedPolynomialBytes = params.getRoundedPolynomialBytes();
        int tau0 = params.getTau0();
        int tau1 = params.getTau1();
        int tau2 = params.getTau2();
        int tau3 = params.getTau3();

        /*
         * a = Decode(pk)
         */
        byte[] a = new byte[p];
        Utils.getDecodedSmallPolynomial(a, privateKey.getEncoded(), p);

        /*
         * B = Decode(encB)
         */
        byte[] encB = new byte[roundedPolynomialBytes];
        System.arraycopy(encapsulation, 0, encB, 0, roundedPolynomialBytes);

        short[] B = new short[p];
        Utils.getRoundedDecodedPolynomial(B, encB, p, q);

        /*
         * T = Decode(encT)
         */
        byte[] encT = new byte[128];
        System.arraycopy(encapsulation, roundedPolynomialBytes, encT, 0,encT.length);

        byte[] T = new byte[256];
        Utils.getTopDecodedPolynomial(T, encT);

        /*
         * r = Right(aB, T)
         */
        short[] aB = new short[p];
        Utils.multiplicationInRQ(aB, B, a, p, q);

        byte[] r = new byte[256];
        Utils.right(r, aB, T, q, w, tau2, tau3);

        /*
         * encR = Encode(r)
         */
        byte[] encR = new byte[32];
        Utils.getEncodedInputs(encR, r);

        /*
         * A = Decode(encA)
         */
        byte[] encA = new byte[params.getPublicKeyBytes() - 32];
        System.arraycopy(privateKey.getPk(), 32, encA, 0, encA.length);

        short[] A = new short[p];
        Utils.getRoundedDecodedPolynomial(A, encA, p, q);

        /*
         * Generate Polynomial G in R/Q
         */
        byte[] seed = new byte[32];
        System.arraycopy(privateKey.getPk(), 0, seed, 0, seed.length);

        short[] G = new short[p];
        Utils.generatePolynomialInRQFromSeed(G, seed, p, q);

        /*
         * hs = SHA-512(5|encR)[0:32]
         */
        byte[] hsPrefix = {5};
        byte[] hsHash = Utils.getHashWithPrefix(hsPrefix, encR);
        byte[] hs = Arrays.copyOfRange(hsHash, 0, hsHash.length / 2);

        /*
         * L = Expand(hs)
         * Generate short polynomial b from L by sorting
         */
        int[] L = new int[p];
        Utils.expand(L, hs);

        byte[] b = new byte[p];
        Utils.sortGenerateShortPolynomial(b, L, p, w);

        /*
         * Bnew = Round(bG)
         * encBnew = Encode(Bnew)
         */
        short[] bG = new short[p];
        Utils.multiplicationInRQ(bG, G, b, p, q);

        short[] Bnew = new short[p];
        Utils.roundPolynomial(Bnew, bG);

        byte[] encBnew = new byte[roundedPolynomialBytes];
        Utils.getRoundedEncodedPolynomial(encBnew, Bnew, p, q);

        /*
         * Tnew = Top(bA)
         * encTnew = Encode(Tnew)
         */
        short[] bA = new short[p];
        Utils.multiplicationInRQ(bA, A, b, p, q);

        byte[] Tnew = new byte[256];
        Utils.top(Tnew, bA, r, q, tau0, tau1);

        byte[] encTnew = new byte[128];
        Utils.getTopEncodedPolynomial(encTnew, T);

        /*
         * hc = SHA-512(2 | encR | cache[0:32])
         */

        byte[] hcInput = new byte[encR.length + (privateKey.getHash().length)];
        System.arraycopy(encR, 0, hcInput, 0, encR.length);
        System.arraycopy(privateKey.getHash(), 0, hcInput, encR.length, privateKey.getHash().length);

        byte[] hcPrefix = {2};
        byte[] hc = Utils.getHashWithPrefix(hcPrefix, hcInput);

        /*
         * ct = encB | encT | hc[0:32]
         */
        byte[] ct = new byte[encB.length + encT.length + (hc.length / 2)];
        System.arraycopy(encB, 0, ct, 0, encB.length);
        System.arraycopy(encT, 0, ct, encB.length, encT.length);
        System.arraycopy(hc, 0, ct, encB.length + encT.length, hc.length / 2);

        /*
         * Match Ciphertext ct with input encapsulation
         * Update encR accordingly
         */
        int mask = (Arrays.areEqual(encapsulation, ct)) ? 0 : -1;

        /*
         * Update encR with Ciphertext diff mask
         */
        Utils.updateDiffMask(encR, privateKey.getRho(), mask);

        /*
         * ss = SHA-512(1 | encR | ct)[0:32]
         */
        byte[] ssInput = new byte[encR.length + ct.length];
        System.arraycopy(encR, 0, ssInput, 0, encR.length);
        System.arraycopy(ct, 0, ssInput, encR.length, ct.length);

        byte[] ssPrefix = {1};
        byte[] ssHash = Utils.getHashWithPrefix(ssPrefix, ssInput);

        return Arrays.copyOfRange(ssHash, 0, params.getSessionKeySize() / 8);
    }

    public int getEncapsulationLength()
    {
        return privateKey.getParameters().getRoundedPolynomialBytes() + 128 + 32;
    }
}
