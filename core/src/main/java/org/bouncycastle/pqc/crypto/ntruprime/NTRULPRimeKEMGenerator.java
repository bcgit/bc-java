package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;

public class NTRULPRimeKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    public NTRULPRimeKEMGenerator(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        NTRULPRimePublicKeyParameters publicKey = (NTRULPRimePublicKeyParameters)recipientKey;
        NTRULPRimeParameters params = publicKey.getParameters();

        int p = params.getP();
        int q = params.getQ();
        int w = params.getW();
        int roundedPolynomialBytes = params.getRoundedPolynomialBytes();
        int tau0 = params.getTau0();
        int tau1 = params.getTau1();

        /*
         * cache = SHA-512(4|pk)
         */
        byte[] cachePrefix = {4};
        byte[] cache = Utils.getHashWithPrefix(cachePrefix, publicKey.getEncoded());

        /*
         * Generate Random Inputs r
         * encR = Encode(r)
         */
        byte[] r = new byte[256];
        Utils.getRandomInputs(random, r);

        byte[] encR = new byte[32];
        Utils.getEncodedInputs(encR, r);

        /*
         * A = Decode(encA)
         */
        short[] A = new short[p];
        Utils.getRoundedDecodedPolynomial(A, publicKey.getRoundEncA(), p, q);

        /*
         * Generate Polynomial G in R/Q
         */
        short[] G = new short[p];
        Utils.generatePolynomialInRQFromSeed(G, publicKey.getSeed(), p, q);

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
         * B = Round(bG)
         * encB = Encode(B)
         */
        short[] bG = new short[p];
        Utils.multiplicationInRQ(bG, G, b, p, q);

        short[] B = new short[p];
        Utils.roundPolynomial(B, bG);

        byte[] encB = new byte[roundedPolynomialBytes];
        Utils.getRoundedEncodedPolynomial(encB, B, p, q);

        /*
         * T = Top(bA)
         * encT = Encode(T)
         */
        short[] bA = new short[p];
        Utils.multiplicationInRQ(bA, A, b, p, q);

        byte[] T = new byte[256];
        Utils.top(T, bA, r, q, tau0, tau1);

        byte[] encT = new byte[128];
        Utils.getTopEncodedPolynomial(encT, T);

        /*
         * hc = SHA-512(2 | encR | cache[0:32])
         */

        byte[] hcInput = new byte[encR.length + (cache.length / 2)];
        System.arraycopy(encR, 0, hcInput, 0, encR.length);
        System.arraycopy(cache, 0, hcInput, encR.length, cache.length / 2);

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
         * ss = SHA-512(1 | encR | ct)[0:32]
         */
        byte[] ssInput = new byte[encR.length + ct.length];
        System.arraycopy(encR, 0, ssInput, 0, encR.length);
        System.arraycopy(ct, 0, ssInput, encR.length, ct.length);

        byte[] ssPrefix = {1};
        byte[] ssHash = Utils.getHashWithPrefix(ssPrefix, ssInput);
        byte[] ss = Arrays.copyOfRange(ssHash, 0, params.getSessionKeySize() / 8);

        return new SecretWithEncapsulationImpl(ss, ct);
    }
}
