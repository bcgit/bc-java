package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

public class SNTRUPrimeKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final SNTRUPrimePrivateKeyParameters privateKey;

    public SNTRUPrimeKEMExtractor(SNTRUPrimePrivateKeyParameters privateKey)
    {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        SNTRUPrimeParameters params = privateKey.getParameters();

        int p = params.getP();
        int q = params.getQ();
        int w = params.getW();
        int roundedPolynomialBytes = params.getRoundedPolynomialBytes();

        /*
         * Decode(f)
         */
        byte[] f = new byte[p];
        Utils.getDecodedSmallPolynomial(f, privateKey.getF(), p);

        /*
         * Decode(ginv)
         */
        byte[] ginv = new byte[p];
        Utils.getDecodedSmallPolynomial(ginv, privateKey.getGinv(), p);

        /*
         * c = Decode(ct)
         */
        short[] c = new short[p];
        Utils.getRoundedDecodedPolynomial(c, encapsulation, p, q);

        /*
         *  Generate 3cf
         */
        short[] cf = new short[p];
        Utils.multiplicationInRQ(cf, c, f, p, q);

        short[] cf3 = new short[p];
        Utils.scalarMultiplicationInRQ(cf3, cf, 3, q);

        /*
         * Transform 3cf from RQ to R3
         */
        byte[] e = new byte[p];
        Utils.transformRQToR3(e, cf3);

        /*
         * ev = e.ginv in R3
         */
        byte[] ev = new byte[p];
        Utils.multiplicationInR3(ev, e, ginv, p);

        /*
         * Check if ev in R3 can be lifted to small polynomial with weight w
         */
        byte[] r = new byte[p];
        Utils.checkForSmallPolynomial(r, ev, p, w);

        /*
         * encR = Encode(r)
         */

        byte[] encR = new byte[(p + 3) / 4];
        Utils.getEncodedSmallPolynomial(encR, r, p);

        /*
         * h = Decode(pk)
         */
        short[] h = new short[p];
        Utils.getDecodedPolynomial(h, privateKey.getPk(), p, q);

        /*
         * cnew = Round(hr)
         */
        short[] hr = new short[p];
        Utils.multiplicationInRQ(hr, h, r, p, q);

        short[] cnew = new short[p];
        Utils.roundPolynomial(cnew, hr);

        /*
         * C = Encode(cnew)
         */
        byte[] C = new byte[roundedPolynomialBytes];
        Utils.getRoundedEncodedPolynomial(C, cnew, p, q);

        /*
         * hc = SHA-512(2 | SHA-512(3|encR)[0:32] | cache[0:32])
         */
        byte[] innerHCPrefix = {3};
        byte[] innerHCHash = Utils.getHashWithPrefix(innerHCPrefix, encR);

        byte[] hcInput = new byte[(innerHCHash.length / 2) + privateKey.getHash().length];
        System.arraycopy(innerHCHash, 0, hcInput, 0, innerHCHash.length / 2);
        System.arraycopy(privateKey.getHash(), 0, hcInput, innerHCHash.length / 2, privateKey.getHash().length);

        byte[] hcPrefix = {2};
        byte[] hc = Utils.getHashWithPrefix(hcPrefix, hcInput);

        /*
         * ct = C | hc[0:32]
         */
        byte[] ct = new byte[C.length + (hc.length / 2)];
        System.arraycopy(C, 0, ct, 0, C.length);
        System.arraycopy(hc, 0, ct, C.length, hc.length / 2);

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
         * ss = SHA-512((mask + 1) | SHA-512(3|encR)[0:32] | ct)[0:32]
         */
        byte[] innerSSPrefix = {3};
        byte[] innerSSHash = Utils.getHashWithPrefix(innerSSPrefix, encR);

        byte[] ssInput = new byte[(innerSSHash.length / 2) + ct.length];
        System.arraycopy(innerSSHash, 0, ssInput, 0, innerSSHash.length / 2);
        System.arraycopy(ct, 0, ssInput, innerSSHash.length / 2, ct.length);

        byte[] ssPrefix = {(byte)(mask + 1)};
        byte[] ssHash = Utils.getHashWithPrefix(ssPrefix, ssInput);

        return Arrays.copyOfRange(ssHash, 0, params.getSessionKeySize() / 8);
    }
    
    public int getEncapsulationLength()
    {
        return privateKey.getParameters().getRoundedPolynomialBytes() + 32;
    }
}
