package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;

public class SNTRUPrimeKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    public SNTRUPrimeKEMGenerator(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        SNTRUPrimePublicKeyParameters publicKey = (SNTRUPrimePublicKeyParameters)recipientKey;
        SNTRUPrimeParameters params = publicKey.getParameters();

        int p = params.getP();
        int q = params.getQ();
        int w = params.getW();
        int roundedPolynomialBytes = params.getRoundedPolynomialBytes();

        /*
         * cache = SHA-512(4|pk)
         */
        byte[] cachePrefix = {4};
        byte[] cache = Utils.getHashWithPrefix(cachePrefix, publicKey.getEncoded());

        /*
         * Generate Random Short Polynomial r
         * encR = Encode(r)
         */
        byte[] r = new byte[p];
        Utils.getRandomShortPolynomial(random, r, p, w);

        byte[] encR = new byte[(p + 3) / 4];
        Utils.getEncodedSmallPolynomial(encR, r, p);

        /*
         * h = Decode(pk)
         */
        short[] h = new short[p];
        Utils.getDecodedPolynomial(h, publicKey.getEncH(), p, q);

        /*
         * c = Round(hr)
         */
        short[] hr = new short[p];
        Utils.multiplicationInRQ(hr, h, r, p, q);

        short[] c = new short[p];
        Utils.roundPolynomial(c, hr);

        /*
         * C = Encode(c)
         */
        byte[] C = new byte[roundedPolynomialBytes];
        Utils.getRoundedEncodedPolynomial(C, c, p, q);

        /*
         * hc = SHA-512(2 | SHA-512(3|encR)[0:32] | cache[0:32])
         */
        byte[] innerHCPrefix = {3};
        byte[] innerHCHash = Utils.getHashWithPrefix(innerHCPrefix, encR);

        byte[] hcInput = new byte[(innerHCHash.length / 2) + (cache.length / 2)];
        System.arraycopy(innerHCHash, 0, hcInput, 0, innerHCHash.length / 2);
        System.arraycopy(cache, 0, hcInput, innerHCHash.length / 2, cache.length / 2);

        byte[] hcPrefix = {2};
        byte[] hc = Utils.getHashWithPrefix(hcPrefix, hcInput);

        /*
         * ct = C | hc[0:32]
         */
        byte[] ct = new byte[C.length + (hc.length / 2)];
        System.arraycopy(C, 0, ct, 0, C.length);
        System.arraycopy(hc, 0, ct, C.length, hc.length / 2);

        /*
         * ss = SHA-512(1 | SHA-512(3|encR)[0:32] | ct)[0:32]
         */
        byte[] innerSSPrefix = {3};
        byte[] innerSSHash = Utils.getHashWithPrefix(innerSSPrefix, encR);

        byte[] ssInput = new byte[(innerSSHash.length / 2) + ct.length];
        System.arraycopy(innerSSHash, 0, ssInput, 0, innerSSHash.length / 2);
        System.arraycopy(ct, 0, ssInput, innerSSHash.length / 2, ct.length);

        byte[] ssPrefix = {1};
        byte[] ssHash = Utils.getHashWithPrefix(ssPrefix, ssInput);
        byte[] ss = Arrays.copyOfRange(ssHash, 0, params.getSessionKeySize() / 8);

        return new SecretWithEncapsulationImpl(ss, ct);
    }
}
