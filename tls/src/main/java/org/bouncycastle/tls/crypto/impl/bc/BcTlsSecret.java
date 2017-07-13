package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * BC light-weight support class for handling TLS secrets and deriving key material and other secrets from them.
 */
public class BcTlsSecret
    extends AbstractTlsSecret
{
    protected final BcTlsCrypto crypto;

    public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    protected AbstractTlsCrypto getCrypto()
    {
        return crypto;
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length)
    {
        checkAlive();

        byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);

        byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            ?   prf_1_0(data, labelSeed, length)
            :   prf_1_2(crypto.createPRFHash(prfAlgorithm), data, labelSeed, length);

        return crypto.adoptLocalSecret(result);
    }

    protected void hmacHash(Digest digest, byte[] secret, byte[] seed, byte[] output)
    {
        HMac mac = new HMac(digest);
        mac.init(new KeyParameter(secret));
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (output.length + size - 1) / size;
        byte[] b1 = new byte[mac.getMacSize()];
        byte[] b2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, (size * i), Math.min(size, output.length - (size * i)));
        }
    }

    protected byte[] prf_1_0(byte[] secret, byte[] labelSeed, int length)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[length];
        byte[] b2 = new byte[length];
        hmacHash(crypto.createDigest(HashAlgorithm.md5), s1, labelSeed, b1);
        hmacHash(crypto.createDigest(HashAlgorithm.sha1), s2, labelSeed, b2);
        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(Digest prfDigest, byte[] secret, byte[] labelSeed, int length)
    {
        byte[] result = new byte[length];
        hmacHash(prfDigest, secret, labelSeed, result);
        return result;
    }
}
