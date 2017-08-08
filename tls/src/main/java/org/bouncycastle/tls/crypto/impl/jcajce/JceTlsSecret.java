package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * JCE support class for handling TLS secrets and deriving key material and other secrets from them.
 */
public class JceTlsSecret
    extends AbstractTlsSecret
{
    protected final JcaTlsCrypto crypto;

    public JceTlsSecret(JcaTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length)
    {
        checkAlive();

        byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);

        try
        {
            byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
                ? prf_1_0(data, labelSeed, length)
                : prf_1_2(prfAlgorithm, data, labelSeed, length);

            return crypto.adoptLocalSecret(result);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(); // TODO
        }
    }

    protected AbstractTlsCrypto getCrypto()
    {
        return crypto;
    }

    protected void hmacHash(String digestName, byte[] secret, int secretOff, int secretLen, byte[] seed, byte[] output)
        throws GeneralSecurityException
    {
        String macName = "Hmac" + digestName;
        Mac mac = crypto.getHelper().createMac(macName);
        mac.init(new SecretKeySpec(secret, secretOff, secretLen, macName));

        byte[] a = seed;

        int macSize = mac.getMacLength();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }
    }

    protected byte[] prf_1_0(byte[] secret, byte[] labelSeed, int length)
        throws GeneralSecurityException
    {
        int s_half = (secret.length + 1) / 2;

        byte[] b1 = new byte[length];
        hmacHash("MD5", secret, 0, s_half, labelSeed, b1);

        byte[] b2 = new byte[length];
        hmacHash("SHA1", secret, secret.length - s_half, s_half, labelSeed, b2);

        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(int prfAlgorithm, byte[] secret, byte[] labelSeed, int length)
        throws GeneralSecurityException
    {
        String digestName = crypto.getDigestName(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm)).replace("-", "");
        byte[] result = new byte[length];
        hmacHash(digestName, secret, 0, secret.length, labelSeed, result);
        return result;
    }
}
