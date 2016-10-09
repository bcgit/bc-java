package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * JCE support class for handling TLS secrets and deriving key material and other secrets from them.
 */
public class JceTlsSecret
    extends AbstractTlsSecret
{
    private final JcaTlsCrypto crypto;

    public JceTlsSecret(JcaTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    public synchronized TlsSecret deriveSSLKeyBlock(byte[] seed, int length)
    {
        checkAlive();

        try
        {
            int md5Count = (length + MD5_SIZE - 1) / MD5_SIZE;
            byte[] md5Buf = prf_SSL(seed, md5Count);

            TlsSecret result = crypto.adoptLocalSecret(Arrays.copyOfRange(md5Buf, 0, length));
            Arrays.fill(md5Buf, (byte)0);
            return result;
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException(); // TODO:
        }
    }

    public synchronized TlsSecret deriveSSLMasterSecret(byte[] seed)
    {
        checkAlive();
        try
        {
            return crypto.adoptLocalSecret(prf_SSL(seed, 3));
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException(); // TODO:
        }
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, byte[] labelSeed, int length)
    {
        checkAlive();

        try
        {
            byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
                ? prf_1_0(data, labelSeed, length)
                : prf_1_2(crypto.getDigestName(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm)), data, labelSeed, length);

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

    protected void hmacHash(String digestName, byte[] secret, byte[] seed, byte[] output)
        throws GeneralSecurityException
    {
        String macName = "Hmac" + digestName;
        Mac mac = crypto.getHelper().createMac(macName);
        mac.init(new SecretKeySpec(secret, macName));
        byte[] a = seed;
        int size = mac.getMacLength();
        int iterations = (output.length + size - 1) / size;
        byte[] b1 = new byte[mac.getMacLength()];
        byte[] b2 = new byte[mac.getMacLength()];
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

    protected byte[] prf_SSL(byte[] seed, int md5Count)
        throws GeneralSecurityException
    {
        MessageDigest md5 = crypto.getHelper().createDigest("MD5");
        MessageDigest sha1 = crypto.getHelper().createDigest("SHA-1");

        int md5Size = md5.getDigestLength();
        byte[] md5Buf = new byte[md5Size * md5Count];
        int md5Pos = 0;

        byte[] sha1Buf = new byte[sha1.getDigestLength()];

        for (int i = 0; i < md5Count; ++i)
        {
            byte[] ssl3Const = SSL3_CONST[i];

            sha1.update(ssl3Const, 0, ssl3Const.length);
            sha1.update(data, 0, data.length);
            sha1.update(seed, 0, seed.length);
            sha1.digest(sha1Buf, 0, sha1Buf.length);

            md5.update(data, 0, data.length);
            md5.update(sha1Buf, 0, sha1Buf.length);
            md5.digest(md5Buf, md5Pos, md5Size);

            md5Pos += md5Size;
        }

        return md5Buf;
    }

    protected byte[] prf_1_0(byte[] secret, byte[] labelSeed, int length)
        throws GeneralSecurityException
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[length];
        byte[] b2 = new byte[length];
        hmacHash("MD5", s1, labelSeed, b1);
        hmacHash("SHA1", s2, labelSeed, b2);
        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(String prfDigest, byte[] secret, byte[] labelSeed, int length)
        throws GeneralSecurityException
    {
        byte[] result = new byte[length];
        hmacHash(prfDigest.replace("-", ""), secret, labelSeed, result);
        return result;
    }
}
