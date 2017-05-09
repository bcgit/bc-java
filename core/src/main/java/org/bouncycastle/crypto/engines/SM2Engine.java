package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM2 public key encryption engine - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
 */
public class SM2Engine
{
    private final Digest digest;
    
    private boolean forEncryption;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private SecureRandom random;

    public SM2Engine()
    {
        this(new SM3Digest());
    }

    public SM2Engine(Digest digest)
    {
        this.digest = digest;
    }

    public void init(boolean forEncryption, CipherParameters param)
    {
        this.forEncryption = forEncryption;

        if (forEncryption)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            ecKey = (ECKeyParameters)rParam.getParameters();
            ecParams = ecKey.getParameters();

            ECPoint s = ((ECPublicKeyParameters)ecKey).getQ().multiply(ecParams.getH());
            if (s.isInfinity())
            {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }

            random = rParam.getRandom();
        }
        else
        {
            ecKey = (ECKeyParameters)param;
            ecParams = ecKey.getParameters();
        }

        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] processBlock(
        byte[] in,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            return encrypt(in, inOff, inLen);
        }
        else
        {
            return decrypt(in, inOff, inLen);
        }
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] c2 = new byte[inLen];

        System.arraycopy(in, inOff, c2, 0, c2.length);

        byte[] c1;
        ECPoint kPB;
        do
        {
            BigInteger k = nextK();

            ECPoint c1P = ecParams.getG().multiply(k).normalize();

            c1 = c1P.getEncoded(false);

            kPB = ((ECPublicKeyParameters)ecKey).getQ().multiply(k).normalize();

            kdf(digest, kPB, c2);
        }
        while (notEncrypted(c2, in, inOff));

        byte[] c3 = new byte[digest.getDigestSize()];

        addFieldElement(digest, kPB.getAffineXCoord());
        digest.update(in, inOff, inLen);
        addFieldElement(digest, kPB.getAffineYCoord());

        digest.doFinal(c3, 0);
        
        return Arrays.concatenate(c1, c2, c3);
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] c1 = new byte[curveLength * 2 + 1];

        System.arraycopy(in, inOff, c1, 0, c1.length);

        ECPoint c1P = ecParams.getCurve().decodePoint(c1);

        ECPoint s = c1P.multiply(ecParams.getH());
        if (s.isInfinity())
        {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        }

        c1P = c1P.multiply(((ECPrivateKeyParameters)ecKey).getD()).normalize();

        byte[] c2 = new byte[inLen - c1.length - digest.getDigestSize()];

        System.arraycopy(in, inOff + c1.length, c2, 0, c2.length);

        kdf(digest, c1P, c2);

        byte[] c3 = new byte[digest.getDigestSize()];

        addFieldElement(digest, c1P.getAffineXCoord());
        digest.update(c2, 0, c2.length);
        addFieldElement(digest, c1P.getAffineYCoord());

        digest.doFinal(c3, 0);

        int check = 0;
        for (int i = 0; i != c3.length; i++)
        {
            check |= c3[i] ^ in[c1.length + c2.length + i];
        }

        clearBlock(c1);
        clearBlock(c3);

        if (check != 0)
        {
           clearBlock(c2);
           throw new InvalidCipherTextException("invalid cipher text");
        }

        return c2;
    }

    private boolean notEncrypted(byte[] encData, byte[] in, int inOff)
    {
        for (int i = 0; i != encData.length; i++)
        {
            if (encData[i] != in[inOff])
            {
                return false;
            }
        }

        return true;
    }

    private void kdf(Digest digest, ECPoint c1, byte[] encData)
    {
        int ct = 1;
        int v = digest.getDigestSize();

        byte[] buf = new byte[digest.getDigestSize()];
        int off = 0;

        for (int i = 1; i <= ((encData.length + v - 1) / v); i++)
        {
            addFieldElement(digest, c1.getAffineXCoord());
            addFieldElement(digest, c1.getAffineYCoord());
            digest.update((byte)(ct >> 24));
            digest.update((byte)(ct >> 16));
            digest.update((byte)(ct >> 8));
            digest.update((byte)ct);

            digest.doFinal(buf, 0);

            if (off + buf.length < encData.length)
            {
                xor(encData, buf, off, buf.length);
            }
            else
            {
                xor(encData, buf, off, encData.length - off);
            }

            off += buf.length;
            ct++;
        }
    }

    private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining)
    {
        for (int i = 0; i != dRemaining; i++)
        {
            data[dOff + i] ^= kdfOut[i];
        }
    }

    private BigInteger nextK()
    {
        int qBitLength = ecParams.getN().bitLength();

        BigInteger k;
        do
        {
            k = new BigInteger(qBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || k.compareTo(ecParams.getN()) >= 0);

        return k;
    }

    private void addFieldElement(Digest digest, ECFieldElement v)
    {
        byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v.toBigInteger());

        digest.update(p, 0, p.length);
    }

    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }
}
