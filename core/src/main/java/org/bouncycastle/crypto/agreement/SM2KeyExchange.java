package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * SM2 Key Exchange protocol - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 */
public class SM2KeyExchange
{
    private final Digest digest;

    private byte[] userID;
    private ECPrivateKeyParameters staticKey;
    private ECPoint staticPubPoint;
    private ECPoint ephemeralPubPoint;
    private ECDomainParameters ecParams;
    private int w;
    private ECPrivateKeyParameters ephemeralKey;
    private boolean initiator;

    public SM2KeyExchange()
    {
        this(new SM3Digest());
    }

    public SM2KeyExchange(Digest digest)
    {
        this.digest = digest;
    }

    public void init(
        CipherParameters privParam)
    {
        SM2KeyExchangePrivateParameters baseParam;

        if (privParam instanceof ParametersWithID)
        {
            baseParam = (SM2KeyExchangePrivateParameters)((ParametersWithID)privParam).getParameters();
            userID = ((ParametersWithID)privParam).getID();
        }
        else
        {
            baseParam = (SM2KeyExchangePrivateParameters)privParam;
            userID = new byte[0];
        }

        initiator = baseParam.isInitiator();
        staticKey = baseParam.getStaticPrivateKey();
        ephemeralKey = baseParam.getEphemeralPrivateKey();
        ecParams = staticKey.getParameters();
        staticPubPoint = baseParam.getStaticPublicPoint();
        ephemeralPubPoint = baseParam.getEphemeralPublicPoint();

        w = ecParams.getCurve().getFieldSize() / 2 - 1;
    }

    public byte[] calculateKey(int kLen, CipherParameters pubParam)
    {
        SM2KeyExchangePublicParameters otherPub;
        byte[] otherUserID;

        if (pubParam instanceof ParametersWithID)
        {
            otherPub = (SM2KeyExchangePublicParameters)((ParametersWithID)pubParam).getParameters();
            otherUserID = ((ParametersWithID)pubParam).getID();
        }
        else
        {
            otherPub = (SM2KeyExchangePublicParameters)pubParam;
            otherUserID = new byte[0];
        }

        byte[] za = getZ(digest, userID, staticPubPoint);
        byte[] zb = getZ(digest, otherUserID, otherPub.getStaticPublicKey().getQ());

        ECPoint U = calculateU(otherPub);

        byte[] rv;
        if (initiator)
        {
            rv = kdf(U, za, zb, kLen);
        }
        else
        {
            rv = kdf(U, zb, za, kLen);
        }

        return rv;
    }

    public byte[][] calculateKeyWithConfirmation(int kLen, byte[] confirmationTag, CipherParameters pubParam)
    {
        SM2KeyExchangePublicParameters otherPub;
        byte[] otherUserID;

        if (pubParam instanceof ParametersWithID)
        {
            otherPub = (SM2KeyExchangePublicParameters)((ParametersWithID)pubParam).getParameters();
            otherUserID = ((ParametersWithID)pubParam).getID();
        }
        else
        {
            otherPub = (SM2KeyExchangePublicParameters)pubParam;
            otherUserID = new byte[0];
        }

        if (initiator && confirmationTag == null)
        {
            throw new IllegalArgumentException("if initiating, confirmationTag must be set");
        }
        
        byte[] za = getZ(digest, userID, staticPubPoint);
        byte[] zb = getZ(digest, otherUserID, otherPub.getStaticPublicKey().getQ());

        ECPoint U = calculateU(otherPub);

        byte[] rv;
        if (initiator)
        {
            rv = kdf(U, za, zb, kLen);

            byte[] inner = calculateInnerHash(digest, U, za, zb, ephemeralPubPoint, otherPub.getEphemeralPublicKey().getQ());

            byte[] s1 = S1(digest, U, inner);

            if (!Arrays.constantTimeAreEqual(s1, confirmationTag))
            {
                throw new IllegalStateException("confirmation tag mismatch");
            }
            
            return new byte[][] { rv, S2(digest, U, inner)};
        }
        else
        {
            rv = kdf(U, zb, za, kLen);

            byte[] inner = calculateInnerHash(digest, U, zb, za, otherPub.getEphemeralPublicKey().getQ(), ephemeralPubPoint);

            return new byte[][] { rv, S1(digest, U, inner), S2(digest, U, inner) };
        }
    }

    private ECPoint calculateU(SM2KeyExchangePublicParameters otherPub)
    {
        ECDomainParameters params = staticKey.getParameters();

        ECPoint p1 = ECAlgorithms.cleanPoint(params.getCurve(), otherPub.getStaticPublicKey().getQ());
        ECPoint p2 = ECAlgorithms.cleanPoint(params.getCurve(), otherPub.getEphemeralPublicKey().getQ());

        BigInteger x1 = reduce(ephemeralPubPoint.getAffineXCoord().toBigInteger());
        BigInteger x2 = reduce(p2.getAffineXCoord().toBigInteger());
        BigInteger tA = staticKey.getD().add(x1.multiply(ephemeralKey.getD()));
        BigInteger k1 = ecParams.getH().multiply(tA).mod(ecParams.getN());
        BigInteger k2 = k1.multiply(x2).mod(ecParams.getN());

        return ECAlgorithms.sumOfTwoMultiplies(p1, k1, p2, k2).normalize();
    }

    private byte[] kdf(ECPoint u, byte[] za, byte[] zb, int klen)
    {
         int digestSize = digest.getDigestSize();
         byte[] buf = new byte[Math.max(4, digestSize)];
         byte[] rv = new byte[(klen + 7) / 8];
         int off = 0;

         Memoable memo = null;
         Memoable copy = null;

         if (digest instanceof Memoable)
         {
             addFieldElement(digest, u.getAffineXCoord());
             addFieldElement(digest, u.getAffineYCoord());
             digest.update(za, 0, za.length);
             digest.update(zb, 0, zb.length);
             memo = (Memoable)digest;
             copy = memo.copy();
         }

         int ct = 0;

         while (off < rv.length)
         {
             if (memo != null)
             {
                 memo.reset(copy);
             }
             else
             {
                 addFieldElement(digest, u.getAffineXCoord());
                 addFieldElement(digest, u.getAffineYCoord());
                 digest.update(za, 0, za.length);
                 digest.update(zb, 0, zb.length);
             }

             Pack.intToBigEndian(++ct, buf, 0);
             digest.update(buf, 0, 4);
             digest.doFinal(buf, 0);

             int copyLen = Math.min(digestSize, rv.length - off);
             System.arraycopy(buf, 0, rv, off, copyLen);
             off += copyLen;
         }

         return rv;
    }

    //x1~=2^w+(x1 AND (2^w-1))
    private BigInteger reduce(BigInteger x)
    {
        return x.and(BigInteger.valueOf(1).shiftLeft(w).subtract(BigInteger.valueOf(1))).setBit(w);
    }

    private byte[] S1(Digest digest, ECPoint u, byte[] inner)
    {
        digest.update((byte)0x02);
        addFieldElement(digest, u.getAffineYCoord());
        digest.update(inner, 0, inner.length);

        return digestDoFinal();
    }

    private byte[] calculateInnerHash(Digest digest, ECPoint u, byte[] za, byte[] zb, ECPoint p1, ECPoint p2)
    {
        addFieldElement(digest, u.getAffineXCoord());
        digest.update(za, 0, za.length);
        digest.update(zb, 0, zb.length);
        addFieldElement(digest, p1.getAffineXCoord());
        addFieldElement(digest, p1.getAffineYCoord());
        addFieldElement(digest, p2.getAffineXCoord());
        addFieldElement(digest, p2.getAffineYCoord());

        return digestDoFinal();
    }

    private byte[] S2(Digest digest, ECPoint u, byte[] inner)
    {
        digest.update((byte)0x03);
        addFieldElement(digest, u.getAffineYCoord());
        digest.update(inner, 0, inner.length);

        return digestDoFinal();
    }

    private byte[] getZ(Digest digest, byte[] userID, ECPoint pubPoint)
    {
        addUserID(digest, userID);

        addFieldElement(digest, ecParams.getCurve().getA());
        addFieldElement(digest, ecParams.getCurve().getB());
        addFieldElement(digest, ecParams.getG().getAffineXCoord());
        addFieldElement(digest, ecParams.getG().getAffineYCoord());
        addFieldElement(digest, pubPoint.getAffineXCoord());
        addFieldElement(digest, pubPoint.getAffineYCoord());

        return digestDoFinal();
    }

    private void addUserID(Digest digest, byte[] userID)
    {
        int len = userID.length * 8;

        digest.update((byte)(len >>> 8));
        digest.update((byte)len);
        digest.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement v)
    {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

    private byte[] digestDoFinal()
    {
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }
}
