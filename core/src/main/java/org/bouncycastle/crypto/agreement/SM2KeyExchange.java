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
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

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
    private int curveLength;
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

        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;
        w = ecParams.getCurve().getFieldSize() / 2 - 1;
    }

    public int getFieldSize()
    {
        return (staticKey.getParameters().getCurve().getFieldSize() + 7) / 8;
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
        BigInteger x1 = reduce(ephemeralPubPoint.getAffineXCoord().toBigInteger());

        BigInteger tA = staticKey.getD().add(x1.multiply(ephemeralKey.getD())).mod(ecParams.getN());

        BigInteger x2 = reduce(otherPub.getEphemeralPublicKey().getQ().getAffineXCoord().toBigInteger());

        ECPoint B0 = otherPub.getEphemeralPublicKey().getQ().multiply(x2).normalize();

        ECPoint B1 = otherPub.getStaticPublicKey().getQ().add(B0).normalize();

        return B1.multiply(ecParams.getH().multiply(tA)).normalize();
    }

    private byte[] kdf(ECPoint u, byte[] za, byte[] zb, int klen)
    {
         int ct = 1;
         int v = digest.getDigestSize() * 8;

         byte[] buf = new byte[digest.getDigestSize()];
         byte[] rv = new byte[(klen + 7) / 8];
         int off = 0;

         for (int i = 1; i <= ((klen + v - 1) / v); i++)
         {
             addFieldElement(digest, u.getAffineXCoord());
             addFieldElement(digest, u.getAffineYCoord());
             digest.update(za, 0, za.length);
             digest.update(zb, 0, zb.length);
             digest.update((byte)(ct >> 24));
             digest.update((byte)(ct >> 16));
             digest.update((byte)(ct >> 8));
             digest.update((byte)ct);

             digest.doFinal(buf, 0);

             if (off + buf.length < rv.length)
             {
                 System.arraycopy(buf, 0, rv, off, buf.length);
             }
             else
             {
                 System.arraycopy(buf, 0, rv, off, rv.length - off);
             }

             off += buf.length;
             ct++;
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
        byte[] rv = new byte[digest.getDigestSize()];

        digest.update((byte)0x02);
        addFieldElement(digest, u.getAffineYCoord());
        digest.update(inner, 0, inner.length);

        digest.doFinal(rv, 0);

        return rv;
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

        byte[] rv = new byte[digest.getDigestSize()];

        digest.doFinal(rv, 0);
        return rv;
    }

    private byte[] S2(Digest digest, ECPoint u, byte[] inner)
    {
        byte[] rv = new byte[digest.getDigestSize()];

        digest.update((byte)0x03);
        addFieldElement(digest, u.getAffineYCoord());
        digest.update(inner, 0, inner.length);

        digest.doFinal(rv, 0);

        return rv;
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

        byte[] rv = new byte[digest.getDigestSize()];

        digest.doFinal(rv, 0);

        return rv;
    }

    private void addUserID(Digest digest, byte[] userID)
    {
        int len = userID.length * 8;

        digest.update((byte)(len >> 8 & 0xFF));
        digest.update((byte)(len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement v)
    {
        byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v.toBigInteger());

        digest.update(p, 0, p.length);
    }
}
