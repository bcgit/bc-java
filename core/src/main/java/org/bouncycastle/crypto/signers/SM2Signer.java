package org.bouncycastle.crypto.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SM2 Digital Signature algorithm.
 */
public class SM2Signer
    implements Signer, ECConstants
{
    private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
    private final Digest digest;
    private final DSAEncoding encoding;

    private ECDomainParameters ecParams;
    private ECPoint pubPoint;
    private ECKeyParameters ecKey;
    private byte[] z;

    public SM2Signer()
    {
        this(StandardDSAEncoding.INSTANCE, new SM3Digest());
    }

    public SM2Signer(Digest digest)
    {
        this(StandardDSAEncoding.INSTANCE, digest);
    }

    public SM2Signer(DSAEncoding encoding)
    {
        this.encoding = encoding;
        this.digest = new SM3Digest();
    }

    public SM2Signer(DSAEncoding encoding, Digest digest)
    {
        this.encoding = encoding;
        this.digest = digest;
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        CipherParameters baseParam;
        byte[] userID;

        if (param instanceof ParametersWithID)
        {
            baseParam = ((ParametersWithID)param).getParameters();
            userID = ((ParametersWithID)param).getID();

            if (userID.length >= 8192)
            {
                throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
        }
        else
        {
            baseParam = param;
            // the default value, string value is "1234567812345678"
            userID = Hex.decodeStrict("31323334353637383132333435363738");
        }

        if (forSigning)
        {
            if (baseParam instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)baseParam;

                ecKey = (ECKeyParameters)rParam.getParameters();
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), rParam.getRandom());
            }
            else
            {
                ecKey = (ECKeyParameters)baseParam;
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
            }
            pubPoint = createBasePointMultiplier().multiply(ecParams.getG(), ((ECPrivateKeyParameters)ecKey).getD()).normalize();
        }
        else
        {
            ecKey = (ECKeyParameters)baseParam;
            ecParams = ecKey.getParameters();
            pubPoint = ((ECPublicKeyParameters)ecKey).getQ();
        }

        z = getZ(userID);
        
        digest.update(z, 0, z.length);
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public boolean verifySignature(byte[] signature)
    {
        try
        {
            BigInteger[] rs = encoding.decode(ecParams.getN(), signature);

            return verifySignature(rs[0], rs[1]);
        }
        catch (Exception e)
        {
        }

        return false;
    }

    public void reset()
    {
        digest.reset();

        if (z != null)
        {
            digest.update(z, 0, z.length);
        }
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        byte[] eHash = digestDoFinal();

        BigInteger n = ecParams.getN();
        BigInteger e = calculateE(n, eHash);
        BigInteger d = ((ECPrivateKeyParameters)ecKey).getD();

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                // A3
                k = kCalculator.nextK();

                // A4
                ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

                // A5
                r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
            }
            while (r.equals(ZERO) || r.add(k).equals(n));

            // A6
            BigInteger dPlus1ModN = BigIntegers.modOddInverse(n, d.add(ONE));

            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        }
        while (s.equals(ZERO));

        // A7
        try
        {
            return encoding.encode(ecParams.getN(), r, s);
        }
        catch (Exception ex)
        {
            throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
        }
    }

    private boolean verifySignature(BigInteger r, BigInteger s)
    {
        BigInteger n = ecParams.getN();

        // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
        // B1
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0)
        {
            return false;
        }

        // B2
        if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        // B3
        byte[] eHash = digestDoFinal();

        // B4
        BigInteger e = calculateE(n, eHash);

        // B5
        BigInteger t = r.add(s).mod(n);
        if (t.equals(ZERO))
        {
            return false;
        }

        // B6
        ECPoint q = ((ECPublicKeyParameters)ecKey).getQ();
        ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(ecParams.getG(), s, q, t).normalize();
        if (x1y1.isInfinity())
        {
            return false;
        }

        // B7
        BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);

        return expectedR.equals(r);
    }

    private byte[] digestDoFinal()
    {
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);

        reset();
        
        return result;
    }

    private byte[] getZ(byte[] userID)
    {
        digest.reset();

        addUserID(digest, userID);

        addFieldElement(digest, ecParams.getCurve().getA());
        addFieldElement(digest, ecParams.getCurve().getB());
        addFieldElement(digest, ecParams.getG().getAffineXCoord());
        addFieldElement(digest, ecParams.getG().getAffineYCoord());
        addFieldElement(digest, pubPoint.getAffineXCoord());
        addFieldElement(digest, pubPoint.getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];

        digest.doFinal(result, 0);

        return result;
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
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }

    protected BigInteger calculateE(BigInteger n, byte[] message)
    {
        // TODO Should hashes larger than the order be truncated as with ECDSA?
        return new BigInteger(1, message);
    }
}
