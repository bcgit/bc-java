package org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SM2 Digital Signature algorithm.
 */
public class SM2Signer
    implements Signer, ECConstants
{
    private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
    private final SM3Digest digest = new SM3Digest();

    private int curveLength;
    private ECDomainParameters ecParams;
    private ECPoint pubPoint;
    private ECKeyParameters ecKey;
    private byte[] z;

    public void init(boolean forSigning, CipherParameters param)
    {
        CipherParameters baseParam;
        byte[] userID;

        if (param instanceof ParametersWithID)
        {
            baseParam = ((ParametersWithID)param).getParameters();
            userID = ((ParametersWithID)param).getID();
        }
        else
        {
            baseParam = param;
            userID = Hex.decode("31323334353637383132333435363738"); // the default value
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
                kCalculator.init(ecParams.getN(), new SecureRandom());
            }
            pubPoint = ecParams.getG().multiply(((ECPrivateKeyParameters)ecKey).getD()).normalize();
        }
        else
        {
            ecKey = (ECKeyParameters)baseParam;
            ecParams = ecKey.getParameters();
            pubPoint = ((ECPublicKeyParameters)ecKey).getQ();
        }

        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;

        z = getZ(userID);

        reset();
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
            ASN1Sequence s = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(signature));
            if (s.size() != 2)
            {
                return false;
            }
            if (!Arrays.constantTimeAreEqual(signature, s.getEncoded(ASN1Encoding.DER)))
            {
                return false;
            }

            return verifySignature(ASN1Integer.getInstance(s.getObjectAt(0)).getValue(),
                ASN1Integer.getInstance(s.getObjectAt(1)).getValue());
        }
        catch (IOException e)
        {
            Arrays.constantTimeAreEqual(signature, signature);

            // TODO: maybe introduce arithmetic delay?
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
        digest.update(z, 0, z.length);
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        byte[] eHash = new byte[digest.getDigestSize()];

        digest.doFinal(eHash, 0);

        BigInteger n = ecParams.getN();
        BigInteger e = calculateE(eHash);
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
            BigInteger dPlus1ModN = d.add(ONE).modInverse(n);

            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        }
        while (s.equals(ZERO));

        // A7

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));

        try
        {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException ex)
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

        ECPoint q = ((ECPublicKeyParameters)ecKey).getQ();

        byte[] eHash = new byte[digest.getDigestSize()];

        // B3
        digest.doFinal(eHash, 0);

        // B4
        BigInteger e = calculateE(eHash);

        // B5
        BigInteger t = r.add(s).mod(n);
        if (t.equals(ZERO))
        {
            return false;
        }
        else
        {
            // B6
            ECPoint x1y1 = ecParams.getG().multiply(s);
            x1y1 = x1y1.add(q.multiply(t)).normalize();

            // B7
            return r.equals(e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n));
        }
    }

    private byte[] getZ(byte[] userID)
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

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }

    protected BigInteger calculateE(byte[] message)
    {
        return new BigInteger(1, message);
    }
}
