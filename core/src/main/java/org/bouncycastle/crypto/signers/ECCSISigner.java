package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECCSIPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class ECCSISigner
    implements Signer
{
    private static final X9ECParameters params = CustomNamedCurves.getByName("secP256r1");
    private static final ECCurve curve = params.getCurve();

    private static final BigInteger q = ((ECCurve.Fp)curve).getQ();

    //BigInteger p = ((ECCurve.Fp)curve).getOrder();

    // The subgroup order is available as:
    //BigInteger n = params.getN();

    // And the base point (generator) is:
    private static final ECPoint G = params.getG();
    private final Digest digest = new SHA256Digest();
    BigInteger j;
    ECPoint J;
    BigInteger r;

    public ECCSISigner()
    {

    }

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        SecureRandom random = null;
        if (param instanceof ParametersWithRandom)
        {
            random = ((ParametersWithRandom)param).getRandom();
            param = ((ParametersWithRandom)param).getParameters();
        }

        if (forSigning)
        {
            ECCSIPrivateKeyParameters parameters = (ECCSIPrivateKeyParameters)param;

            j = new BigInteger(256, random).mod(q);
            J = G.multiply(j).normalize();
            r = J.getAffineXCoord().toBigInteger();
            byte[] rBytes = BigIntegers.asUnsignedByteArray(256, r);
//            BigInteger kpak = parameters
            byte[] tmp = G.getEncoded(false);
            digest.update(tmp, 0, tmp.length);
//            tmp = kpak.getEncoded(false);
//            digest.update(tmp, 0, tmp.length);
//            digest.update(id, 0, id.length);
//            tmp = pvt.getEncoded(false);
//            digest.update(tmp, 0, tmp.length);
            tmp = new byte[digest.getDigestSize()];
            digest.doFinal(tmp, 0);
            BigInteger HS = new BigInteger(1, tmp).mod(q);
        }

    }

    @Override
    public void update(byte b)
    {

    }

    @Override
    public void update(byte[] in, int off, int len)
    {

    }

    @Override
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        return new byte[0];
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        return false;
    }

    @Override
    public void reset()
    {

    }
}
