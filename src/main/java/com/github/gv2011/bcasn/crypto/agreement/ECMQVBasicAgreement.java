package com.github.gv2011.bcasn.crypto.agreement;

import java.math.BigInteger;

import com.github.gv2011.bcasn.crypto.BasicAgreement;
import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.params.ECDomainParameters;
import com.github.gv2011.bcasn.crypto.params.ECPrivateKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;
import com.github.gv2011.bcasn.crypto.params.MQVPrivateParameters;
import com.github.gv2011.bcasn.crypto.params.MQVPublicParameters;
import com.github.gv2011.bcasn.math.ec.ECAlgorithms;
import com.github.gv2011.bcasn.math.ec.ECConstants;
import com.github.gv2011.bcasn.math.ec.ECCurve;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.util.Properties;

public class ECMQVBasicAgreement
    implements BasicAgreement
{
    MQVPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (MQVPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        if (Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv"))
        {
            throw new IllegalStateException("ECMQV explicitly disabled");
        }

        MQVPublicParameters pubParams = (MQVPublicParameters)pubKey;

        ECPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

        ECPoint agreement = calculateMqvAgreement(staticPrivateKey.getParameters(), staticPrivateKey,
            privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getStaticPublicKey(), pubParams.getEphemeralPublicKey()).normalize();

        if (agreement.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
        }

        return agreement.getAffineXCoord().toBigInteger();
    }

    // The ECMQV Primitive as described in SEC-1, 3.4
    private ECPoint calculateMqvAgreement(
        ECDomainParameters      parameters,
        ECPrivateKeyParameters  d1U,
        ECPrivateKeyParameters  d2U,
        ECPublicKeyParameters   Q2U,
        ECPublicKeyParameters   Q1V,
        ECPublicKeyParameters   Q2V)
    {
        BigInteger n = parameters.getN();
        int e = (n.bitLength() + 1) / 2;
        BigInteger powE = ECConstants.ONE.shiftLeft(e);

        ECCurve curve = parameters.getCurve();

        ECPoint[] points = new ECPoint[]{
            // The Q2U public key is optional
            ECAlgorithms.importPoint(curve, Q2U == null ? parameters.getG().multiply(d2U.getD()) : Q2U.getQ()),
            ECAlgorithms.importPoint(curve, Q1V.getQ()),
            ECAlgorithms.importPoint(curve, Q2V.getQ())
        };

        curve.normalizeAll(points);

        ECPoint q2u = points[0], q1v = points[1], q2v = points[2];

        BigInteger x = q2u.getAffineXCoord().toBigInteger();
        BigInteger xBar = x.mod(powE);
        BigInteger Q2UBar = xBar.setBit(e);
        BigInteger s = d1U.getD().multiply(Q2UBar).add(d2U.getD()).mod(n);

        BigInteger xPrime = q2v.getAffineXCoord().toBigInteger();
        BigInteger xPrimeBar = xPrime.mod(powE);
        BigInteger Q2VBar = xPrimeBar.setBit(e);

        BigInteger hs = parameters.getH().multiply(s).mod(n);

        return ECAlgorithms.sumOfTwoMultiplies(
            q1v, Q2VBar.multiply(hs).mod(n), q2v, hs);
    }
}
