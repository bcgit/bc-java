package org.bouncycastle.crypto.agreement;


import java.math.BigInteger;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public class MQVBasicAgreement
    implements BasicAgreement
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    DHMQVPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (DHMQVPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        DHMQVPublicParameters pubParams = (DHMQVPublicParameters)pubKey;

        DHPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

        if (!privParams.getStaticPrivateKey().getParameters().equals(pubParams.getStaticPublicKey().getParameters()))
        {
            throw new IllegalStateException("MQV public key components have wrong domain parameters");
        }

        if (privParams.getStaticPrivateKey().getParameters().getQ() == null)
        {
            throw new IllegalStateException("MQV key domain parameters do not have Q set");
        }

        BigInteger agreement = calculateDHMQVAgreement(staticPrivateKey.getParameters(), staticPrivateKey,
            pubParams.getStaticPublicKey(), privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getEphemeralPublicKey());

        if (agreement.equals(ONE))
        {
            throw new IllegalStateException("1 is not a valid agreement value for MQV");
        }

        return agreement;
    }

    private BigInteger calculateDHMQVAgreement(
        DHParameters parameters,
        DHPrivateKeyParameters xA,
        DHPublicKeyParameters yB,
        DHPrivateKeyParameters rA,
        DHPublicKeyParameters tA,
        DHPublicKeyParameters tB)
    {
        BigInteger q = parameters.getQ();

        int w = (q.bitLength() + 1) / 2;
        BigInteger twoW = BigInteger.valueOf(2).pow(w);

        BigInteger TA =  tA.getY().mod(twoW).add(twoW);
        BigInteger SA =  rA.getX().add(TA.multiply(xA.getX())).mod(q);
        BigInteger TB =  tB.getY().mod(twoW).add(twoW);
        BigInteger Z =   tB.getY().multiply(yB.getY().modPow(TB, parameters.getP())).modPow(SA, parameters.getP());

        return Z;
    }
}
