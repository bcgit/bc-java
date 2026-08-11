package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;

public class MQVBasicAgreement
    implements BasicAgreement
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private SecureRandom random;

    DHMQVPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        if (key instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)key;

            this.privParams = (DHMQVPrivateParameters)rParam.getParameters();
            this.random = CryptoServicesRegistrar.getSecureRandom(rParam.getRandom());
        }
        else
        {
            this.privParams = (DHMQVPrivateParameters)key;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("MQV", this.privParams.getStaticPrivateKey()));
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

        // SA carries the static private key, and the base below is built entirely from values the
        // other party supplied, so the exponent is blinded before the variable-time modPow sees it.
        // TB is derived from a public value and is left alone.
        //
        // A multiple of q is sound here, rather than of p-1, because every value in that base has
        // been checked to lie in the order-q subgroup before it arrives: calculateAgreement requires
        // q to be present and the peer's static parameters to equal ours, DHMQVPublicParameters
        // requires the peer's two public keys to share domain parameters, and
        // DHPublicKeyParameters rejects a y outside the subgroup whenever q is present. A product of
        // subgroup elements is a subgroup element, so base^q = 1. q also keeps the exponent the size
        // of SA, which is already reduced mod q - blinding with p-1 would grow it to the size of p.
        BigInteger blindedSA = BigIntegers.createBlindedExponent(SA, q, random);

        BigInteger Z =   tB.getY().multiply(yB.getY().modPow(TB, parameters.getP())).modPow(blindedSA, parameters.getP());

        return Z;
    }
}
