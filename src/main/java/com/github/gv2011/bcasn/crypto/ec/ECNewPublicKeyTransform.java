package com.github.gv2011.bcasn.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.params.ECDomainParameters;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ParametersWithRandom;
import com.github.gv2011.bcasn.math.ec.ECMultiplier;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.math.ec.FixedPointCombMultiplier;

/**
 * this does your basic Elgamal encryption algorithm using EC
 */
public class ECNewPublicKeyTransform
    implements ECPairTransform
{
    private ECPublicKeyParameters key;
    private SecureRandom          random;

    /**
     * initialise the EC Elgamal engine.
     *
     * @param param the necessary EC key parameters.
     */
    public void init(
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            if (!(p.getParameters() instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
            }
            this.key = (ECPublicKeyParameters)p.getParameters();
            this.random = p.getRandom();
        }
        else
        {
            if (!(param instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
            }

            this.key = (ECPublicKeyParameters)param;
            this.random = new SecureRandom();
        }
    }

    /**
     * Transform an existing cipher text pair using the ElGamal algorithm. Note: the input cipherText will
     * need to be preserved in order to complete the transformation to the new public key.
     *
     * @param cipherText the EC point to process.
     * @return returns a new ECPair representing the result of the process.
     */
    public ECPair transform(ECPair cipherText)
    {
        if (key == null)
        {
            throw new IllegalStateException("ECNewPublicKeyTransform not initialised");
        }

        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();

        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        BigInteger k = ECUtil.generateK(n, random);

        ECPoint[] gamma_phi = new ECPoint[]{
            basePointMultiplier.multiply(ec.getG(), k),
            key.getQ().multiply(k).add(cipherText.getY())
        };

        ec.getCurve().normalizeAll(gamma_phi);

        return new ECPair(gamma_phi[0], gamma_phi[1]);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
