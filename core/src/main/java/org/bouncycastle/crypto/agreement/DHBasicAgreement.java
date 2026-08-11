package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;

/**
 * a Diffie-Hellman key agreement class.
 * <p>
 * note: This is only the basic algorithm, it doesn't take advantage of
 * long term public keys if they are available. See the DHAgreement class
 * for a "better" implementation.
 */
public class DHBasicAgreement
    implements BasicAgreement
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private DHPrivateKeyParameters  key;
    private DHParameters            dhParams;
    private SecureRandom            random;

    public void init(
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
            this.random = CryptoServicesRegistrar.getSecureRandom(rParam.getRandom());
        }
        else
        {
            kParam = (AsymmetricKeyParameter)param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        if (!(kParam instanceof DHPrivateKeyParameters))
        {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }

        this.key = (DHPrivateKeyParameters)kParam;
        this.dhParams = key.getParameters();

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("DHB", key));
    }

    public int getFieldSize()
    {
        return (key.getParameters().getP().bitLength() + 7) / 8;
    }

    /**
     * given a short term public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    public BigInteger calculateAgreement(
        CipherParameters   pubKey)
    {
        DHPublicKeyParameters   pub = (DHPublicKeyParameters)pubKey;

        if (!pub.getParameters().equals(dhParams))
        {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }

        BigInteger p = dhParams.getP();
        BigInteger pSub1 = p.subtract(ONE);

        BigInteger peerY = pub.getY();
        if (peerY == null || peerY.compareTo(ONE) <= 0 || peerY.compareTo(pSub1) >= 0)
        {
            throw new IllegalArgumentException("Diffie-Hellman public key is weak");
        }

        // peerY is peer-supplied and the exponent is our private value, which for static-static
        // agreement is long lived, so the exponent is blinded before the variable-time modPow sees
        // it. The multiple is of p-1 rather than of the subgroup order: peerY has only been range
        // checked here, so it need not lie in the order-q subgroup, and for a safe prime an odd
        // multiple of q would give the wrong shared secret for the values that do not.
        BigInteger blindedX = BigIntegers.createBlindedExponent(key.getX(), pSub1, random);

        BigInteger result = peerY.modPow(blindedX, p);
        if (result.equals(ONE))
        {
            throw new IllegalStateException("Shared key can't be 1");
        }

        return result;
    }
}
