package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;

/**
 * a Diffie-Hellman key exchange engine.
 * <p>
 * note: This uses MTI/A0 key agreement in order to make the key agreement
 * secure against passive attacks. If you're doing Diffie-Hellman and both
 * parties have long term public keys you should look at using this. For
 * further information have a look at RFC 2631.
 * <p>
 * It's possible to extend this to more than two parties as well, for the moment
 * that is left as an exercise for the reader.
 */
public class DHAgreement
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private DHPrivateKeyParameters  key;
    private DHParameters            dhParams;
    private BigInteger              privateValue;
    private SecureRandom            random;

    public void init(
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            kParam = (AsymmetricKeyParameter)param;
        }

        
        if (!(kParam instanceof DHPrivateKeyParameters))
        {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }

        this.key = (DHPrivateKeyParameters)kParam;
        this.dhParams = key.getParameters();

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("DH", key));
    }

    /**
     * calculate our initial message.
     */
    public BigInteger calculateMessage()
    {
        DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(random, dhParams));
        AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();

        this.privateValue = ((DHPrivateKeyParameters)dhPair.getPrivate()).getX();

        return ((DHPublicKeyParameters)dhPair.getPublic()).getY();
    }

    /**
     * given a message from a given party and the corresponding public key,
     * calculate the next message in the agreement sequence. In this case
     * this will represent the shared secret.
     */
    public BigInteger calculateAgreement(DHPublicKeyParameters pub, BigInteger message)
    {
        if (pub == null)
        {
            throw new NullPointerException("'pub' cannot be null");
        }
        if (message == null)
        {
            throw new NullPointerException("'message' cannot be null");
        }

        if (!pub.getParameters().equals(dhParams))
        {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }

        BigInteger p = dhParams.getP();

        // Both peer-supplied values are raised to our (potentially static) private key, so both must
        // satisfy the DH public-value range/subgroup checks; otherwise a peer can submit a small-order
        // or out-of-range element to mount a small-subgroup confinement attack and, when our private
        // key is reused, recover it via CRT. The 'message' is a raw BigInteger, so validate it by
        // construction. A normally-constructed DHPublicKeyParameters already validated its Y; but Y is
        // virtual and a subclass can override it to return an unvalidated value, so re-validate unless
        // pub is exactly the base type.
        BigInteger peerMessage = new DHPublicKeyParameters(message, dhParams).getY();

        BigInteger peerY = pub.getClass() == DHPublicKeyParameters.class
            ? pub.getY()
            : new DHPublicKeyParameters(pub.getY(), dhParams).getY();

        // Both bases are peer-supplied and both exponents are private - privateValue is this run's
        // ephemeral, key.getX() is the long-term key - so both exponents are blinded before the
        // variable-time modPow. The multiples are of p-1 rather than of the subgroup order: the
        // DHPublicKeyParameters construction above only checks the subgroup when the parameters carry
        // q, so a base outside the order-q subgroup is possible, and for a safe prime an odd multiple
        // of q would give the wrong shared secret for such a base.
        BigInteger pSub1 = p.subtract(ONE);

        BigInteger blindedPrivateValue = BigIntegers.createBlindedExponent(privateValue, pSub1, random);

        BigInteger result = peerY.modPow(blindedPrivateValue, p);
        if (result.equals(ONE))
        {
            throw new IllegalStateException("Shared key can't be 1");
        }

        BigInteger blindedX = BigIntegers.createBlindedExponent(key.getX(), pSub1, random);

        return peerMessage.modPow(blindedX, p).multiply(result).mod(p);
    }
}
