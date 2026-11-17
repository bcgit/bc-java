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
            throw new IllegalArgumentException("DHBasicAgreement expects DHPrivateKeyParameters");
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

        // The exponent is our private value, long lived for static-static agreement, and the peer
        // chooses the base, so the base is blinded: the timing of the variable-time modPow could
        // otherwise be accumulated against the key over many agreements. A key used only once gains
        // nothing from this, but that cannot be told here. The exponent is not blinded with a
        // multiple of the order as well: peerY has only been range checked, so the multiple would
        // have to be of p-1, which grows a short exponent to the size of p, and a small multiple
        // only dilutes the leak.
        BigInteger result = BigIntegers.modPowBaseBlinded(p, peerY, key.getX(), random);
        if (result.equals(ONE))
        {
            throw new IllegalStateException("Shared key can't be 1");
        }

        return result;
    }
}
