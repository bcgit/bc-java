package org.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

/**
 * utility class for converting jce/jca ElGamal objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class ElGamalUtil
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ElGamalPublicKey)
        {
            ElGamalPublicKey    k = (ElGamalPublicKey)key;

            return new ElGamalPublicKeyParameters(k.getY(),
                new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
        }
        else if (key instanceof DHPublicKey)
        {
            DHPublicKey    k = (DHPublicKey)key;

            return new ElGamalPublicKeyParameters(k.getY(),
                new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
        }

        throw new InvalidKeyException("can't identify public key for ElGamal.");
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ElGamalPrivateKey)
        {
            ElGamalPrivateKey    k = (ElGamalPrivateKey)key;

            return new ElGamalPrivateKeyParameters(k.getX(),
                new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
        }
        else if (key instanceof DHPrivateKey)
        {
            DHPrivateKey    k = (DHPrivateKey)key;

            try
            {
                return new ElGamalPrivateKeyParameters(k.getX(),
                    new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
            }
            catch (RuntimeException e)
            {
                throw SecurityExceptions.invalidKeyException(
                    "cannot recognise ElGamal private key - its parameters are not accessible (a hardware-backed key?): " + e.getMessage(), e);
            }
        }

        throw new InvalidKeyException("can't identify private key for ElGamal.");
    }
}
