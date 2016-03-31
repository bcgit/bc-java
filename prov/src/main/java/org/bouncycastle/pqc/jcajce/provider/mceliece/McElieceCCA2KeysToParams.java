package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * utility class for converting jce/jca McElieceCCA2 objects
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class McElieceCCA2KeysToParams
{


    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCMcElieceCCA2PublicKey)
        {
            BCMcElieceCCA2PublicKey k = (BCMcElieceCCA2PublicKey)key;

            return k.getKeyParams();
        }

        throw new InvalidKeyException("can't identify McElieceCCA2 public key: " + key.getClass().getName());
    }


    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey key)
        throws InvalidKeyException
    {
        if (key instanceof BCMcElieceCCA2PrivateKey)
        {
            BCMcElieceCCA2PrivateKey k = (BCMcElieceCCA2PrivateKey)key;

            return k.getKeyParams();
        }

        throw new InvalidKeyException("can't identify McElieceCCA2 private key.");
    }
}
