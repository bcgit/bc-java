package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class HSSSigner
    implements MessageSigner
{
    private HSSPrivateKeyParameters privKey;
    private HSSPublicKeyParameters pubKey;
    private SecureRandom random;

    public void init(boolean forSigning, CipherParameters param)
    {
         if (forSigning)
         {
             if (param instanceof ParametersWithRandom)
              {
                  ParametersWithRandom rParam = (ParametersWithRandom)param;

                  this.privKey = (HSSPrivateKeyParameters)rParam.getParameters();
                  random = rParam.getRandom();
              }
              else
              {
                  this.privKey = (HSSPrivateKeyParameters)param;
                  random = CryptoServicesRegistrar.getSecureRandom();
              }
         }
         else
         {
             this.pubKey = (HSSPublicKeyParameters)param;
         }
    }

    public byte[] generateSignature(byte[] message)
    {
        try
        {
            return HSS.generateSignature(privKey, message, random).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode signature: " + e.getMessage());
        }
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        try
        {
            return HSS.verifySignature(pubKey, HSSSignature.getInstance(signature, pubKey.getL()), message);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to decode signature: " + e.getMessage());
        }
    }
}
