package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class FalconSigner
    implements MessageSigner
{
    private byte[] encodedkey;
    private FalconNIST nist;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                FalconPrivateKeyParameters skparam = ((FalconPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                encodedkey = skparam.getEncoded();
                nist = new FalconNIST(skparam.getParameters().getLogN(),
                    skparam.getParameters().getNonceLength(),
                    ((ParametersWithRandom)param).getRandom());
            }
            else
            {
                FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)param;
                encodedkey = ((FalconPrivateKeyParameters)param).getEncoded();
                nist = new FalconNIST(skparam.getParameters().getLogN(),
                    skparam.getParameters().getNonceLength(),
                    CryptoServicesRegistrar.getSecureRandom());
            }
        }
        else
        {
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)param;
            encodedkey = pkparam.getEncoded();
            nist = new FalconNIST(pkparam.getParameters().getLogN(),
                pkparam.getParameters().getNonceLength(),
                CryptoServicesRegistrar.getSecureRandom());
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        byte[] sm = new byte[nist.CRYPTO_BYTES];

        return nist.crypto_sign(sm, message, 0, message.length, encodedkey, 0);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (signature[0] != (byte)(0x30 + nist.LOGN))
        {
            return false;
        }
        byte[] nonce = new byte[nist.NONCELEN];
        byte[] sig = new byte[signature.length - nist.NONCELEN - 1];
        System.arraycopy(signature, 1, nonce, 0, nist.NONCELEN);
        System.arraycopy(signature, nist.NONCELEN + 1, sig, 0, signature.length - nist.NONCELEN - 1);
        byte[] sm = new byte[2 + message.length + signature.length - 1];
        sm[0] = (byte)(sig.length >>> 8);
        sm[1] = (byte)sig.length;
        System.arraycopy(nonce, 0, sm, 2, nist.NONCELEN);
        System.arraycopy(message, 0, sm, 2 + nist.NONCELEN, message.length);
        System.arraycopy(sig, 0, sm, 2 + nist.NONCELEN + message.length, sig.length);
        boolean res = nist.crypto_sign_open(new byte[message.length], 0, new int[1],
            sm, 0, sm.length, encodedkey, 0) == 0;
        return res;
    }
}
