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
                nist = new FalconNIST(skparam.getParams().getLogN(),
                    skparam.getParams().getNonceLength(),
                    ((ParametersWithRandom)param).getRandom());
            }
            else
            {
                FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)param;
                encodedkey = ((FalconPrivateKeyParameters)param).getEncoded();
                nist = new FalconNIST(skparam.getParams().getLogN(),
                    skparam.getParams().getNonceLength(),
                    CryptoServicesRegistrar.getSecureRandom());
            }
        }
        else
        {
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)param;
            encodedkey = pkparam.getEncoded();
            nist = new FalconNIST(pkparam.getParams().getLogN(),
                pkparam.getParams().getNonceLength(),
                CryptoServicesRegistrar.getSecureRandom());
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        int smmaxlen;
        smmaxlen = nist.CRYPTO_BYTES + message.length;
        byte[] sm = new byte[smmaxlen];
        int[] smlen = new int[1];
        int[] siglen = new int[1];
        nist.crypto_sign(sm, 0, smlen, siglen, message, 0, message.length, encodedkey, 0);
        byte[] signature = new byte[siglen[0] + nist.NONCELEN + 1];
        signature[0] = (byte)(0x30 + nist.LOGN);
        System.arraycopy(sm, 2, signature, 1, nist.NONCELEN);
        System.arraycopy(sm, 2 + nist.NONCELEN + message.length,
            signature, nist.NONCELEN + 1, siglen[0]);
        return signature;
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
