package org.bouncycastle.pqc.jcajce.provider.util;

import java.security.InvalidKeyException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

public class WrapUtil
{
    public static Wrapper getKeyWrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(true, new KeyParameter(Arrays.copyOfRange(secret, 0, (ktsParameterSpec.getKeySize() + 7) / 8)));
        }
        else
        {
            kWrap.init(true, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getKeyUnwrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(false, new KeyParameter(secret, 0, (ktsParameterSpec.getKeySize()+ 7) / 8));
        }
        else
        {
            kWrap.init(false, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AESWRAP") || keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            kWrap = new RFC3394WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA"))
        {
            kWrap = new RFC3394WrapEngine(new ARIAEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia"))
        {
            kWrap = new RFC3394WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("SEED"))
        {
            kWrap = new RFC3394WrapEngine(new SEEDEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new ARIAEngine());
        }
        else
        {
            throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
        }
        return kWrap;
    }

    private static byte[] makeKeyBytes(KTSParameterSpec ktsSpec, byte[] secret)
        throws InvalidKeyException
    {
        try
        {
            return KdfUtil.makeKeyBytes(ktsSpec.getKdfAlgorithm(), secret, ktsSpec.getOtherInfo(), ktsSpec.getKeySize());
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
    }
}
