package com.github.gv2011.bcasn.crypto.generators;

import com.github.gv2011.bcasn.crypto.AsymmetricCipherKeyPair;
import com.github.gv2011.bcasn.crypto.params.ECPrivateKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;

public class DSTU4145KeyPairGenerator
    extends ECKeyPairGenerator
{
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = super.generateKeyPair();

        ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

        pub = new ECPublicKeyParameters(pub.getQ().negate(), pub.getParameters());

        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
