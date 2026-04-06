package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class XWingPrivateKeyParameters
    extends XWingKeyParameters
{
    private final transient byte[] seed;
    private final transient MLKEMPrivateKeyParameters kyberPrivateKey;
    private final transient X25519PrivateKeyParameters xdhPrivateKey;
    private final transient MLKEMPublicKeyParameters kyberPublicKey;
    private final transient X25519PublicKeyParameters xdhPublicKey;

    public XWingPrivateKeyParameters(byte[] seed,
                                     MLKEMPrivateKeyParameters kyberPrivateKey,
                                     X25519PrivateKeyParameters xdhPrivateKey,
                                     MLKEMPublicKeyParameters kyberPublicKey,
                                     X25519PublicKeyParameters xdhPublicKey)
    {
        super(true);
        this.seed = Arrays.clone(seed);
        this.kyberPrivateKey = kyberPrivateKey;
        this.xdhPrivateKey = xdhPrivateKey;
        this.kyberPublicKey = kyberPublicKey;
        this.xdhPublicKey = xdhPublicKey;
    }

    /**
     * @deprecated use the constructor taking org.bouncycastle.crypto.params.MLKEMKeyPublicKeyParameters
     */
    @Deprecated
    public XWingPrivateKeyParameters(byte[] seed,
                                     org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters kyberPrivateKey,
                                     X25519PrivateKeyParameters xdhPrivateKey,
                                     org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters kyberPublicKey,
                                     X25519PublicKeyParameters xdhPublicKey)
    {
        super(true);
        MLKEMParameters params;
        if (kyberPublicKey.getParameters().getName().equals("ML-KEM-512"))
        {
            params = MLKEMParameters.ml_kem_512;
        }
        else if (kyberPublicKey.getParameters().getName().equals("ML-KEM-768"))
        {
            params = MLKEMParameters.ml_kem_768;
        }
        else
        {
            params = MLKEMParameters.ml_kem_1024;
        }
        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(params, kyberPublicKey.getEncoded());
        this.seed = Arrays.clone(seed);
        this.kyberPrivateKey = new MLKEMPrivateKeyParameters(params, kyberPrivateKey.getEncoded(), pubKey);
        this.xdhPrivateKey = xdhPrivateKey;
        this.kyberPublicKey = pubKey;
        this.xdhPublicKey = xdhPublicKey;
    }

    public XWingPrivateKeyParameters(byte[] seed)
    {
        super(true);
        XWingPrivateKeyParameters key = (XWingPrivateKeyParameters)XWingKeyPairGenerator.genKeyPair(seed).getPrivate();
        this.seed = key.seed;
        this.kyberPrivateKey = key.kyberPrivateKey;
        this.xdhPrivateKey = key.xdhPrivateKey;
        this.kyberPublicKey = key.kyberPublicKey;
        this.xdhPublicKey = key.xdhPublicKey;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    MLKEMPrivateKeyParameters getKyberPrivateKey()
    {
        return kyberPrivateKey;
    }

    MLKEMPublicKeyParameters getKyberPublicKey()
    {
        return kyberPublicKey;
    }

    X25519PrivateKeyParameters getXDHPrivateKey()
    {
        return xdhPrivateKey;
    }

    X25519PublicKeyParameters getXDHPublicKey()
    {
        return xdhPublicKey;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed);
    }
}
