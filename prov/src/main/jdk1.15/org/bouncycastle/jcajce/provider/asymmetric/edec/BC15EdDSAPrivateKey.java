package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;

class BC15EdDSAPrivateKey
    extends BCEdDSAPrivateKey
    implements EdECPrivateKey
{
    BC15EdDSAPrivateKey(AsymmetricKeyParameter privKey)
    {
        super(privKey);
    }

    BC15EdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        super(keyInfo);
    }

    @Override
    public Optional<byte[]> getBytes()
    {
        if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters)
        {
            return Optional.of(((Ed448PrivateKeyParameters)eddsaPrivateKey).getEncoded());
        }
        else
        {
            return Optional.of(((Ed25519PrivateKeyParameters)eddsaPrivateKey).getEncoded());
        }
    }

    @Override
    public NamedParameterSpec getParams()
    {
        if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters)
        {
            return NamedParameterSpec.ED448;
        }
        else
        {
            return NamedParameterSpec.ED25519;
        }
    }
}
