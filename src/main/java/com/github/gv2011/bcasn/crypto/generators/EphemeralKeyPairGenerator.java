package com.github.gv2011.bcasn.crypto.generators;

import com.github.gv2011.bcasn.crypto.AsymmetricCipherKeyPair;
import com.github.gv2011.bcasn.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.gv2011.bcasn.crypto.EphemeralKeyPair;
import com.github.gv2011.bcasn.crypto.KeyEncoder;

public class EphemeralKeyPairGenerator
{
    private AsymmetricCipherKeyPairGenerator gen;
    private KeyEncoder keyEncoder;

    public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator gen, KeyEncoder keyEncoder)
    {
        this.gen = gen;
        this.keyEncoder = keyEncoder;
    }

    public EphemeralKeyPair generate()
    {
        AsymmetricCipherKeyPair eph = gen.generateKeyPair();

        // Encode the ephemeral public key
         return new EphemeralKeyPair(eph, keyEncoder);
    }
}
