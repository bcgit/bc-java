package org.bouncycastle.crypto.kems;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

public class CMCEKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public CMCEKEMGenerator(SecureRandom random)
    {
        this.sr = CryptoServicesRegistrar.getSecureRandom(random);
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        CMCEPublicKeyParameters key = (CMCEPublicKeyParameters)recipientKey;
        CMCEEngine engine = CMCEEngine.getInstance(key.getParameters());
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[engine.getSessionKeySize()];
        engine.kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
