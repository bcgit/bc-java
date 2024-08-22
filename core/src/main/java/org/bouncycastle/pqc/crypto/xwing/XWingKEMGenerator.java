package org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class XWingKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public XWingKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        XWingPublicKeyParameters key = (XWingPublicKeyParameters)recipientKey;

        MLKEMGenerator kybKem = new MLKEMGenerator(sr);

        SecretWithEncapsulation kybSecWithEnc = kybKem.generateEncapsulated(key.getKyberPublicKey());
        X25519Agreement xdhAgree = new X25519Agreement();
        byte[] kybSecret = kybSecWithEnc.getSecret();
        byte[] k = new byte[kybSecret.length + xdhAgree.getAgreementSize()];

        System.arraycopy(kybSecret, 0, k, 0, kybSecret.length);

        Arrays.clear(kybSecret);

        X25519KeyPairGenerator xdhGen = new X25519KeyPairGenerator();

        xdhGen.init(new X25519KeyGenerationParameters(sr));

        AsymmetricCipherKeyPair ephXdh = xdhGen.generateKeyPair();

        xdhAgree.init(ephXdh.getPrivate());

        xdhAgree.calculateAgreement(key.getXDHPublicKey(), k, kybSecret.length);

        X25519PublicKeyParameters ephXdhPub = (X25519PublicKeyParameters)ephXdh.getPublic();

        SHA3Digest sha3 = new SHA3Digest(256);

        sha3.update(Strings.toByteArray("\\.//^\\"), 0, 6);
        sha3.update(k, 0, k.length);
        sha3.update(ephXdhPub.getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);
        sha3.update(((X25519PublicKeyParameters)key.getXDHPublicKey()).getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);

        byte[] kemSecret = new byte[32];

        sha3.doFinal(kemSecret, 0);

        return new SecretWithEncapsulationImpl(kemSecret, Arrays.concatenate(kybSecWithEnc.getEncapsulation(), ephXdhPub.getEncoded()));
    }
}
