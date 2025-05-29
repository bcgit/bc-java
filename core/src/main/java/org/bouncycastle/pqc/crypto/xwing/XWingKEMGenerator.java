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
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Implements the encapsulation process of the X-Wing hybrid Key Encapsulation Mechanism (KEM).
 * <p>
 * X-Wing is a general-purpose hybrid post-quantum/traditional KEM that combines X25519 and ML-KEM-768,
 * as specified in the IETF draft: draft-connolly-cfrg-xwing-kem-07.
 * </p>
 * <p>
 * This class facilitates the generation of ciphertexts and shared secrets using a recipient's public key.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/07/">X-Wing KEM Draft</a>
 */
public class XWingKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;
    private static final byte[] XWING_LABEL = Strings.toByteArray("\\.//^\\");

    public XWingKEMGenerator(SecureRandom random)
    {
        this.random = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        XWingPublicKeyParameters key = (XWingPublicKeyParameters)recipientKey;
        MLKEMPublicKeyParameters kyberPub = key.getKyberPublicKey();
        X25519PublicKeyParameters xdhPub = key.getXDHPublicKey();
        byte[] xdhPubBytes = xdhPub.getEncoded();

        // 1. Perform ML-KEM encapsulation
        MLKEMGenerator mlkemGen = new MLKEMGenerator(random);
        SecretWithEncapsulation mlkemSec = mlkemGen.generateEncapsulated(kyberPub);
        byte[] ctM = mlkemSec.getEncapsulation();

        // 2. Generate ephemeral X25519 key pair
        X25519KeyPairGenerator xdhGen = new X25519KeyPairGenerator();
        xdhGen.init(new X25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair ephXdhKp = xdhGen.generateKeyPair();
        byte[] ctX = ((X25519PublicKeyParameters)ephXdhKp.getPublic()).getEncoded();

        // 3. Perform X25519 agreement
        byte[] ssX = computeSSX(xdhPub, (X25519PrivateKeyParameters)ephXdhKp.getPrivate());

        // 4. Compute shared secret: SHA3-256(ssM || ssX || ctX || pkX || label)
        byte[] ss = computeSharedSecret(xdhPubBytes, mlkemSec.getSecret(), ctX, ssX);

        // 5. Cleanup intermediate values
        Arrays.clear(ssX);

        // 6. Return shared secret and encapsulation (ctM || ctX)
        return new SecretWithEncapsulationImpl(ss, Arrays.concatenate(ctM, ctX));
    }

    static byte[] computeSSX(X25519PublicKeyParameters xdhPub, X25519PrivateKeyParameters ephXdhPriv)
    {
        X25519Agreement xdhAgreement = new X25519Agreement();
        xdhAgreement.init(ephXdhPriv);
        byte[] ssX = new byte[xdhAgreement.getAgreementSize()];
        xdhAgreement.calculateAgreement(xdhPub, ssX, 0);
        return ssX;
    }

    static byte[] computeSharedSecret(byte[] xdhPubBytes, byte[] ssM, byte[] ctX, byte[] ssX)
    {
        SHA3Digest sha3 = new SHA3Digest(256);
        sha3.update(ssM, 0, ssM.length);
        sha3.update(ssX, 0, ssX.length);
        sha3.update(ctX, 0, ctX.length);
        sha3.update(xdhPubBytes, 0, xdhPubBytes.length);
        sha3.update(XWING_LABEL, 0, XWING_LABEL.length);

        byte[] ss = new byte[32];
        sha3.doFinal(ss, 0);
        return ss;
    }
}
