package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.util.Arrays;

/**
 * Implements the decapsulation process of the X-Wing hybrid Key Encapsulation Mechanism (KEM).
 * <p>
 * This class allows the recipient to derive the shared secret from a given ciphertext using their private key,
 * as defined in the X-Wing KEM specification.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/07/">X-Wing KEM Draft</a>
 */
public class XWingKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private static final int MLKEM_CIPHERTEXT_SIZE = 1088;
    private final XWingPrivateKeyParameters key;
    private final MLKEMExtractor mlkemExtractor;

    public XWingKEMExtractor(XWingPrivateKeyParameters privParams)
    {
        this.key = privParams;
        this.mlkemExtractor = new MLKEMExtractor(key.getKyberPrivateKey());
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // 1. Split ciphertext into ML-KEM and X25519 parts
        byte[] ctM = Arrays.copyOfRange(encapsulation, 0, MLKEM_CIPHERTEXT_SIZE);
        byte[] ctX = Arrays.copyOfRange(encapsulation, MLKEM_CIPHERTEXT_SIZE, encapsulation.length);

        // 2. Compute X25519 shared secret
        byte[] ssX = XWingKEMGenerator.computeSSX(new X25519PublicKeyParameters(ctX, 0), key.getXDHPrivateKey());

        // 3. Compute combiner: SHA3-256(ssM || ssX || ctX || pkX || XWING_LABEL)
        byte[] kemSecret = XWingKEMGenerator.computeSharedSecret(key.getXDHPublicKey().getEncoded(),
            mlkemExtractor.extractSecret(ctM), ctX, ssX);

        // 4. Cleanup intermediate values
        Arrays.clear(ssX);

        return kemSecret;
    }

    public int getEncapsulationLength()
    {
        return mlkemExtractor.getEncapsulationLength() + X25519PublicKeyParameters.KEY_SIZE;
    }
}
