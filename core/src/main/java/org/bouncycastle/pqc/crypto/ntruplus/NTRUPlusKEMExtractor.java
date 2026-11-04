package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.util.Arrays;

/**
 * NTRU+ decapsulation.
 * <p>
 * <b>Not thread safe.</b> The NTRUPlusEngine built here keeps one SHAKE instance in a field, so two
 * threads sharing an extractor interleave its absorb and squeeze phases: the secrets they recover do
 * not match the sender's, and an IllegalStateException from the digest is also possible. Give each
 * thread its own extractor - construction is cheap, roughly a thousandth of a decapsulation. The
 * KEM.Decapsulator that javax.crypto.KEM builds does exactly that, since that API requires
 * decapsulate to be safe for concurrent use.
 */
public class NTRUPlusKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final NTRUPlusPrivateKeyParameters privateKey;
    private final NTRUPlusEngine engine;

    public NTRUPlusKEMExtractor(NTRUPlusPrivateKeyParameters privateKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
        this.engine = new NTRUPlusEngine(privateKey.getParameters());
    }

    /**
     * Extract the shared secret from an NTRU+ encapsulation.
     * <p>
     * NTRU+ rejects an invalid encapsulation explicitly rather than implicitly: there is no
     * pseudorandom rejection secret, so an encapsulation that fails the re-encryption check, or is not
     * a canonical encoding, is refused with an exception instead of yielding a secret.
     *
     * @param encapsulation the encapsulated secret.
     * @return the shared secret.
     * @throws IllegalArgumentException if the encapsulation is the wrong length or is rejected.
     */
    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("encapsulation wrong length");
        }
        byte[] ss = new byte[NTRUPlusEngine.SSBytes];
        if (engine.crypto_kem_dec(ss, 0, encapsulation, 0, privateKey.getEncoded(), 0) != 0)
        {
            Arrays.clear(ss);
            throw new IllegalArgumentException("invalid encapsulation");
        }
        return ss;
    }

    @Override
    public int getEncapsulationLength()
    {
        return privateKey.getParameters().getCiphertextBytes();
    }
}
