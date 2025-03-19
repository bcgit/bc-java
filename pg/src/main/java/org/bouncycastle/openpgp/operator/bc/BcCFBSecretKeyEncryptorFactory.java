package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * Return a factory for {@link PBESecretKeyEncryptor} instances which protect the secret key material by deriving
 * a key-encryption-key using {@link org.bouncycastle.bcpg.S2K#SALTED_AND_ITERATED} S2K and apply
 * that key using {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_SHA1} (CFB mode).
 * <p>
 * This particular factory derives a key-encryption-key via salted+iterated S2K derivation using SHA256
 * and uses AES256 for secret key protection.
 */
public class BcCFBSecretKeyEncryptorFactory
        implements PBESecretKeyEncryptorFactory
{
    private final int symmetricKeyAlgorithm;
    private final int iterationCount;

    public BcCFBSecretKeyEncryptorFactory(int symmetricKeyAlgorithm,
                                          int iterationCount)
    {
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.iterationCount = iterationCount;
    }

    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        if (passphrase == null)
        {
            return null;
        }

        PGPDigestCalculator checksumCalc;
        try
        {
            checksumCalc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        }
        catch (PGPException e)
        {
            throw new RuntimeException(e); // Does not happen in practice
        }

        return new BcPBESecretKeyEncryptorBuilder(
            symmetricKeyAlgorithm,
            checksumCalc,
            iterationCount) // MAX iteration count
            .build(passphrase);
    }
}
