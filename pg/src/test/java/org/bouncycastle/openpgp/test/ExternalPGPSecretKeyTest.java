package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class ExternalPGPSecretKeyTest
        extends AbstractPgpKeyPairTest
{
    /**
     * TSK with external secret keys for both the primary and subkey.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-dkg-openpgp-external-secrets-02.html#name-as-an-external-secret-key">
     *     External Key Test Vector</a>
     */
    private static final String V4_TSK_AS_EXTERNAL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xTQEZgWtcxYJKwYBBAHaRw8BAQdAlLK6UPQsVHR2ETk1SwVIG3tBmpiEtikYYlCy\n" +
            "1TIiqzb8zR08aGFyZHdhcmUtc2VjcmV0QGV4YW1wbGUub3JnPsKNBBAWCAA1AhkB\n" +
            "BQJmBa1zAhsDCAsJCAcKDQwLBRUKCQgLAhYCFiEEXlP8Tur0WZR+f0I33/i9Uh4O\n" +
            "HEkACgkQ3/i9Uh4OHEnryAD8CzH2ajJvASp46ApfI4pLPY57rjBX++d/2FQPRyqG\n" +
            "HJUA/RLsNNgxiFYmK5cjtQe2/DgzWQ7R6PxPC6oa3XM7xPcCxzkEZgWtcxIKKwYB\n" +
            "BAGXVQEFAQEHQE1YXOKeaklwG01Yab4xopP9wbu1E+pCrP1xQpiFZW5KAwEIB/zC\n" +
            "eAQYFggAIAUCZgWtcwIbDBYhBF5T/E7q9FmUfn9CN9/4vVIeDhxJAAoJEN/4vVIe\n" +
            "DhxJVTgA/1WaFrKdP3AgL0Ffdooc5XXbjQsj0uHo6FZSHRI4pchMAQCyJnKQ3RvW\n" +
            "/0gm41JCqImyg2fxWG4hY0N5Q7Rc6PyzDQ==\n" +
            "=3w/O\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Override
    public String getName()
    {
        return "ExternalPGPSecretKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(V4_TSK_AS_EXTERNAL_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        for (PGPSecretKey key : secretKeys)
        {
            isTrue(key.isPrivateKeyEmpty());
            isTrue(key.isExternalKey());
            PGPKeyPair kp = key.extractKeyPair(
                    new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                            .build("arbitrary".toCharArray()));
            isNull(kp.getPrivateKey());
        }
    }

    public static void main(String[] args)
    {
        runTest(new ExternalPGPSecretKeyTest());
    }
}
