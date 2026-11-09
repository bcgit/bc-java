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
import org.bouncycastle.util.Strings;

import java.io.ByteArrayInputStream;
import java.util.Iterator;

public class ExternalPGPSecretKeyTest
        extends AbstractPgpKeyPairTest
{
    /**
     * V4 TSK with external secret keys for both the primary and subkey.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-external-secrets-01.html#name-as-an-external-secret-key-w">
     *     External Key Test Vector</a>
     */
    private static final String V4_TSK_AS_EXTERNAL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xTUEZgWtcxYJKwYBBAHaRw8BAQdAlLK6UPQsVHR2ETk1SwVIG3tBmpiEtikYYlCy\n" +
            "1TIiqzb8AM0dPGhhcmR3YXJlLXNlY3JldEBleGFtcGxlLm9yZz7CjQQQFggANQIZ\n" +
            "AQUCZgWtcwIbAwgLCQgHCg0MCwUVCgkICwIWAhYhBF5T/E7q9FmUfn9CN9/4vVIe\n" +
            "DhxJAAoJEN/4vVIeDhxJ68gA/Asx9moybwEqeOgKXyOKSz2Oe64wV/vnf9hUD0cq\n" +
            "hhyVAP0S7DTYMYhWJiuXI7UHtvw4M1kO0ej8TwuqGt1zO8T3Asc6BGYFrXMSCisG\n" +
            "AQQBl1UBBQEBB0BNWFzinmpJcBtNWGm+MaKT/cG7tRPqQqz9cUKYhWVuSgMBCAf8\n" +
            "AMJ4BBgWCAAgBQJmBa1zAhsMFiEEXlP8Tur0WZR+f0I33/i9Uh4OHEkACgkQ3/i9\n" +
            "Uh4OHElVOAD/VZoWsp0/cCAvQV92ihzldduNCyPS4ejoVlIdEjilyEwBALImcpDd\n" +
            "G9b/SCbjUkKoibKDZ/FYbiFjQ3lDtFzo/LMN\n" +
            "=Qy7n\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V4_TSK_AS_EXTERNAL_KEY));
        ArmoredInputStream aIn = ArmoredInputStream.builder().build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        for (Iterator<PGPSecretKey> it = secretKeys.getSecretKeys(); it.hasNext(); )
        {
            PGPSecretKey key = (PGPSecretKey)it.next();

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
