package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class HardwareSecretKeyTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "HardwareSecretKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        parseHardwareKey();
    }

    private void parseHardwareKey()
            throws IOException, PGPException
    {
        // Test vector from https://www.ietf.org/archive/id/draft-dkg-openpgp-hardware-secrets-02.html#name-as-a-hardware-backed-secret
        String armored = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder().setIgnoreCRC(false).build(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(pIn, new BcKeyFingerprintCalculator());
        for (PGPSecretKey k : secretKeys)
        {
            isEquals("S2K Usage mismatch", SecretKeyPacket.USAGE_HARDWARE_BACKED, k.getS2KUsage());
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().clearHeaders().build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();

        isEquals("Armor encoding mismatch", armored, bOut.toString());
    }

    public static void main(String[] args)
    {
        runTest(new HardwareSecretKeyTest());
    }
}
