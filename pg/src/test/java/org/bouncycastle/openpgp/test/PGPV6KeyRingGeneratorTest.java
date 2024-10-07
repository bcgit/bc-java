package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

public class PGPV6KeyRingGeneratorTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "PGPV6KeyRingGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testGenerateMinimalKey();
    }

    private void testGenerateMinimalKey()
            throws PGPException, IOException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator gen = new OpenPGPV6KeyGenerator(
                new BcOpenPGPImplementation(), HashAlgorithmTags.SHA3_512, false, creationTime);
        OpenPGPKey key = gen.withPrimaryKey(
                        PGPKeyPairGenerator::generateEd25519KeyPair,
                        subpackets ->
                        {
                            subpackets.addNotationData(false, true, "foo@bouncycastle.org", "bar");
                            return subpackets;
                        },
                        null)
                .addUserId("Alice <alice@example.org>")
                .addEncryptionSubkey((char[]) null)
                .addSigningSubkey((char[]) null)
                .build();
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new PGPV6KeyRingGeneratorTest());
    }
}
