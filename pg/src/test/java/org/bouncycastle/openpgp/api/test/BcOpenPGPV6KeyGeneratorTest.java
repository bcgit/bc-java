package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.BcOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.test.AbstractPgpKeyPairTest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Iterator;

public class BcOpenPGPV6KeyGeneratorTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "OpenPGPV6KeyGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testGenerateMinimalKey();
    }

    private void testGenerateMinimalKey()
            throws PGPException, IOException {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator gen = new BcOpenPGPV6KeyGenerator(
                HashAlgorithmTags.SHA3_512,
                creationTime
        );
        PGPSecretKeyRing secretKeys = gen.withPrimaryKey(
                        PGPKeyPairGenerator::generateEd25519KeyPair,
                        subpackets ->
                        {
                            subpackets.addNotationData(false, true, "foo@bouncycastle.org", "bar");
                            return subpackets;
                        },
                "hello".toCharArray())
                .addUserId("Alice <alice@example.org>")
                .addEncryptionSubkey(null)
                .addSigningSubkey(null)
                .build();

        // Test creation time
        for (PGPPublicKey key : secretKeys.toCertificate())
        {
            isEquals(creationTime, key.getCreationTime());
            for (Iterator<PGPSignature> it = key.getSignatures(); it.hasNext(); ) {
                PGPSignature sig = it.next();
                isEquals(creationTime, sig.getCreationTime());
            }
        }

        PGPPublicKey primaryKey = secretKeys.getPublicKey();
        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.org>", uids.next());
        isFalse(uids.hasNext());

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
        runTest(new BcOpenPGPV6KeyGeneratorTest());
    }
}
