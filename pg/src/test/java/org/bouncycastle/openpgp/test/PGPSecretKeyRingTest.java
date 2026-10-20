package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PGPSecretKeyRingTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPSecretKeyRingTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        insertOrReplacePublicKeyTestWithRevocationInjection();
    }

    private void insertOrReplacePublicKeyTestWithRevocationInjection()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(OpenPGPTestKeys.ALICE_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing sKeyRing = (PGPSecretKeyRing) objFac.nextObject();

        isEquals("Test key MUST consist of two component keys", 2, sKeyRing.size());
        isTrue("Initially there MUST NOT be a revocation signature present",
                !sKeyRing.getPublicKey().getSignaturesOfType(PGPSignature.KEY_REVOCATION).hasNext());

        bIn = new ByteArrayInputStream(OpenPGPTestKeys.ALICE_REVOCATION_CERT.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature revocation = sigList.get(0);

        // Inject revocation to primary key
        PGPPublicKey primaryKey = sKeyRing.getPublicKey();
        primaryKey = PGPPublicKey.addCertification(primaryKey, revocation);

        // Replace primary key
        sKeyRing = PGPSecretKeyRing.insertOrReplacePublicKey(sKeyRing, primaryKey);
        isEquals("All keys are added to the new key ring", 2, sKeyRing.size());

        // Check if revocation sig is now present
        primaryKey = sKeyRing.getPublicKey();
        isTrue("Revocation has been injected properly",
                primaryKey.getSignaturesOfType(PGPSignature.KEY_REVOCATION).hasNext());
    }

    public static void main(String[] args)
    {
        runTest(new PGPSecretKeyRingTest());
    }
}
