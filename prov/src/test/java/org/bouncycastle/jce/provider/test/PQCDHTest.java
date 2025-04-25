package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class PQCDHTest
    extends SimpleTest
{
    public String getName()
    {
        return "PQCDHTest";
    }

    private void testMLKemECDH()
        throws Exception
    {

        KeyPairGenerator kemKeyGen = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kemKeyGen.initialize(MLKEMParameterSpec.ml_kem_768);

        KeyPair kemKp = kemKeyGen.generateKeyPair();

        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", "BC");

        ecKeyGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKeyGen.generateKeyPair();

        byte[] ukm = Hex.decode("030f136fa7fef90d185655ed1c6d46bacdb820");

        KeyGenerator keyGen = KeyGenerator.getInstance("ML-KEM", "BC");

        keyGen.init(new KEMGenerateSpec.Builder(kemKp.getPublic(), "DEF", 256).withNoKdf().build());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA256CKDF", "BC");

        agreement.init(ecKp.getPrivate(), new HybridValueParameterSpec(secEnc1.getEncoded(), new UserKeyingMaterialSpec(ukm)));

        agreement.doPhase(ecKp.getPublic(), true);

        SecretKey k1 = agreement.generateSecret("AES[256]");

        keyGen.init(new KEMExtractSpec.Builder(kemKp.getPrivate(), secEnc1.getEncapsulation(), "DEF", 256).withNoKdf().build());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        agreement.init(ecKp.getPrivate(), new HybridValueParameterSpec(secEnc2.getEncoded(), new UserKeyingMaterialSpec(ukm)));

        agreement.doPhase(ecKp.getPublic(), true);

        SecretKey k2 = agreement.generateSecret("AES[256]");

        isTrue(Arrays.areEqual(k1.getEncoded(), k2.getEncoded()));
    }

    @Override
    public void performTest()
        throws Exception
    {
         testMLKemECDH();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PQCDHTest());
    }
}
