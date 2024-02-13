package org.bouncycastle.jcacje.provider.test;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Arrays;

import static org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec.sntrup653;


public class SNTRUPrimeKEMTest
    extends TestCase
{
    public void testKEM()
            throws Exception
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        // Receiver side
        KeyPairGenerator g = KeyPairGenerator.getInstance("SNTRUPrime");

        g.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("SNTRUPrime"); //Should the name be "SNTRUPrime-KEM" ?
        KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder("Camellia", 256).build();
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();
        byte[] params = enc.params();

        // Receiver side
        KEM kemR = KEM.getInstance("SNTRUPrime");
//        AlgorithmParameters algParams = AlgorithmParameters.getInstance("SNTRUPrime");
//        algParams.init(params);
//        SNTRUPrimeParameterSpec specR = algParams.getParameterSpec(SNTRUPrimeParameterSpec.class);
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

}
