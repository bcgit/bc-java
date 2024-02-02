package org.bouncycastle.jcacje.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastleKEMProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.SNTRUPrimeKEMSpi;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;

import static org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec.sntrup653;


public class SNTRUPrimeKEMTest
    extends TestCase
{
    public void testKEM()
            throws Exception
    {
        if (Security.getProvider(BouncyCastleKEMProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        // Receiver side
        KeyPairGenerator g = KeyPairGenerator.getInstance("SNTRUPrime");
        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("SNTRUPrime"); //Should the name be "SNTRUPrime-KEM" ?
        SNTRUPrimeParameterSpec specS = sntrup653;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, specS, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();
        byte[] params = enc.params();

        // Receiver side
        KEM kemR = KEM.getInstance("SNTRUPrime");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("SNTRUPrime");
        algParams.init(params);
        SNTRUPrimeParameterSpec specR = algParams.getParameterSpec(SNTRUPrimeParameterSpec.class);
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), specR);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

}
