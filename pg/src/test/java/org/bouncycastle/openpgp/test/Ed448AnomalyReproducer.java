package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.test.SimpleTest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

public class Ed448AnomalyReproducer
        extends SimpleTest
{
    @Override
    public String getName() {
        return "Ed448AnomalyReproducer";
    }

    @Override
    public void performTest()
            throws Exception
    {
        JcaPGPKeyConverter jcaPGPKeyConverter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        int failure = 0;
        for (int total = 0; total < 2000; total++)
        {
            Date creationDate = new Date();
            KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed448", "BC");
            KeyPair keyPair = gen.generateKeyPair();
            PGPKeyPair jcaPgpPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed448, keyPair, creationDate);

            try
            {
                PublicKey pubKey = jcaPGPKeyConverter.getPublicKey(jcaPgpPair.getPublicKey()); // fails in ~1/200 of times
            }
            catch (PGPException e)
            {
                failure++;
                System.out.println(failure + "/" + total + " (" + (((double)(failure)) / total) * 100 + "%)");
            }
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new Ed448AnomalyReproducer());
    }
}
