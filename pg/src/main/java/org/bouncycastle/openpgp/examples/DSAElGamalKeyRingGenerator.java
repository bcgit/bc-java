package org.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a public/secret keyring containing a DSA signing
 * key and an El Gamal key for encryption.
 * <p>
 * usage: DSAElGamalKeyRingGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed 
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 * <p>
 * <b>Note</b>: this example encrypts the secret key using AES_256, many PGP products still
 * do not support this, if you are having problems importing keys try changing the algorithm
 * id to PGPEncryptedData.CAST5. CAST5 is more widely supported.
 */
public class DSAElGamalKeyRingGenerator
{
    private static void exportKeyPair(
        OutputStream    secretOut,
        OutputStream    publicOut,
        KeyPair         dsaKp,
        KeyPair         elgKp,
        String          identity,
        char[]          passPhrase,
        boolean         armor)
        throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException
    {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyPair        dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair        elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                 identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));
        
        keyRingGen.addSubKey(elgKeyPair);
        
        keyRingGen.generateSecretKeyRing().encode(secretOut);
        
        secretOut.close();
        
        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }
        
        keyRingGen.generatePublicKeyRing().encode(publicOut);
        
        publicOut.close();
    }
    
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length < 2)
        {
            System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
            System.exit(0);
        }
        
        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
        
        dsaKpg.initialize(1024);
        
        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair             dsaKp = dsaKpg.generateKeyPair();
        
        KeyPairGenerator    elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger          g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger          p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
            
        DHParameterSpec elParams = new DHParameterSpec(p, g);
            
        elgKpg.initialize(elParams);
        
        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair                    elgKp = elgKpg.generateKeyPair();
        
        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
                System.exit(0);
            }
            
            FileOutputStream    out1 = new FileOutputStream("secret.asc");
            FileOutputStream    out2 = new FileOutputStream("pub.asc");
            
            exportKeyPair(out1, out2, dsaKp, elgKp, args[1], args[2].toCharArray(), true);
        }
        else
        {
            FileOutputStream    out1 = new FileOutputStream("secret.bpg");
            FileOutputStream    out2 = new FileOutputStream("pub.bpg");
            
            exportKeyPair(out1, out2, dsaKp, elgKp, args[0], args[1].toCharArray(), false);
        }
    }
}
