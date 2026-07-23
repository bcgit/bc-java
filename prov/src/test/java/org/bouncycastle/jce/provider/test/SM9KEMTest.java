package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * JCE-level tests for the SM9 key encapsulation mechanism exposed as
 * {@code KeyGenerator.SM9-KEM}: an encapsulate/decapsulate round-trip through the
 * provider, the {@code KeyFactory.SM9} master-key encodings, and the spec/key-type
 * guards on the {@code KeyGenerator} SPI.
 */
public class SM9KEMTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9KEM";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        byte[] bob = "Bob".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair masterPair = kpGen.generateKeyPair();
        isTrue("master public key implements SM9EncMasterPublicKey",
            masterPair.getPublic() instanceof SM9EncMasterPublicKey);
        isTrue("master private key implements SM9EncMasterPrivateKey",
            masterPair.getPrivate() instanceof SM9EncMasterPrivateKey);
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)masterPair.getPublic();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();

        // KGC side: the user key pair from the master private key; sender side: the
        // recipient public key from the published master public key + identity. The
        // derivations are deterministic and their public halves must agree.
        KeyPair bobPair = masterPriv.generateUserKeyPair(bob);
        PublicKey bobRecipient = masterPub.getUserPublicKey(bob);
        isTrue("getUserPublicKey agrees with the generated user public key",
            Arrays.areEqual(bobRecipient.getEncoded(), bobPair.getPublic().getEncoded()));
        isTrue("user key derivation is deterministic",
            Arrays.areEqual(bobPair.getPrivate().getEncoded(),
                masterPriv.generateUserKeyPair(bob).getPrivate().getEncoded()));

        // encapsulate (to the sender-derived public key) / decapsulate round-trip
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(bobRecipient, "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();

        isTrue("SM9-KEM secret length", encapsulated.getEncoded().length == 16);
        isTrue("SM9-KEM key algorithm", "AES".equals(encapsulated.getAlgorithm()));

        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(bobPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation decapsulated = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        isTrue("SM9-KEM decapsulation recovers the shared key",
            Arrays.constantTimeAreEqual(encapsulated.getEncoded(), decapsulated.getEncoded()));

        // a different identity must not recover the same key
        PrivateKey eveKey = masterPriv.generateUserKeyPair("Eve".getBytes("US-ASCII")).getPrivate();
        KeyGenerator wrongId = KeyGenerator.getInstance("SM9-KEM", "BC");
        wrongId.init(new KEMExtractSpec(eveKey, encapsulated.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation eveSecret = (SecretKeyWithEncapsulation)wrongId.generateKey();
        isTrue("SM9-KEM wrong identity does not recover the key",
            !Arrays.constantTimeAreEqual(encapsulated.getEncoded(), eveSecret.getEncoded()));

        // SPI guards: SM9-ENC generates master pairs only, no AlgorithmParameterSpec
        try
        {
            KeyPairGenerator.getInstance("SM9-ENC", "BC").initialize(new AlgorithmParameterSpec()
            {
            });
            fail("SM9-ENC accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }

        // KeyFactory.SM9 master-key encoding round-trip
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(masterPub.getEncoded()));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(masterPriv.getEncoded()));
        isTrue("SM9 KeyFactory enc master public round-trip",
            Arrays.areEqual(pub.getEncoded(), masterPub.getEncoded()));
        isTrue("SM9 KeyFactory enc master private round-trip",
            Arrays.areEqual(priv.getEncoded(), masterPriv.getEncoded()));

        // SPI guards: wrong key type for encapsulation (a master public key is not a recipient)
        try
        {
            KeyGenerator bad = KeyGenerator.getInstance("SM9-KEM", "BC");
            bad.init(new KEMGenerateSpec(masterPub, "AES", 128), random);
            fail("SM9-KEM encapsulation accepted a non-recipient public key");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }

        // SPI guards: an uninitialised SM9-KEM KeyGenerator must not produce a key
        try
        {
            KeyGenerator.getInstance("SM9-KEM", "BC").generateKey();
            fail("SM9-KEM produced a key without a KEM spec");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM9KEMTest());
    }
}
