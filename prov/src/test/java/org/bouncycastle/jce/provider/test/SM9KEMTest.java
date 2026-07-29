package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
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
import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator;
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
        KeyPair bobPair = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);
        PublicKey bobRecipient = masterPub.getUserPublicKey(bob);
        isTrue("getUserPublicKey agrees with the generated user public key",
            Arrays.areEqual(bobRecipient.getEncoded(), bobPair.getPublic().getEncoded()));
        isTrue("user key derivation is deterministic",
            Arrays.areEqual(bobPair.getPrivate().getEncoded(),
                masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate().getEncoded()));

        // the KGC extraction is also reachable through the capability interface
        SM9EncUserKeyGenerator kgc = masterPriv;
        isTrue("SM9EncUserKeyGenerator derives the same user key",
            Arrays.areEqual(bobPair.getPrivate().getEncoded(),
                kgc.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate().getEncoded()));

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
        PrivateKey eveKey = masterPriv.generateUserKeyPair("Eve".getBytes("US-ASCII"), SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        KeyGenerator wrongIdentity = KeyGenerator.getInstance("SM9-KEM", "BC");
        wrongIdentity.init(new KEMExtractSpec(eveKey, encapsulated.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation eveSecret = (SecretKeyWithEncapsulation)wrongIdentity.generateKey();
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

        destroyTest(random);
    }

    private void destroyTest(SecureRandom random)
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair masterPair = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)masterPair.getPublic();

        KeyPair bobPair = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);

        // destroying the user private key stops decapsulation and encoding
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(masterPub.getUserPublicKey(bob), "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();

        isTrue("user key not destroyed yet", !((Destroyable)bobPair.getPrivate()).isDestroyed());
        ((Destroyable)bobPair.getPrivate()).destroy();
        isTrue("user key destroyed", ((Destroyable)bobPair.getPrivate()).isDestroyed());

        try
        {
            bobPair.getPrivate().getEncoded();
            fail("destroyed user key still encodes");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(bobPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128));
        try
        {
            decapsulator.generateKey();
            fail("destroyed user key still decapsulates");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

        // destroying the master private key stops key generation and encoding; the
        // published master public key (and so the sender side) is unaffected
        isTrue("master key not destroyed yet", !masterPriv.isDestroyed());
        masterPriv.destroy();
        isTrue("master key destroyed", masterPriv.isDestroyed());

        try
        {
            masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);
            fail("destroyed master key still generates user keys");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

        try
        {
            masterPriv.getEncoded();
            fail("destroyed master key still encodes");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

        try
        {
            new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(masterPriv);
            fail("destroyed master key still serializes");
        }
        catch (NotSerializableException e)
        {
            // expected
        }

        isTrue("sender side unaffected by master destroy",
            masterPub.getUserPublicKey(bob) != null);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM9KEMTest());
    }
}
