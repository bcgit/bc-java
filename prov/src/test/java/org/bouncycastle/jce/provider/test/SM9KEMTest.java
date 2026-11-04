package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecureRandomProvider;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * JCE-level tests for the SM9 key encapsulation mechanism exposed as
 * {@code KeyGenerator.SM9-KEM}: an encapsulate/decapsulate round-trip and the GM/T 0044.5
 * vector through the provider, the {@code KeyFactory.SM9} encoding of the encryption master
 * private key, the spec/key-type guards on the {@code KeyGenerator} SPI, and the encryption
 * keys' equality and Destroyable behaviour.
 */
public class SM9KEMTest
    extends SimpleTest
{
    // performTest's random and master key pair, which rejectedInitTest, hidEqualityTest and
    // userKeyEqualityTest use too; the destroy tests make master keys of their own
    private SecureRandom random;
    private SM9EncMasterPublicKey masterPub;
    private SM9EncMasterPrivateKey masterPriv;

    public String getName()
    {
        return "SM9KEM";
    }

    public void performTest()
        throws Exception
    {
        random = CryptoServicesRegistrar.getSecureRandom();
        byte[] bob = "Bob".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair masterPair = kpGen.generateKeyPair();
        isTrue("master public key implements SM9EncMasterPublicKey",
            masterPair.getPublic() instanceof SM9EncMasterPublicKey);
        isTrue("master private key implements SM9EncMasterPrivateKey",
            masterPair.getPrivate() instanceof SM9EncMasterPrivateKey);
        masterPub = (SM9EncMasterPublicKey)masterPair.getPublic();
        masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();

        // KGC side: the user key pair from the master private key; sender side: the recipient
        // public key from the master public key and identity - the public halves agree
        KeyPair bobPair = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);
        PublicKey bobRecipient = masterPub.getUserPublicKey(bob);
        isTrue("getUserPublicKey agrees with the generated user public key",
            Arrays.areEqual(bobRecipient.getEncoded(), bobPair.getPublic().getEncoded()));

        // the KGC extraction is deterministic, and reachable through the capability interface
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

        // KeyFactory.SM9 master private key encoding round-trip
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(masterPriv.getEncoded()));
        isTrue("SM9 KeyFactory enc master private round-trip",
            Arrays.areEqual(priv.getEncoded(), masterPriv.getEncoded()));

        // an SM9-KEM KeyGenerator never initialised does not produce a key
        try
        {
            KeyGenerator.getInstance("SM9-KEM", "BC").generateKey();
            fail("SM9-KEM produced a key without a KEM spec");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        destroyTest();
        hidEqualityTest();
        userKeyEqualityTest();
        rejectedInitTest();
        knownAnswerTest();
        keyUsageTest();
        handedOverUsageTest();
        declaredUsageTest();
        failedInitTest();
    }

    /**
     * A key's use is recorded when it is handed to Cipher.SM9 or KeyGenerator.SM9-KEM, at init. One
     * taken while Properties.SM9_ALLOW_MULTI_USE was set for the thread goes on serving the Cipher or
     * generator that took it after the key has been recorded for the other function: doFinal decrypts
     * rather than reporting the ciphertext as malformed, and generateKey decapsulates rather than
     * throwing an unchecked exception. A new init is refused.
     */
    private void handedOverUsageTest()
        throws Exception
    {
        byte[] message = "a message of twenty-nine bytes".getBytes("US-ASCII");

        byte[] quentin = "Quentin".getBytes("US-ASCII");
        KeyPair quentinPair = masterPriv.generateUserKeyPair(quentin, SM9EncMasterPrivateKeyParameters.HID);
        Cipher encryptor = Cipher.getInstance("SM9", "BC");
        encryptor.init(Cipher.ENCRYPT_MODE, quentinPair.getPublic(), random);
        byte[] ciphertext = encryptor.doFinal(message);
        Cipher decryptor = Cipher.getInstance("SM9", "BC");
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decryptor.init(Cipher.DECRYPT_MODE, quentinPair.getPrivate());
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(quentinPair.getPublic(), "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(quentinPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128));
        isTrue("the key decapsulates once the Cipher has taken it",
            Arrays.areEqual(encapsulated.getEncoded(), decapsulator.generateKey().getEncoded()));
        isTrue("a Cipher initialised before the key decapsulated still decrypts",
            Arrays.areEqual(message, decryptor.doFinal(ciphertext)));
        try
        {
            decryptor.init(Cipher.DECRYPT_MODE, quentinPair.getPrivate());
            fail("Cipher.SM9 took a key that has decapsulated");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }

        byte[] rupert = "Rupert".getBytes("US-ASCII");
        KeyPair rupertPair = masterPriv.generateUserKeyPair(rupert, SM9EncMasterPrivateKeyParameters.HID);
        encapsulator.init(new KEMGenerateSpec(rupertPair.getPublic(), "AES", 128), random);
        encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();
        KEMExtractSpec rupertSpec = new KEMExtractSpec(rupertPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128);
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decapsulator.init(rupertSpec);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
        encryptor.init(Cipher.ENCRYPT_MODE, rupertPair.getPublic(), random);
        decryptor.init(Cipher.DECRYPT_MODE, rupertPair.getPrivate());
        isTrue("the key decrypts once the KeyGenerator has taken it",
            Arrays.areEqual(message, decryptor.doFinal(encryptor.doFinal(message))));
        isTrue("a KeyGenerator initialised before the key decrypted still decapsulates",
            Arrays.areEqual(encapsulated.getEncoded(), decapsulator.generateKey().getEncoded()));
        try
        {
            decapsulator.init(rupertSpec);
            fail("KeyGenerator.SM9-KEM took a key that has decrypted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }
    }

    /**
     * Within one JVM an encryption user key is held to the first of the KEM and Cipher.SM9 decryption it
     * is used for. Cipher.SM9 refuses at init a key that has decapsulated, and KeyGenerator.SM9-KEM one
     * that has decrypted, each with the checked exception its init declares, and the key is recognised
     * however it is rebuilt. With Properties.SM9_ALLOW_MULTI_USE set for the thread both are taken.
     */
    private void keyUsageTest()
        throws Exception
    {
        String usedForKem = "SM9 encryption user key has been used for KEM decapsulation in this JVM: key-usage"
            + " separation refuses it for decryption (set org.bouncycastle.sm9.allow_multi_use to true to turn"
            + " the check off)";
        String usedForDecryption = "SM9 encryption user key has been used for decryption in this JVM: key-usage"
            + " separation refuses it for KEM decapsulation (set org.bouncycastle.sm9.allow_multi_use to true to"
            + " turn the check off)";

        byte[] oscar = "Oscar".getBytes("US-ASCII");
        KeyPair oscarPair = masterPriv.generateUserKeyPair(oscar, SM9EncMasterPrivateKeyParameters.HID);
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(oscarPair.getPublic(), "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(oscarPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128));
        isTrue("SM9-KEM round trip before the key-usage refusal",
            Arrays.areEqual(encapsulated.getEncoded(), decapsulator.generateKey().getEncoded()));

        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PrivateKey[] oscarKeys = { oscarPair.getPrivate(), kf.generatePrivate(new SM9EncUserPrivateKeySpec(
            oscarPair.getPrivate().getEncoded(), masterPub, oscar, SM9EncMasterPrivateKeyParameters.HID)) };
        Cipher decryptor = Cipher.getInstance("SM9", "BC");
        for (int i = 0; i != oscarKeys.length; i++)
        {
            try
            {
                decryptor.init(Cipher.DECRYPT_MODE, oscarKeys[i]);
                fail("Cipher.SM9 took a key that has decapsulated");
            }
            catch (InvalidKeyException e)
            {
                isTrue("Cipher.SM9 key-usage message: " + e.getMessage(), usedForKem.equals(e.getMessage()));
                isTrue("Cipher.SM9 key-usage cause", e.getCause() instanceof IllegalArgumentException);
            }
        }

        byte[] peggy = "Peggy".getBytes("US-ASCII");
        KeyPair peggyPair = masterPriv.generateUserKeyPair(peggy, SM9EncMasterPrivateKeyParameters.HID);
        byte[] message = "a message of twenty-nine bytes".getBytes("US-ASCII");
        Cipher encryptor = Cipher.getInstance("SM9", "BC");
        encryptor.init(Cipher.ENCRYPT_MODE, peggyPair.getPublic(), random);
        byte[] ciphertext = encryptor.doFinal(message);
        decryptor.init(Cipher.DECRYPT_MODE, peggyPair.getPrivate());
        isTrue("Cipher.SM9 round trip before the key-usage refusal",
            Arrays.areEqual(message, decryptor.doFinal(ciphertext)));
        KeyGenerator refused = KeyGenerator.getInstance("SM9-KEM", "BC");
        KEMExtractSpec peggySpec = new KEMExtractSpec(peggyPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128);
        try
        {
            refused.init(peggySpec);
            fail("KeyGenerator.SM9-KEM took a key that has decrypted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("KeyGenerator.SM9-KEM key-usage message: " + e.getMessage(), usedForDecryption.equals(e.getMessage()));
            isTrue("KeyGenerator.SM9-KEM key-usage cause", e.getCause() instanceof IllegalArgumentException);
        }
        checkUninitialised(refused, "an init refused for the key's usage");

        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decryptor.init(Cipher.DECRYPT_MODE, oscarPair.getPrivate());
            refused.init(peggySpec);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
    }

    /**
     * A user key rebuilt through KeyFactory.SM9 with a declared usage is held to it: Cipher.SM9 refuses a
     * key declared for the KEM on its first use, KeyGenerator.SM9-KEM one declared for decryption, the
     * second with the property set as well, and each goes on serving the use it was declared for.
     * KeyFactory.getKeySpec reports the usage a key carries, and the spec refuses a usage it does not know.
     */
    private void declaredUsageTest()
        throws Exception
    {
        String declaredForKem = "SM9 encryption user key is declared for KEM decapsulation and cannot be used for"
            + " decryption";
        String declaredForDecryption = "SM9 encryption user key is declared for decryption and cannot be used for"
            + " KEM decapsulation";
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");

        byte[] trent = "Trent".getBytes("US-ASCII");
        KeyPair trentPair = masterPriv.generateUserKeyPair(trent, SM9EncMasterPrivateKeyParameters.HID);
        PrivateKey kemKey = kf.generatePrivate(new SM9EncUserPrivateKeySpec(trentPair.getPrivate().getEncoded(),
            masterPub, trent, SM9EncMasterPrivateKeyParameters.HID, SM9EncUserPrivateKeySpec.USAGE_KEM));
        try
        {
            Cipher.getInstance("SM9", "BC").init(Cipher.DECRYPT_MODE, kemKey);
            fail("Cipher.SM9 took a key declared for the KEM");
        }
        catch (InvalidKeyException e)
        {
            isTrue("Cipher.SM9 declared-usage message: " + e.getMessage(), declaredForKem.equals(e.getMessage()));
        }
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(trentPair.getPublic(), "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(kemKey, encapsulated.getEncapsulation(), "AES", 128));
        isTrue("a key declared for the KEM decapsulates",
            Arrays.areEqual(encapsulated.getEncoded(), decapsulator.generateKey().getEncoded()));

        byte[] victor = "Victor".getBytes("US-ASCII");
        KeyPair victorPair = masterPriv.generateUserKeyPair(victor, SM9EncMasterPrivateKeyParameters.HID);
        PrivateKey decryptionKey = kf.generatePrivate(new SM9EncUserPrivateKeySpec(victorPair.getPrivate().getEncoded(),
            masterPub, victor, SM9EncMasterPrivateKeyParameters.HID, SM9EncUserPrivateKeySpec.USAGE_DECRYPTION));
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            KeyGenerator.getInstance("SM9-KEM", "BC").init(
                new KEMExtractSpec(decryptionKey, encapsulated.getEncapsulation(), "AES", 128));
            fail("KeyGenerator.SM9-KEM took a key declared for decryption");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("KeyGenerator.SM9-KEM declared-usage message: " + e.getMessage(),
                declaredForDecryption.equals(e.getMessage()));
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
        byte[] message = "a message of twenty-nine bytes".getBytes("US-ASCII");
        Cipher encryptor = Cipher.getInstance("SM9", "BC");
        encryptor.init(Cipher.ENCRYPT_MODE, victorPair.getPublic(), random);
        Cipher decryptor = Cipher.getInstance("SM9", "BC");
        decryptor.init(Cipher.DECRYPT_MODE, decryptionKey);
        isTrue("a key declared for decryption decrypts",
            Arrays.areEqual(message, decryptor.doFinal(encryptor.doFinal(message))));

        isTrue("getKeySpec reports a declared usage", ((SM9EncUserPrivateKeySpec)kf.getKeySpec(kemKey,
            SM9EncUserPrivateKeySpec.class)).getUsage() == SM9EncUserPrivateKeySpec.USAGE_KEM);
        isTrue("getKeySpec reports no usage for an undeclared key", ((SM9EncUserPrivateKeySpec)kf.getKeySpec(
            trentPair.getPrivate(), SM9EncUserPrivateKeySpec.class)).getUsage() == SM9EncUserPrivateKeySpec.USAGE_UNSPECIFIED);
        SM9EncUserPrivateKeySpec exchangeSpec = (SM9EncUserPrivateKeySpec)kf.getKeySpec(
            masterPriv.generateExchangeKeyPair(trent).getPrivate(), SM9EncUserPrivateKeySpec.class);
        isTrue("getKeySpec reports the key exchange's usage",
            exchangeSpec.getUsage() == SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE && exchangeSpec.isExchangeKey());

        // the usage constructor takes what SM9EncPrivateKeyParameters.fromEncoded takes; a key-exchange key
        // is named by the exchangeKey flag alone
        int[] badUsages = { SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE, 4, -1 };
        for (int i = 0; i != badUsages.length; i++)
        {
            try
            {
                new SM9EncUserPrivateKeySpec(trentPair.getPrivate().getEncoded(), masterPub, trent,
                    SM9EncMasterPrivateKeyParameters.HID, badUsages[i]);
                fail("SM9EncUserPrivateKeySpec took usage " + badUsages[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(), ("usage must be USAGE_UNSPECIFIED, USAGE_KEM or USAGE_DECRYPTION - a"
                    + " key-exchange key is named by the constructor taking exchangeKey").equals(e.getMessage()));
            }
        }
        try
        {
            new SM9EncUserPrivateKeySpec(trentPair.getPrivate().getEncoded(), masterPub, trent,
                SM9EncMasterPrivateKeyParameters.HID_EXCHANGE, SM9EncUserPrivateKeySpec.USAGE_KEM);
            fail("SM9EncUserPrivateKeySpec took the KEM usage under HID_EXCHANGE");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), ("hid must not be HID_EXCHANGE (0x02) for a KEM or decryption user key - that"
                + " hid names the key exchange").equals(e.getMessage()));
        }
    }

    /**
     * The GM/T 0044.5-2016 Annex C vector through KeyGenerator.SM9-KEM: handed the vector's r it
     * reproduces C and K, and it decapsulates C back to K - holding the keys the provider builds from
     * their encodings, the spec it takes and the random it hands down to the standard.
     */
    private void knownAnswerTest()
        throws Exception
    {
        Map v = SM9Vectors.load("sm9_kem.txt");
        byte[] identity = SM9Vectors.hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte[] expectedK = SM9Vectors.hex(v, "K");
        byte[] expectedC = Arrays.concatenate(SM9Vectors.hex(v, "C_x"), SM9Vectors.hex(v, "C_y"));

        SM9EncMasterPrivateKeyParameters master =
            new SM9EncMasterPrivateKeyParameters(new BigInteger((String)v.get("ke"), 16));
        AlgorithmIdentifier sm9encrypt = new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt);
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        SM9EncMasterPrivateKey katPriv = (SM9EncMasterPrivateKey)kf.generatePrivate(new PKCS8EncodedKeySpec(
            new PrivateKeyInfo(sm9encrypt, new DEROctetString(master.getEncoded())).getEncoded()));
        SM9EncMasterPublicKey katPub = (SM9EncMasterPublicKey)kf.generatePublic(new X509EncodedKeySpec(
            new SubjectPublicKeyInfo(sm9encrypt, master.getPublicKeyParameters().getEncoded()).getEncoded()));

        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(katPub.getUserPublicKey(identity), "AES", klen),
            new TestRandomBigInteger(256, SM9Vectors.hex(v, "r")));
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();
        isTrue("KeyGenerator.SM9-KEM reproduces the GM/T 0044.5 K", Arrays.areEqual(expectedK, encapsulated.getEncoded()));
        isTrue("KeyGenerator.SM9-KEM reproduces the GM/T 0044.5 C", Arrays.areEqual(expectedC, encapsulated.getEncapsulation()));

        // GM/T 0044.5 Annex C decapsulates with the user key Annex D decrypts with, which the key-usage
        // check refuses within one JVM - SM9CipherTest decrypts the Annex D ciphertexts in the same run -
        // so the known answer is taken with the check turned off for this thread
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
            decapsulator.init(new KEMExtractSpec(
                katPriv.generateUserKeyPair(identity, SM9EncMasterPrivateKeyParameters.HID).getPrivate(), expectedC, "AES", klen));
            isTrue("KeyGenerator.SM9-KEM decapsulates the GM/T 0044.5 C to K",
                Arrays.areEqual(expectedK, decapsulator.generateKey().getEncoded()));
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
    }

    /**
     * An init the KeyGenerator refuses, whatever for, leaves it uninitialised, as a refused init leaves
     * Cipher.SM9 and KeyAgreement.SM9: generateKey() then refuses with an IllegalStateException rather
     * than run the operation the last successful init configured, and none of a refused spec is installed.
     */
    private void rejectedInitTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        PublicKey bobRecipient = masterPub.getUserPublicKey(bob);
        PrivateKey bobKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        KeyPair bobExchange = masterPriv.generateExchangeKeyPair(bob);
        PrivateKey destroyedKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        ((Destroyable)destroyedKey).destroy();

        KeyGenerator kGen = KeyGenerator.getInstance("SM9-KEM", "BC");
        kGen.init(new KEMGenerateSpec(bobRecipient, "AES", 128), random);
        byte[] encapsulation = ((SecretKeyWithEncapsulation)kGen.generateKey()).getEncapsulation();

        // the two operations a generator can be configured for when an init is refused
        AlgorithmParameterSpec[] configured = {
            new KEMGenerateSpec(bobRecipient, "AES", 128),
            new KEMExtractSpec(bobKey, encapsulation, "AES", 128) };

        // each spec engineInit refuses, with what it says: a key or a spec of the wrong kind, or none;
        // what the mechanism would otherwise refuse unchecked inside generateKey() - a fractional-byte
        // size, a key-exchange key, a recipient key under HID_EXCHANGE, under which no decapsulation
        // key can be derived, and a destroyed key; and a KDF or otherInfo, which cannot be honoured,
        // the key being the GM/T 0044.4 KDF's own output
        AlgorithmIdentifier kdf2 = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        String unhonoured = "SM9-KEM derives its key with the GM/T 0044.4 KDF and applies no other KDF or otherInfo - "
            + "layer one through KEM.SM9-KEM with a KTSParameterSpec";
        Object[][] refused = {
            { new KEMGenerateSpec(masterPub, "AES", 128),
                "SM9-KEM encapsulation requires the recipient's SM9EncUserPublicKey, from SM9EncMasterPublicKey.getUserPublicKey(identity)" },
            { new KEMExtractSpec(masterPriv, encapsulation, "AES", 128),
                "SM9-KEM decapsulation requires the recipient's SM9EncUserPrivateKey, the KEM / decryption key from the KGC" },
            { new IvParameterSpec(new byte[16]), "SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec" },
            { null, "SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec" },
            { new KEMGenerateSpec(bobRecipient, "AES", 12), "SM9-KEM key size must be a positive whole number of bytes: 12" },
            { new KEMExtractSpec(bobExchange.getPrivate(), encapsulation, "AES", 128),
                "SM9-KEM decapsulation requires a KEM / decryption user key, not a key-exchange key" },
            { new KEMGenerateSpec(bobExchange.getPublic(), "AES", 128),
                "SM9-KEM encapsulation requires a KEM / encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)" },
            { new KEMExtractSpec(destroyedKey, encapsulation, "AES", 128), "key destroyed" },
            { new KEMGenerateSpec.Builder(bobRecipient, "AES", 128).withOtherInfo(new byte[]{ 0x01 }).build(), unhonoured },
            { new KEMGenerateSpec.Builder(bobRecipient, "AES", 128).withKdfAlgorithm(kdf2).build(), unhonoured },
            { new KEMExtractSpec.Builder(bobKey, encapsulation, "AES", 128).withOtherInfo(new byte[]{ 0x01 }).build(), unhonoured },
            { new KEMExtractSpec.Builder(bobKey, encapsulation, "AES", 128).withKdfAlgorithm(kdf2).build(), unhonoured } };

        for (int c = 0; c != configured.length; c++)
        {
            for (int i = 0; i != refused.length; i++)
            {
                kGen.init(configured[c], random);
                try
                {
                    kGen.init((AlgorithmParameterSpec)refused[i][0], random);
                    fail("SM9-KEM KeyGenerator took spec " + i);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    isTrue("SM9-KEM refuses spec " + i + " with: " + e.getMessage(), refused[i][1].equals(e.getMessage()));
                }
                checkUninitialised(kGen, "spec " + i + " was refused, configured " + c);
            }

            // the two inits that take no spec are always refused, leaving the generator as any refused init does
            kGen.init(configured[c], random);
            try
            {
                kGen.init(random);
                fail("SM9-KEM KeyGenerator took init(SecureRandom)");
            }
            catch (UnsupportedOperationException e)
            {
                isTrue("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec".equals(e.getMessage()));
            }
            checkUninitialised(kGen, "init(SecureRandom) was refused, configured " + c);
            kGen.init(configured[c], random);
            try
            {
                kGen.init(128, random);
                fail("SM9-KEM KeyGenerator took init(int, SecureRandom)");
            }
            catch (UnsupportedOperationException e)
            {
                isTrue("SM9-KEM requires a KEMGenerateSpec or KEMExtractSpec".equals(e.getMessage()));
            }
            checkUninitialised(kGen, "init(int, SecureRandom) was refused, configured " + c);
        }

        // an init that succeeds after them serves as it would on a generator never refused
        kGen.init(new KEMGenerateSpec(bobRecipient, "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)kGen.generateKey();
        kGen.init(new KEMExtractSpec(bobKey, encapsulated.getEncapsulation(), "AES", 128), random);
        isTrue("SM9-KEM serves an init that succeeds after refused ones",
            Arrays.areEqual(encapsulated.getEncoded(), kGen.generateKey().getEncoded()));

        // the default KDF every spec carries unless told otherwise and no KDF at all both give the
        // GM/T 0044.4 output, and so the same key
        kGen.init(new KEMGenerateSpec.Builder(bobRecipient, "AES", 128).withNoKdf().build(), random);
        SecretKeyWithEncapsulation noKdf = (SecretKeyWithEncapsulation)kGen.generateKey();
        kGen.init(new KEMExtractSpec(bobKey, noKdf.getEncapsulation(), "AES", 128), random);
        isTrue("SM9-KEM gives one key with or without the default KDF named",
            Arrays.areEqual(noKdf.getEncoded(), kGen.generateKey().getEncoded()));
    }

    /**
     * An init that fails after it has examined the spec - here because it was given no random source
     * and the default one cannot be had - leaves the generator uninitialised, and leaves no record of
     * the use of the key it was given to decapsulate with, which then decrypts.
     */
    private void failedInitTest()
        throws Exception
    {
        byte[] message = "a message of twenty-nine bytes".getBytes("US-ASCII");
        byte[] sybil = "Sybil".getBytes("US-ASCII");
        KeyPair sybilPair = masterPriv.generateUserKeyPair(sybil, SM9EncMasterPrivateKeyParameters.HID);
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(sybilPair.getPublic(), "AES", 128), random);
        byte[] encapsulation = ((SecretKeyWithEncapsulation)encapsulator.generateKey()).getEncapsulation();

        // a default source this thread cannot have, and the one there was put back afterwards
        final Thread caller = Thread.currentThread();
        final boolean specified = CryptoServicesRegistrar.isSecureRandomSpecified();
        final SecureRandom previous = CryptoServicesRegistrar.getSecureRandom();
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        CryptoServicesRegistrar.setSecureRandomProvider(new SecureRandomProvider()
        {
            public SecureRandom get()
            {
                if (Thread.currentThread() == caller)
                {
                    throw new IllegalStateException("no default source");
                }
                return previous;
            }
        });
        try
        {
            decapsulator.init(new KEMExtractSpec(sybilPair.getPrivate(), encapsulation, "AES", 128), (SecureRandom)null);
            fail("KeyGenerator.SM9-KEM was initialised with no random source to be had");
        }
        catch (IllegalStateException e)
        {
            isTrue(e.getMessage(), "no default source".equals(e.getMessage()));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(specified ? previous : null);
        }
        checkUninitialised(decapsulator, "an init that could not have a random source");

        Cipher encryptor = Cipher.getInstance("SM9", "BC");
        encryptor.init(Cipher.ENCRYPT_MODE, sybilPair.getPublic(), random);
        Cipher decryptor = Cipher.getInstance("SM9", "BC");
        decryptor.init(Cipher.DECRYPT_MODE, sybilPair.getPrivate());
        isTrue("a key the failed init did not take decrypts",
            Arrays.areEqual(message, decryptor.doFinal(encryptor.doFinal(message))));
    }

    private void checkUninitialised(KeyGenerator kGen, String after)
    {
        try
        {
            kGen.generateKey();
            fail("SM9-KEM KeyGenerator generated a key after " + after);
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9-KEM KeyGenerator not initialised - supply a KEMGenerateSpec or KEMExtractSpec"
                .equals(e.getMessage()));
        }
    }

    /**
     * The hid is part of what an SM9 encryption key is, so it takes part in equals() and hashCode():
     * an identity's keys under two hids are two different keys, which an application pinning,
     * allowlisting or de-duplicating keys by equality has to be able to tell apart.
     */
    private void hidEqualityTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        PublicKey kemPub = masterPub.getUserPublicKey(bob, SM9EncMasterPublicKey.HID);
        PublicKey exchangePub = masterPub.getUserPublicKey(bob, SM9EncMasterPublicKey.HID_EXCHANGE);

        isTrue("the same hid compares equal",
            kemPub.equals(masterPub.getUserPublicKey(bob, SM9EncMasterPublicKey.HID)));
        isTrue("the same hid hashes equal",
            kemPub.hashCode() == masterPub.getUserPublicKey(bob, SM9EncMasterPublicKey.HID).hashCode());
        isTrue("recipient keys under different hids are not equal", !kemPub.equals(exchangePub));
        isTrue("a HashSet tells recipient keys under different hids apart",
            !java.util.Collections.singleton(kemPub).contains(exchangePub));

        // and the private halves likewise: the encoding is the point alone, so the hid and the usage
        // are what separate a decryption key from an exchange key
        PrivateKey kemKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPublicKey.HID).getPrivate();
        PrivateKey exchangeKey = masterPriv.generateExchangeKeyPair(bob).getPrivate();
        isTrue("a KEM user key equals itself", kemKey.equals(
            masterPriv.generateUserKeyPair(bob, SM9EncMasterPublicKey.HID).getPrivate()));
        isTrue("user keys of different usage are not equal", !kemKey.equals(exchangeKey));

        // the same key material imported under another identity is refused: KeyFactory.SM9 holds the
        // spec's four parts to the KGC's own relation
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        isTrue("a derived key imports under its own identity", kemKey.equals(kf.generatePrivate(
            new SM9EncUserPrivateKeySpec(kemKey.getEncoded(), masterPub, bob, SM9EncMasterPublicKey.HID))));
        try
        {
            kf.generatePrivate(new SM9EncUserPrivateKeySpec(
                kemKey.getEncoded(), masterPub, "Carol".getBytes("US-ASCII"), SM9EncMasterPublicKey.HID));
            fail("a key was imported under the wrong identity");
        }
        catch (InvalidKeySpecException e)
        {
            isTrue(e.getMessage(), ("unable to decode SM9 user private key: SM9 encryption private key does not "
                + "match its master public key, identity and hid").equals(e.getMessage()));
        }
    }

    /**
     * equals() and hashCode() on a user private key agree, and the same point in another context -
     * another master public key, another identity - is another key. A user key's point is refused
     * in a context it is not the key of, so its other context here is a master public key under
     * which it is another identity's key.
     */
    private void userKeyEqualityTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        byte[] eve = "Eve".getBytes("US-ASCII");
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");

        byte[] encKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPublicKey.HID).getPrivate().getEncoded();
        checkEqualsAgreesWithHashCode("SM9-ENC", new PrivateKey[]
        {
            kf.generatePrivate(new SM9EncUserPrivateKeySpec(encKey, masterPub, bob, SM9EncMasterPublicKey.HID)),
            kf.generatePrivate(new SM9EncUserPrivateKeySpec(encKey, masterPub, bob, SM9EncMasterPublicKey.HID)),
            kf.generatePrivate(new SM9EncUserPrivateKeySpec(encKey,
                masterMakingKeyOf(kf, masterPriv, bob, eve), eve, SM9EncMasterPublicKey.HID))
        });

        KeyPairGenerator sigGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        sigGen.initialize(256, random);
        KeyPair sigMaster = sigGen.generateKeyPair();
        SM9SigMasterPublicKey sigPub = (SM9SigMasterPublicKey)sigMaster.getPublic();
        SM9SigMasterPublicKey otherSigPub = (SM9SigMasterPublicKey)sigGen.generateKeyPair().getPublic();
        byte[] sigKey = ((SM9SigMasterPrivateKey)sigMaster.getPrivate())
            .generateUserKeyPair(bob).getPrivate().getEncoded();
        checkEqualsAgreesWithHashCode("SM9-SIGN", new PrivateKey[]
        {
            kf.generatePrivate(new SM9SigUserPrivateKeySpec(sigKey, sigPub, bob)),
            kf.generatePrivate(new SM9SigUserPrivateKeySpec(sigKey, sigPub, bob)),
            kf.generatePrivate(new SM9SigUserPrivateKeySpec(sigKey,
                sigMasterMakingKeyOf(kf, sigMaster.getPrivate(), bob, eve), eve))
        });

        // a signature key's point is refused in a context it is not the key of, as an encryption key's is
        String[] contexts = { "another master public key", "another identity" };
        SM9SigUserPrivateKeySpec[] misfiled = {
            new SM9SigUserPrivateKeySpec(sigKey, otherSigPub, bob),
            new SM9SigUserPrivateKeySpec(sigKey, sigPub, eve) };
        for (int i = 0; i != misfiled.length; i++)
        {
            try
            {
                kf.generatePrivate(misfiled[i]);
                fail("a signature key was imported under " + contexts[i]);
            }
            catch (InvalidKeySpecException e)
            {
                isTrue(e.getMessage(), ("unable to decode SM9 user private key: SM9 signature private key does not "
                    + "match its master public key and identity").equals(e.getMessage()));
            }
        }
    }

    /**
     * An encryption master public key under which the key that master derives for identity is
     * also the key of other, both under the published hid: for ke' with
     * ke' / (H1(other || hid, N) + ke') = ke / (H1(identity || hid, N) + ke) mod N, [ke' (H1(other ||
     * hid, N) + ke')^-1]P2 is the same point.
     */
    private static SM9EncMasterPublicKey masterMakingKeyOf(KeyFactory kf, PrivateKey master, byte[] identity,
                                                           byte[] other)
        throws Exception
    {
        BigInteger n = SM9Curve.N;
        BigInteger ke = new BigInteger(1, ASN1OctetString.getInstance(
            PrivateKeyInfo.getInstance(master.getEncoded()).parsePrivateKey()).getOctets());
        BigInteger h = SM9Sm3.h1(Arrays.append(identity, SM9EncMasterPublicKey.HID), n);
        BigInteger hOther = SM9Sm3.h1(Arrays.append(other, SM9EncMasterPublicKey.HID), n);
        BigInteger c = ke.multiply(h.add(ke).modInverse(n)).mod(n);
        BigInteger otherKe = c.multiply(hOther).multiply(BigInteger.ONE.subtract(c).modInverse(n)).mod(n);
        byte[] pPube = new SM9EncMasterPrivateKeyParameters(otherKe).getPublicKeyParameters().getEncoded();
        return (SM9EncMasterPublicKey)kf.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), pPube).getEncoded(ASN1Encoding.DER)));
    }

    /**
     * The signature counterpart of masterMakingKeyOf: ds = [ks (H1(ID || hid, N) + ks)^-1]P1 has the
     * same shape as an encryption key, so the same ks' makes identity's key other's as well.
     */
    private static SM9SigMasterPublicKey sigMasterMakingKeyOf(KeyFactory kf, PrivateKey master, byte[] identity,
                                                              byte[] other)
        throws Exception
    {
        BigInteger n = SM9Curve.N;
        BigInteger ks = new BigInteger(1, ASN1OctetString.getInstance(
            PrivateKeyInfo.getInstance(master.getEncoded()).parsePrivateKey()).getOctets());
        BigInteger h = SM9Sm3.h1(Arrays.append(identity, SM9SigMasterPrivateKeyParameters.HID), n);
        BigInteger hOther = SM9Sm3.h1(Arrays.append(other, SM9SigMasterPrivateKeyParameters.HID), n);
        BigInteger c = ks.multiply(h.add(ks).modInverse(n)).mod(n);
        BigInteger otherKs = c.multiply(hOther).multiply(BigInteger.ONE.subtract(c).modInverse(n)).mod(n);
        byte[] pPubs = new SM9SigMasterPrivateKeyParameters(otherKs).getPublicKeyParameters().getEncoded();
        return (SM9SigMasterPublicKey)kf.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), pPubs).getEncoded(ASN1Encoding.DER)));
    }

    /**
     * keys[0] and keys[1] are two imports of one key; each one after them carries the same point in
     * another context.
     */
    private void checkEqualsAgreesWithHashCode(String name, PrivateKey[] keys)
    {
        for (int i = 0; i != keys.length; i++)
        {
            for (int j = 0; j != keys.length; j++)
            {
                if (keys[i].equals(keys[j]))
                {
                    isTrue(name + " keys " + i + " and " + j + " are equal, so hash equal",
                        keys[i].hashCode() == keys[j].hashCode());
                }
            }
        }
        isTrue(name + " two imports of one key are equal", keys[0].equals(keys[1]) && keys[1].equals(keys[0]));
        for (int i = 2; i != keys.length; i++)
        {
            isTrue(name + " the same point in another context is another key (" + i + ")",
                !keys[0].equals(keys[i]) && !keys[i].equals(keys[0]));
        }
    }

    private void destroyTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair ownMaster = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey ownPriv = (SM9EncMasterPrivateKey)ownMaster.getPrivate();
        SM9EncMasterPublicKey ownPub = (SM9EncMasterPublicKey)ownMaster.getPublic();

        KeyPair bobPair = ownPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(ownPub.getUserPublicKey(bob), "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();

        // a destroyed user private key neither encodes nor is taken for decapsulation - refused at
        // init, where it can be reported, as generateKey() can throw nothing checked
        destroyAndCheck("user key", bobPair.getPrivate());
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        try
        {
            decapsulator.init(new KEMExtractSpec(bobPair.getPrivate(), encapsulated.getEncapsulation(), "AES", 128));
            fail("destroyed user key still taken for decapsulation");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }

        // a destroyed master private key neither encodes, derives user keys nor serializes; the
        // published master public key, and so the sender side, is unaffected
        destroyAndCheck("master key", ownPriv);
        try
        {
            ownPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID);
            fail("destroyed master key still generates user keys");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }
        try
        {
            new ObjectOutputStream(new ByteArrayOutputStream()).writeObject(ownPriv);
            fail("destroyed master key still serializes");
        }
        catch (NotSerializableException e)
        {
            // expected
        }
        isTrue("sender side unaffected by master destroy", ownPub.getUserPublicKey(bob) != null);

        checkDestroyedEqualsDoesNotThrow();
    }

    /**
     * Destroy key, checking isDestroyed() before and after, and that getEncoded() then refuses.
     */
    private void destroyAndCheck(String label, PrivateKey key)
        throws Exception
    {
        Destroyable destroyable = (Destroyable)key;
        isTrue(label + " not destroyed yet", !destroyable.isDestroyed());
        destroyable.destroy();
        isTrue(label + " destroyed", destroyable.isDestroyed());
        try
        {
            key.getEncoded();
            fail("destroyed " + label + " still encodes");
        }
        catch (IllegalStateException e)
        {
            isTrue("key destroyed".equals(e.getMessage()));
        }
    }

    /**
     * Object.equals must not throw, although these keys' getEncoded() throws once they are destroyed:
     * a destroyed key still equals itself, so a HashSet can still find and remove it, and compares
     * unequal to a live copy of itself from either side. hashCode() reads only public material.
     */
    private void checkDestroyedEqualsDoesNotThrow()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");

        KeyPairGenerator encGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        encGen.initialize(256, random);
        KeyPair encMaster = encGen.generateKeyPair();
        KeyPairGenerator sigGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        sigGen.initialize(256, random);
        KeyPair sigMaster = sigGen.generateKeyPair();

        PrivateKey[] live = new PrivateKey[]
        {
            ((SM9EncMasterPrivateKey)encMaster.getPrivate()).generateUserKeyPair(
                bob, SM9EncMasterPublicKey.HID).getPrivate(),
            ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(bob).getPrivate(),
            encMaster.getPrivate(),
            sigMaster.getPrivate()
        };

        for (int i = 0; i != live.length; i++)
        {
            PrivateKey key = live[i];
            String name = key.getAlgorithm() + "[" + i + "]";
            java.util.Set set = new java.util.HashSet();
            set.add(key);

            ((Destroyable)key).destroy();
            isTrue(name + " destroyed", ((Destroyable)key).isDestroyed());

            // equals answers rather than throws, in either direction
            isTrue(name + " equals itself when destroyed", key.equals(key));
            isTrue(name + " does not equal an unrelated object", !key.equals("not a key"));
            isTrue(name + " hashCode still answers", key.hashCode() == key.hashCode());
            isTrue(name + " is still found in a HashSet", set.contains(key));
            isTrue(name + " is still removable from a HashSet", set.remove(key));
        }

        // two separately derived copies of one user key are equal while both are live
        SM9EncMasterPrivateKey freshMaster = (SM9EncMasterPrivateKey)encGen.generateKeyPair().getPrivate();
        PrivateKey liveKey = freshMaster.generateUserKeyPair(bob, SM9EncMasterPublicKey.HID).getPrivate();
        PrivateKey deadKey = freshMaster.generateUserKeyPair(bob, SM9EncMasterPublicKey.HID).getPrivate();
        isTrue("two copies of one user key are equal", liveKey.equals(deadKey));

        ((Destroyable)deadKey).destroy();
        isTrue("a live key does not equal a destroyed one", !liveKey.equals(deadKey));

        // a user public key hands back the same master public key object each time
        SM9EncUserPublicKey userPub = (SM9EncUserPublicKey)((SM9EncMasterPublicKey)encMaster.getPublic()).getUserPublicKey(bob);
        isTrue("getMasterPublicKey() returns one object", userPub.getMasterPublicKey() == userPub.getMasterPublicKey());
        isTrue("a destroyed key does not equal a live one", !deadKey.equals(liveKey));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM9KEMTest());
    }
}
