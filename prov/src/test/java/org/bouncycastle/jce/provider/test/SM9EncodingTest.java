package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamConstants;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.gm.SM9Signature;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPublicKey;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression pin for the SM9 DER encodings (the GM/T 0080-2020 structures, nationally adopted as
 * GB/T 41389-2022) of the generators, representative keys, the signature, the stream-mode ciphertext
 * and the KEM key package, with checks of the provider's SM9 key handling. The values are the
 * GM/T 0044.5-2016 worked examples, but the expected DER in crypto/sm9/sm9_der_encodings.txt was
 * produced by this implementation, so this guards the encodings against change and is no conformance
 * check; the official KATs in SM9SignerTest, SM9KEMTest, SM9KeyExchangeTest and SM9CipherTest are.
 */
public class SM9EncodingTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Encoding";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        checkKeyInfoConverters();
        checkTranslateKeyTakesEveryKey();
        checkUserPublicKeyTypes();
        checkEmbeddedPublicKey();
        checkCanonicalKeyEncodings();
        checkKeyFactoryTypesAndMessages();
        checkAsn1Guards();
        checkDirectStreamsRefused();
        checkDestroyedKeysRefused();
        checkKeysDestroyedAfterInit();
        checkUserKeyHashCoversIdentity();
        checkThirdPartyMasterPublicKey();
        checkUserKeyEqualityCoversHidAndUsage();
        checkKeyPairGeneratorTakesCallerRandom();
        checkConstantTimeKeyComparison();

        Map enc = SM9Vectors.load("sm9_der_encodings.txt");
        Map sig = SM9Vectors.load("sm9_signature.txt");
        Map kex = SM9Vectors.load("sm9_keyexchange.txt");
        Map kem = SM9Vectors.load("sm9_kem.txt");
        Map cipher = SM9Vectors.load("sm9_encryption.txt");

        isEncoding("SM9 DER P1", bitString(SM9Curve.P1.getEncoded(false)), enc, "P1_DER");
        isEncoding("SM9 DER P2", bitString(SM9Curve.P2.getEncoded()), enc, "P2_DER");

        SM9SigMasterPrivateKeyParameters signMaster =
            new SM9SigMasterPrivateKeyParameters(new BigInteger((String)sig.get("ks"), 16));
        SM9SigPrivateKeyParameters signUser = signMaster.generateUserKey(SM9Vectors.hex(sig, "IDA"));
        isEncoding("SM9 DER ks", integer((String)sig.get("ks")), enc, "ks_DER");
        isEncoding("SM9 DER Ppub-s", bitString(signMaster.getPublicKeyParameters().getEncoded()),
            enc, "Ppubs_DER");
        isEncoding("SM9 DER dsA", bitString(signUser.getEncoded()), enc, "dsA_DER");

        byte hid = (byte)Integer.parseInt((String)kex.get("hid"), 16);
        SM9EncMasterPrivateKeyParameters encMaster =
            new SM9EncMasterPrivateKeyParameters(new BigInteger((String)kex.get("ke"), 16));
        SM9EncPrivateKeyParameters encUser = encMaster.generateExchangeKey(SM9Vectors.hex(kex, "IDA"), hid);
        isEncoding("SM9 DER ke", integer((String)kex.get("ke")), enc, "ke_DER");
        isEncoding("SM9 DER Ppub-e", bitString(encMaster.getPublicKeyParameters().getEncoded()),
            enc, "Ppube_DER");
        isEncoding("SM9 DER deA", bitString(encUser.getEncoded()), enc, "deA_DER");

        byte[] s = Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(sig, "Sx"), SM9Vectors.hex(sig, "Sy"));
        byte[] signatureEncoding = new SM9Signature(SM9Vectors.hex(sig, "h"), s).getEncoded();
        isEncoding("SM9 DER SM9Signature", signatureEncoding, enc, "signature_DER");
        SM9Signature parsedSignature = SM9Signature.getInstance(SM9Vectors.hex(enc, "signature_DER"));
        isTrue("SM9 DER SM9Signature h", Arrays.areEqual(parsedSignature.getH(), SM9Vectors.hex(sig, "h")));
        isTrue("SM9 DER SM9Signature S", Arrays.areEqual(parsedSignature.getS(), s));

        byte[] c1 = Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(cipher, "C1_x"), SM9Vectors.hex(cipher, "C1_y"));
        byte[] cipherEncoding = new SM9Cipher(SM9Cipher.EN_TYPE_STREAM, c1,
            SM9Vectors.hex(cipher, "modeA_C3"), SM9Vectors.hex(cipher, "modeA_C2")).getEncoded();
        isEncoding("SM9 DER SM9Cipher", cipherEncoding, enc, "cipher_DER");
        SM9Cipher parsedCipher = SM9Cipher.getInstance(SM9Vectors.hex(enc, "cipher_DER"));
        isTrue("SM9 DER SM9Cipher type", parsedCipher.getEnType() == SM9Cipher.EN_TYPE_STREAM);
        isTrue("SM9 DER SM9Cipher C1", Arrays.areEqual(parsedCipher.getC1(), c1));
        isTrue("SM9 DER SM9Cipher C3",
            Arrays.areEqual(parsedCipher.getC3(), SM9Vectors.hex(cipher, "modeA_C3")));
        isTrue("SM9 DER SM9Cipher C2",
            Arrays.areEqual(parsedCipher.getC2(), SM9Vectors.hex(cipher, "modeA_C2")));

        ASN1EncodableVector keyPackage = new ASN1EncodableVector(2);
        keyPackage.add(new DEROctetString(SM9Vectors.hex(kem, "K")));
        keyPackage.add(new DERBitString(
            Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(kem, "C_x"), SM9Vectors.hex(kem, "C_y"))));
        isEncoding("SM9 DER SM9KeyPackage", new DERSequence(keyPackage).getEncoded(),
            enc, "keypackage_DER");
    }

    /**
     * BouncyCastleProvider resolves an SM9 key by its algorithm OID through the key-info converter
     * table, the path generic BC subsystems take, as well as through KeyFactory.getInstance("SM9").
     */
    private void checkKeyInfoConverters()
        throws Exception
    {
        String[] families = { "SM9-SIGN", "SM9-ENC" };
        for (int i = 0; i != families.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(families[i], "BC");
            kpGen.initialize(256, new SecureRandom());
            KeyPair pair = kpGen.generateKeyPair();

            PublicKey pub = BouncyCastleProvider.getPublicKey(
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
            isTrue(families[i] + " master public key resolves through the converter table", pub != null);
            isTrue(families[i] + " master public key round-trips through the converter table",
                Arrays.areEqual(pub.getEncoded(), pair.getPublic().getEncoded()));

            PrivateKey priv = BouncyCastleProvider.getPrivateKey(
                PrivateKeyInfo.getInstance(pair.getPrivate().getEncoded()));
            isTrue(families[i] + " master private key resolves through the converter table", priv != null);
            isTrue(families[i] + " master private key round-trips through the converter table",
                Arrays.areEqual(priv.getEncoded(), pair.getPrivate().getEncoded()));

            KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
            // the OID spellings every other family registers resolve too
            isTrue(families[i] + " resolves a KeyFactory by OID",
                KeyFactory.getInstance(pub.getAlgorithm().equals("SM9-SIGN")
                    ? GMObjectIdentifiers.sm9sign.getId() : GMObjectIdentifiers.sm9encrypt.getId(), "BC") != null);

            // a BIT STRING with pad bits holds no whole octets for the point: the converter refuses it, directly
            // or through BouncyCastleProvider, with the IOException it declares, the KeyFactory with InvalidKeySpecException
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
            ASN1EncodableVector padded = new ASN1EncodableVector(2);
            padded.add(info.getAlgorithm());
            padded.add(new DERBitString(info.getPublicKeyData().getBytes(), 1));
            SubjectPublicKeyInfo unaligned = SubjectPublicKeyInfo.getInstance(new DERSequence(padded));
            try
            {
                new org.bouncycastle.jcajce.provider.asymmetric.sm9.KeyFactorySpi().generatePublic(unaligned);
                fail(families[i] + " converter decoded a master public key with pad bits");
            }
            catch (IOException e)
            {
                isTrue("SM9 master public key must be an octet-aligned BIT STRING".equals(e.getMessage()));
            }
            try
            {
                BouncyCastleProvider.getPublicKey(unaligned);
                fail(families[i] + " master public key with pad bits resolved through the converter table");
            }
            catch (IOException e)
            {
                isTrue("SM9 master public key must be an octet-aligned BIT STRING".equals(e.getMessage()));
            }
            isTrue("SM9 master public key must be an octet-aligned BIT STRING".equals(publicRefusal(kf,
                new X509EncodedKeySpec(unaligned.getEncoded()), "an " + families[i] + " master public key with pad bits")
                .getMessage()));
        }
    }

    /**
     * translateKey() answers for every kind of SM9 key the provider hands out, as does the factory looked
     * up under the key's own algorithm name. The factory names the nine key classes one by one, and all
     * nine are translated here, so leaving one out again fails.
     */
    private void checkTranslateKeyTakesEveryKey()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");

        KeyPairGenerator sigGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        sigGen.initialize(256, new SecureRandom());
        KeyPair sigMaster = sigGen.generateKeyPair();
        KeyPair sigUser = ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(identity);

        KeyPairGenerator encGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        encGen.initialize(256, new SecureRandom());
        KeyPair encMaster = encGen.generateKeyPair();
        SM9EncMasterPublicKey encMasterPub = (SM9EncMasterPublicKey)encMaster.getPublic();
        KeyPair encUser = ((SM9EncMasterPrivateKey)encMaster.getPrivate())
            .generateUserKeyPair(identity, SM9EncMasterPublicKey.HID);

        Key[] keys = {
            sigMaster.getPublic(), sigMaster.getPrivate(), sigUser.getPublic(), sigUser.getPrivate(),
            encMaster.getPublic(), encMaster.getPrivate(), encUser.getPublic(), encUser.getPrivate(),
            encMasterPub.getExchangeEphemeral(SM9Curve.g1ToBytes(SM9Curve.P1)) };
        for (int i = 0; i != keys.length; i++)
        {
            isTrue("translateKey answers for " + keys[i].getClass().getName(), kf.translateKey(keys[i]) == keys[i]);

            // and the factory is found under the name the key gives, as generic JCA code looks it up
            KeyFactory named = KeyFactory.getInstance(keys[i].getAlgorithm(), "BC");
            isTrue("KeyFactory " + keys[i].getAlgorithm() + " answers for " + keys[i].getClass().getName(),
                named.translateKey(keys[i]) == keys[i]);
        }

        // only the master public keys have an X.509 encoding, which round-trips; a spec for a user public
        // key, which has none, or for the key-exchange ephemeral, the raw point, is refused however named
        Key[] masterPublic = { sigMaster.getPublic(), encMaster.getPublic() };
        for (int i = 0; i != masterPublic.length; i++)
        {
            X509EncodedKeySpec spec = (X509EncodedKeySpec)kf.getKeySpec(masterPublic[i], X509EncodedKeySpec.class);
            isTrue("the X.509 spec of " + masterPublic[i].getClass().getName() + " round-trips",
                masterPublic[i].equals(kf.generatePublic(spec)));
        }
        Key[] noX509 = { sigUser.getPublic(), encUser.getPublic(), keys[8] };
        Class[] specs = { X509EncodedKeySpec.class, EncodedKeySpec.class, KeySpec.class };
        for (int i = 0; i != noX509.length; i++)
        {
            for (int j = 0; j != specs.length; j++)
            {
                isTrue(("not an SM9 key or unsupported spec: " + specs[j].getName()).equals(keySpecRefusal(kf, noX509[i],
                    specs[j], "getKeySpec gave " + noX509[i].getClass().getName() + " a " + specs[j].getName()).getMessage()));
            }
        }

        // likewise only the master private keys decode from PKCS#8 alone; a user private key's PKCS#8 spec
        // is refused, and asked for by that spec's superclasses getKeySpec gives its user key spec
        Key[] masterPrivate = { sigMaster.getPrivate(), encMaster.getPrivate() };
        for (int i = 0; i != masterPrivate.length; i++)
        {
            PKCS8EncodedKeySpec spec = (PKCS8EncodedKeySpec)kf.getKeySpec(masterPrivate[i], PKCS8EncodedKeySpec.class);
            isTrue("the PKCS#8 spec of " + masterPrivate[i].getClass().getName() + " round-trips",
                masterPrivate[i].equals(kf.generatePrivate(spec)));
        }
        PrivateKey[] userPrivate = { sigUser.getPrivate(), encUser.getPrivate(),
            ((SM9EncMasterPrivateKey)encMaster.getPrivate()).generateExchangeKeyPair(identity).getPrivate() };
        Class[] userSpecs = { EncodedKeySpec.class, KeySpec.class };
        for (int i = 0; i != userPrivate.length; i++)
        {
            isTrue(("not an SM9 key or unsupported spec: " + PKCS8EncodedKeySpec.class.getName()).equals(keySpecRefusal(kf,
                userPrivate[i], PKCS8EncodedKeySpec.class, "getKeySpec gave " + userPrivate[i].getClass().getName()
                + " a PKCS#8 spec").getMessage()));
            for (int j = 0; j != userSpecs.length; j++)
            {
                KeySpec spec = kf.getKeySpec(userPrivate[i], userSpecs[j]);
                isTrue("the " + userSpecs[j].getName() + " of " + userPrivate[i].getClass().getName() + " is its user key spec",
                    spec instanceof SM9SigUserPrivateKeySpec || spec instanceof SM9EncUserPrivateKeySpec);
                isTrue("the user key spec of " + userPrivate[i].getClass().getName() + " round-trips",
                    userPrivate[i].equals(kf.generatePrivate(spec)));
            }
        }
    }

    /**
     * Every SM9 key class is written as SM9KeyProxy or not at all and holds its key parameters in
     * transient fields, so each refuses a stream holding the class itself - which no key writes, but
     * anyone can put together - rather than read back a key with no parameters.
     */
    private void checkDirectStreamsRefused()
        throws Exception
    {
        String[][] classes = {
            { "BCSM9EncMasterPrivateKey", "BCSM9EncMasterPublicKey", "BCSM9SigMasterPrivateKey", "BCSM9SigMasterPublicKey" },
            { "BCSM9EncPrivateKey", "BCSM9EncPublicKey", "BCSM9SigPrivateKey", "BCSM9SigPublicKey" },
            { "BCSM9ExchangeEphemeralPublicKey" } };
        String[] messages = {
            "SM9 master keys are read through their serialization proxy",
            "SM9 user keys are not serializable",
            "SM9 exchange ephemeral keys are not serializable" };
        for (int i = 0; i != classes.length; i++)
        {
            for (int j = 0; j != classes[i].length; j++)
            {
                byte[] stream = directStream("org.bouncycastle.jcajce.provider.asymmetric.sm9." + classes[i][j]);
                try
                {
                    new ObjectInputStream(new ByteArrayInputStream(stream)).readObject();
                    fail("read " + classes[i][j] + " from a stream holding the class itself");
                }
                catch (InvalidObjectException e)
                {
                    isTrue(classes[i][j] + " refusal message", messages[i].equals(e.getMessage()));
                }
            }
        }
    }

    /**
     * A destroyed private key is refused where it is handed over - at the init of the service that
     * would use it, and by getKeySpec - as the other SPIs in the provider refuse one. SM9SignatureTest
     * and SM9KEMTest hold Signature.SM9 and KeyGenerator.SM9-KEM to the same.
     */
    private void checkDestroyedKeysRefused()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");
        KeyPair sigMaster = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        PrivateKey sigKey = ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(identity).getPrivate();
        KeyPair encMaster = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        SM9EncMasterPrivateKey encMasterPrivate = (SM9EncMasterPrivateKey)encMaster.getPrivate();
        PrivateKey encKey = encMasterPrivate.generateUserKeyPair(identity, SM9EncMasterPublicKey.HID).getPrivate();
        PrivateKey exchangeKey = encMasterPrivate.generateExchangeKeyPair(identity).getPrivate();

        PrivateKey[] keys = { sigKey, encKey, exchangeKey, sigMaster.getPrivate(), encMaster.getPrivate() };
        for (int i = 0; i != keys.length; i++)
        {
            ((Destroyable)keys[i]).destroy();
        }

        try
        {
            Cipher.getInstance("SM9", "BC").init(Cipher.DECRYPT_MODE, encKey);
            fail("Cipher.SM9 took a destroyed key");
        }
        catch (InvalidKeyException e)
        {
            isTrue("Cipher.SM9 refusal message", "key destroyed".equals(e.getMessage()));
        }
        try
        {
            KeyAgreement.getInstance("SM9", "BC").init(exchangeKey, new SM9KeyExchangeSpec(true, 128), new SecureRandom());
            fail("KeyAgreement.SM9 took a destroyed key");
        }
        catch (InvalidKeyException e)
        {
            isTrue("KeyAgreement.SM9 refusal message", "key destroyed".equals(e.getMessage()));
        }
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        for (int i = 0; i != keys.length; i++)
        {
            isTrue("KeyFactory.SM9 refusal message", "key destroyed".equals(keySpecRefusal(kf, keys[i],
                PKCS8EncodedKeySpec.class, "KeyFactory.SM9 gave a destroyed " + keys[i].getClass().getName() + " a key spec")
                .getMessage()));
        }
    }

    /**
     * A key destroyed after the service took it is reported as destroyed by the operation that would
     * use it, through the exception the operation declares for a state it cannot run in - for
     * KeyGenerator.SM9-KEM, whose generateKey() declares none, through the key's own IllegalStateException.
     */
    private void checkKeysDestroyedAfterInit()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");
        byte[] message = "a message of twenty-nine bytes".getBytes("US-ASCII");
        KeyPair sigMaster = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        PrivateKey sigKey = ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(identity).getPrivate();
        KeyPair encMaster = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        SM9EncMasterPrivateKey encMasterPrivate = (SM9EncMasterPrivateKey)encMaster.getPrivate();
        PrivateKey encKey = encMasterPrivate.generateUserKeyPair(identity, SM9EncMasterPublicKey.HID).getPrivate();
        PrivateKey exchangeKey = encMasterPrivate.generateExchangeKeyPair(identity).getPrivate();
        PublicKey recipient = ((SM9EncMasterPublicKey)encMaster.getPublic()).getUserPublicKey(identity);
        PublicKey peer = ((SM9EncMasterPublicKey)encMaster.getPublic()).getUserPublicKey(
            "Bob".getBytes("US-ASCII"), SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);

        Cipher encryptor = Cipher.getInstance("SM9", "BC");
        encryptor.init(Cipher.ENCRYPT_MODE, recipient);
        byte[] ciphertext = encryptor.doFinal(message);
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(recipient, "AES", 128), new SecureRandom());
        byte[] encapsulation = ((SecretKeyWithEncapsulation)encapsulator.generateKey()).getEncapsulation();

        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(sigKey);
        signer.update(message);
        Cipher decryptor = Cipher.getInstance("SM9", "BC");
        decryptor.init(Cipher.DECRYPT_MODE, encKey);
        KeyGenerator extractor = KeyGenerator.getInstance("SM9-KEM", "BC");
        extractor.init(new KEMExtractSpec(encKey, encapsulation, "AES", 128));
        KeyAgreement agreement = KeyAgreement.getInstance("SM9", "BC");
        agreement.init(exchangeKey, new SM9KeyExchangeSpec(true, 128), new SecureRandom());

        ((Destroyable)sigKey).destroy();
        ((Destroyable)encKey).destroy();
        ((Destroyable)exchangeKey).destroy();

        try
        {
            signer.sign();
            fail("Signature.SM9 signed under a key destroyed after init");
        }
        catch (java.security.SignatureException e)
        {
            isTrue("Signature.SM9 message: " + e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
        try
        {
            decryptor.doFinal(ciphertext);
            fail("Cipher.SM9 decrypted under a key destroyed after init");
        }
        catch (IllegalStateException e)
        {
            isTrue("Cipher.SM9 message: " + e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
        try
        {
            extractor.generateKey();
            fail("KeyGenerator.SM9-KEM extracted under a key destroyed after init");
        }
        catch (IllegalStateException e)
        {
            isTrue("KeyGenerator.SM9-KEM message: " + e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
        try
        {
            agreement.doPhase(peer, false);
            fail("KeyAgreement.SM9 sent an ephemeral for a key destroyed after init");
        }
        catch (IllegalStateException e)
        {
            isTrue("KeyAgreement.SM9 message: " + e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
    }

    /**
     * A user private key's hashCode() takes in the identity, as the user public keys' does, so the user
     * keys of one KGC hash apart. It is fixed when the key is made, as the identity is erased with the
     * key and a destroyed key has to go on hashing as it did.
     */
    private void checkUserKeyHashCoversIdentity()
        throws Exception
    {
        KeyPair encMaster = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        KeyPair sigMaster = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        java.util.Set encHashes = new java.util.HashSet();
        java.util.Set sigHashes = new java.util.HashSet();
        for (int i = 0; i != 16; i++)
        {
            byte[] identity = ("user" + i).getBytes("US-ASCII");
            PrivateKey[] keys = {
                ((SM9EncMasterPrivateKey)encMaster.getPrivate()).generateUserKeyPair(identity, SM9EncMasterPublicKey.HID)
                    .getPrivate(),
                ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(identity).getPrivate() };
            for (int j = 0; j != keys.length; j++)
            {
                int hash = keys[j].hashCode();
                ((j == 0) ? encHashes : sigHashes).add(org.bouncycastle.util.Integers.valueOf(hash));
                ((Destroyable)keys[j]).destroy();
                isTrue(keys[j].getAlgorithm() + " user key hashes as before once destroyed", keys[j].hashCode() == hash);
            }
        }
        isTrue("SM9-ENC user keys of one KGC hash apart: " + encHashes.size(), encHashes.size() == 16);
        isTrue("SM9-SIGN user keys of one KGC hash apart: " + sigHashes.size(), sigHashes.size() == 16);
    }

    /**
     * A master public key from another implementation is taken through its X.509 encoding, whose
     * algorithm identifier has to name the key's own family. The encodings here are BC's own under the
     * other family's OID, so each would decode as that family's key but for the check.
     */
    private void checkThirdPartyMasterPublicKey()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");

        KeyPair sig = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        PrivateKey sigUser = ((SM9SigMasterPrivateKey)sig.getPrivate()).generateUserKeyPair(identity).getPrivate();
        byte[] sigSpki = sig.getPublic().getEncoded();
        isTrue("a foreign signature master public key under its own OID is taken",
            sigUser.equals(kf.generatePrivate(new SM9SigUserPrivateKeySpec(sigUser.getEncoded(),
                new ForeignSigMasterPublicKey(sigSpki), identity))));
        String refused = privateRefusal(kf, new SM9SigUserPrivateKeySpec(sigUser.getEncoded(),
            new ForeignSigMasterPublicKey(underAlgorithm(sigSpki, GMObjectIdentifiers.sm9encrypt)), identity),
            "a user key under a signature master public key with the encryption OID").getMessage();
        isTrue(("unable to decode SM9 user private key: master public key is not an SM9 key: "
            + GMObjectIdentifiers.sm9encrypt).equals(refused));

        KeyPair enc = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        PrivateKey encUser = ((SM9EncMasterPrivateKey)enc.getPrivate())
            .generateUserKeyPair(identity, SM9EncMasterPublicKey.HID).getPrivate();
        byte[] encSpki = enc.getPublic().getEncoded();
        isTrue("a foreign encryption master public key under its own OID is taken",
            encUser.equals(kf.generatePrivate(new SM9EncUserPrivateKeySpec(encUser.getEncoded(),
                new ForeignEncMasterPublicKey(encSpki), identity, SM9EncMasterPublicKey.HID))));
        refused = privateRefusal(kf, new SM9EncUserPrivateKeySpec(encUser.getEncoded(),
            new ForeignEncMasterPublicKey(underAlgorithm(encSpki, GMObjectIdentifiers.sm9sign)), identity,
            SM9EncMasterPublicKey.HID), "a user key under an encryption master public key with the signature OID")
            .getMessage();
        isTrue(("unable to decode SM9 user private key: master public key is not an SM9 key: "
            + GMObjectIdentifiers.sm9sign).equals(refused));
    }

    private static byte[] underAlgorithm(byte[] spkiEncoding, ASN1ObjectIdentifier oid)
        throws IOException
    {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid),
            SubjectPublicKeyInfo.getInstance(spkiEncoding).getPublicKeyData().getOctets()).getEncoded(ASN1Encoding.DER);
    }

    /**
     * equals() on the encryption user private keys compares the hid and the usage the key was imported
     * under, since each names a different key: the same point is imported here under both usages, and
     * under a second hid, where it is not the key the master key derives, the import refuses it.
     */
    private void checkUserKeyEqualityCoversHidAndUsage()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");

        KeyPair enc = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        SM9EncMasterPublicKey encMaster = (SM9EncMasterPublicKey)enc.getPublic();
        byte[] point = ((SM9EncMasterPrivateKey)enc.getPrivate())
            .generateUserKeyPair(identity, SM9EncMasterPublicKey.HID).getPrivate().getEncoded();
        PrivateKey asKem = kf.generatePrivate(new SM9EncUserPrivateKeySpec(point, encMaster, identity, (byte)0x03));
        String refused = privateRefusal(kf, new SM9EncUserPrivateKeySpec(point, encMaster, identity, (byte)0x05),
            "a user key under a hid it was not derived under").getMessage();
        isTrue(refused, ("unable to decode SM9 user private key: SM9 encryption private key does not "
            + "match its master public key, identity and hid").equals(refused));
        isTrue("an encryption user key for the key exchange is another key",
            !asKem.equals(kf.generatePrivate(new SM9EncUserPrivateKeySpec(point, encMaster, identity, (byte)0x03, true))));
    }

    /**
     * KeyPairGenerator.SM9-SIGN and SM9-ENC draw the master private key from the SecureRandom handed to
     * initialize(): two generators given the same fixed source generate the same key, which a draw from
     * any other source would not.
     */
    private void checkKeyPairGeneratorTakesCallerRandom()
        throws Exception
    {
        byte[] seed = Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        String[] families = { "SM9-SIGN", "SM9-ENC" };
        for (int i = 0; i != families.length; i++)
        {
            KeyPairGenerator first = KeyPairGenerator.getInstance(families[i], "BC");
            first.initialize(256, new FixedSecureRandom(seed));
            KeyPairGenerator second = KeyPairGenerator.getInstance(families[i], "BC");
            second.initialize(256, new FixedSecureRandom(seed));
            isTrue(families[i] + " draws its master key from the caller's SecureRandom",
                first.generateKeyPair().getPrivate().equals(second.generateKeyPair().getPrivate()));
        }
    }

    /**
     * equals() on the SM9 user private keys compares the secret point in constant time, which no
     * functional test can tell from an early-exit comparison, so the class files are checked for the
     * call, as core's ConstantTimeUsageTest checks secret arithmetic; a read that finds nothing fails.
     */
    private void checkConstantTimeKeyComparison()
        throws Exception
    {
        String[] classes = { "BCSM9EncPrivateKey", "BCSM9SigPrivateKey" };
        for (int i = 0; i != classes.length; i++)
        {
            String name = "/org/bouncycastle/jcajce/provider/asymmetric/sm9/" + classes[i] + ".class";
            java.io.InputStream in = getClass().getResourceAsStream(name);
            if (in == null)
            {
                fail("unable to read " + name + " - the check cannot run");
            }
            byte[] classFile;
            try
            {
                classFile = org.bouncycastle.util.io.Streams.readAll(in);
            }
            finally
            {
                in.close();
            }
            isTrue(classes[i] + " no longer compares its secret with constantTimeAreEqual",
                Strings.fromByteArray(classFile).indexOf("constantTimeAreEqual") >= 0);
        }
    }

    // a signature master public key of another implementation, known by its X.509 encoding alone
    private static class ForeignSigMasterPublicKey
        implements SM9SigMasterPublicKey
    {
        private final byte[] encoding;

        ForeignSigMasterPublicKey(byte[] encoding)
        {
            this.encoding = encoding;
        }

        public PublicKey getUserPublicKey(byte[] identity)
        {
            throw new UnsupportedOperationException();
        }

        public String getAlgorithm()
        {
            return "SM9-SIGN";
        }

        public String getFormat()
        {
            return "X.509";
        }

        public byte[] getEncoded()
        {
            return Arrays.clone(encoding);
        }
    }

    // an encryption master public key of another implementation, known by its X.509 encoding alone
    private static class ForeignEncMasterPublicKey
        implements SM9EncMasterPublicKey
    {
        private final byte[] encoding;

        ForeignEncMasterPublicKey(byte[] encoding)
        {
            this.encoding = encoding;
        }

        public PublicKey getUserPublicKey(byte[] identity)
        {
            throw new UnsupportedOperationException();
        }

        public PublicKey getUserPublicKey(byte[] identity, byte hid)
        {
            throw new UnsupportedOperationException();
        }

        public PublicKey getExchangeEphemeral(byte[] encoded)
        {
            throw new UnsupportedOperationException();
        }

        public String getAlgorithm()
        {
            return "SM9-ENC";
        }

        public String getFormat()
        {
            return "X.509";
        }

        public byte[] getEncoded()
        {
            return Arrays.clone(encoding);
        }
    }

    /**
     * A serialization stream holding one object of the named class written as itself, with no
     * field data: the SM9 key classes have no field that is not transient.
     */
    private static byte[] directStream(String className)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DataOutputStream dOut = new DataOutputStream(bOut);
        dOut.writeShort(ObjectStreamConstants.STREAM_MAGIC);
        dOut.writeShort(ObjectStreamConstants.STREAM_VERSION);
        dOut.writeByte(ObjectStreamConstants.TC_OBJECT);
        dOut.writeByte(ObjectStreamConstants.TC_CLASSDESC);
        dOut.writeUTF(className);
        dOut.writeLong(1L);                                     // serialVersionUID
        dOut.writeByte(ObjectStreamConstants.SC_SERIALIZABLE);
        dOut.writeShort(0);                                     // no serializable fields
        dOut.writeByte(ObjectStreamConstants.TC_ENDBLOCKDATA);
        dOut.writeByte(ObjectStreamConstants.TC_NULL);          // no serializable superclass
        dOut.close();
        return bOut.toByteArray();
    }

    /**
     * getUserPublicKey is declared to return PublicKey and documented to return the SM9 user public key
     * interface, which gives the identity and the master public key back, so the cast a caller makes to
     * reach them is part of the contract.
     */
    private void checkUserPublicKeyTypes()
        throws Exception
    {
        byte[] identity = "Alice".getBytes("US-ASCII");

        KeyPairGenerator encGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        encGen.initialize(256, new SecureRandom());
        SM9EncMasterPublicKey encMaster = (SM9EncMasterPublicKey)encGen.generateKeyPair().getPublic();
        isTrue("getUserPublicKey(identity) is an SM9EncUserPublicKey",
            encMaster.getUserPublicKey(identity) instanceof SM9EncUserPublicKey);
        isTrue("getUserPublicKey(identity, hid) is an SM9EncUserPublicKey",
            encMaster.getUserPublicKey(identity, SM9EncMasterPublicKey.HID_EXCHANGE) instanceof SM9EncUserPublicKey);

        KeyPairGenerator sigGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        sigGen.initialize(256, new SecureRandom());
        SM9SigMasterPublicKey sigMaster = (SM9SigMasterPublicKey)sigGen.generateKeyPair().getPublic();
        isTrue("the signature getUserPublicKey is an SM9SigUserPublicKey",
            sigMaster.getUserPublicKey(identity) instanceof SM9SigUserPublicKey);
    }

    /**
     * An SM9 key decodes only from the form getEncoded() writes: algorithm identifier parameters,
     * PKCS#8 attributes, a length written long and the privateKey variants below are each refused
     * rather than read back as a further accepted encoding of the same key.
     */
    private void checkCanonicalKeyEncodings()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        String[] families = { "SM9-SIGN", "SM9-ENC" };
        ASN1Encodable[] parameters = { DERNull.INSTANCE, new ASN1ObjectIdentifier("1.2.3.4") };
        ASN1Encodable attribute = new DERSequence(
            new ASN1Encodable[]{ new ASN1ObjectIdentifier("1.2.3.4"), new DERSet(DERNull.INSTANCE) });
        for (int i = 0; i != families.length; i++)
        {
            KeyPair pair = KeyPairGenerator.getInstance(families[i], "BC").generateKeyPair();
            byte[] spkiEncoding = pair.getPublic().getEncoded();
            byte[] pkcs8Encoding = pair.getPrivate().getEncoded();
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEncoding);
            PrivateKeyInfo pkcs8 = PrivateKeyInfo.getInstance(pkcs8Encoding);

            for (int j = 0; j != parameters.length; j++)
            {
                AlgorithmIdentifier withParameters = new AlgorithmIdentifier(spki.getAlgorithm().getAlgorithm(), parameters[j]);
                rejectsPublic(kf, new SubjectPublicKeyInfo(withParameters, spki.getPublicKeyData().getOctets())
                    .getEncoded(ASN1Encoding.DER), "SM9 key algorithm identifier takes no parameters");
                rejectsPrivate(kf, new PrivateKeyInfo(withParameters, pkcs8.parsePrivateKey())
                    .getEncoded(ASN1Encoding.DER), "SM9 key algorithm identifier takes no parameters");
            }
            rejectsPrivate(kf, new PrivateKeyInfo(pkcs8.getPrivateKeyAlgorithm(), pkcs8.parsePrivateKey(),
                new DERSet(attribute)).getEncoded(ASN1Encoding.DER), "SM9 private key takes no attributes");
            rejectsPublic(kf, nonMinimalLength(spkiEncoding), "SM9 key encoding is not DER");
            rejectsPrivate(kf, nonMinimalLength(pkcs8Encoding), "SM9 key encoding is not DER");

            // the privateKey OCTET STRING, which the outer check does not see into, is held to DER too - no
            // long length, no constructed form - as is the version, v2 only with the public key
            byte[] inner = pkcs8.getPrivateKey().getOctets();
            rejectsPrivate(kf, privateKeyInfo(0, pkcs8.getPrivateKeyAlgorithm(), nonMinimalLength(inner)),
                "SM9 key encoding is not DER");
            rejectsPrivate(kf, privateKeyInfo(0, pkcs8.getPrivateKeyAlgorithm(),
                Arrays.concatenate(new byte[]{ 0x24, (byte)0x80 }, inner, new byte[]{ 0x00, 0x00 })),
                "SM9 key encoding is not DER");
            rejectsPrivate(kf, privateKeyInfo(1, pkcs8.getPrivateKeyAlgorithm(), inner),
                "SM9 private key of version v2 carries no public key");
        }

        // and the PKCS#8 encoding a user key spec carries is held to the same form
        byte[] identity = "Alice".getBytes("US-ASCII");
        KeyPair sigMaster = KeyPairGenerator.getInstance("SM9-SIGN", "BC").generateKeyPair();
        SM9SigMasterPublicKey sigMasterPub = (SM9SigMasterPublicKey)sigMaster.getPublic();
        PrivateKey userKey = ((SM9SigMasterPrivateKey)sigMaster.getPrivate()).generateUserKeyPair(identity).getPrivate();
        isTrue("unable to decode SM9 user private key: SM9 key encoding is not DER".equals(privateRefusal(kf,
            new SM9SigUserPrivateKeySpec(nonMinimalLength(userKey.getEncoded()), sigMasterPub, identity),
            "a user private key from a non-DER encoding").getMessage()));
        PrivateKeyInfo userInfo = PrivateKeyInfo.getInstance(userKey.getEncoded());
        byte[] userInner = userInfo.getPrivateKey().getOctets();
        byte[][] userEncodings = { privateKeyInfo(0, userInfo.getPrivateKeyAlgorithm(), nonMinimalLength(userInner)),
            privateKeyInfo(1, userInfo.getPrivateKeyAlgorithm(), userInner) };
        String[] messages = { "SM9 key encoding is not DER", "SM9 private key of version v2 carries no public key" };
        for (int i = 0; i != userEncodings.length; i++)
        {
            String refused = privateRefusal(kf, new SM9SigUserPrivateKeySpec(userEncodings[i], sigMasterPub, identity),
                "a user private key: " + messages[i]).getMessage();
            isTrue("SM9 user private key refusal: " + refused,
                ("unable to decode SM9 user private key: " + messages[i]).equals(refused));
        }
    }

    // a PKCS#8 encoding, in DER, of the given version, algorithm and privateKey octets
    private static byte[] privateKeyInfo(int version, AlgorithmIdentifier algorithm, byte[] privateKey)
        throws IOException
    {
        return new DERSequence(new ASN1Encodable[]{ new ASN1Integer(version), algorithm,
            new DEROctetString(privateKey) }).getEncoded(ASN1Encoding.DER);
    }

    private void rejectsPublic(KeyFactory kf, byte[] encoding, String message)
    {
        String refused = publicRefusal(kf, new X509EncodedKeySpec(encoding), "a master public key: " + message)
            .getMessage();
        isTrue("SM9 public key refusal: " + refused, message.equals(refused));
    }

    private void rejectsPrivate(KeyFactory kf, byte[] encoding, String message)
    {
        String refused = privateRefusal(kf, new PKCS8EncodedKeySpec(encoding), "a master private key: " + message)
            .getMessage();
        isTrue("SM9 private key refusal: " + refused, message.equals(refused));
    }

    // the InvalidKeySpecException KeyFactory.SM9 refuses generatePublic(spec) with; label names the spec
    private InvalidKeySpecException publicRefusal(KeyFactory kf, KeySpec spec, String label)
    {
        try
        {
            kf.generatePublic(spec);
        }
        catch (InvalidKeySpecException e)
        {
            return e;
        }
        fail("KeyFactory.SM9 decoded " + label);
        return null;
    }

    // the InvalidKeySpecException KeyFactory.SM9 refuses generatePrivate(spec) with; label names the spec
    private InvalidKeySpecException privateRefusal(KeyFactory kf, KeySpec spec, String label)
    {
        try
        {
            kf.generatePrivate(spec);
        }
        catch (InvalidKeySpecException e)
        {
            return e;
        }
        fail("KeyFactory.SM9 decoded " + label);
        return null;
    }

    // the InvalidKeySpecException KeyFactory.SM9 refuses getKeySpec(key, spec) with; label is the failure
    // reported if it does not
    private InvalidKeySpecException keySpecRefusal(KeyFactory kf, Key key, Class spec, String label)
    {
        try
        {
            kf.getKeySpec(key, spec);
        }
        catch (InvalidKeySpecException e)
        {
            return e;
        }
        fail(label);
        return null;
    }

    // the same DER encoding with its outer length written one byte longer than it need be
    private static byte[] nonMinimalLength(byte[] der)
    {
        if ((der[1] & 0x80) == 0)
        {
            return Arrays.concatenate(new byte[]{ der[0], (byte)0x81 }, Arrays.copyOfRange(der, 1, der.length));
        }
        return Arrays.concatenate(new byte[]{ der[0], (byte)(0x81 + (der[1] & 0x7f)), 0x00 },
            Arrays.copyOfRange(der, 2, der.length));
    }

    /**
     * A master scalar decoded alone always agrees with the public key it derives, so a PKCS#8 encoding
     * carrying the public key as well (RFC 5958 OneAsymmetricKey) is held to it: the one check that
     * tells a stale or substituted scalar from the KGC's.
     */
    private void checkEmbeddedPublicKey()
        throws Exception
    {
        String[] families = { "SM9-SIGN", "SM9-ENC" };
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        for (int i = 0; i != families.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(families[i], "BC");
            kpGen.initialize(256, new SecureRandom());
            KeyPair pair = kpGen.generateKeyPair();
            KeyPair other = kpGen.generateKeyPair();

            PrivateKeyInfo info = PrivateKeyInfo.getInstance(pair.getPrivate().getEncoded());
            byte[] ownPoint = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()).getPublicKeyData().getOctets();
            byte[] otherPoint = SubjectPublicKeyInfo.getInstance(other.getPublic().getEncoded()).getPublicKeyData().getOctets();

            PrivateKey rebuilt = kf.generatePrivate(new PKCS8EncodedKeySpec(new PrivateKeyInfo(
                info.getPrivateKeyAlgorithm(), info.parsePrivateKey(), null, ownPoint).getEncoded()));
            isTrue(families[i] + " master key rebuilds against its own public key",
                Arrays.areEqual(rebuilt.getEncoded(), pair.getPrivate().getEncoded()));
            String refused = privateRefusal(kf, new PKCS8EncodedKeySpec(new PrivateKeyInfo(info.getPrivateKeyAlgorithm(),
                info.parsePrivateKey(), null, otherPoint).getEncoded()),
                "an " + families[i] + " master key against another key's public key").getMessage();
            isTrue("unable to decode SM9 private key: SM9 master private key does not match its master public key"
                .equals(refused));
        }
    }

    /**
     * An unsupported key spec is named in the refusal by its class, never its toString(), which for a
     * third-party spec over key material may print the material; and an encoding the KeyFactory refuses
     * keeps the decode failure as the cause, on the X.509 and the PKCS#8 path alike.
     */
    private void checkKeyFactoryTypesAndMessages()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        KeySpec leaky = new KeySpec()
        {
            public String toString()
            {
                return "SECRET-MATERIAL";
            }
        };
        String refused = publicRefusal(kf, leaky, "an unsupported key spec").getMessage();
        isTrue("the message names the spec's class, not its toString(): " + refused,
            refused.indexOf("SECRET-MATERIAL") < 0);

        // the key of another algorithm, and a user key's point handed over without the context it needs
        InvalidKeySpecException e = publicRefusal(kf, new X509EncodedKeySpec(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm2encrypt), new byte[65]).getEncoded()),
            "a public key of another algorithm");
        isTrue(("not an SM9 master public key: " + GMObjectIdentifiers.sm2encrypt).equals(e.getMessage()));
        isTrue("the X.509 decode failure is kept as the cause", e.getCause() instanceof IOException);
        e = privateRefusal(kf, new PKCS8EncodedKeySpec(new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), new DEROctetString(new byte[65])).getEncoded()),
            "a user private key from PKCS#8 alone");
        isTrue(e.getMessage().startsWith("SM9 user private keys cannot be decoded standalone"));
        isTrue("the PKCS#8 decode failure is kept as the cause", e.getCause() instanceof IOException);
    }

    /**
     * The ASN.1 parse guards: an unknown enType, a C1 or S BIT STRING that is not octet-aligned, fields
     * of the wrong size and absent fields. SM9Cipher represents every GM/T 0080-2020 enType - 2, 4 and 8
     * included, which Cipher.SM9 does not implement - and writes no value it would refuse to read back.
     */
    private void checkAsn1Guards()
        throws Exception
    {
        byte[] c1 = Arrays.concatenate(new byte[]{ 0x04 }, new byte[64]);
        byte[] c3 = new byte[32];
        byte[] c2 = new byte[16];

        int[] standard = { SM9Cipher.EN_TYPE_STREAM, SM9Cipher.EN_TYPE_SM4, SM9Cipher.EN_TYPE_SM4_CBC,
            SM9Cipher.EN_TYPE_SM4_OFB, SM9Cipher.EN_TYPE_SM4_CFB };
        for (int i = 0; i != standard.length; i++)
        {
            byte[] enc = new SM9Cipher(standard[i], c1, c3, c2).getEncoded();
            isTrue("SM9Cipher enType " + standard[i] + " round-trips",
                SM9Cipher.getInstance(enc).getEnType() == standard[i]);
        }

        int[] unknown = { 3, 5, 16, -1 };
        for (int i = 0; i != unknown.length; i++)
        {
            try
            {
                new SM9Cipher(unknown[i], c1, c3, c2);
                fail("SM9Cipher wrote enType " + unknown[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(("unknown SM9 encryption type: " + unknown[i]).equals(e.getMessage()));
            }
            isTrue("unknown SM9 encryption type".equals(parseRefusal(false,
                cipherEncoding(unknown[i], new DERBitString(c1), c3, c2), "SM9Cipher parsed enType " + unknown[i])));
        }

        // a C1, or the signature's S, with pad bits is not the octet string of a point
        isTrue("SM9 ciphertext C1 must be an octet-aligned BIT STRING".equals(parseRefusal(false,
            cipherEncoding(SM9Cipher.EN_TYPE_SM4, new DERBitString(c1, 1), c3, c2), "SM9Cipher parsed a C1 with pad bits")));
        ASN1EncodableVector sig = new ASN1EncodableVector();
        sig.add(new DEROctetString(new byte[32]));
        sig.add(new DERBitString(c1, 1));
        isTrue("SM9 signature S must be an octet-aligned BIT STRING".equals(
            parseRefusal(true, new DERSequence(sig).getEncoded(), "SM9Signature parsed an S with pad bits")));

        // C1 and C3 have fixed sizes; C2 is as long as the message makes it
        checkCipherLengths(Arrays.copyOfRange(c1, 0, 64), c3, c2, "SM9 ciphertext C1 must be 65 bytes");
        checkCipherLengths(Arrays.append(c1, (byte)0x00), c3, c2, "SM9 ciphertext C1 must be 65 bytes");
        checkCipherLengths(c1, Arrays.copyOfRange(c3, 0, 31), c2, "SM9 ciphertext C3 must be 32 bytes");
        checkCipherLengths(c1, Arrays.append(c3, (byte)0x00), c2, "SM9 ciphertext C3 must be 32 bytes");

        // h and S have fixed sizes, held to by both constructors, a byte short and a byte long
        byte[] h = new byte[32];
        checkSignatureLengths(Arrays.copyOfRange(h, 0, 31), c1, "SM9 signature h must be 32 bytes");
        checkSignatureLengths(Arrays.append(h, (byte)0x00), c1, "SM9 signature h must be 32 bytes");
        checkSignatureLengths(h, Arrays.copyOfRange(c1, 0, 64), "SM9 signature S must be 65 bytes");
        checkSignatureLengths(h, Arrays.append(c1, (byte)0x00), "SM9 signature S must be 65 bytes");

        // absent fields are refused at construction, not at encoding
        try
        {
            new SM9Cipher(SM9Cipher.EN_TYPE_SM4, null, c3, c2);
            fail("SM9Cipher took a null C1");
        }
        catch (NullPointerException e)
        {
            isTrue("SM9Cipher fields cannot be null".equals(e.getMessage()));
        }
        try
        {
            new SM9Signature(new byte[32], null);
            fail("SM9Signature took a null S");
        }
        catch (NullPointerException e)
        {
            isTrue("SM9Signature fields cannot be null".equals(e.getMessage()));
        }
    }

    private void checkCipherLengths(byte[] c1, byte[] c3, byte[] c2, String expected)
        throws Exception
    {
        try
        {
            new SM9Cipher(SM9Cipher.EN_TYPE_SM4, c1, c3, c2);
            fail("SM9Cipher took C1 of " + c1.length + " bytes and C3 of " + c3.length);
        }
        catch (IllegalArgumentException e)
        {
            isTrue(expected.equals(e.getMessage()));
        }
        isTrue(expected.equals(parseRefusal(false, cipherEncoding(SM9Cipher.EN_TYPE_SM4, new DERBitString(c1), c3, c2),
            "SM9Cipher parsed C1 of " + c1.length + " bytes and C3 of " + c3.length)));
    }

    private void checkSignatureLengths(byte[] h, byte[] s, String expected)
        throws Exception
    {
        try
        {
            new SM9Signature(h, s);
            fail("SM9Signature took h of " + h.length + " bytes and S of " + s.length);
        }
        catch (IllegalArgumentException e)
        {
            isTrue(expected.equals(e.getMessage()));
        }
        isTrue(expected.equals(parseRefusal(true, new DERSequence(new DEROctetString(h), new DERBitString(s)).getEncoded(),
            "SM9Signature parsed h of " + h.length + " bytes and S of " + s.length)));
    }

    // the message of the IllegalArgumentException SM9Signature, or else SM9Cipher, refuses to parse encoding
    // with; label is the failure reported if it parses
    private String parseRefusal(boolean signature, byte[] encoding, String label)
    {
        try
        {
            if (signature)
            {
                SM9Signature.getInstance(encoding);
            }
            else
            {
                SM9Cipher.getInstance(encoding);
            }
            fail(label);
        }
        catch (IllegalArgumentException e)
        {
            return e.getMessage();
        }
        return null;
    }

    // an SM9Cipher encoding written field by field, so that it can carry values the type refuses
    private static byte[] cipherEncoding(int enType, DERBitString c1, byte[] c3, byte[] c2)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(enType));
        v.add(c1);
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded();
    }

    private void isEncoding(String message, byte[] actual, Map vectors, String expected)
    {
        isTrue(message, Arrays.areEqual(actual, SM9Vectors.hex(vectors, expected)));
    }

    private static byte[] bitString(byte[] value)
        throws Exception
    {
        return new DERBitString(value).getEncoded();
    }

    private static byte[] integer(String value)
        throws Exception
    {
        return new ASN1Integer(new BigInteger(value, 16)).getEncoded();
    }

    public static void main(String[] args)
    {
        runTest(new SM9EncodingTest());
    }
}
