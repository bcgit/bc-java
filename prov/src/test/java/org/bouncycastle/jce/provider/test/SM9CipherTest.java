package org.bouncycastle.jce.provider.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * JCE-level tests for SM9 public-key encryption exposed as {@code Cipher.SM9}.
 */
public class SM9CipherTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Cipher";
    }

    public void performTest()
        throws Exception
    {
        byte[] bob = "Bob".getBytes("US-ASCII");
        byte[] plaintext = "hello sm9 encryption".getBytes("US-ASCII");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair masterPair = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();
        PrivateKey bobKey = masterPriv.generateUserKeyPair(bob, SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        PublicKey bobPublic = ((SM9EncMasterPublicKey)masterPair.getPublic()).getUserPublicKey(bob);

        // KeyFactory round-trip of the encryption master public key
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory enc master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));

        // default (SM4) mode round-trip - encryption takes the recipient's public key
        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ct = enc.doFinal(plaintext);
        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher SM4-mode round-trip", Arrays.areEqual(dec.doFinal(ct), plaintext));

        // KDF stream mode round-trip
        Cipher encX = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
        encX.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ctX = encX.doFinal(plaintext);
        Cipher decX = Cipher.getInstance("SM9", "BC");
        decX.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher stream-mode round-trip", Arrays.areEqual(decX.doFinal(ctX), plaintext));

        // empty plaintext: SM4 mode round-trips (one padding block); the stream mode
        // has no K1 for an empty message and must reject it rather than loop retrying
        Cipher encEmpty = Cipher.getInstance("SM9", "BC");
        encEmpty.init(Cipher.ENCRYPT_MODE, bobPublic);
        byte[] ctEmpty = encEmpty.doFinal(new byte[0]);
        Cipher decEmpty = Cipher.getInstance("SM9", "BC");
        decEmpty.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher SM4-mode empty plaintext round-trip", decEmpty.doFinal(ctEmpty).length == 0);

        try
        {
            Cipher encXEmpty = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
            encXEmpty.init(Cipher.ENCRYPT_MODE, bobPublic);
            encXEmpty.doFinal(new byte[0]);
            fail("SM9 stream mode encrypted an empty plaintext");
        }
        catch (BadPaddingException e)
        {
            // expected - no K1 to derive for an empty message
        }

        // a tampered C3 (MAC) must be rejected
        SM9Cipher parsed = SM9Cipher.getInstance(ct);
        byte[] brokenC3 = Arrays.clone(parsed.getC3());
        brokenC3[0] ^= 1;
        byte[] tampered = new SM9Cipher(parsed.getEnType(), parsed.getC1(), brokenC3, parsed.getC2()).getEncoded();
        try
        {
            Cipher decBad = Cipher.getInstance("SM9", "BC");
            decBad.init(Cipher.DECRYPT_MODE, bobKey);
            decBad.doFinal(tampered);
            fail("SM9 decryption accepted a tampered C3");
        }
        catch (BadPaddingException e)
        {
            // expected - MAC check failed
        }

        // guards: a master public key is not a recipient key, and no spec is accepted
        try
        {
            Cipher bad = Cipher.getInstance("SM9", "BC");
            bad.init(Cipher.ENCRYPT_MODE, masterPair.getPublic());
            fail("SM9 encryption accepted a master public key");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
        try
        {
            Cipher bad = Cipher.getInstance("SM9", "BC");
            bad.init(Cipher.ENCRYPT_MODE, bobPublic, new AlgorithmParameterSpec()
            {
            });
            fail("SM9 encryption accepted an AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }

        // Reproduce both GM/T 0044.5-2016 Annex D encryption modes through the
        // provider. The KAT master key is reconstructed from its
        // known scalar through the public KeyFactory / PKCS#8 path.
        Map kat = loadVectors("sm9_encryption.txt");
        byte[] katScalar = BigIntegers.asUnsignedByteArray(32,
            new BigInteger((String)kat.get("ke"), 16));
        PrivateKeyInfo katPkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(katScalar));
        SM9EncMasterPrivateKey katMaster = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(katPkcs8.getEncoded()));
        KeyPair katBobPair = katMaster.generateUserKeyPair(hex(kat, "IDB"),
            SM9EncMasterPrivateKeyParameters.HID);
        checkEncryptionVector(kat, katBobPair, "SM9/XOR/NoPadding", SM9Cipher.EN_TYPE_STREAM, "modeA");
        checkEncryptionVector(kat, katBobPair, "SM9", SM9Cipher.EN_TYPE_SM4, "modeB");

        // SM9 KEM (GM/T 0044.4) through KeyGenerator.SM9-KEM - the same recipient
        // public key the cipher encrypts to
        KeyGenerator kemGen = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemGen.init(new KEMGenerateSpec(bobPublic, "AES", 128));
        SecretKeyWithEncapsulation kemEnc = (SecretKeyWithEncapsulation)kemGen.generateKey();

        KeyGenerator kemExt = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemExt.init(new KEMExtractSpec(bobKey, kemEnc.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation kemDec = (SecretKeyWithEncapsulation)kemExt.generateKey();
        isTrue("SM9-KEM encapsulate/decapsulate agree on a 128-bit key",
            kemEnc.getEncoded().length == 16 && Arrays.areEqual(kemEnc.getEncoded(), kemDec.getEncoded()));

        // a different recipient identity must not recover the same key
        PrivateKey mallory = masterPriv.generateUserKeyPair("Mallory".getBytes("US-ASCII"), SM9EncMasterPrivateKeyParameters.HID).getPrivate();
        KeyGenerator kemBad = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemBad.init(new KEMExtractSpec(mallory, kemEnc.getEncapsulation(), "AES", 128));
        isTrue("SM9-KEM wrong identity yields a different key",
            !Arrays.areEqual(kemEnc.getEncoded(), ((SecretKeyWithEncapsulation)kemBad.generateKey()).getEncoded()));

        // a truncated encapsulation must be rejected cleanly
        try
        {
            KeyGenerator kemShort = KeyGenerator.getInstance("SM9-KEM", "BC");
            kemShort.init(new KEMExtractSpec(bobKey, new byte[10], "AES", 128));
            kemShort.generateKey();
            fail("SM9-KEM did not reject a truncated encapsulation");
        }
        catch (IllegalArgumentException e)
        {
            // expected - invalid SM9 KEM encapsulation
        }
    }

    private void checkEncryptionVector(Map kat, KeyPair recipient, String transformation,
                                       int enType, String fieldPrefix)
        throws Exception
    {
        byte[] c1 = Arrays.concatenate(new byte[]{0x04}, hex(kat, "C1_x"), hex(kat, "C1_y"));
        byte[] expectedC2 = hex(kat, fieldPrefix + "_C2");
        byte[] expectedC3 = hex(kat, fieldPrefix + "_C3");
        byte[] message = hex(kat, "M");

        Cipher katEnc = Cipher.getInstance(transformation, "BC");
        katEnc.init(Cipher.ENCRYPT_MODE, recipient.getPublic(),
            new TestRandomBigInteger(256, hex(kat, "r")));
        SM9Cipher actual = SM9Cipher.getInstance(katEnc.doFinal(message));
        isTrue(fieldPrefix + " GM/T 0044.5 enType", actual.getEnType() == enType);
        isTrue(fieldPrefix + " GM/T 0044.5 C1", Arrays.areEqual(actual.getC1(), c1));
        isTrue(fieldPrefix + " GM/T 0044.5 C2", Arrays.areEqual(actual.getC2(), expectedC2));
        isTrue(fieldPrefix + " GM/T 0044.5 C3", Arrays.areEqual(actual.getC3(), expectedC3));

        byte[] officialCiphertext = new SM9Cipher(enType, c1, expectedC3, expectedC2).getEncoded();
        Cipher katDec = Cipher.getInstance("SM9", "BC");
        katDec.init(Cipher.DECRYPT_MODE, recipient.getPrivate());
        isTrue(fieldPrefix + " GM/T 0044.5 decrypt",
            Arrays.areEqual(katDec.doFinal(officialCiphertext), message));
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map vectors = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }

                int equals = line.indexOf('=');
                if (equals > 0)
                {
                    vectors.put(line.substring(0, equals).trim(), line.substring(equals + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return vectors;
    }

    private byte[] hex(Map vectors, String key)
    {
        return Hex.decode((String)vectors.get(key));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9CipherTest());
    }
}
