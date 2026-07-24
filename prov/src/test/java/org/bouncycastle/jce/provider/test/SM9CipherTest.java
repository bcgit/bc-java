package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.SM9ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

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
        PrivateKey bobKey = masterPriv.generateUserKeyPair(bob).getPrivate();

        // KeyFactory round-trip of the encryption master public key
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(masterPair.getPublic().getEncoded()));
        isTrue("SM9 KeyFactory enc master public round-trip",
            Arrays.areEqual(pub2.getEncoded(), masterPair.getPublic().getEncoded()));

        // default (SM4) mode round-trip
        Cipher enc = Cipher.getInstance("SM9", "BC");
        enc.init(Cipher.ENCRYPT_MODE, masterPair.getPublic(), new SM9ParameterSpec(bob));
        byte[] ct = enc.doFinal(plaintext);
        Cipher dec = Cipher.getInstance("SM9", "BC");
        dec.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher SM4-mode round-trip", Arrays.areEqual(dec.doFinal(ct), plaintext));

        // KDF stream mode round-trip
        Cipher encX = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
        encX.init(Cipher.ENCRYPT_MODE, masterPair.getPublic(), new SM9ParameterSpec(bob));
        byte[] ctX = encX.doFinal(plaintext);
        Cipher decX = Cipher.getInstance("SM9", "BC");
        decX.init(Cipher.DECRYPT_MODE, bobKey);
        isTrue("SM9 Cipher stream-mode round-trip", Arrays.areEqual(decX.doFinal(ctX), plaintext));

        // decrypt the official GM/T 0044.5 Annex D (stream) ciphertext through the provider.
        // The KAT master key is reconstructed from its known scalar through the public
        // KeyFactory / PKCS#8 path, then the user decryption key is derived from it.
        byte[] katScalar = BigIntegers.asUnsignedByteArray(32,
            new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16));
        PrivateKeyInfo katPkcs8 = new PrivateKeyInfo(
            new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(katScalar));
        SM9EncMasterPrivateKey katMaster = (SM9EncMasterPrivateKey)kf.generatePrivate(
            new PKCS8EncodedKeySpec(katPkcs8.getEncoded()));
        PrivateKey katBob = katMaster.generateUserKeyPair(bob).getPrivate();
        byte[] c1 = Arrays.concatenate(new byte[]{0x04},
            Hex.decode("2445471164490618E1EE20528FF1D545B0F14C8BCAA44544F03DAB5DAC07D8FF"),
            Hex.decode("42FFCA97D57CDDC05EA405F2E586FEB3A6930715532B8000759F13059ED59AC0"));
        byte[] katCt = new SM9Cipher(SM9Cipher.EN_TYPE_STREAM, c1,
            Hex.decode("BA672387BCD6DE5016A158A52BB2E7FC429197BCAB70B25AFEE37A2B9DB9F367"),
            Hex.decode("1B5F5B0E951489682F3E64E1378CDD5DA9513B1C")).getEncoded();
        Cipher katDec = Cipher.getInstance("SM9", "BC");
        katDec.init(Cipher.DECRYPT_MODE, katBob);
        isTrue("SM9 Cipher decrypts GM/T 0044.5 KAT ciphertext",
            Arrays.areEqual(katDec.doFinal(katCt), "Chinese IBE standard".getBytes("US-ASCII")));

        // SM9 KEM (GM/T 0044.4) through KeyGenerator.SM9-KEM
        PublicKey bobRecipient = ((SM9EncMasterPublicKey)masterPair.getPublic()).getUserPublicKey(bob);
        KeyGenerator kemGen = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemGen.init(new KEMGenerateSpec(bobRecipient, "AES", 128));
        SecretKeyWithEncapsulation kemEnc = (SecretKeyWithEncapsulation)kemGen.generateKey();

        KeyGenerator kemExt = KeyGenerator.getInstance("SM9-KEM", "BC");
        kemExt.init(new KEMExtractSpec(bobKey, kemEnc.getEncapsulation(), "AES", 128));
        SecretKeyWithEncapsulation kemDec = (SecretKeyWithEncapsulation)kemExt.generateKey();
        isTrue("SM9-KEM encapsulate/decapsulate agree on a 128-bit key",
            kemEnc.getEncoded().length == 16 && Arrays.areEqual(kemEnc.getEncoded(), kemDec.getEncoded()));

        // a different recipient identity must not recover the same key
        PrivateKey mallory = masterPriv.generateUserKeyPair("Mallory".getBytes("US-ASCII")).getPrivate();
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

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SM9CipherTest());
    }
}
