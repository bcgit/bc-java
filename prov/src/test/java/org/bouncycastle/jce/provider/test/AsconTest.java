package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.AsconCXof128;
import org.bouncycastle.crypto.digests.AsconHash256;
import org.bouncycastle.crypto.digests.AsconXof128;
import org.bouncycastle.crypto.engines.AsconAEAD128;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The SP 800-232 Ascon services of the BC provider against the light-weight implementations,
 * which carry the NIST known-answer tests.
 */
public class AsconTest
    extends SimpleTest
{
    public String getName()
    {
        return "Ascon";
    }

    public void performTest()
        throws Exception
    {
        testAEAD();
        testDigests();
    }

    private void testAEAD()
        throws Exception
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] nonce = Hex.decode("101112131415161718191a1b1c1d1e1f");
        byte[] aad = Strings.toByteArray("additional data");
        byte[] msg = Strings.toByteArray("Hello, world! Ascon-AEAD128 through the JCA.");

        // the light-weight engine is the reference
        AsconAEAD128 engine = new AsconAEAD128();
        engine.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
        engine.processAADBytes(aad, 0, aad.length);
        byte[] expected = new byte[engine.getOutputSize(msg.length)];
        int len = engine.processBytes(msg, 0, msg.length, expected, 0);
        engine.doFinal(expected, len);

        Cipher enc = Cipher.getInstance("ASCON-AEAD128", "BC");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ASCON-AEAD128"), new IvParameterSpec(nonce));
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        isTrue("JCA ciphertext differs from the light-weight engine", Arrays.areEqual(expected, ct));
        isEquals("tag length", msg.length + 16, ct.length);

        Cipher dec = Cipher.getInstance("ASCON-AEAD128", "BC");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ASCON-AEAD128"), new IvParameterSpec(nonce));
        dec.updateAAD(aad);
        isTrue("round trip", Arrays.areEqual(msg, dec.doFinal(ct)));

        // a tampered tag is refused
        byte[] faulty = Arrays.clone(ct);
        faulty[faulty.length - 1] ^= 0xff;
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ASCON-AEAD128"), new IvParameterSpec(nonce));
        dec.updateAAD(aad);
        try
        {
            dec.doFinal(faulty);
            fail("tampered ciphertext accepted");
        }
        catch (Exception e)
        {
            isTrue(e.getClass().getName(), e.getClass().getName().endsWith("AEADBadTagException") || e.getMessage().indexOf("mac check") >= 0);
        }

        // the wrong associated data is refused
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ASCON-AEAD128"), new IvParameterSpec(nonce));
        dec.updateAAD(Strings.toByteArray("other data"));
        try
        {
            dec.doFinal(ct);
            fail("wrong associated data accepted");
        }
        catch (Exception e)
        {
            isTrue(e.getClass().getName(), e.getClass().getName().endsWith("AEADBadTagException") || e.getMessage().indexOf("mac check") >= 0);
        }

        // key generator and a generated nonce, carried as AlgorithmParameters
        KeyGenerator keyGen = KeyGenerator.getInstance("ASCON-AEAD128", "BC");
        SecretKey genKey = keyGen.generateKey();
        isEquals("key size", 16, genKey.getEncoded().length);

        enc = Cipher.getInstance("ASCON-AEAD128", "BC");
        enc.init(Cipher.ENCRYPT_MODE, genKey);
        AlgorithmParameters params = enc.getParameters();
        isTrue("no parameters generated", params != null);
        isEquals("nonce length", 16, params.getParameterSpec(IvParameterSpec.class).getIV().length);
        ct = enc.doFinal(msg);

        dec = Cipher.getInstance("ASCON-AEAD128", "BC");
        dec.init(Cipher.DECRYPT_MODE, genKey, params);
        isTrue("round trip with generated nonce", Arrays.areEqual(msg, dec.doFinal(ct)));

        AlgorithmParameters.getInstance("ASCON-AEAD128", "BC");
    }

    private void testDigests()
        throws Exception
    {
        byte[] msg = Strings.toByteArray("The quick brown fox jumps over the lazy dog");

        checkDigest("ASCON-HASH256", new AsconHash256(), msg);
        checkDigest("ASCON-XOF128", new AsconXof128(), msg);
        checkDigest("ASCON-CXOF128", new AsconCXof128(), msg);
    }

    private void checkDigest(String name, org.bouncycastle.crypto.Digest reference, byte[] msg)
        throws Exception
    {
        byte[] expected = new byte[reference.getDigestSize()];
        reference.update(msg, 0, msg.length);
        reference.doFinal(expected, 0);

        MessageDigest digest = MessageDigest.getInstance(name, "BC");
        isEquals(name + " length", 32, digest.getDigestLength());
        isTrue(name + " differs from the light-weight digest", Arrays.areEqual(expected, digest.digest(msg)));

        // incremental use and reset give the same answer
        digest.update(msg, 0, 10);
        digest.update(msg, 10, msg.length - 10);
        isTrue(name + " incremental", Arrays.areEqual(expected, digest.digest()));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AsconTest());
    }
}
