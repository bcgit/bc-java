package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.AEAD;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class HPKETestVectors
        extends TestCase
{

    static class Export
    {
        byte[] exporterContext;
        int L;
        byte[] exportedValue;

        Export(byte[] exporterContext, int L, byte[] exportedValue)
        {
            this.exporterContext = exporterContext;
            this.L = L;
            this.exportedValue = exportedValue;
        }
    }

    static class Encryption
    {
        byte[] aad;
        byte[] ct;
        byte[] nonce;
        byte[] pt;

        Encryption(byte[] aad, byte[] ct, byte[] nonce, byte[] pt)
        {
            this.aad = aad;
            this.ct = ct;
            this.nonce = nonce;
            this.pt = pt;
        }

    }

    public void testBaseOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair kp = hpke.generatePrivateKey();
        byte[][] output = hpke.seal(kp.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, null);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), ct, null, null, null);
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, null);
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }
    }
    public void testAuthOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 2, (short) 18, (short) 1, (short) 1);

        AsymmetricCipherKeyPair reciever = hpke.generatePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.generatePrivateKey();

        byte[][] output = hpke.seal(reciever.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, sender);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, sender.getPublic());
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        // incorrect ct/tag
        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, sender.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

        // incorrect public key
        try
        {
            message = hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, reciever.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

    }

    public void testBasePairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.generatePrivateKey();

        HPKEContextWithEncapsulation ctxS = hpke.setupBaseS(receiver.getPublic(), "info".getBytes());
        HPKEContext ctxR = hpke.setupBaseR(ctxS.getEncapsulation(), receiver, "info".getBytes());

        assertTrue(Arrays.areEqual(ctxS.export("context".getBytes(), 512), ctxR.export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.open(aad, ct)));
        }
    }

    public void testAuthPairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 2, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.generatePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.generatePrivateKey();

        HPKEContextWithEncapsulation ctxS = hpke.setupAuthS(receiver.getPublic(), "info".getBytes(), sender);
        HPKEContext ctxR = hpke.setupAuthR(ctxS.getEncapsulation(), receiver, "info".getBytes(), sender.getPublic());

        assertTrue(Arrays.areEqual(ctxS.export("context".getBytes(), 512), ctxR.export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.open(aad, ct)));
        }
    }



    //todo test for not implemented for export only aead


    public void testVectors()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("crypto", "hpke.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> encBuf = new HashMap<String, String>();
        HashMap<String, String> expBuf = new HashMap<String, String>();
        ArrayList<Encryption> encryptions = new ArrayList<Encryption>();
        ArrayList<Export> exports = new ArrayList<Export>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    String count = (String)buf.get("count");

                    byte mode = Byte.parseByte((String)buf.get("mode"));
                    short kem_id = Short.parseShort((String)buf.get("kem_id"));
                    short kdf_id = Short.parseShort((String)buf.get("kdf_id"));
                    short aead_id = (short) Integer.parseInt((String)buf.get("aead_id"));
                    byte[] info = Hex.decode((String)buf.get("info"));
                    byte[] ikmR = Hex.decode((String)buf.get("ikmR"));
                    byte[] ikmS = null;    // -> mode 2, 3
                    byte[] ikmE = Hex.decode((String)buf.get("ikmE"));
                    byte[] skRm = Hex.decode((String)buf.get("skRm"));
                    byte[] skSm = null;    // -> mode 2, 3
                    byte[] skEm = Hex.decode((String)buf.get("skEm"));
                    byte[] psk = null;     // -> mode 1, 3
                    byte[] psk_id = null;  // -> mode 1, 3
                    byte[] pkRm = Hex.decode((String)buf.get("pkRm"));
                    byte[] pkSm = null;    // -> mode 2, 3
                    byte[] pkEm = Hex.decode((String)buf.get("pkEm"));
                    byte[] enc = Hex.decode((String)buf.get("enc"));
                    byte[] shared_secret = Hex.decode((String)buf.get("shared_secret"));
                    byte[] key_schedule_context = Hex.decode((String)buf.get("key_schedule_context"));
                    byte[] secret = Hex.decode((String)buf.get("secret"));
                    byte[] key = Hex.decode((String)buf.get("key"));
                    byte[] base_nonce = Hex.decode((String)buf.get("base_nonce"));
                    byte[] exporter_secret = Hex.decode((String)buf.get("exporter_secret"));
                    if (mode == 2 || mode == 3)
                    {
                        ikmS = Hex.decode((String)buf.get("ikmS"));
                        skSm = Hex.decode((String)buf.get("skSm"));
                        pkSm = Hex.decode((String)buf.get("pkSm"));
                    }
                    if (mode == 1 || mode == 3)
                    {
                        psk = Hex.decode((String)buf.get("psk"));
                        psk_id = Hex.decode((String)buf.get("psk_id"));
                    }

                    System.out.println("test case: " + count);
//                    System.out.println("mode: " + mode + " kemID: " + kem_id + " kdfID: " + kdf_id + " aeadID: " + aead_id);

                    HPKE hpke = new HPKE(mode, kem_id, kdf_id, aead_id);

                    // Testing AEAD ( encryptions )

                    // init aead with key and nonce
                    AEAD aead = new AEAD(aead_id, key, base_nonce);
                    // enumerate encryptions
                    for (Iterator it = encryptions.iterator(); it.hasNext();)
                    {
                        Encryption encryption = (Encryption)it.next();

                        // seal with aad and pt and check if output is the same as ct
                        byte[] got_ct = aead.seal(encryption.aad, encryption.pt);
                        assertTrue( "AEAD failed Sealing:", Arrays.areEqual(got_ct, encryption.ct));
                    }

                    // Testing main ( different modes )

                    // generate key pair from ikmR ( should be the same as below )
                    AsymmetricCipherKeyPair derivedKeyPairR = hpke.deriveKeyPair(ikmR);
                    // generate a private key from skRm and pkRm
                    AsymmetricCipherKeyPair kp = hpke.deserializePrivateKey(skRm, pkRm);

                    // tesing serialize
                    assertTrue("serialize public key failed", Arrays.areEqual(pkRm, hpke.serializePublicKey(kp.getPublic())));
                    assertTrue("serialize private key failed", Arrays.areEqual(skRm, hpke.serializePrivateKey(kp.getPrivate())));

                    // testing receiver derive key pair
                    assertTrue("receiver derived public key pair incorrect", Arrays.areEqual(pkRm, hpke.serializePublicKey(derivedKeyPairR.getPublic())));
                    assertTrue("receiver derived secret key pair incorrect", Arrays.areEqual(skRm, hpke.serializePrivateKey(derivedKeyPairR.getPrivate())));

                    // testing sender's derived key pair
                    if (mode == 2 || mode == 3)
                    {
                        AsymmetricCipherKeyPair derivedSenderKeyPair = hpke.deriveKeyPair(ikmS);
                        assertTrue("sender derived public key pair incorrect", Arrays.areEqual(pkSm, hpke.serializePublicKey(derivedSenderKeyPair.getPublic())));
                        assertTrue("sender derived private key pair incorrect", Arrays.areEqual(skSm, hpke.serializePrivateKey(derivedSenderKeyPair.getPrivate())));
                    }

                    // testing ephemeral derived key pair
                    AsymmetricCipherKeyPair derivedEKeyPair = hpke.deriveKeyPair(ikmE);
                    assertTrue("ephemeral derived public key pair incorrect", Arrays.areEqual(pkEm, hpke.serializePublicKey(derivedEKeyPair.getPublic())));
                    assertTrue("ephemeral derived private key pair incorrect", Arrays.areEqual(skEm, hpke.serializePrivateKey(derivedEKeyPair.getPrivate())));

                    // create a context with setupRecv
                    // use pkEm as encap, private key from above, info as info

                    HPKEContext c = null;
                    AsymmetricKeyParameter senderPub = null;
                    switch (mode)
                    {
                        case 0:
                            c = hpke.setupBaseR(pkEm, kp, info);
                            break;
                        case 1:
                            c = hpke.setupPSKR(pkEm, kp, info, psk, psk_id);
                            break;
                        case 2:
                            senderPub = hpke.deserializePublicKey(pkSm);
                            c = hpke.setupAuthR(pkEm, kp, info, senderPub);
                            break;
                        case 3:
                            senderPub = hpke.deserializePublicKey(pkSm);
                            c = hpke.setupAuthPSKR(pkEm, kp, info, psk, psk_id, senderPub);
                            break;
                        default:
                            fail("invalid mode");
                    }

                    // enumerate encryptions
                    for (int i = 0; i < encryptions.size(); i++)
                    {
                        Encryption encryption = (Encryption)encryptions.get(i);

                        if (i == 0)
                        {
                            // test one shot api (first only!)
                            // open with pkEm, private key, info, aad, ct
                            // compare output with pt
                            byte[] message = hpke.open(pkEm, kp, info, encryption.aad, encryption.ct, psk, psk_id, senderPub);

                            // use context open with aad, ct and compare output with pt
                            assertTrue("Single-shot failed", Arrays.areEqual(message, encryption.pt));
                        }

                        byte[] got_pt = c.open(encryption.aad, encryption.ct);
                        assertTrue("context failed Open", Arrays.areEqual(got_pt, encryption.pt));
                    }

                    // enumerate exports
                    for (Iterator it = exports.iterator(); it.hasNext();)
                    {
                        Export export = (Export)it.next();
                        // use context export with exporter context and L
                        byte[] got_val = c.export(export.exporterContext, export.L);

                        // compare output with exported value
                        assertTrue("context failed Open", Arrays.areEqual(got_val, export.exportedValue));
                    }

                }
                buf.clear();
                encryptions.clear();
                exports.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.equals("encryptionsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("encryptionsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] aad = Hex.decode((String)encBuf.get("aad"));
                        byte[] ct = Hex.decode((String)encBuf.get("ct"));
                        byte[] nonce = Hex.decode((String)encBuf.get("nonce"));
                        byte[] pt = Hex.decode((String)encBuf.get("pt"));
                        encryptions.add(new Encryption(aad, ct, nonce, pt));
                        encBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            encBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }

            if (line.equals("exportsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("exportsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] exporterContext = Hex.decode((String) expBuf.get("exporter_context"));
                        int L = Integer.parseInt((String)expBuf.get("L"));
                        byte[] exportedValue = Hex.decode((String) expBuf.get("exported_value"));
                        exports.add(new Export(exporterContext, L, exportedValue));
                        expBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            expBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }
        }
        System.out.println("testing successful!");

    }
}
