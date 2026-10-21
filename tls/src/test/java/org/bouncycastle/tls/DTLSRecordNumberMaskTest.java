package org.bouncycastle.tls;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.tls.crypto.impl.TlsRecordNumberMask;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsAESRecordNumberMask;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsChaCha20RecordNumberMask;
import org.bouncycastle.tls.crypto.impl.jcajce.JceAESRecordNumberMask;
import org.bouncycastle.tls.crypto.impl.jcajce.JceChaCha20RecordNumberMask;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 4.2.3 record number encryption masks: AES-ECB over the first 16 ciphertext bytes, or the ChaCha20
 * block selected by the first 4 ciphertext bytes (counter) and the next 12 (nonce). Both backends must agree
 * with an independent lightweight reference.
 */
public class DTLSRecordNumberMaskTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    public void testAESMaskMatchesECBReference() throws Exception
    {
        byte[] key = new byte[16];
        byte[] ciphertext = new byte[40];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(ciphertext);

        AESEngine reference = new AESEngine();
        reference.init(true, new KeyParameter(key));
        byte[] expected = new byte[16];
        reference.processBlock(ciphertext, 8, expected, 0);

        TlsRecordNumberMask bc = new BcTlsAESRecordNumberMask(new AESEngine());
        bc.setKey(key, 0, key.length);
        byte[] actualBc = new byte[16];
        bc.generateMask(ciphertext, 8, actualBc, 0);
        assertTrue(Arrays.areEqual(expected, actualBc));

        TlsRecordNumberMask jce = new JceAESRecordNumberMask(new DefaultJcaJceHelper());
        jce.setKey(key, 0, key.length);
        byte[] actualJce = new byte[16];
        jce.generateMask(ciphertext, 8, actualJce, 0);
        assertTrue(Arrays.areEqual(expected, actualJce));
    }

    public void testChaCha20MaskMatchesKeystreamReference() throws Exception
    {
        byte[] key = new byte[32];
        byte[] ciphertext = new byte[32];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(ciphertext);

        // counter = 3 (little-endian), so the mask is keystream bytes [192, 208)
        ciphertext[0] = 3;
        ciphertext[1] = 0;
        ciphertext[2] = 0;
        ciphertext[3] = 0;

        byte[] nonce = Arrays.copyOfRange(ciphertext, 4, 16);
        ChaCha7539Engine reference = new ChaCha7539Engine();
        reference.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] stream = new byte[3 * 64 + 16];
        reference.processBytes(stream, 0, stream.length, stream, 0);
        byte[] expected = Arrays.copyOfRange(stream, 192, 208);

        TlsRecordNumberMask bc = new BcTlsChaCha20RecordNumberMask();
        bc.setKey(key, 0, key.length);
        byte[] actualBc = new byte[16];
        bc.generateMask(ciphertext, 0, actualBc, 0);
        assertTrue(Arrays.areEqual(expected, actualBc));

        TlsRecordNumberMask jce = new JceChaCha20RecordNumberMask();
        jce.setKey(key, 0, key.length);
        byte[] actualJce = new byte[16];
        jce.generateMask(ciphertext, 0, actualJce, 0);
        assertTrue(Arrays.areEqual(expected, actualJce));
    }

    public void testChaCha20MaskLargeCounter() throws Exception
    {
        byte[] key = new byte[32];
        byte[] ciphertext = new byte[16];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(ciphertext);
        ciphertext[3] = (byte)0xFF; // counter near 2^32

        TlsRecordNumberMask bc = new BcTlsChaCha20RecordNumberMask();
        bc.setKey(key, 0, key.length);
        byte[] a = new byte[16];
        bc.generateMask(ciphertext, 0, a, 0);

        TlsRecordNumberMask jce = new JceChaCha20RecordNumberMask();
        jce.setKey(key, 0, key.length);
        byte[] b = new byte[16];
        jce.generateMask(ciphertext, 0, b, 0);

        assertTrue(Arrays.areEqual(a, b));
        assertFalse(Arrays.areEqual(new byte[16], a));
    }
}
