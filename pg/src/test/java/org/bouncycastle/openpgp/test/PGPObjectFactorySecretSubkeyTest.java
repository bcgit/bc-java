package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for a parser-robustness defect in
 * {@link org.bouncycastle.openpgp.PGPObjectFactory#nextObject()}: a top-level SECRET_SUBKEY packet
 * is a tag the {@code nextObject()} switch does not handle, yet
 * {@link BCPGInputStream#readPacket()} decodes it into a typed {@link SecretSubkeyPacket}. The
 * factory's default tail used to blindly cast the result to {@code UnknownPacket}, so such a stream
 * escaped the declared {@code throws IOException} contract with an unchecked
 * {@code ClassCastException}. It must now surface as an {@link IOException}.
 */
public class PGPObjectFactorySecretSubkeyTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PGPObjectFactorySecretSubkeyTest());
    }

    public String getName()
    {
        return "PGPObjectFactorySecretSubkeyTest";
    }

    public void performTest()
        throws Exception
    {
        byte[] secretSubkeyPacket = generateSecretSubkeyPacketEncoding();

        // Guard against a vacuous pass: the encoding really must be a SECRET_SUBKEY packet that
        // BCPGInputStream.readPacket() types (otherwise the CCE path the fix targets is not exercised).
        Object decoded = new BCPGInputStream(new ByteArrayInputStream(secretSubkeyPacket)).readPacket();
        isTrue("fixture is not a SecretSubkeyPacket", decoded instanceof SecretSubkeyPacket);

        try
        {
            new BcPGPObjectFactory(secretSubkeyPacket).nextObject();
            fail("nextObject() must reject a top-level SECRET_SUBKEY packet");
        }
        catch (IOException e)
        {
            // expected: reported through the declared throws IOException contract, not a ClassCastException
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().startsWith("unexpected packet in stream:"));
        }
    }

    private byte[] generateSecretSubkeyPacketEncoding()
        throws Exception
    {
        char[] passPhrase = "test".toCharArray();
        Date date = new Date();

        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 1024, 25));
        AsymmetricCipherKeyPair kpSgn = kpg.generateKeyPair();
        AsymmetricCipherKeyPair kpEnc = kpg.generateKeyPair();

        PGPKeyPair sgnKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpSgn, date);
        PGPKeyPair encKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpEnc, date);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
            sgnKeyPair, "TEST <test@test.org>", new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            null, null, new BcPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1),
            new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).build(passPhrase));

        keyRingGen.addSubKey(encKeyPair);

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        for (Iterator<PGPSecretKey> it = secRing.getSecretKeys(); it.hasNext(); )
        {
            PGPSecretKey key = (PGPSecretKey)it.next();
            if (!key.isMasterKey())
            {
                // PGPSecretKey.encode() writes the SecretSubkeyPacket first for a subkey.
                return key.getEncoded();
            }
        }

        fail("generated secret key ring contained no subkey");
        return null; // unreachable
    }
}
