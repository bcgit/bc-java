package org.bouncycastle.pqc.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.bouncycastle.pqc.crypto.DigestingStateAwareMessageSigner;
import org.bouncycastle.pqc.crypto.gmss.GMSSDigestProvider;
import org.bouncycastle.pqc.crypto.gmss.GMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSSigner;
import org.bouncycastle.pqc.crypto.gmss.GMSSStateAwareSigner;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;


public class GMSSSignerTest
    extends SimpleTest
{
    byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");

    SecureRandom keyRandom = new FixedSecureRandom(
        new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(keyData)});

    public String getName()
    {
        return "GMSS";
    }

    public void performTest()
        throws Exception
    {

        GMSSParameters params = new GMSSParameters(3,
            new int[]{15, 15, 10}, new int[]{5, 5, 4}, new int[]{3, 3, 2});

        GMSSDigestProvider digProvider = new GMSSDigestProvider()
        {
            public Digest get()
            {
                return new SHA224Digest();
            }
        };

        GMSSKeyPairGenerator gmssKeyGen = new GMSSKeyPairGenerator(digProvider);

        GMSSKeyGenerationParameters genParam = new GMSSKeyGenerationParameters(keyRandom, params);

        gmssKeyGen.init(genParam);

        AsymmetricCipherKeyPair pair = gmssKeyGen.generateKeyPair();

        GMSSPrivateKeyParameters privKey = (GMSSPrivateKeyParameters)pair.getPrivate();

        ParametersWithRandom param = new ParametersWithRandom(privKey, keyRandom);

        // TODO
        Signer gmssSigner = new DigestingMessageSigner(new GMSSSigner(digProvider), new SHA224Digest());
        gmssSigner.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        gmssSigner.update(message, 0, message.length);
        byte[] sig = gmssSigner.generateSignature();


        gmssSigner.init(false, pair.getPublic());
        gmssSigner.update(message, 0, message.length);
        if (!gmssSigner.verifySignature(sig))
        {
            fail("verification fails");
        }

        if (!((GMSSPrivateKeyParameters)pair.getPrivate()).isUsed())
        {
            fail("private key not marked as used");
        }

        stateAwareTest(privKey.nextKey(), pair.getPublic());
    }

    private void stateAwareTest(GMSSPrivateKeyParameters privKey, AsymmetricKeyParameter pub)
    {
        DigestingStateAwareMessageSigner statefulSigner = new DigestingStateAwareMessageSigner(new GMSSStateAwareSigner(new SHA224Digest()), new SHA224Digest());
        statefulSigner.init(true, new ParametersWithRandom(privKey, new SecureRandom()));

        byte[] mes1 = Strings.toByteArray("Message One");
        statefulSigner.update(mes1, 0, mes1.length);
        byte[] sig1 = statefulSigner.generateSignature();

        isTrue(privKey.isUsed());

        byte[] mes2 = Strings.toByteArray("Message Two");
        statefulSigner.update(mes2, 0, mes2.length);
        byte[] sig2 = statefulSigner.generateSignature();

        GMSSPrivateKeyParameters recoveredKey = (GMSSPrivateKeyParameters)statefulSigner.getUpdatedPrivateKey();

        isTrue(recoveredKey.isUsed() == false);

        try
        {
            statefulSigner.generateSignature();
        }
        catch (IllegalStateException e)
        {
            isEquals("signing key no longer usable", e.getMessage());
        }

        statefulSigner.init(false, pub);
        statefulSigner.update(mes2, 0, mes2.length);
        if (!statefulSigner.verifySignature(sig2))
        {
            fail("verification two fails");
        }

        statefulSigner.update(mes1, 0, mes1.length);
        if (!statefulSigner.verifySignature(sig1))
        {
            fail("verification one fails");
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new GMSSSignerTest());
    }
}
