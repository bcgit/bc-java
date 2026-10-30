package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.util.Arrays;

/**
 * Test-only stand-ins for the stateful XMSS and XMSSMT key holders of the removed
 * org.bouncycastle.pqc.crypto.xmss package, built on the promoted key pair generators and
 * signers, so the known-answer and state tests written against them carry over unchanged. Not a
 * test case itself; the name ends in Tests so the legacy Ant builds keep it out of the provider
 * jar, as they do the other test classes in this package.
 */
public final class XMSSHarnessTests
{
    private XMSSHarnessTests()
    {
    }

    static byte[] sign(XMSSSigner signer, byte[] message)
    {
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    static boolean verify(XMSSSigner signer, byte[] message, byte[] signature)
    {
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

    static byte[] sign(XMSSMTSigner signer, byte[] message)
    {
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    static boolean verify(XMSSMTSigner signer, byte[] message, byte[] signature)
    {
        signer.update(message, 0, message.length);

        return signer.verifySignature(signature);
    }

    /**
     * An XMSS key pair that is signed with in place, as the removed pqc.crypto.xmss.XMSS was.
     */
    public static class XMSS
    {
        private final XMSSParameters params;
        private final SecureRandom prng;

        private XMSSPrivateKeyParameters privateKey;
        private XMSSPublicKeyParameters publicKey;

        public XMSS(XMSSParameters params, SecureRandom prng)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
            this.prng = prng;
        }

        public void generateKeys()
        {
            XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();

            kpGen.init(new XMSSKeyGenerationParameters(params, prng));

            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();
            publicKey = (XMSSPublicKeyParameters)kp.getPublic();
        }

        public void importState(XMSSPrivateKeyParameters privateKey, XMSSPublicKeyParameters publicKey)
        {
            checkMatch(privateKey.getRoot(), publicKey.getRoot(), privateKey.getPublicSeed(), publicKey.getPublicSeed());

            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public void importState(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null)
            {
                throw new NullPointerException("privateKey == null");
            }
            if (publicKey == null)
            {
                throw new NullPointerException("publicKey == null");
            }

            importState(new XMSSPrivateKeyParameters.Builder(params).withPrivateKey(privateKey).build(),
                new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey).build());
        }

        public byte[] sign(byte[] message)
        {
            if (message == null)
            {
                throw new NullPointerException("message == null");
            }
            XMSSSigner signer = new XMSSSigner();

            signer.init(true, privateKey);

            byte[] signature = XMSSHarnessTests.sign(signer, message);

            privateKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

            return signature;
        }

        public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey)
            throws ParseException
        {
            if (message == null)
            {
                throw new NullPointerException("message == null");
            }
            if (signature == null)
            {
                throw new NullPointerException("signature == null");
            }
            if (publicKey == null)
            {
                throw new NullPointerException("publicKey == null");
            }
            XMSSSigner signer = new XMSSSigner();

            signer.init(false, new XMSSPublicKeyParameters.Builder(params).withPublicKey(publicKey).build());

            return verify(signer, message, signature);
        }

        public XMSSPrivateKeyParameters exportPrivateKey()
        {
            return privateKey;
        }

        public XMSSPublicKeyParameters exportPublicKey()
        {
            return publicKey;
        }

        public XMSSPrivateKeyParameters getPrivateKey()
        {
            return privateKey;
        }

        public XMSSParameters getParams()
        {
            return params;
        }

        public byte[] getRoot()
        {
            return privateKey.getRoot();
        }

        public int getIndex()
        {
            return privateKey.getIndex();
        }

        public byte[] getPublicSeed()
        {
            return privateKey.getPublicSeed();
        }
    }

    /**
     * An XMSS^MT key pair that is signed with in place, as the removed pqc.crypto.xmss.XMSSMT was.
     */
    public static class XMSSMT
    {
        private final XMSSMTParameters params;
        private final SecureRandom prng;

        private XMSSMTPrivateKeyParameters privateKey;
        private XMSSMTPublicKeyParameters publicKey;

        public XMSSMT(XMSSMTParameters params, SecureRandom prng)
        {
            if (params == null)
            {
                throw new NullPointerException("params == null");
            }
            this.params = params;
            this.prng = prng;
        }

        public void generateKeys()
        {
            XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();

            kpGen.init(new XMSSMTKeyGenerationParameters(params, prng));

            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
            publicKey = (XMSSMTPublicKeyParameters)kp.getPublic();
        }

        public void importState(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null)
            {
                throw new NullPointerException("privateKey == null");
            }
            if (publicKey == null)
            {
                throw new NullPointerException("publicKey == null");
            }
            XMSSMTPrivateKeyParameters priv = new XMSSMTPrivateKeyParameters.Builder(params)
                .withPrivateKey(privateKey).build();
            XMSSMTPublicKeyParameters pub = new XMSSMTPublicKeyParameters.Builder(params)
                .withPublicKey(publicKey).build();

            checkMatch(priv.getRoot(), pub.getRoot(), priv.getPublicSeed(), pub.getPublicSeed());

            this.privateKey = priv;
            this.publicKey = pub;
        }

        public byte[] sign(byte[] message)
        {
            if (message == null)
            {
                throw new NullPointerException("message == null");
            }
            XMSSMTSigner signer = new XMSSMTSigner();

            signer.init(true, privateKey);

            byte[] signature = XMSSHarnessTests.sign(signer, message);

            privateKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

            return signature;
        }

        public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey)
            throws ParseException
        {
            if (message == null)
            {
                throw new NullPointerException("message == null");
            }
            if (signature == null)
            {
                throw new NullPointerException("signature == null");
            }
            if (publicKey == null)
            {
                throw new NullPointerException("publicKey == null");
            }
            XMSSMTSigner signer = new XMSSMTSigner();

            signer.init(false, new XMSSMTPublicKeyParameters.Builder(params).withPublicKey(publicKey).build());

            return verify(signer, message, signature);
        }

        public byte[] exportPrivateKey()
        {
            return privateKey.toByteArray();
        }

        public byte[] exportPublicKey()
        {
            return publicKey.toByteArray();
        }

        public XMSSMTParameters getParams()
        {
            return params;
        }

        public byte[] getPublicSeed()
        {
            return privateKey.getPublicSeed();
        }
    }

    private static void checkMatch(byte[] privRoot, byte[] pubRoot, byte[] privSeed, byte[] pubSeed)
    {
        if (!Arrays.areEqual(privRoot, pubRoot))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(privSeed, pubSeed))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
    }
}
