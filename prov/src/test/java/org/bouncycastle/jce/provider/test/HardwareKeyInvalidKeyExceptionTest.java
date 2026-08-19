package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.ElGamalUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A private key from another provider whose key material is held in hardware answers its
 * getModulus() / getX() / getS() / getParams() with an UnsupportedOperationException. The
 * provider's key-parameter helpers must surface that as the declared InvalidKeyException rather
 * than leak the unchecked type out of engineInitSign / engineInit (github #1440).
 */
public class HardwareKeyInvalidKeyExceptionTest
    extends SimpleTest
{
    private static final RuntimeException HARDWARE =
        new UnsupportedOperationException("Hardware error, function has no meaning in hardware");

    public String getName()
    {
        return "HardwareKeyInvalidKeyException";
    }

    public void performTest()
        throws Exception
    {
        // RSASSA-PSS through the public API - the path reported in github #1440.
        expectInvalidKey("RSA", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                Signature.getInstance("SHA256withRSAandMGF1", "BC").initSign(new OpaqueRSAPrivateKey());
            }
        });

        expectInvalidKey("DSA", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                DSAUtil.generatePrivateKeyParameter(new OpaqueDSAPrivateKey());
            }
        });

        expectInvalidKey("EC", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                ECUtil.generatePrivateKeyParameter(new OpaqueECPrivateKey());
            }
        });

        expectInvalidKey("DH (jcajce)", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                org.bouncycastle.jcajce.provider.asymmetric.util.DHUtil.generatePrivateKeyParameter(new OpaqueDHPrivateKey());
            }
        });

        expectInvalidKey("DH (jce)", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                org.bouncycastle.jce.provider.DHUtil.generatePrivateKeyParameter(new OpaqueDHPrivateKey());
            }
        });

        expectInvalidKey("ElGamal", new KeyOp()
        {
            public void extract()
                throws Exception
            {
                ElGamalUtil.generatePrivateKeyParameter(new OpaqueDHPrivateKey());
            }
        });
    }

    private void expectInvalidKey(String label, KeyOp op)
    {
        try
        {
            op.extract();
            fail(label + ": expected InvalidKeyException, none thrown");
        }
        catch (InvalidKeyException e)
        {
            isTrue(label + ": original hardware exception not chained as cause", e.getCause() == HARDWARE);
        }
        catch (Exception e)
        {
            fail(label + ": expected InvalidKeyException, got " + e.getClass().getName());
        }
    }

    private interface KeyOp
    {
        void extract()
            throws Exception;
    }

    private static class OpaqueRSAPrivateKey
        implements RSAPrivateKey
    {
        public BigInteger getModulus()
        {
            throw HARDWARE;
        }

        public BigInteger getPrivateExponent()
        {
            throw HARDWARE;
        }

        public String getAlgorithm()
        {
            return "RSA";
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }
    }

    private static class OpaqueDSAPrivateKey
        implements DSAPrivateKey
    {
        public BigInteger getX()
        {
            throw HARDWARE;
        }

        public DSAParams getParams()
        {
            throw HARDWARE;
        }

        public String getAlgorithm()
        {
            return "DSA";
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }
    }

    private static class OpaqueECPrivateKey
        implements ECPrivateKey
    {
        public BigInteger getS()
        {
            throw HARDWARE;
        }

        public java.security.spec.ECParameterSpec getParams()
        {
            throw HARDWARE;
        }

        public String getAlgorithm()
        {
            return "EC";
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }
    }

    private static class OpaqueDHPrivateKey
        implements DHPrivateKey
    {
        public BigInteger getX()
        {
            throw HARDWARE;
        }

        public DHParameterSpec getParams()
        {
            throw HARDWARE;
        }

        public String getAlgorithm()
        {
            return "DH";
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new HardwareKeyInvalidKeyExceptionTest());
    }
}
