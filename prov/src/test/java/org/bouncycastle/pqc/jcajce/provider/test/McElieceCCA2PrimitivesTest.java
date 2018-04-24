package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceCCA2Primitives;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;


public class McElieceCCA2PrimitivesTest
    extends FlexiTest
{

    KeyPairGenerator kpg;

    protected void setUp()
    {
        super.setUp();
        try
        {
            kpg = KeyPairGenerator.getInstance("McElieceKobaraImai");
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }

    public void testPrimitives()
        throws Exception
    {
        int m = 11;
        int t = 50;
        initKPG(m, t);
        int n = 1 << m;

        KeyPair pair = kpg.genKeyPair();
        BCMcElieceCCA2PublicKey pubKey = (BCMcElieceCCA2PublicKey)pair.getPublic();
        BCMcElieceCCA2PrivateKey privKey = (BCMcElieceCCA2PrivateKey)pair
            .getPrivate();

        GF2Vector plaintext = new GF2Vector(pubKey.getK(), sr);
        GF2Vector errors = new GF2Vector(n, t, sr);

        GF2Vector ciphertext = McElieceCCA2Primitives.encryptionPrimitive(
            pubKey, plaintext, errors);

        GF2Vector[] dec = McElieceCCA2Primitives.decryptionPrimitive(privKey,
            ciphertext);
        GF2Vector plaintextAgain = dec[0];
        GF2Vector errorsAgain = dec[1];

        assertEquals(plaintext, plaintextAgain);
        assertEquals(errors, errorsAgain);
    }

    /**
     * Initialize the key pair generator with the given parameters.
     */
    private void initKPG(int m, int t)
        throws Exception
    {
        McElieceKeyGenParameterSpec params = new McElieceKeyGenParameterSpec(m, t);
        kpg.initialize(params);
    }

}
