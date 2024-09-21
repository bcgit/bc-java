package org.bouncycastle.jcajce.provider.test;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PQCSignatureTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    private static Signature deriveSignatureFromKey(Key key)
        throws Exception
    {
        return Signature.getInstance(key.getAlgorithm(), "BC");
    }

    public void testNistSignature()
        throws Exception
    {
        ASN1ObjectIdentifier[] nistOids = new ASN1ObjectIdentifier[]
        {
            NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
            NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
            NISTObjectIdentifiers.id_slh_dsa_shake_128s,
            NISTObjectIdentifiers.id_slh_dsa_shake_128f,
            NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
            NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
            NISTObjectIdentifiers.id_slh_dsa_shake_192s,
            NISTObjectIdentifiers.id_slh_dsa_shake_192f,
            NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
            NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
            NISTObjectIdentifiers.id_slh_dsa_shake_256s,
            NISTObjectIdentifiers.id_slh_dsa_shake_256f,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
            NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
            NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256
        };

        for (int i = 0; i != nistOids.length; i++)
        {
            KeyPairGenerator ml_dsa_kp = KeyPairGenerator.getInstance(nistOids[i].getId(), "BC");
            Signature ml_dsa_sig = deriveSignatureFromKey(ml_dsa_kp.generateKeyPair().getPrivate());
        }
    }
}
