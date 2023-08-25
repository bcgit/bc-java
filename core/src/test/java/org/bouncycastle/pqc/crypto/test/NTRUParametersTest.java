package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048509;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS701;

public class NTRUParametersTest
    extends TestCase
{
    public void testParameters()
        throws Exception
    {
        assertEquals(256, NTRUParameters.ntruhps2048509.getSessionKeySize());
        assertEquals(256, NTRUParameters.ntruhps2048677.getSessionKeySize());
        assertEquals(256, NTRUParameters.ntruhps4096821.getSessionKeySize());

        assertEquals(256, NTRUParameters.ntruhrss701.getSessionKeySize());
    }

    public void testHpsParameters()
    {
        NTRUHPS2048509 hps2048509 = new NTRUHPS2048509();
        // n
        assertEquals(509, hps2048509.n());
        // q
        assertEquals(2048, hps2048509.q());
        // sample_fixed_type_bits
        assertEquals(15240, hps2048509.sampleFixedTypeBytes() * 8);
        // sample_iid_bits
        assertEquals(4064, hps2048509.sampleIidBytes() * 8);
        // sample_key_bits
        assertEquals(19304, hps2048509.sampleFgBytes() * 8);
        // sample_plaintext_bits
        assertEquals(19304, hps2048509.sampleRmBytes() * 8);
        // dpke_public_key_bytes
        assertEquals(699, hps2048509.owcpaPublicKeyBytes());
        // dpke_private_key_bytes
        assertEquals(903, hps2048509.owcpaSecretKeyBytes());
        // dpke_plaintext_bytes
        assertEquals(204, hps2048509.owcpaMsgBytes());
        // dpke_ciphertext_bytes
        assertEquals(699, hps2048509.owcpaBytes());
        // kem_public_key_bytes
        assertEquals(699, hps2048509.ntruPublicKeyBytes());
        // kem_private_key_bytes
        assertEquals(935, hps2048509.ntruSecretKeyBytes());
        // kem_ciphertext_bytes
        assertEquals(699, hps2048509.ntruCiphertextBytes());
        // kem_shared_key_bytes - category 1
        assertEquals(256, hps2048509.sharedKeyBytes() * 8);
        // prf_key_bits
        assertEquals(256, hps2048509.prfKeyBytes() * 8);
    }

    public void testHrssParameters()
    {
        NTRUHRSS701 hrss701 = new NTRUHRSS701();
        // n
        assertEquals(701, hrss701.n());
        // q
        assertEquals(8192, hrss701.q());
        // sample_iid_bits
        assertEquals(5600, hrss701.sampleIidBytes() * 8);
        // sample_key_bits
        assertEquals(11200, hrss701.sampleFgBytes() * 8);
        // sample_plaintext_bits
        assertEquals(11200, hrss701.sampleRmBytes() * 8);
        // dpke_public_key_bytes
        assertEquals(1138, hrss701.owcpaPublicKeyBytes());
        // dpke_private_key_bytes
        assertEquals(1418, hrss701.owcpaSecretKeyBytes());
        // dpke_plaintext_bytes
        assertEquals(280, hrss701.owcpaMsgBytes());
        // dpke_ciphertext_bytes
        assertEquals(1138, hrss701.owcpaBytes());
        // kem_public_key_bytes
        assertEquals(1138, hrss701.ntruPublicKeyBytes());
        // kem_private_key_bytes
        assertEquals(1450, hrss701.ntruSecretKeyBytes());
        // kem_ciphertext_bytes
        assertEquals(1138, hrss701.ntruCiphertextBytes());
        // kem_shared_key_bytes  - category 3
        assertEquals(256, hrss701.sharedKeyBytes() * 8);
        // prf_key_bits
        assertEquals(256, hrss701.prfKeyBytes() * 8);
    }
}
