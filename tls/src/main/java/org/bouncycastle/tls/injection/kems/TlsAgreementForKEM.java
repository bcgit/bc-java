package org.bouncycastle.tls.injection.kems;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
import org.openquantumsafe.Pair;

import java.io.IOException;


/**
 * #tls-injection
 * Wraps a Half-KEM and represents it as a BouncyCastle TlsAgreement.
 * In the Half-KEM, keyGen() is invoked at the client side, encapsulate() at the server side,
 * and decapsulate() at the client side.
 *
 * @author Sergejs Kozlovics
 */
public class TlsAgreementForKEM
        implements TlsAgreement
{
    private JcaTlsCrypto crypto;
    private boolean isServer;
    private KEM kem; // delegate


    // writable object state (=assignable "coordinates"):
    private byte[] peerEncapsulated;
    protected byte[] clientSecretKey;
    protected byte[] serverSecret;

    public TlsAgreementForKEM(
            JcaTlsCrypto crypto,
            boolean isServer,
            KEM kem)
    {
        this.crypto = crypto;
        this.isServer = isServer;
        this.kem = kem;
        this.peerEncapsulated = null;
        this.clientSecretKey = null;
        this.serverSecret = null;
    }

    public byte[] generateEphemeral() throws IOException
    {



        if (isServer)
        {
            // Half-KEM Step2: client <--- peerEncapsulated ciphertext <--- server
            if (this.peerEncapsulated == null)
            {
                throw new IOException("receivePeerValue must be called before generateEphemeral for KEMs");
            }

            Pair<byte[], byte[]> p;

            try
            {
                p = kem.encapsulate(this.peerEncapsulated); // peerEncapsulated === client public key
            } catch (Exception e)
            {
                throw new RuntimeException(e);
            }
            this.serverSecret = p.getLeft(); // server secret
            return p.getRight();
        }
        else
        {
            // Half-KEM Step1: client ---> generated pk ---> server
            Pair<byte[], byte[]> p;

            try
            {
                p = kem.keyGen();
            } catch (Exception e)
            {
                throw new RuntimeException(e);
            }
            byte[] pk = p.getLeft();
            byte[] sk = p.getRight();
            this.clientSecretKey = sk;
            return pk;
        }
    }

    public void receivePeerValue(byte[] peerEncapsulated) throws IOException
    {
        this.peerEncapsulated = peerEncapsulated;
    }

    public TlsSecret calculateSecret() throws IOException
    {

        if (isServer)
        {
            if (this.serverSecret == null)
            {
                throw new IOException("Server-side secret has not been generated: generateEphemeral must be called before calculateSecret");
            }
            return new JceTlsSecret(this.crypto, this.serverSecret.clone()); // added .clone() since BC may alter the key
        }
        else
        {
            if (this.clientSecretKey == null)
            {
                throw new IOException("Client-side key pair has not been generated: generateEphemeral must be called before calculateSecret");
            }
            if (this.peerEncapsulated == null)
            {
                throw new IOException("receivePeerValue must be called before calculateSecret for KEMs");
            }

            try
            {
                // Half-KEM Step3: decapsulate at the client
                byte[] receivedSecret = kem.decapsulate(this.clientSecretKey, this.peerEncapsulated);
                return new JceTlsSecret(this.crypto, receivedSecret.clone()); // added .clone() since BC may alter the key
            } catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }

    }


}
