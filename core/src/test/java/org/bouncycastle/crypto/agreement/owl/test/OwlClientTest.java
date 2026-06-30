package org.bouncycastle.crypto.agreement.owl.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.ECSchnorrZKP;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationFinish;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationInitiate;
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationServerResponse;
import org.bouncycastle.crypto.agreement.owl.OwlClient;
import org.bouncycastle.crypto.agreement.owl.OwlClientRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlCurve;
import org.bouncycastle.crypto.agreement.owl.OwlCurves;
import org.bouncycastle.crypto.agreement.owl.OwlFinishRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlInitialRegistration;
import org.bouncycastle.crypto.agreement.owl.OwlKeyConfirmation;
import org.bouncycastle.crypto.agreement.owl.OwlServer;
import org.bouncycastle.crypto.agreement.owl.OwlServerRegistration;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;


public class OwlClientTest
    extends TestCase
{
    public void testConstruction()
        throws CryptoException
    {
        OwlCurve curve = OwlCurves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String clientId = "clientId";
        char[] password = "password".toCharArray();

        // should succeed
        new OwlClient(clientId, password, curve, digest, random);

        // null clientId
        try
        {
            new OwlClient(null, password, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null password
        try
        {
            new OwlClient(clientId, null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // empty password
        try
        {
            new OwlClient(clientId, "".toCharArray(), curve, digest, random);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // null curve
        try
        {
            new OwlClient(clientId, password, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new OwlClient(clientId, password, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new OwlClient(clientId, password, curve, digest, null);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testSuccessfulExchange()
        throws CryptoException
    {
        OwlServer server = createServer();
        OwlClient client = createClient();

        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        OwlAuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        OwlAuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        OwlKeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        OwlKeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);
    }

    public void testIncorrectPassword()
        throws CryptoException
    {
        OwlServer server = createServer();
        OwlClient client = createClientWithWrongPassword();
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        OwlAuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        final OwlAuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        try
        {
            server.authenticationServerEnd(clientLoginFinishPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testStateValidation()
        throws CryptoException
    {
        OwlServer server = createServer();
        final OwlClient client = createClient();

        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        // We're testing client here. Server and registration objects are just used for help.

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        // --- LOGIN INITIALIZATION CHECKS ---
        assertEquals(OwlClient.STATE_INITIALISED, client.getState());

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        assertEquals(OwlClient.STATE_LOGIN_INITIALISED, client.getState());

        // client cannot initiate login twice
        try
        {
            client.authenticationInitiate();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        final OwlAuthenticationServerResponse serverLoginResponsePayload =
            server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        // --- LOGIN FINISH CHECKS ---
        // cannot calculate key before finishing authentication
        try
        {
            client.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        OwlAuthenticationFinish clientLoginFinishPayload =
            client.authenticationFinish(serverLoginResponsePayload);
        assertEquals(OwlClient.STATE_LOGIN_FINISHED, client.getState());

        // cannot finish login twice
        try
        {
            client.authenticationFinish(serverLoginResponsePayload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        server.authenticationServerEnd(clientLoginFinishPayload);

        // --- KEY CALCULATION CHECKS ---
        // cannot start key confirmation before calculating key
        try
        {
            client.initiateKeyConfirmation(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // cannot validate key confirmation before calculating key
        try
        {
            client.validateKeyConfirmation(null, null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        final BigInteger rawClientKey = client.calculateKeyingMaterial();
        assertEquals(OwlClient.STATE_KEY_CALCULATED, client.getState());

        // cannot calculate key twice
        try
        {
            client.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawServerKey = server.calculateKeyingMaterial();

        // --- KEY CONFIRMATION CHECKS ---

        OwlKeyConfirmation clientKC = client.initiateKeyConfirmation(rawClientKey);
        assertEquals(OwlClient.STATE_KC_INITIALISED, client.getState());

        // cannot initiate key confirmation twice
        try
        {
            client.initiateKeyConfirmation(rawClientKey);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        final OwlKeyConfirmation serverKC = server.initiateKeyConfirmation(rawServerKey);

        client.validateKeyConfirmation(serverKC, rawClientKey);
        assertEquals(OwlClient.STATE_KC_VALIDATED, client.getState());

        // cannot validate key confirmation twice
        try
        {
            client.validateKeyConfirmation(serverKC, rawClientKey);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // server should validate successfully at the end
        server.validateKeyConfirmation(clientKC, rawServerKey);
    }

    public void testAuthenticationFinish()
        throws CryptoException
    {
        OwlClient client = createClient();
        OwlServer server = createServer();
        OwlAuthenticationServerResponse serverResponse = runExchangeUntilPass3(client, server);
        // should succeed
        client.authenticationFinish(serverResponse);

        final OwlClient client2 = createClient();
        OwlServer server2 = createServer();
        final OwlAuthenticationServerResponse serverResponse2 = runExchangeUntilPass3(client2, server2);

        final OwlCurve curve = OwlCurves.NIST_P256;

        // clientId == serverId
        try
        {
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setServerId("client");
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx3 is infinity
        try
        {
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setGx3(curve.getCurve().getInfinity());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx4 is infinity
        try
        {
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setGx4(curve.getCurve().getInfinity());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Invalid zero-knowledge proof for X3
        try
        {
            OwlAuthenticationServerResponse invalidX3Proof = runExchangeUntilPass3(createClient(), createServer());
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setKnowledgeProofForX3(invalidX3Proof.getKnowledgeProofForX3());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Invalid zero-knowledge proof for X4
        try
        {
            OwlAuthenticationServerResponse invalidX4Proof = runExchangeUntilPass3(createClient(), createServer());
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setKnowledgeProofForX4(invalidX4Proof.getKnowledgeProofForX4());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Beta is infinity
        try
        {
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setBeta(curve.getCurve().getInfinity());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Invalid zero-knowledge proof for Beta
        try
        {
            OwlAuthenticationServerResponse invalidBetaProof = runExchangeUntilPass3(createClient(), createServer());
            OwlAuthenticationServerResponseBuilder b = new OwlAuthenticationServerResponseBuilder(serverResponse2);
            b.setKnowledgeProofForBeta(invalidBetaProof.getKnowledgeProofForBeta());
            client2.authenticationFinish(b.build());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    private OwlServer createServer()
    {
        return new OwlServer("server", OwlCurves.NIST_P256);
    }

    private OwlClient createClient()
    {
        return new OwlClient("client", "password".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlClientRegistration createClientReg()
    {
        return new OwlClientRegistration("client", "password".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlServerRegistration createServerReg()
    {
        return new OwlServerRegistration("server", OwlCurves.NIST_P256);
    }

    private OwlClient createClientWithWrongPassword()
    {
        return new OwlClient("client", "wrong".toCharArray(), OwlCurves.NIST_P256);
    }

    private OwlAuthenticationServerResponse runExchangeUntilPass3(OwlClient client, OwlServer server)
        throws CryptoException
    {
        OwlClientRegistration clientReg = createClientReg();
        OwlServerRegistration serverReg = createServerReg();

        OwlInitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        OwlAuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        return server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);
    }

    private static class OwlAuthenticationServerResponseBuilder
    {
        private String serverId;
        private ECPoint gx3;
        private ECPoint gx4;
        private ECPoint beta;
        private ECSchnorrZKP zkpX3;
        private ECSchnorrZKP zkpX4;
        private ECSchnorrZKP zkpBeta;

        OwlAuthenticationServerResponseBuilder(OwlAuthenticationServerResponse resp)
        {
            this.serverId = resp.getServerId();
            this.gx3 = resp.getGx3();
            this.gx4 = resp.getGx4();
            this.beta = resp.getBeta();
            this.zkpX3 = resp.getKnowledgeProofForX3();
            this.zkpX4 = resp.getKnowledgeProofForX4();
            this.zkpBeta = resp.getKnowledgeProofForBeta();
        }

        void setServerId(String id)
        {
            this.serverId = id;
        }

        void setGx3(ECPoint gx3)
        {
            this.gx3 = gx3;
        }

        void setGx4(ECPoint gx4)
        {
            this.gx4 = gx4;
        }

        void setBeta(ECPoint beta)
        {
            this.beta = beta;
        }

        void setKnowledgeProofForX3(ECSchnorrZKP zkp)
        {
            this.zkpX3 = zkp;
        }

        void setKnowledgeProofForX4(ECSchnorrZKP zkp)
        {
            this.zkpX4 = zkp;
        }

        void setKnowledgeProofForBeta(ECSchnorrZKP zkp)
        {
            this.zkpBeta = zkp;
        }

        OwlAuthenticationServerResponse build()
        {
            return new OwlAuthenticationServerResponse(
                serverId, gx3, gx4, zkpX3, zkpX4, beta, zkpBeta);
        }
    }
}
