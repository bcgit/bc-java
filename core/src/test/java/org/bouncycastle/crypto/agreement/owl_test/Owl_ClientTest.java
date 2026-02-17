package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.function.Function;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ClientTest
{

    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String clientId = "clientId";
        char[] password = "password".toCharArray();

        //should succeed
        assertDoesNotThrow(() ->
            new Owl_Client(clientId, password, curve, digest, random)
        );

        //null clientId
        assertThrows(NullPointerException.class, () ->
            new Owl_Client(null, password, curve, digest, random)
        );

        //null password
        assertThrows(NullPointerException.class, () ->
            new Owl_Client(clientId, null, curve, digest, random)
        );

        //empty password
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Client(clientId, "".toCharArray(), curve, digest, random)
        );

        //null curve
        assertThrows(NullPointerException.class, () ->
            new Owl_Client(clientId, password, null, digest, random)
        );

        //null digest
        assertThrows(NullPointerException.class, () ->
            new Owl_Client(clientId, password, curve, null, random)
        );

        //null random
        assertThrows(NullPointerException.class, () ->
            new Owl_Client(clientId, password, curve, digest, null)
        );
    }
    @Test
    public void testSuccessfulExchange()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);

    }
    @Test
    public void testIncorrectPassword()
        throws CryptoException
    {
        Owl_Server server = createServer();
        Owl_Client client = createClientWithWrongPassword();
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);
        assertThrows(CryptoException.class, () -> 
            server.authenticationServerEnd(clientLoginFinishPayload)
        );
/*
        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException

        assertThrows(CryptoException.class,
                () -> server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial),
                "Server validation should fail with incorrect password");

        assertThrows(CryptoException.class,
                () -> client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial),
                "Client validation should fail with incorrect password");*/
    }
    @Test
    public void testStateValidation()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        // We're testing client here. Server and registration objects are just used for help.

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        // --- LOGIN INITIALIZATION CHECKS ---
        assertEquals(Owl_Client.STATE_INITIALISED, client.getState());

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        assertEquals(Owl_Client.STATE_LOGIN_INITIALISED, client.getState());

        // client cannot initiate login twice
        assertThrows(IllegalStateException.class,
                client::authenticationInitiate);

        Owl_AuthenticationServerResponse serverLoginResponsePayload =
                server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        // --- LOGIN FINISH CHECKS ---
        // cannot calculate key before finishing authentication
        assertThrows(IllegalStateException.class,
                client::calculateKeyingMaterial);

        Owl_AuthenticationFinish clientLoginFinishPayload =
                client.authenticationFinish(serverLoginResponsePayload);
        assertEquals(Owl_Client.STATE_LOGIN_FINISHED, client.getState());

        // cannot finish login twice
        assertThrows(IllegalStateException.class,
                () -> client.authenticationFinish(serverLoginResponsePayload));

        server.authenticationServerEnd(clientLoginFinishPayload);
        // --- KEY CALCULATION CHECKS ---
        // cannot start key confirmation before calculating key
        assertThrows(IllegalStateException.class,
                () -> client.initiateKeyConfirmation(null));

        // cannot validate key confirmation before calculating key
        assertThrows(IllegalStateException.class,
                () -> client.validateKeyConfirmation(null, null));

        BigInteger rawClientKey = client.calculateKeyingMaterial();
        assertEquals(Owl_Client.STATE_KEY_CALCULATED, client.getState());

        // cannot calculate key twice
        assertThrows(IllegalStateException.class,
                client::calculateKeyingMaterial);

        BigInteger rawServerKey = server.calculateKeyingMaterial();

        // --- KEY CONFIRMATION CHECKS ---

        Owl_KeyConfirmation clientKC = client.initiateKeyConfirmation(rawClientKey);
        assertEquals(Owl_Client.STATE_KC_INITIALISED, client.getState());

        // cannot initiate key confirmation twice
        assertThrows(IllegalStateException.class,
                () -> client.initiateKeyConfirmation(rawClientKey));

        Owl_KeyConfirmation serverKC = server.initiateKeyConfirmation(rawServerKey);

        client.validateKeyConfirmation(serverKC, rawClientKey);
        assertEquals(Owl_Client.STATE_KC_VALIDATED, client.getState());

        // cannot validate key confirmation twice
        assertThrows(IllegalStateException.class,
                () -> client.validateKeyConfirmation(serverKC, rawClientKey));

        // server should validate successfully at the end
        server.validateKeyConfirmation(clientKC, rawServerKey);
    }
    @Test
    public void testAuthenticationFinish()
        throws CryptoException
    {
        Owl_Client client = createClient();
        Owl_Server server = createServer();
        Owl_AuthenticationServerResponse serverResponse = runExchangeUntilPass3(client, server);
        //should succeed
        Owl_AuthenticationFinish clientLoginFinishPayload = assertDoesNotThrow(() -> client.authenticationFinish(serverResponse));

        Owl_Client client2 = createClient();
        Owl_Server server2 = createServer();
        Owl_AuthenticationServerResponse serverResponse2 = runExchangeUntilPass3(client2, server2);
        // Helper to modify server response
        Function<Consumer<Owl_AuthenticationServerResponseBuilder>, Owl_AuthenticationServerResponse> buildResponse =
            modifier -> {
                Owl_AuthenticationServerResponseBuilder builder = new Owl_AuthenticationServerResponseBuilder(serverResponse2);
                modifier.accept(builder);
                return builder.build();
            };


        // Test cases where client should throw CryptoException
        // clientId == serverId
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setServerId("client"))
            )
        );
        Owl_Curve curve = Owl_Curves.NIST_P256;
        // gx3 is infinity
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setGx3(curve.getCurve().getInfinity()))
            )
        );

        // gx4 is infinity
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setGx4(curve.getCurve().getInfinity()))
            )
        );

        // Invalid zero-knowledge proof for X3
        Owl_AuthenticationServerResponse invalidX3Proof = runExchangeUntilPass3(createClient(), createServer());
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setKnowledgeProofForX3(invalidX3Proof.getKnowledgeProofForX3()))
            )
        );

        // Invalid zero-knowledge proof for X4
        Owl_AuthenticationServerResponse invalidX4Proof = runExchangeUntilPass3(createClient(), createServer());
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setKnowledgeProofForX4(invalidX4Proof.getKnowledgeProofForX4()))
            )
        );

        // Beta is infinity
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setBeta(curve.getCurve().getInfinity()))
            )
        );

        // Invalid zero-knowledge proof for Beta
        Owl_AuthenticationServerResponse invalidBetaProof = runExchangeUntilPass3(createClient(), createServer());
        assertThrows(CryptoException.class, () ->
            client2.authenticationFinish(
                buildResponse.apply(b -> b.setKnowledgeProofForBeta(invalidBetaProof.getKnowledgeProofForBeta()))
            )
        );
    }

    private Owl_Server createServer()
    {
        return new Owl_Server("server", Owl_Curves.NIST_P256);
    }

    private Owl_Client createClient()
    {
        return new Owl_Client("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ClientRegistration createClientReg()
    {
        return new Owl_ClientRegistration("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_ServerRegistration createServerReg()
    {
        return new Owl_ServerRegistration("server", Owl_Curves.NIST_P256);
    }

    private Owl_Client createClientWithWrongPassword()
    {
        return new Owl_Client("client", "wrong".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_AuthenticationServerResponse runExchangeUntilPass3(Owl_Client client, Owl_Server server)
    throws CryptoException
    {
        Owl_ClientRegistration clientReg = createClientReg();
        Owl_ServerRegistration serverReg = createServerReg();

        Owl_InitialRegistration clientRegistrationPayload = clientReg.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = serverReg.registerUseronServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        return server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);
    }

    private class Owl_AuthenticationServerResponseBuilder {
        private String serverId;
        private ECPoint gx3, gx4, beta;
        private ECSchnorrZKP zkpX3, zkpX4, zkpBeta;

        public Owl_AuthenticationServerResponseBuilder(Owl_AuthenticationServerResponse resp) {
            this.serverId = resp.getServerId();
            this.gx3 = resp.getGx3();
            this.gx4 = resp.getGx4();
            this.beta = resp.getBeta();
            this.zkpX3 = resp.getKnowledgeProofForX3();
            this.zkpX4 = resp.getKnowledgeProofForX4();
            this.zkpBeta = resp.getKnowledgeProofForBeta();
        }

        public void setServerId(String id) { this.serverId = id; }
        public void setGx3(ECPoint gx3) { this.gx3 = gx3; }
        public void setGx4(ECPoint gx4) { this.gx4 = gx4; }
        public void setBeta(ECPoint beta) { this.beta = beta; }
        public void setKnowledgeProofForX3(ECSchnorrZKP zkp) { this.zkpX3 = zkp; }
        public void setKnowledgeProofForX4(ECSchnorrZKP zkp) { this.zkpX4 = zkp; }
        public void setKnowledgeProofForBeta(ECSchnorrZKP zkp) { this.zkpBeta = zkp; }

        public Owl_AuthenticationServerResponse build() {
            return new Owl_AuthenticationServerResponse(
                serverId, gx3, gx4, zkpX3, zkpX4, beta, zkpBeta
            );
        }
    }

}