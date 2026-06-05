package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SavableDigest;
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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * An example of an Owl password-authenticated key exchange.
 * <p>
 * Owl is an academic augmented PAKE protocol (Hao, Bag, Chen, Lopez 2024) — not
 * (yet) an IETF standard. This example is here for users who want to evaluate
 * the construction against the standards-track alternatives BC already ships
 * (J-PAKE in {@code org.bouncycastle.crypto.agreement.jpake} / {@code .ecjpake}).
 * <p>
 * In this example, both the client and the server are on the same JVM. In a
 * real deployment they would be in different locations, exchanging the
 * generated payloads over the network.
 */
public class OwlExample
{
    public static void main(String[] args)
        throws CryptoException
    {
        /*
         * Initialization
         *
         * Pick an appropriate elliptic curve to use throughout the exchange.
         * Both participants must use the same group, and the same curve must
         * be used between user registration, user login and password update.
         */
        OwlCurve curve = OwlCurves.NIST_P256;

        ECCurve ecCurve = curve.getCurve();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        ECPoint g = curve.getG();
        BigInteger h = curve.getH();
        BigInteger n = curve.getN();
        BigInteger q = curve.getQ();

        String clientPassword = "password";

        System.out.println("********* Initialization **********");
        System.out.println("Public parameters for the elliptic curve over prime field:");
        System.out.println("Curve param a (" + a.bitLength() + " bits): " + a.toString(16));
        System.out.println("Curve param b (" + b.bitLength() + " bits): " + b.toString(16));
        System.out.println("Co-factor h (" + h.bitLength() + " bits): " + h.toString(16));
        System.out.println("Base point G (" + g.getEncoded(true).length + " bytes): " + new BigInteger(g.getEncoded(true)).toString(16));
        System.out.println("X coord of G (G not normalised) (" + g.getXCoord().toBigInteger().bitLength() + " bits): " + g.getXCoord().toBigInteger().toString(16));
        System.out.println("y coord of G (G not normalised) (" + g.getYCoord().toBigInteger().bitLength() + " bits): " + g.getYCoord().toBigInteger().toString(16));
        System.out.println("Order of the base point n (" + n.bitLength() + " bits): " + n.toString(16));
        System.out.println("Prime field q (" + q.bitLength() + " bits): " + q.toString(16));
        System.out.println("");

        System.out.println("(Secret password used by Client: " + clientPassword + ")");
        System.out.println("");

        /*
         * Both participants must use the same hashing algorithm and elliptic
         * curve for registration and authentication.
         */
        Digest digest = SHA256Digest.newInstance();
        SecureRandom random = new SecureRandom();

        OwlClientRegistration clientReg = new OwlClientRegistration("client", clientPassword.toCharArray(), curve, digest, random);
        OwlServerRegistration serverReg = new OwlServerRegistration("server", curve, digest, random);

        OwlClient client = new OwlClient("client", clientPassword.toCharArray(), curve, digest, random);
        OwlServer server = new OwlServer("server", curve, digest, random);

        /*
         * Initial User Registration.
         *
         * The client initiates registration using its chosen username and
         * password, and sends a payload (over a secure channel) to the server,
         * which stores it internally. Server-side storage is up to the
         * application that uses this handshake.
         */

        OwlInitialRegistration clientUserRegistration = clientReg.initiateUserRegistration();
        OwlFinishRegistration serverUserRegistration = serverReg.registerUseronServer(clientUserRegistration);

        System.out.println("************ User Registration **************");
        System.out.println("Client sends to Server: ");
        System.out.println("Username used to register = " + clientUserRegistration.getClientId());
        System.out.println("pi=" + clientUserRegistration.getPi().toString(16));
        System.out.println("T=" + new BigInteger(clientUserRegistration.getGt().getEncoded(true)).toString(16));
        System.out.println("");

        System.out.println("Server stores internally: ");
        System.out.println("Username used to register = " + serverUserRegistration.getClientId());
        System.out.println("KP{x3}: {V=" + new BigInteger(serverUserRegistration.getKnowledgeProofForX3().getV().getEncoded(true)).toString(16) + "; r=" + serverUserRegistration.getKnowledgeProofForX3().getr().toString(16) + "}");
        System.out.println("X3=" + new BigInteger(serverUserRegistration.getGx3().getEncoded(true)).toString(16));
        System.out.println("pi=" + serverUserRegistration.getPi().toString(16));
        System.out.println("T=" + new BigInteger(serverUserRegistration.getGt().getEncoded(true)).toString(16));
        System.out.println("");

        /*
         * First Pass.
         *
         * The client initiates the login authentication process by creating
         * and sending a payload to the server.
         */

        OwlAuthenticationInitiate clientLoginStart = client.authenticationInitiate();
        System.out.println("************ First Pass ************");
        System.out.println("Client sends to server: ");
        System.out.println("Username used to login: " + clientLoginStart.getClientId());
        System.out.println("X1=" + new BigInteger(clientLoginStart.getGx1().getEncoded(true)).toString(16));
        System.out.println("X2=" + new BigInteger(clientLoginStart.getGx2().getEncoded(true)).toString(16));
        System.out.println("KP{x1}: {V=" + new BigInteger(clientLoginStart.getKnowledgeProofForX1().getV().getEncoded(true)).toString(16) + "; r=" + clientLoginStart.getKnowledgeProofForX1().getr().toString(16) + "}");
        System.out.println("KP{x2}: {V=" + new BigInteger(clientLoginStart.getKnowledgeProofForX2().getV().getEncoded(true)).toString(16) + "; r=" + clientLoginStart.getKnowledgeProofForX2().getr().toString(16) + "}");
        System.out.println("");

        /*
         * Second Pass.
         *
         * The server validates the client's initial payload, then creates and
         * sends its own payload back to the client.
         */

        OwlAuthenticationServerResponse serverLoginResponse = server.authenticationServerResponse(clientLoginStart, serverUserRegistration);

        System.out.println("************ Second Pass **************");
        System.out.println("Server verifies the client's KP{x1}: OK");
        System.out.println("Server verifies the client's KP{x2}: OK\n");
        System.out.println("Server sends to Client: ");
        System.out.println("Server's unique ID: " + serverLoginResponse.getServerId());
        System.out.println("X3=" + new BigInteger(serverLoginResponse.getGx3().getEncoded(true)).toString(16));
        System.out.println("X4=" + new BigInteger(serverLoginResponse.getGx4().getEncoded(true)).toString(16));
        System.out.println("KP{x3}: {V=" + new BigInteger(serverLoginResponse.getKnowledgeProofForX3().getV().getEncoded(true)).toString(16) + "; r=" + serverLoginResponse.getKnowledgeProofForX3().getr().toString(16) + "}");
        System.out.println("KP{x4}: {V=" + new BigInteger(serverLoginResponse.getKnowledgeProofForX4().getV().getEncoded(true)).toString(16) + "; r=" + serverLoginResponse.getKnowledgeProofForX4().getr().toString(16) + "}");
        System.out.println("Beta=" + new BigInteger(serverLoginResponse.getBeta().getEncoded(true)).toString(16));
        System.out.println("KP{Beta}: {V=" + new BigInteger(serverLoginResponse.getKnowledgeProofForBeta().getV().getEncoded(true)).toString(16) + ", r=" + serverLoginResponse.getKnowledgeProofForBeta().getr().toString(16) + "}");
        System.out.println("");

        /*
         * Third Pass.
         *
         * The client receives and validates the server's response, then sends
         * the final payload of the handshake. In the same pass, the client may
         * send an explicit key confirmation string — optional but recommended.
         */

        OwlAuthenticationFinish clientLoginEnd = client.authenticationFinish(serverLoginResponse);

        System.out.println("************ Third Pass ************");
        System.out.println("Client verifies the server's KP{x3}: OK");
        System.out.println("Client verifies the server's KP{x4}: OK");
        System.out.println("Client verifies the server's KP{Beta}: OK\n");

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        System.out.println("Client computes key material K=" + clientKeyingMaterial.toString(16));
        System.out.println("");

        System.out.println("Client sends to Server: ");
        System.out.println("Username used to login: " + clientLoginEnd.getClientId());
        System.out.println("Alpha=" + new BigInteger(clientLoginEnd.getAlpha().getEncoded(true)).toString(16));
        System.out.println("KP{Alpha}: {V=" + new BigInteger(clientLoginEnd.getKnowledgeProofForAlpha().getV().getEncoded(true)).toString(16) + ", r=" + clientLoginEnd.getKnowledgeProofForAlpha().getr().toString(16) + "}");
        System.out.println("r=" + clientLoginEnd.getR().toString(16));

        /* The client sends an explicit key confirmation string. This is optional but recommended. */
        OwlKeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        System.out.println("MacTag=" + clientKCPayload.getMacTag().toString(16));
        System.out.println("");

        /*
         * Fourth Pass.
         *
         * The server receives the client payload, validates it, and uses it to
         * compute its own key. The server may then send an explicit key
         * confirmation string — optional but recommended.
         */

        System.out.println("********* Fourth Pass ***********");
        server.authenticationServerEnd(clientLoginEnd);
        System.out.println("Server verifies the client's KP{Alpha}: OK");
        System.out.println("Server verifies the client's r: OK\n");

        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();
        System.out.println("Server computes key material K=" + serverKeyingMaterial.toString(16));
        System.out.println("");

        OwlKeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);
        System.out.println("Server checks Client's MacTag for key confirmation: OK\n");

        System.out.println("Server sends to Client:");
        System.out.println("MacTag=" + serverKCPayload.getMacTag().toString(16));
        System.out.println("");

        System.out.println("********* After the fourth Pass ***********");
        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        System.out.println("Client checks Server's MacTag for key confirmation: OK");
        System.out.println("");

        /*
         * Derive a session key from the keying material applicable to whatever
         * encryption algorithm you want to use.
         */

        BigInteger clientKey = deriveSessionKey(clientKeyingMaterial);
        BigInteger serverKey = deriveSessionKey(serverKeyingMaterial);

        System.out.println("Client's session key \t clientKey=" + clientKey.toString(16));
        System.out.println("Server's session key \t serverKey=" + serverKey.toString(16));
    }

    private static BigInteger deriveSessionKey(BigInteger keyingMaterial)
    {
        /*
         * Use a secure key derivation function (KDF) to derive the session key.
         * For the purposes of this example we just hash the keying material.
         */
        SavableDigest digest = SHA256Digest.newInstance();

        byte[] keyByteArray = keyingMaterial.toByteArray();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(keyByteArray, 0, keyByteArray.length);
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }
}
