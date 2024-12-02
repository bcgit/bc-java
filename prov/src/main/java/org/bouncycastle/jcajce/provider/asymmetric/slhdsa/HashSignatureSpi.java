package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.pqc.crypto.slhdsa.HashSLHDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;

public class HashSignatureSpi
    extends BaseDeterministicOrRandomSignature
 {
     private final HashSLHDSASigner signer;

     protected HashSignatureSpi(HashSLHDSASigner signer)
     {
         super("HASH-SLH-DSA");
         
         this.signer = signer;
     }

     protected void verifyInit(PublicKey publicKey)
         throws InvalidKeyException
     {
         if (publicKey instanceof BCSLHDSAPublicKey)
         {
             BCSLHDSAPublicKey key = (BCSLHDSAPublicKey)publicKey;

             this.keyParams = key.getKeyParams();
         }
         else
         {
             throw new InvalidKeyException("unknown public key passed to SLH-DSA");
         }
     }

     protected void signInit(PrivateKey privateKey, SecureRandom random)
         throws InvalidKeyException
     {
         this.appRandom = random;
         if (privateKey instanceof BCSLHDSAPrivateKey)
         {
             BCSLHDSAPrivateKey key = (BCSLHDSAPrivateKey)privateKey;

             this.keyParams = key.getKeyParams();
         }
         else
         {
             throw new InvalidKeyException("unknown private key passed to SLH-DSA");
         }
     }

     protected void updateEngine(byte b)
         throws SignatureException
     {
         signer.update(b);
     }

     protected void updateEngine(byte[] buf, int off, int len)
         throws SignatureException
     {
         signer.update(buf, off, len);
     }

     protected byte[] engineSign()
         throws SignatureException
     {
         CipherParameters param = keyParams;

         if (!(param instanceof SLHDSAPrivateKeyParameters))
         {
             throw new SignatureException("engine initialized for verification");
         }

         try
         {
             byte[] sig = signer.generateSignature();

             return sig;
         }
         catch (Exception e)
         {
             throw new SignatureException(e.toString());
         }
         finally
         {
             this.isInitState = true;
         }
     }

     protected boolean engineVerify(byte[] sigBytes)
         throws SignatureException
     {
         CipherParameters param = keyParams;

         if (!(param instanceof SLHDSAPublicKeyParameters))
         {
             throw new SignatureException("engine initialized for signing");
         }

         try
         {
             return signer.verifySignature(sigBytes);
         }
         finally
         {
             this.isInitState = true;
         }
     }

     protected void reInitialize(boolean forSigning, CipherParameters params)
     {
         signer.init(forSigning, params);
     }

     static public class Direct
         extends HashSignatureSpi
     {
         public Direct()
         {
             super(new HashSLHDSASigner());
         }
     }
 }