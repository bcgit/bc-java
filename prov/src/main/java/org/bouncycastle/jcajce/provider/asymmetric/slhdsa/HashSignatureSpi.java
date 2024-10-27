package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.pqc.crypto.slhdsa.HashSLHDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;

public class HashSignatureSpi
    extends BaseDeterministicOrRandomSignature
 {
     private final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
     private final HashSLHDSASigner signer;

     protected HashSignatureSpi(HashSLHDSASigner signer)
     {
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

         if (appRandom != null)
         {
             param = new ParametersWithRandom(param, appRandom);
         }

         if (paramSpec != null)
         {
             param = new ParametersWithContext(param, paramSpec.getContext());
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
             bOut.reset();
         }
     }

     protected void reInit()
     {
         CipherParameters param = keyParams;
         
         if (keyParams instanceof SLHDSAPublicKeyParameters)
         {
             if (paramSpec != null)
             {
                 param = new ParametersWithContext(param, paramSpec.getContext());
             }

             signer.init(false, param);
         }
         else
         {
             if (appRandom != null)
             {
                 param = new ParametersWithRandom(param, appRandom);
             }

             if (paramSpec != null)
             {
                 param = new ParametersWithContext(param, paramSpec.getContext());
             }

             signer.init(true, param);
         }

         bOut.reset();
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