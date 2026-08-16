package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.HashSLHDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseDeterministicOrRandomSignature;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

public class HashSignatureSpi
    extends BaseDeterministicOrRandomSignature
 {
     private final HashSLHDSASigner signer;
     private final SLHDSAParameters parameters;
     private final SLHDSAParameters pureParameters;

     protected HashSignatureSpi(HashSLHDSASigner signer)
     {
         super("HASH-SLH-DSA");

         this.signer = signer;
         this.parameters = null;
         this.pureParameters = null;
     }

     protected HashSignatureSpi(HashSLHDSASigner signer, SLHDSAParameters parameters, SLHDSAParameters pureParameters)
     {
         super(SLHDSAParameterSpec.fromName(parameters.getName()).getName());

         this.signer = signer;
         this.parameters = parameters;
         this.pureParameters = pureParameters;
     }

     /**
      * FIPS 205 defines one key generation algorithm per parameter set, and a key it produces
      * carries no commitment to pure SLH-DSA over HashSLH-DSA, so a <b>pure</b> key of the matching
      * parameter set is admissible on the pre-hash path. That matters in practice because a key
      * recovered from an X.509 certificate carries the pure OID, and mirrors the ML-DSA behaviour
      * asked for in <a href="https://github.com/bcgit/bc-java/issues/2397">github #2397</a>.
      * <p>
      * The tolerance is one way only: a key that already names a HashSLH-DSA parameter set has been
      * narrowed to the pre-hash mode, so it stays refused by the pure {@link SignatureSpi}. A key of
      * a different parameter set is refused either way.
      * </p>
      *
      * @param parameters the parameter set this SPI is bound to, null for the unbound SPIs.
      * @param alsoAllowed a second admissible parameter set, the pure variant on the pre-hash path,
      *                    null where only <code>parameters</code> itself is admissible.
      * @param keyParameters the parameter set the key names.
      */
     static void checkKeyParameters(SLHDSAParameters parameters, SLHDSAParameters alsoAllowed, SLHDSAParameters keyParameters)
         throws InvalidKeyException
     {
         if (parameters == null)
         {
             return;
         }

         if (parameters != keyParameters && alsoAllowed != keyParameters)
         {
             throw new InvalidKeyException("signature configured for "
                 + SLHDSAParameterSpec.fromName(parameters.getName()).getName());
         }
     }

     protected void verifyInit(PublicKey publicKey)
         throws InvalidKeyException
     {
         if (publicKey instanceof BCSLHDSAPublicKey)
         {
             BCSLHDSAPublicKey key = (BCSLHDSAPublicKey)publicKey;

             this.keyParams = key.getKeyParams();

             checkKeyParameters(parameters, pureParameters, key.getKeyParams().getParameters());
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

             checkKeyParameters(parameters, pureParameters, key.getKeyParams().getParameters());
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

     public static class Direct
         extends HashSignatureSpi
     {
         public Direct()
         {
             super(new HashSLHDSASigner());
         }
     }

     public static class Sha2_128s
         extends HashSignatureSpi
     {
         public Sha2_128s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_128s_with_sha256, SLHDSAParameters.sha2_128s);
         }
     }

     public static class Sha2_128f
         extends HashSignatureSpi
     {
         public Sha2_128f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_128f_with_sha256, SLHDSAParameters.sha2_128f);
         }
     }

     public static class Sha2_192s
         extends HashSignatureSpi
     {
         public Sha2_192s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_192s_with_sha512, SLHDSAParameters.sha2_192s);
         }
     }

     public static class Sha2_192f
         extends HashSignatureSpi
     {
         public Sha2_192f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_192f_with_sha512, SLHDSAParameters.sha2_192f);
         }
     }

     public static class Sha2_256s
         extends HashSignatureSpi
     {
         public Sha2_256s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_256s_with_sha512, SLHDSAParameters.sha2_256s);
         }
     }

     public static class Sha2_256f
         extends HashSignatureSpi
     {
         public Sha2_256f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.sha2_256f_with_sha512, SLHDSAParameters.sha2_256f);
         }
     }

     public static class Shake_128s
         extends HashSignatureSpi
     {
         public Shake_128s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_128s_with_shake128, SLHDSAParameters.shake_128s);
         }
     }

     public static class Shake_128f
         extends HashSignatureSpi
     {
         public Shake_128f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_128f_with_shake128, SLHDSAParameters.shake_128f);
         }
     }

     public static class Shake_192s
         extends HashSignatureSpi
     {
         public Shake_192s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_192s_with_shake256, SLHDSAParameters.shake_192s);
         }
     }

     public static class Shake_192f
         extends HashSignatureSpi
     {
         public Shake_192f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_192f_with_shake256, SLHDSAParameters.shake_192f);
         }
     }

     public static class Shake_256s
         extends HashSignatureSpi
     {
         public Shake_256s()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_256s_with_shake256, SLHDSAParameters.shake_256s);
         }
     }

     public static class Shake_256f
         extends HashSignatureSpi
     {
         public Shake_256f()
         {
             super(new HashSLHDSASigner(), SLHDSAParameters.shake_256f_with_shake256, SLHDSAParameters.shake_256f);
         }
     }
 }
