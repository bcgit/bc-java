package org.bouncycastle.crypto.modes.gcm;

import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StatelessProcessing;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class GCMCache
{
    private static WeakHashMap<CoreIndex, WeakReference<CoreEngine>> cache = new WeakHashMap<CoreIndex, WeakReference<CoreEngine>>();

    public static CoreEngine getCore(BlockCipher cipher, GCMMultiplier multiplier, KeyParameter keyParam)
    {
        CoreIndex idx = new CoreIndex(cipher, keyParam);
        CoreEngine coreEngine = null;

        synchronized (cache)
        {
            WeakReference<CoreEngine> markerRef = cache.get(idx);
            if (markerRef != null)
            {
                coreEngine = markerRef.get();
            }

            if (cipher instanceof StatelessProcessing)
            {
                if (coreEngine != null)
                {
                    return coreEngine;
                }

                cipher = ((StatelessProcessing)cipher).newInstance();
            }
            else
            {
                 if (coreEngine != null)
                 {
                     return new GCMCache.CoreEngine(cipher, keyParam, coreEngine);
                 }
            }

            coreEngine = new GCMCache.CoreEngine(cipher, multiplier, keyParam);

            cache.put(idx, new WeakReference<GCMCache.CoreEngine>(coreEngine));

            return coreEngine;
        }
    }

    static class CoreIndex
    {
        private final BlockCipher cipher;
        private final byte[] keyBytes;
        private final int hash_code;

        CoreIndex(BlockCipher cipher, KeyParameter keyParam)
        {
            this.cipher = cipher;
            this.keyBytes = Arrays.clone(keyParam.getKey());
            this.hash_code = Arrays.hashCode(this.keyBytes);
        }

        public boolean equals(Object o)
        {
            if (o instanceof CoreIndex)
            {
                CoreIndex other = (CoreIndex)o;
                return other.cipher.getAlgorithmName().equals(this.cipher.getAlgorithmName())
                    && Arrays.areEqual(other.keyBytes, this.keyBytes);
            }

            return false;
        }

        public int hashCode()
        {
            return hash_code;
        }
    }

    public static class CoreEngine
    {
        public final BlockCipher cipher;
        public final GCMMultiplier multiplier;
        public final GCMExponentiator exp;

        public CoreEngine(BlockCipher cipher, GCMMultiplier multiplier, KeyParameter keyParam)
        {
            this.cipher = cipher;

            cipher.init(true, keyParam);

            byte[] H = new byte[cipher.getBlockSize()];

            cipher.processBlock(H, 0, H, 0);

            this.multiplier = multiplier;

            // GCMMultiplier tables don't change unless the key changes (and are expensive to init)
            this.multiplier.init(H);

            exp = new Tables1kGCMExponentiator();
            exp.init(H);
        }

        public CoreEngine(BlockCipher cipher, KeyParameter keyParam, CoreEngine coreEngine)
        {
            this.cipher = cipher;
            cipher.init(true, keyParam);

            this.multiplier = coreEngine.multiplier;
            this.exp = coreEngine.exp;
        }
    }
}
