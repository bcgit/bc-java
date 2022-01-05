package org.bouncycastle.crypto.modes;

import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StatelessProcessing;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class ECBCache
{
    private static WeakHashMap<CoreIndex, WeakReference<CoreEngine>> cache = new WeakHashMap<CoreIndex, WeakReference<CoreEngine>>();

    public static CoreEngine getCore(BlockCipher cipher, boolean isEncrypt, CipherParameters params)
    {
        if (cipher instanceof StatelessProcessing && params instanceof KeyParameter)
        {
            synchronized (cache)
            {
                KeyParameter keyParam = (KeyParameter)params;
                CoreIndex idx = new CoreIndex(cipher, isEncrypt, keyParam);
                CoreEngine coreEngine = null;

                WeakReference<CoreEngine> markerRef = cache.get(idx);
                if (markerRef != null)
                {
                    coreEngine = markerRef.get();
                }

                if (coreEngine != null)
                {
                    return coreEngine;
                }

                coreEngine = new CoreEngine(((StatelessProcessing)cipher).newInstance(), isEncrypt, keyParam);

                cache.put(idx, new WeakReference<CoreEngine>(coreEngine));

                return coreEngine;
            }
        }

        return new CoreEngine(cipher, isEncrypt, params);
    }

    static class CoreIndex
    {
        private final BlockCipher cipher;
        private final byte[] keyBytes;
        private final boolean isEncrypt;
        private final int hash_code;

        CoreIndex(BlockCipher cipher, boolean isEncrypt, KeyParameter keyParam)
        {
            this.cipher = cipher;
            this.keyBytes = Arrays.clone(keyParam.getKey());
            this.isEncrypt = isEncrypt;
            this.hash_code = Arrays.hashCode(this.keyBytes);
        }

        public boolean equals(Object o)
        {
            if (o instanceof CoreIndex)
            {
                CoreIndex other = (CoreIndex)o;
                return other.isEncrypt == this.isEncrypt
                    && other.cipher.getAlgorithmName().equals(this.cipher.getAlgorithmName())
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

        public CoreEngine(BlockCipher cipher, boolean isEncrypt, CipherParameters keyParam)
        {
            this.cipher = cipher;
            cipher.init(isEncrypt, keyParam);
        }
    }
}
