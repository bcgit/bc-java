package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.function.BiFunction;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;

abstract class JsseUtils_9
    extends JsseUtils_8
{
    static class ExportAPSelector<T> implements BiFunction<T, List<String>, String>
    {
        private final BCApplicationProtocolSelector<T> selector;

        ExportAPSelector(BCApplicationProtocolSelector<T> selector)
        {
            this.selector = selector;
        }

        @Override
        public String apply(T t, List<String> u)
        {
            return selector.select(t, u);
        }

        BCApplicationProtocolSelector<T> unwrap()
        {
            return selector;
        }
    }

    static class ImportAPSelector<T> implements BCApplicationProtocolSelector<T>
    {
        private final BiFunction<T, List<String>, String> selector;

        ImportAPSelector(BiFunction<T, List<String>, String> selector)
        {
            this.selector = selector;
        }

        @Override
        public String select(T transport, List<String> protocols)
        {
            return selector.apply(transport, protocols);
        }

        BiFunction<T, List<String>, String> unwrap()
        {
            return selector;
        }
    }

    static <T> BiFunction<T, List<String>, String> exportAPSelector(BCApplicationProtocolSelector<T> selector)
    {
        if (null == selector)
        {
            return null;
        }

        if (selector instanceof ImportAPSelector)
        {
            return ((ImportAPSelector<T>)selector).unwrap();
        }

        return new ExportAPSelector<T>(selector);
    }

    static <T> BCApplicationProtocolSelector<T> importAPSelector(BiFunction<T, List<String>, String> selector)
    {
        if (null == selector)
        {
            return null;
        }

        if (selector instanceof ExportAPSelector)
        {
            return ((ExportAPSelector<T>)selector).unwrap();
        }

        return new ImportAPSelector<T>(selector);
    }
}
