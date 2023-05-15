package com.fsk.hellosecurity.config;

import cn.hutool.cache.CacheUtil;
import cn.hutool.cache.impl.TimedCache;

public class LocalCache {
    private static TimedCache<String, String> cache = CacheUtil.newTimedCache(60 * 1000);
    public static TimedCache<String, String> getCache() {
        return cache;
    }
}
