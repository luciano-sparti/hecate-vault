use hecate_crypto::SecretBuffer;
use std::collections::HashMap;
use std::sync::RwLock;

/// Local in-memory, memory-locked DEK cache. Keys zeroize on drop.
pub struct KeyCache {
    keys: RwLock<HashMap<String, SecretBuffer>>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key_id: &str, key: SecretBuffer) {
        let mut map = self.keys.write().unwrap();
        map.insert(key_id.to_string(), key);
    }

    pub fn get(&self, key_id: &str) -> Option<SecretBuffer> {
        let map = self.keys.read().unwrap();
        map.get(key_id).cloned()
    }

    pub fn clear(&self) {
        let mut map = self.keys.write().unwrap();
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_cache_operations() {
        let cache = KeyCache::new();

        // 1. Get non-existent
        assert!(cache.get("key-101").is_none());

        // 2. Insert and fetch
        let secret = SecretBuffer::from_str("cached_key_secret_value");
        cache.insert("key-101", secret.clone());
        let fetched = cache.get("key-101").expect("key not found in cache");
        assert_eq!(secret.as_bytes(), fetched.as_bytes());

        // 3. Clear cache
        cache.clear();
        assert!(cache.get("key-101").is_none());
    }
}
