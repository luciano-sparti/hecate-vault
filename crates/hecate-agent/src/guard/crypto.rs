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
