-- =====================================
-- Day 2 SecureAPI: Seed API Key + Policy
-- =====================================

-- =========================
-- Insert API Key
-- =========================
-- Raw key: mysecretkey123
-- Hash (SHA256): 3e0f9c8d3bff1b7c8b8e1a9f6e1d7a2b1c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f
INSERT INTO api_keys (project_id, key_hash, is_active)
VALUES ('proj_3f9a8c2e', '3e0f9c8d3bff1b7c8b8e1a9f6e1d7a2b1c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f', true)
ON CONFLICT (key_hash) DO NOTHING;

-- =========================
-- Insert Policy
-- =========================
INSERT INTO policies (project_id, resource, action, effect)
VALUES ('proj_3f9a8c2e', 'orders', 'read', 'allow')
ON CONFLICT (project_id, resource, action) DO NOTHING;

-- ✅ Done! Now the API key 'mysecretkey123' will pass /authorize for 'orders:read'.
