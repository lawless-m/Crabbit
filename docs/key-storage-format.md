# Crabbit Key Storage Format Specification

This document describes the key file format used by Crabbit for storing user credentials. This format can be implemented in other languages (e.g., C# for Nawin.Auth) for interoperability.

## Overview

The keys file stores **derived cryptographic keys only** - never plaintext passwords. This ensures that even if the keys file is compromised, the original passwords cannot be recovered.

For each user, we store:
1. **DES key** (7 bytes) - used for p9sk1 authentication
2. **PAK hash** (448 bytes) - used for dp9ik authentication (SPAKE2-EE blinding points)

## File Format

### Location
- Default: `~/.crabbit/keys` (or `%USERPROFILE%\.crabbit\keys` on Windows)
- Configurable via `CRABBIT_KEYS` environment variable or `--keys` flag

### Permissions
- File should be mode `0600` (owner read/write only)
- On Windows, use appropriate ACLs to restrict access

### Structure
```
# Crabbit keys file v1
# DO NOT EDIT - managed by crabbit adduser
<username>:<des_key_hex>:<pak_hash_hex>
<username>:<des_key_hex>:<pak_hash_hex>
...
```

### Line Format
Each non-comment line contains three colon-separated fields:

| Field | Size | Format | Description |
|-------|------|--------|-------------|
| username | variable | UTF-8 string | User's login name |
| des_key | 14 chars | lowercase hex | 7-byte DES key |
| pak_hash | 896 chars | lowercase hex | 448-byte PAK hash |

### Example
```
# Crabbit keys file v1
# DO NOT EDIT - managed by crabbit adduser
glenda:f4f29c1e93cd68:df40966d3445560680243a1a009f9deb...
admin:abc123def456ab:0123456789abcdef0123456789abcdef...
```

## Key Derivation

### DES Key (7 bytes)
Use Plan 9's `passtokey` algorithm:

```
function pass_to_key(password: string) -> byte[7]:
    buf = password padded with spaces to 28 bytes, null-terminated
    key = [0] * 7

    for chunk in password (8 bytes at a time):
        # Extract 7-byte key using bit-shift algorithm
        for i in 0..7:
            key[i] = (buf[i] >> i) | (buf[i+1] << (7-i))

        if more chunks:
            # Encrypt next chunk with current key
            next_chunk = plan9_des_encrypt(key, next_8_bytes)
            buf[0:8] = next_chunk

    return key
```

### PAK Hash (448 bytes)
The PAK hash contains two Ed448-Goldilocks curve points (PM and PN) used for SPAKE2-EE blinding.

```
function authpak_hash(password: string, username: string) -> byte[448]:
    # Step 1: Derive AES key using PBKDF2
    salt = "Plan 9 key derivation" (UTF-8 bytes)
    aes_key = PBKDF2-HMAC-SHA1(password, salt, iterations=9001, output_len=16)

    # Step 2: Derive hash material using HKDF
    username_salt = SHA256(username)
    h = HKDF-SHA256(
        ikm = aes_key,
        salt = username_salt,
        info = "Plan 9 AuthPAK hash",
        output_len = 112
    )

    # Step 3: Hash to curve points using Elligator2
    PM = elligator2_hash_to_point(h[0:56])   # First 56 bytes
    PN = elligator2_hash_to_point(h[56:112]) # Second 56 bytes

    # Step 4: Encode as extended points (X, Y, Z, T coordinates)
    result = encode_extended_point(PM) || encode_extended_point(PN)

    return result  # 224 + 224 = 448 bytes
```

### Extended Point Encoding
Each curve point is encoded as 224 bytes (4 × 56-byte field elements):
```
X coordinate: 56 bytes (big-endian)
Y coordinate: 56 bytes (big-endian)
Z coordinate: 56 bytes (big-endian)
T coordinate: 56 bytes (big-endian)
```

## C# Implementation Notes

### Existing Nawin.Auth Functions
You can reuse your existing implementations:
- `AuthPak.Hash(password, username)` returns the 448-byte PAK hash
- For DES key, implement `passtokey` or use the existing Plan 9 DES key derivation

### File I/O
```csharp
public class KeysFile
{
    public string Path { get; }
    public Dictionary<string, UserCredentials> Users { get; }

    public static KeysFile Load(string path);
    public void Save();
    public void AddUser(string username, string password);
    public bool RemoveUser(string username);
}

public class UserCredentials
{
    public string Username { get; }
    public byte[] DesKey { get; }      // 7 bytes
    public byte[] PakHash { get; }     // 448 bytes
}
```

### Parsing
```csharp
public static KeysFile Load(string path)
{
    var users = new Dictionary<string, UserCredentials>();

    foreach (var line in File.ReadAllLines(path))
    {
        if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line))
            continue;

        var parts = line.Split(':');
        if (parts.Length != 3)
            throw new FormatException($"Invalid line format");

        var username = parts[0];
        var desKey = Convert.FromHexString(parts[1]);    // 7 bytes
        var pakHash = Convert.FromHexString(parts[2]);   // 448 bytes

        users[username] = new UserCredentials(username, desKey, pakHash);
    }

    return new KeysFile(path, users);
}
```

### Saving
```csharp
public void Save()
{
    var sb = new StringBuilder();
    sb.AppendLine("# Crabbit keys file v1");
    sb.AppendLine("# DO NOT EDIT - managed by auth server");

    foreach (var (name, creds) in Users)
    {
        sb.AppendLine($"{name}:{Convert.ToHexString(creds.DesKey).ToLower()}:{Convert.ToHexString(creds.PakHash).ToLower()}");
    }

    // Write atomically via temp file
    var tempPath = Path + ".tmp";
    File.WriteAllText(tempPath, sb.ToString());
    File.Move(tempPath, Path, overwrite: true);

    // Set permissions (Unix-like systems)
    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
```

## Security Considerations

1. **Never store plaintext passwords** - only derived keys
2. **Restrict file permissions** - mode 0600 or equivalent
3. **Atomic writes** - use rename to prevent corruption
4. **Memory handling** - clear password from memory after key derivation
5. **Key derivation is deterministic** - same password + username always produces same keys

## Compatibility

Both Crabbit and Nawin.Auth can:
- Read keys files created by the other
- Authenticate users with credentials from the shared keys file
- Add/remove users independently (with appropriate locking if needed)
