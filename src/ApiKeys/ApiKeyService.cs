using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace ApiKeys;

public class ApiKeyService
{
    private readonly ApiKeyDbContext _db;
    private readonly ILogger<ApiKeyService> _logger;
    private readonly IConfiguration _config;

    public ApiKeyService(ApiKeyDbContext db, ILogger<ApiKeyService> logger, IConfiguration config)
    {
        _db = db;
        _logger = logger;
        _config = config;
    }

    private string ServerSecret => _config["ApiKey:HashSecret"] 
        ?? throw new InvalidOperationException("Missing ApiKey:HashSecret configuration.");

    public async Task<(string plainKey, ApiKey entity)> CreateKeyAsync(string ownerUserId, IEnumerable<string>? scopes = null, TimeSpan? lifetime = null)
    {
        // PublicId (short) + SecretPart (random)
        var publicId = GeneratePublicId();
        var secretPart = GenerateSecretPart(32); // 32 bytes ~ 256 bits
        var hash = ApiKeyHashing.ComputeHash(ServerSecret, publicId, secretPart);

        var apiKey = new ApiKey
        {
            PublicId = publicId,
            Hash = hash,
            OwnerUserId = ownerUserId,
            ScopesCsv = scopes != null ? string.Join(",", scopes) : "api1",
            ExpiresUtc = lifetime.HasValue ? DateTime.UtcNow.Add(lifetime.Value) : null
        };

        _db.ApiKeys.Add(apiKey);
        await _db.SaveChangesAsync();

        var full = $"ak_{publicId}.{Base64UrlEncode(secretPart)}"; // present to user once
        _logger.LogInformation("API key created for user {UserId} with publicId {PublicId}", ownerUserId, publicId);

        return (full, apiKey);
    }

    public async Task<ApiKey?> ValidateAsync(string presentedFullKey, bool updateLastUsed = true)
    {
        // Expect: ak_<publicId>.<secretPartEncoded>
        if (!presentedFullKey.StartsWith("ak_")) return null;

        var parts = presentedFullKey.Substring(3).Split('.', 2);
        if (parts.Length != 2) return null;
        var publicId = parts[0];
        string secretPart;
        try
        {
            secretPart = Base64UrlDecode(parts[1]);
        }
        catch
        {
            return null;
        }

        var hash = ApiKeyHashing.ComputeHash(ServerSecret, publicId, secretPart);

        var entity = await _db.ApiKeys.FirstOrDefaultAsync(k => k.PublicId == publicId);
        if (entity == null) return null;
        if (!entity.IsActive(DateTime.UtcNow)) return null;
        if (!CryptographicEquals(hash, entity.Hash)) return null;

        if (updateLastUsed)
        {
            entity.LastUsedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }

        return entity;
    }

    public async Task<bool> RevokeAsync(string publicId, string ownerUserId)
    {
        var key = await _db.ApiKeys.FirstOrDefaultAsync(k => k.PublicId == publicId && k.OwnerUserId == ownerUserId);
        if (key == null || key.RevokedUtc != null) return false;
        key.RevokedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return true;
    }

    public Task<List<ApiKey>> ListAsync(string ownerUserId) =>
        _db.ApiKeys
            .Where(k => k.OwnerUserId == ownerUserId && k.RevokedUtc == null)
            .OrderByDescending(k => k.CreatedUtc)
            .ToListAsync();

    private static string GeneratePublicId()
    {
        var bytes = RandomNumberGenerator.GetBytes(10); // ~80 bits
        return Base32NoPadding(bytes);
    }

    private static string GenerateSecretPart(int size)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        return Convert.ToBase64String(bytes); // raw secret before we base64url for output
    }

    private static string Base64UrlEncode(string base64Raw)
    {
        // first turn raw secret (already base64) into bytes again
        var bytes = Encoding.UTF8.GetBytes(base64Raw);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        var bytes = Convert.FromBase64String(padded);
        return Encoding.UTF8.GetString(bytes);
    }

    private static bool CryptographicEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var result = 0;
        for (int i = 0; i < a.Length; i++) result |= a[i] ^ b[i];
        return result == 0;
    }

    // Simple base32 (no padding) for smaller public ID
    private static string Base32NoPadding(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0;
        var value = 0;
        var output = new StringBuilder();
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(alphabet[(value >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
        {
            output.Append(alphabet[(value << (5 - bits)) & 31]);
        }
        return output.ToString();
    }
}