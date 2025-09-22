using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SaaS.IdentityServerApi.Data;
using SaaS.IdentityServerApi.Models;

namespace SaaS.IdentityServerApi.Services;

public class ApiKeyService
{
    private readonly ApiKeyDbContext _db;
    private readonly IConfiguration _config;
    private readonly ILogger<ApiKeyService> _logger;

    public ApiKeyService(ApiKeyDbContext db, IConfiguration config, ILogger<ApiKeyService> logger)
    {
        _db = db;
        _config = config;
        _logger = logger;
    }

    private string ServerSecret =>
        _config["ApiKeys:HashSecret"] ??
        throw new InvalidOperationException("ApiKeys:HashSecret missing.");

    public async Task<(string plainKey, ApiKey entity)> CreateAsync(
        string ownerUserId,
        string tenantId,
        IEnumerable<string> scopes,
        TimeSpan? lifetime,
        string? name,
        string? metadataJson)
    {
        var publicId = GeneratePublicId();
        var secretPart = GenerateSecretPart(32); // 32 bytes random (before encoding)
        var hash = ApiKeyHashing.ComputeHash(ServerSecret, publicId, secretPart);

        var key = new ApiKey
        {
            PublicId = publicId,
            Hash = hash,
            OwnerUserId = ownerUserId,
            TenantId = tenantId,
            ScopesCsv = string.Join(",", scopes),
            ExpiresUtc = lifetime.HasValue ? DateTime.UtcNow.Add(lifetime.Value) : null,
            Name = name,
            MetadataJson = metadataJson
        };

        _db.ApiKeys.Add(key);
        await _db.SaveChangesAsync();

        var full = $"ak_{publicId}.{Base64UrlEncode(Encoding.UTF8.GetBytes(secretPart))}";
        _logger.LogInformation("API key created: publicId={PublicId} tenant={TenantId} owner={Owner}", publicId, tenantId, ownerUserId);
        return (full, key);
    }

    public async Task<ApiKey?> ValidateAsync(string fullKey, bool updateLastUsed = true)
    {
        if (!fullKey.StartsWith("ak_")) return null;
        var trimmed = fullKey.Substring(3);
        var parts = trimmed.Split('.', 2);
        if (parts.Length != 2) return null;
        var publicId = parts[0];
        string secretPart;
        try
        {
            secretPart = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        }
        catch
        {
            return null;
        }

        var calcHash = ApiKeyHashing.ComputeHash(ServerSecret, publicId, secretPart);
        var entity = await _db.ApiKeys.FirstOrDefaultAsync(k => k.PublicId == publicId);
        if (entity == null) return null;
        if (!entity.IsActive(DateTime.UtcNow)) return null;
        if (!ApiKeyHashing.ConstantTimeEquals(calcHash, entity.Hash)) return null;

        if (updateLastUsed)
        {
            entity.LastUsedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }
        return entity;
    }

    public Task<List<ApiKey>> ListAsync(string ownerUserId, string tenantId) =>
        _db.ApiKeys
            .Where(k => k.OwnerUserId == ownerUserId &&
                        k.TenantId == tenantId &&
                        k.RevokedUtc == null)
            .OrderByDescending(k => k.CreatedUtc)
            .ToListAsync();

    public async Task<bool> RevokeAsync(string publicId, string ownerUserId, string tenantId)
    {
        var key = await _db.ApiKeys.FirstOrDefaultAsync(k =>
            k.PublicId == publicId && k.OwnerUserId == ownerUserId && k.TenantId == tenantId);
        if (key == null || key.RevokedUtc != null) return false;
        key.RevokedUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return true;
    }

    private static string GeneratePublicId()
    {
        var raw = RandomNumberGenerator.GetBytes(10); // ~80 bits
        return Base32(raw);
    }

    private static string GenerateSecretPart(int sizeBytes)
    {
        var bytes = RandomNumberGenerator.GetBytes(sizeBytes);
        return Convert.ToBase64String(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var pad = input.Replace('-', '+').Replace('_', '/');
        switch (pad.Length % 4)
        {
            case 2: pad += "=="; break;
            case 3: pad += "="; break;
        }
        return Convert.FromBase64String(pad);
    }

    private static string Base32(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = 0;
        var value = 0;
        var output = new StringBuilder();
        foreach (var b in data)
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
            output.Append(alphabet[(value << (5 - bits)) & 31]);
        return output.ToString();
    }
}