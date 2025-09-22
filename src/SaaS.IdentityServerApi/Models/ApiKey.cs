namespace SaaS.IdentityServerApi.Models;

// Remove 'required' keyword for compatibility with older C# versions
public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string PublicId { get; set; }               // Short ID (tenant unique)
    public string Hash { get; set; }                   // Hash of (publicId:secret)
    public string OwnerUserId { get; set; }            // Owning user (sub)
    public string TenantId { get; set; }               // Tenant
    public string ScopesCsv { get; set; } = "api1";
    public string? Name { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
    public DateTime? LastUsedUtc { get; set; }
    public string? MetadataJson { get; set; }

    public bool IsActive(DateTime now) =>
        RevokedUtc == null && (ExpiresUtc == null || ExpiresUtc > now);

    public IEnumerable<string> GetScopes() =>
        (ScopesCsv ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}