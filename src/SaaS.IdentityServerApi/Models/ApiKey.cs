namespace SaaS.IdentityServerApi.Models;

public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string PublicId { get; set; }              
    public string Hash { get; set; }                   
    public string OwnerUserId { get; set; }            
    public string TenantId { get; set; }        
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