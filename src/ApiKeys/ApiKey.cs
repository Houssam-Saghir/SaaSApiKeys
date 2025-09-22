using System.ComponentModel.DataAnnotations;

namespace ApiKeys;

public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(50)]
    public required string PublicId { get; set; }      // short identifier part before the dot

    public required string Hash { get; set; }          // hash of secret part

    public required string OwnerUserId { get; set; }   // link to your user system (e.g., sub from IdP)

    [MaxLength(400)]
    public string ScopesCsv { get; set; } = "api1";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
    public DateTime? LastUsedUtc { get; set; }

    public bool IsActive(DateTime now) =>
        RevokedUtc == null && (ExpiresUtc == null || ExpiresUtc > now);
    
    public IEnumerable<string> GetScopes() =>
        (ScopesCsv ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}