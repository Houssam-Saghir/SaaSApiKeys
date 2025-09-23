using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SaaS.IdentityServerApi.Services;

namespace SaaS.IdentityServerApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApiKeysController : ControllerBase
{
    private readonly ApiKeyService _service;
    private readonly ILogger<ApiKeysController> _logger;

    public ApiKeysController(ApiKeyService service, ILogger<ApiKeysController> logger)
    {
        _service = service;
        _logger = logger;
    }

    // Demo user/tenant extraction (replace with real auth in production)
    private (string userId, string tenantId) ResolveContext()
    {
        var user = Request.Headers.TryGetValue("X-Demo-User", out var u) ? u.ToString() : "user-123";
        var tenant = Request.Headers.TryGetValue("X-Demo-Tenant", out var t) ? t.ToString() : "tenant-abc";
        return (user, tenant);
    }

    public record CreateKeyRequest(string? Name, string? Scopes, int? TtlMinutes, string? MetadataJson);

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> Create([FromBody] CreateKeyRequest req)
    {
        var (userId, tenantId) = ResolveContext();
        var scopes = string.IsNullOrWhiteSpace(req.Scopes)
            ? new[] { "api1" }
            : req.Scopes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        TimeSpan? lifetime = req.TtlMinutes.HasValue ? TimeSpan.FromMinutes(req.TtlMinutes.Value) : null;

        var (plain, entity) = await _service.CreateAsync(userId, tenantId, scopes, lifetime, req.Name, req.MetadataJson);
        return Ok(new
        {
            apiKey = plain, // only returned once
            id = entity.PublicId,
            tenant = entity.TenantId,
            name = entity.Name,
            scopes = entity.GetScopes(),
            expiresUtc = entity.ExpiresUtc
        });
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var (userId, tenantId) = ResolveContext();
        var list = await _service.ListAsync(userId, tenantId);
        return Ok(list.Select(k => new
        {
            id = k.PublicId,
            name = k.Name,
            tenant = k.TenantId,
            scopes = k.GetScopes(),
            createdUtc = k.CreatedUtc,
            expiresUtc = k.ExpiresUtc,
            lastUsedUtc = k.LastUsedUtc
        }));
    }

    [HttpDelete("{publicId}")]
    public async Task<IActionResult> Revoke(string publicId)
    {
        var (userId, tenantId) = ResolveContext();
        var ok = await _service.RevokeAsync(publicId, userId, tenantId);
        if (!ok) return NotFound();
        return NoContent();
    }
}