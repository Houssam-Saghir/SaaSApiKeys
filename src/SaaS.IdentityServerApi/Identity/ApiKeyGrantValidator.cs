using IdentityServer4.Validation;
using IdentityServer4.Models;
using SaaS.IdentityServerApi.Services;
using System.Security.Claims;

namespace SaaS.IdentityServerApi.Identity;

// Implements grant_type=api_key
public class ApiKeyGrantValidator : IExtensionGrantValidator
{
    private readonly ApiKeyService _apiKeyService;
    private readonly ILogger<ApiKeyGrantValidator> _logger;

    public ApiKeyGrantValidator(ApiKeyService apiKeyService, ILogger<ApiKeyGrantValidator> logger)
    {
        _apiKeyService = apiKeyService;
        _logger = logger;
    }

    public string GrantType => "api_key";

    public async Task ValidateAsync(ExtensionGrantValidationContext context)
    {
        var rawKey = context.Request.Raw.Get("api_key");
        if (string.IsNullOrWhiteSpace(rawKey))
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "missing api_key");
            return;
        }

        var apiKey = await _apiKeyService.ValidateAsync(rawKey, updateLastUsed: true);
        if (apiKey == null)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "invalid api_key");
            return;
        }

        var requestedScopes = (context.Request.Raw.Get("scope") ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var allowed = apiKey.GetScopes().ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (requestedScopes.Length == 0)
            requestedScopes = allowed.ToArray();
        else if (requestedScopes.Any(s => !allowed.Contains(s)))
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidScope, "scope not allowed");
            return;
        }

        // 'sub' as a service principal subject
        var spn = $"spn:ak_{apiKey.PublicId}";
        var claims = new List<Claim>
        {
            new("sub", spn),
            new("api_key_id", apiKey.PublicId),
            new("owner_sub", apiKey.OwnerUserId),
            new("tenant_id", apiKey.TenantId),
            new("auth_origin", "api_key")
        };
        foreach (var s in requestedScopes)
            claims.Add(new Claim("scope", s));

        context.Result = new GrantValidationResult(
            subject: spn,
            authenticationMethod: GrantType,
            claims: claims);

        _logger.LogInformation("API key {PublicId} (tenant {Tenant}) exchanged for token scopes={Scopes}",
            apiKey.PublicId, apiKey.TenantId, string.Join(",", requestedScopes));
    }
}