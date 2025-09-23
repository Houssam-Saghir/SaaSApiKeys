using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SaaS.IdentityServerApi.Services;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SaaS.IdentityServerApi.Authentication;

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationSchemeOptions>
{
    private readonly ApiKeyService _apiKeyService;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ApiKeyService apiKeyService)
        : base(options, logger, encoder, clock)
    {
        _apiKeyService = apiKeyService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check for API key in Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.NoResult();

        var authHeader = Request.Headers["Authorization"].ToString();
        if (!authHeader.StartsWith("ak_", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        var apiKey = authHeader.Substring("ak_".Length).Trim();
        if (string.IsNullOrEmpty(apiKey))
            return AuthenticateResult.Fail("Invalid API key format");

        try
        {
            //var validatedKey = await _apiKeyService.ValidateAsync(apiKey, updateLastUsed: true);
            var validatedKey = await _apiKeyService.ValidateAsync(apiKey, updateLastUsed: true);

            if (validatedKey == null)
                return AuthenticateResult.Fail("Invalid API key");

            var claims = new List<Claim>
            {
                new("sub", $"spn:ak_{validatedKey.PublicId}"),
                new("api_key_id", validatedKey.PublicId),
                new("owner_sub", validatedKey.OwnerUserId),
                new("tenant_id", validatedKey.TenantId),
                new("auth_origin", "api_key")
            };

            // Add scope claims
            foreach (var scope in validatedKey.GetScopes())
            {
                claims.Add(new Claim("scope", scope));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail($"API key validation failed: {ex.Message}");
        }
    }
}

public class ApiKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "ApiKey";
}