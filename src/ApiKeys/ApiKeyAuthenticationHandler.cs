using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace ApiKeys;

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public string HeaderName { get; set; } = "X-Api-Key";
}

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private readonly ApiKeyService _apiKeyService;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ApiKeyService apiKeyService) : base(options, logger, encoder, clock)
    {
        _apiKeyService = apiKeyService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? raw = null;

        // First check custom header, then Authorization: ApiKey <value>
        if (Request.Headers.TryGetValue(Options.HeaderName, out var headerValues))
        {
            raw = headerValues.FirstOrDefault();
        }
        else if (Request.Headers.TryGetValue("Authorization", out var authValues))
        {
            var parts = authValues.FirstOrDefault()?.Split(' ', 2);
            if (parts?.Length == 2 && parts[0].Equals("ApiKey", StringComparison.OrdinalIgnoreCase))
                raw = parts[1];
        }

        if (string.IsNullOrWhiteSpace(raw))
            return AuthenticateResult.NoResult();

        var apiKey = await _apiKeyService.ValidateAsync(raw);
        if (apiKey == null)
            return AuthenticateResult.Fail("Invalid API key");

        var claims = new List<Claim>
        {
            new("sub", apiKey.OwnerUserId),
            new("api_key_id", apiKey.PublicId)
        };
        foreach (var scope in apiKey.GetScopes())
            claims.Add(new Claim("scope", scope));

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}