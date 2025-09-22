using Duende.IdentityServer.Validation;

namespace ApiKeys;

// Custom extension grant: grant_type=api_key&api_key=<value>
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
        var apiKeyValue = context.Request.Raw.Get("api_key");
        if (string.IsNullOrEmpty(apiKeyValue))
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Missing api_key");
            return;
        }

        var apiKey = await _apiKeyService.ValidateAsync(apiKeyValue, updateLastUsed: false);
        if (apiKey == null)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Invalid api_key");
            return;
        }

        // You can restrict requested scopes to intersection
        var requestedScopes = (context.Request.Raw.Get("scope") ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var allowedScopes = apiKey.GetScopes().ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (requestedScopes.Length == 0)
            requestedScopes = allowedScopes.ToArray();
        else if (requestedScopes.Any(s => !allowedScopes.Contains(s)))
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidScope, "Scope not allowed for this api_key");
            return;
        }

        // Build result (subject = owner)
        context.Result = new GrantValidationResult(
            subject: apiKey.OwnerUserId,
            authenticationMethod: GrantType,
            claims: requestedScopes.Select(s => new System.Security.Claims.Claim("scope", s)));

        _logger.LogInformation("API key {PublicId} exchanged for access token with scopes: {Scopes}", apiKey.PublicId, string.Join(",", requestedScopes));
    }
}