using IdentityServer4.Models;
using IdentityServer4;

namespace SaaS.IdentityServerApi.Identity;

public static class Config
{
    public static IEnumerable<ApiScope> ApiScopes =>
        new[] { new ApiScope("api1", "Primary SaaS API") };

    public static IEnumerable<ApiResource> ApiResources =>
        new[]
        {
            new ApiResource("api1-resource","API 1 Resource")
            {
                Scopes = { "api1" }
            }
        };

    public static IEnumerable<Client> Clients =>
        new[]
        {
            new Client
            {
                ClientId = "api-key-exchange",
                AllowedGrantTypes = { "api_key" },
                AllowedScopes = { "api1" },
                AccessTokenLifetime = 900, // 15 min
                AllowOfflineAccess = false
            },
            // Add client for password grant
            new Client
            {
                ClientId = "password-client",
                AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                ClientSecrets = { new Secret("password-client-secret".Sha256()) },
                AllowedScopes = { "api1", IdentityServerConstants.StandardScopes.OpenId },
                AccessTokenLifetime = 3600, // 1 hour
                AllowOfflineAccess = true
            }
        };

    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email()
        };
}