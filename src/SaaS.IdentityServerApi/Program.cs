using IdentityServer4;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SaaS.IdentityServerApi.Data;
using SaaS.IdentityServerApi.Identity;
using SaaS.IdentityServerApi.Models; 
using SaaS.IdentityServerApi.Services;
using Serilog;
using Microsoft.AspNetCore.Identity;

public class Program
{
    public static string SelectScheme(string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(authorizationHeader))
            return JwtBearerDefaults.AuthenticationScheme;

        if (authorizationHeader.StartsWith("ak_", StringComparison.OrdinalIgnoreCase))
            return SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationSchemeOptions.DefaultScheme;

        if (authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return JwtBearerDefaults.AuthenticationScheme;

        return JwtBearerDefaults.AuthenticationScheme;
    }

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Serilog basic
        builder.Host.UseSerilog((ctx, cfg) =>
        {
            cfg.ReadFrom.Configuration(ctx.Configuration)
               .WriteTo.Console();
        });


        builder.Services.AddDbContext<ApiKeyDbContext>(o => o.UseInMemoryDatabase("ApiKeys"));
        builder.Services.AddScoped<ApiKeyService>();
        builder.Services.AddScoped<UserService>();
        builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

        // IdentityServer4 configuration
        builder.Services.AddIdentityServer(options =>
        {
            options.EmitStaticAudienceClaim = true;
        })
        .AddDeveloperSigningCredential() // dev only
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryApiResources(Config.ApiResources)
        .AddInMemoryClients(Config.Clients)
        .AddInMemoryIdentityResources(Config.IdentityResources)
        .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
        .AddExtensionGrantValidator<ApiKeyGrantValidator>();

        // Configure authentication with automatic scheme selection
        builder.Services.AddAuthentication(options =>
        {
            // Use a custom policy selector that will choose the right scheme
            options.DefaultAuthenticateScheme = "SmartAuth";
            options.DefaultChallengeScheme = "SmartAuth";
        })
        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            opts.Authority = "https://localhost:64130";
            opts.RequireHttpsMetadata = false; // dev
            opts.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false
            };
        })
        .AddScheme<SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationSchemeOptions, 
                    SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationHandler>(
            SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationSchemeOptions.DefaultScheme, 
            options => { })
        .AddPolicyScheme("SmartAuth", "Smart Authentication", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
                return SelectScheme(authHeader);
            };
        });

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var app = builder.Build();

        app.UseSerilogRequestLogging();
        app.UseHttpsRedirection();

        // Swagger (dev convenience)
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseIdentityServer();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}



