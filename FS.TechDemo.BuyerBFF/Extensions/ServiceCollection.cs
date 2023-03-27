using System.Security.Authentication;
using System.Security.Claims;
using System.Text.Json;
using FS.BFF.Common.IdentityProvider.Policies;
using FS.TechDemo.BuyerBFF.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace FS.TechDemo.BuyerBFF.Extensions;


public static class AuthorizationPolicyBuilderExtension
{
    private const string EmailVerified = "email_verified";

    public static AuthorizationPolicyBuilder GetBasePolicy(this AuthorizationPolicyBuilder authorizationPolicyBuilder)
        => authorizationPolicyBuilder.RequireAuthenticatedUser().RequireClaim(EmailVerified, "true");

    public static AuthorizationPolicyBuilder RequireCustomRole(this AuthorizationPolicyBuilder authorizationPolicyBuilder, string role)
        => authorizationPolicyBuilder.GetBasePolicy().RequireRole(role);
}


public static class ServiceCollectionExtension
{
    
    private const string OrganisationAdminRole = "organisation_admin";
    public static void AddS4hAuthorization(this IServiceCollection serviceCollection, Action<AuthorizationOptions>? optionsAction = null)
        => serviceCollection.AddAuthorization(options => {
            options.AddBasePolicy();
            options.AddOrganisationAdminPolicy();
            optionsAction?.Invoke(options);
        });
    
    public static AuthorizationOptions AddOrganisationAdminPolicy(this AuthorizationOptions authorizationOptions)
    {
        authorizationOptions.AddPolicy(AuthorizationPolicies.OrganisationAdminPolicy,
            policyBuilder => policyBuilder.GetBasePolicy()
                .RequireCustomRole(OrganisationAdminRole));
        return authorizationOptions;
    }
    
    public static AuthorizationOptions AddBasePolicy(this AuthorizationOptions authorizationOptions)
    {
        authorizationOptions.AddPolicy(AuthorizationPolicies.DefaultPolicy, policyBuilder => policyBuilder.GetBasePolicy());
        return authorizationOptions;
    }
    
    public static void AddS4HAuthentication(this IServiceCollection serviceCollection, IConfiguration configuration, bool isDevelopment) =>
        serviceCollection.AddAuthentication(options => {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(o => {
            var identityProviderOptions = configuration.GetSection(IdentityProviderOptions.IdentityProvider).Get<IdentityProviderOptions>();
            // TODO AS: Implement proper exceptions to replace NotImplementedException
            o.Authority = string.IsNullOrWhiteSpace(identityProviderOptions.Authority) ? throw new NotImplementedException("identityProviderOptions.Authority")
                : identityProviderOptions.Authority;
            o.Audience = string.IsNullOrWhiteSpace(identityProviderOptions.Audience) ? throw new NotImplementedException("identityProviderOptions.Audience")
                : identityProviderOptions.Audience;
            if (!identityProviderOptions.ValidAudiences.Any()) throw new NotImplementedException("identityProviderOptions.ValidAudiences");
            if (identityProviderOptions.ValidAudiences.Any(string.IsNullOrWhiteSpace)) throw new NotImplementedException("identityProviderOptions.ValidAudiences children empty");

            o.TokenValidationParameters = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.FromMinutes(5),
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                ValidAudiences = identityProviderOptions.ValidAudiences,
                ValidateLifetime = !isDevelopment
            };
            o.RequireHttpsMetadata = !isDevelopment;
            o.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = c => {
                    c.NoResult();
                    c.Response.StatusCode = 401;
                    c.Response.ContentType = "text/plain";
                    var msg = isDevelopment ? c.Exception.ToString() : "An error has occurred while processing your authentication.";
                    return c.Response.WriteAsync(msg);
                },
                OnTokenValidated = context => {
                    if (context.Principal == null) throw new AuthenticationException($"Invalid {nameof(context.Principal)} value.");

                    KeyCloakHelper.MapKeyCloakRolesToClaims(context.Principal);
                    return Task.CompletedTask;
                }
            };
        });

    private static class KeyCloakHelper
    {
        public static void MapKeyCloakRolesToClaims(ClaimsPrincipal contextPrincipal)
        {
            const string realmAccess = "realm_access";
            var resourceAccessSerialized = contextPrincipal.FindFirst(realmAccess)?.Value ?? throw new AuthenticationException($"Invalid {nameof(realmAccess)} value.");
            var resourceAccess = JsonDocument.Parse(resourceAccessSerialized) ?? throw new JsonException("invalid realm_access Json structure.");

            if (contextPrincipal.Identity is not ClaimsIdentity claimsIdentity) return;

            var roleElement = resourceAccess.RootElement.GetProperty("roles");
            var roles = roleElement.EnumerateArray()
                                   .Select(clientRole => clientRole.GetString() ?? "")
                                   .Where(role => !string.IsNullOrWhiteSpace(role));
            foreach (var role in roles)
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
        }
    }
}
