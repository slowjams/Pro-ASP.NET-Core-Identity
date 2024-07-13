## Intro to IdentityServer
==============================

```C#
//--------------------------------V IdentityServer runs on https://localhost:5001
public class IdentityServerProgram
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddIdentityServer()
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients);

        var app = builder.Build();

        app.UseDeveloperExceptionPage();

        app.UseIdentityServer();

        app.Run();
    }
}

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        { 
            new IdentityResources.OpenId()
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        { 
            new ApiScope("api1", "My API")
        };

    public static IEnumerable<Client> Clients =>
        new List<Client>
        { 
            new Client
            {
                ClientId = "client",
                
                // no interactive user, use the clientid/secret for authentication
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                
                // secret for authentication
                ClientSecrets = {
                    new Secret("secret".Sha256())
                },

                // scopes that client has access to
                AllowedScopes = { "api1" }
            }
        };
}
//--------------------------------Ʌ dentityServer
```

```C#
//----------------------V Api
public class ApiProgram   // runs on port 6001
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services
            .AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = "https://localhost:5001";  // IdentityServer runs on 5001

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false
                };
            });

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("ApiScope", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("scope", "api1");
            });
        });

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("identity", (ClaimsPrincipal user) => user.Claims.Select(c => new { c.Type, c.Value }))
            .RequireAuthorization("ApiScope");  // ApiScope is the policy name

        app.Run();
    }
}
//----------------------Ʌ Api
```

```C#
//-------------------------V Client, uses the IdentityModel nuget package
public class ClientProgram
{
    public static async Task Main(string[] args)
    {
        var client = new HttpClient();

        DiscoveryDocumentResponse disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");

        if (disco.IsError)
        {
            Console.WriteLine(disco.Error);
            return;
        }

        // request access token
        var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,  // https://localhost:5001/connect/token

            ClientId = "client",
            ClientSecret = "secret",
            Scope = "api1"
        });

        if (tokenResponse.IsError)  // AccessToken is always non-null when IsError is false
        {
            Console.WriteLine(tokenResponse.Error);
            return;
        }

        Console.WriteLine(tokenResponse.Json);

        <!-- #region access_token decoded-->
        /*

         {
           "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhFNjFCRTk2NEFCQUM5NkVEMDU2RDQ5M0RCODQ3M0E2IiwidHlwIjoiYXQrand0In0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo1MDAxIiwibmJmIjoxNzIwNjE5MjczLCJpYXQiOjE3MjA2MTkyNzMsImV4cCI6MTcyMDYyMjg3Mywic2NvcGUiOlsiYXBpMSJdLCJjbGllbnRfaWQiOiJjbGllbnQiLCJqdGkiOiI4NTBEODIzNUFCRTVERkQwQTJFOTE3MjEyODFDNzE1QyJ9.TPF3XuEpz-HgkIAxpsXKzRBZcyALNiQsK_cCBYHV-qrEiND0zZm7wffqUEXr3OeCNU0uiF06Fs3IBAGcNW6nLCp7vHDi-zCidqD8hTGg1tUCxOzDttltzcDF7CyvK81ZaJUb-KOz1Pivi8GfmKcFeV8hK_UfFSPjqh8BAQtQlbyJCdK2eYFbML3lcujzFDtitP4v5kpq3B6m_cx9xnOQ3fUK2Q8ve7f7DZgWLM51dwkyu11nWliRRcZQBsu5GT9EhmqTiB69y8PsV6mAYbhSb5BKN0YelV2RU5G89wVYoxQPYvNUP5TDOdI-XEgRX2mKYMKy_Ilf60q_KkqAGgilHQ",
           "expires_in": 3600,
           "token_type": "Bearer",
           "scope": "api1"           
         }

         access_token decoded:

         {
           "alg": "RS256",
           "kid": "8E61BE964ABAC96ED056D493DB8473A6",
           "typ": "at+jwt"
         }.{
           "iss": "https://localhost:5001",
           "nbf": 1720619273,
           "iat": 1720619273,
           "exp": 1720622873,
           "scope": [
             "api1"
           ],
           "client_id": "client",
           "jti": "850D8235ABE5DFD0A2E91721281C715C"
         }.[Signature]

        */
       <!-- #endregion -->

        // call api
        var apiClient = new HttpClient();
        apiClient.SetBearerToken(tokenResponse.AccessToken);

        var response = await apiClient.GetAsync("https://localhost:6001/identity");
        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(response.StatusCode);
        }
        else
        {
            var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            Console.WriteLine(JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}
//-------------------------Ʌ Client
```