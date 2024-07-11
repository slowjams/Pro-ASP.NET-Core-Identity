## .NET Identity JWT Authentication Source Code

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {      
        services
            .AddAuthentication()
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts => {  // opts is JwtBearerOptions
                // opts.Authority = "https://localhost:5005"  <------------when you use IdentityServer4, check i1
                opts.TokenValidationParameters.ValidateAudience = false;
                opts.TokenValidationParameters.ValidateIssuer = false;
                opts.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["BearerTokens:Key"]))
                // the IssuerSigningKey above will be used to decrypt the encryped base64 of JWT
            });
    }
    // ... 
}
//------------------Ʌ

//-------------------------------------V
public static class JwtBearerExtensions
{
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder)
        => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });
    
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddJwtBearer(authenticationScheme, _ => { });

    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
        => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureOptions);
    
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerOptions> configureOptions)
        => builder.AddJwtBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);
    
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<JwtBearerOptions> configureOptions)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, JwtBearerConfigureOptions>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
        return builder.AddScheme<JwtBearerOptions, JwtBearerHandler>(authenticationScheme, displayName, configureOptions);
    }
}
//-------------------------------------Ʌ

//----------------------------------->>
public static class JwtBearerDefaults
{
    public const string AuthenticationScheme = "Bearer";
}
//------------------------------------<<

//---------------------------V
public class JwtBearerOptions : AuthenticationSchemeOptions
{
    private readonly JsonWebTokenHandler _defaultTokenHandler = new JsonWebTokenHandler
    {
        MapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims
    };
 
    private bool _mapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims;

    public JwtBearerOptions()
    {
        TokenHandlers = new List<TokenHandler> { _defaultTokenHandler };
    }

    public bool RequireHttpsMetadata { get; set; } = true;
    public string MetadataAddress { get; set; } = default!;
    public string? Authority { get; set; }  // <----------------------------------------gets or sets the Authority to use when making OpenIdConnect calls
    public string? Audience { get; set; }
    public string Challenge { get; set; } = JwtBearerDefaults.AuthenticationScheme;
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }
    public HttpClient Backchannel { get; set; } = default!;
    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromMinutes(1);
    public OpenIdConnectConfiguration? Configuration { get; set; }  // <--------------------------------------
    public IConfigurationManager<OpenIdConnectConfiguration>? ConfigurationManager { get; set; }  // <------------------------------
    public bool RefreshOnIssuerKeyNotFound { get; set; } = true;
    public IList<ISecurityTokenValidator> SecurityTokenValidators { get; private set; }
    public IList<TokenHandler> TokenHandlers { get; private set; }
    public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();
    public bool SaveToken { get; set; } = true;
    public bool IncludeErrorDetails { get; set; } = true;
    public TimeSpan AutomaticRefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
    public TimeSpan RefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval;
    public bool UseSecurityTokenValidators { get; set; }

    public new JwtBearerEvents Events
    {
        get { return (JwtBearerEvents)base.Events!; }
        get { base.Events = value; }
    }

    public bool MapInboundClaims
    {
        get => _mapInboundClaims;
        set
        {
            _mapInboundClaims = value;
            _defaultHandler.MapInboundClaims = value;
            _defaultTokenHandler.MapInboundClaims = value;
        }
    }
}
//---------------------------Ʌ
```

```C#
//----------------------------V controller that generate a sign in jwt token
public class ApiAuthController : ControllerBase
{
    private SignInManager<IdentityUser> SignInManager;
    private UserManager<IdentityUser> UserManager;
    private IConfiguration Configuration;

    // ...

    [HttpPost("signin")]
    public async Task<object> ApiSignIn([FromBody] SignInCredentials creds)
    {
        IdentityUser user = await UserManager.FindByEmailAsync(creds.Email);

        SignInResult result = await SignInManager.CheckPasswordSignInAsync(user, creds.Password, true);  // only to check if the username, password match, not really signin yet

        if (result.Succeeded)
        {
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                // Subject is ClaimsIdentity
                Subject = (await SignInManager.CreateUserPrincipalAsync(user)).Identities.First(),
                Expires = DateTime.Now.AddMinutes(int.Parse(Configuration["BearerTokens:ExpiryMins"])),  // <----------------------------become an JwtRegisteredClaimNames.Exp
                                                                                                         // ("exp") claim in side the ClaimIdentity
                SigningCredentials = new SigningCredentials
                (
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["BearerTokens:Key"])),  // use the same key of IssuerSigningKey to encrypt the ClaimsIdentity
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            SecurityToken secToken = handler.CreateToken(descriptor);

            return new { success = true, token = handler.WriteToken(secToken) };
        }

        return new { success = false };
    }
}
//----------------------------Ʌ

//---------------------------V
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]  // <--------------------
[ApiController]
[Route("/api/data")]
public class ValuesController : Controller  // controller that uses jwt
{
    //...
}
//---------------------------Ʌ
```

```C#
//---------------------------V
public class JwtBearerHandler : AuthenticationHandler<JwtBearerOptions>
{
    public JwtBearerHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

    protected new JwtBearerEvents Events
    {
        get => (JwtBearerEvents)base.Events!;
        set => base.Events = value;
    }

    protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new JwtBearerEvents());

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? token;
        try
        {
            // Give application opportunity to find from a different location, adjust, or reject token
            var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);
 
            // event can set the token
            await Events.MessageReceived(messageReceivedContext);
            if (messageReceivedContext.Result != null)
            {
                return messageReceivedContext.Result;
            }
 
            // If application retrieved token from somewhere else, use that.
            token = messageReceivedContext.Token;
 
            if (string.IsNullOrEmpty(token))
            {
                string authorization = Request.Headers.Authorization.ToString();
 
                // If no authorization header found, nothing to process further
                if (string.IsNullOrEmpty(authorization))
                {
                    return AuthenticateResult.NoResult();
                }
 
                if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))  // <----------------------------------
                {
                    token = authorization.Substring("Bearer ".Length).Trim();
                }
 
                // If no token found, no further work possible
                if (string.IsNullOrEmpty(token))
                {
                    return AuthenticateResult.NoResult();
                }
            }
 
            TokenValidationParameters tvp = await SetupTokenValidationParametersAsync();  // <-----i1, check this method carefully to see how "https://localhost:5005" is called
            List<Exception>? validationFailures = null;
            SecurityToken? validatedToken = null;
            ClaimsPrincipal? principal = null;  // <----------------------
 
            if (!Options.UseSecurityTokenValidators)
            {
                foreach (var tokenHandler in Options.TokenHandlers)
                {
                    try
                    {
                        TokenValidationResult tokenValidationResult = await tokenHandler.ValidateTokenAsync(token, tvp);           
                        if (tokenValidationResult.IsValid)
                        {
                            principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);  // <----------------------
                            validatedToken = tokenValidationResult.SecurityToken;
                            break;
                        }
                        else
                        {
                            validationFailures ??= new List<Exception>(1);
                            RecordTokenValidationError(tokenValidationResult.Exception ?? new SecurityTokenValidationException($"The TokenHandler: '{tokenHandler}', was unable to validate the Token."), validationFailures);
                        }
                    }
                    catch (Exception ex)
                    {
                        validationFailures ??= new List<Exception>(1);
                        RecordTokenValidationError(ex, validationFailures);
                    }
                }
            }
            else
            {
                foreach (var validator in Options.SecurityTokenValidators)
                {
                    if (validator.CanReadToken(token))
                    {
                        try
                        {
                            principal = validator.ValidateToken(token, tvp, out validatedToken);
                        }
                        catch (Exception ex)
                        {
                            validationFailures ??= new List<Exception>(1);
                            RecordTokenValidationError(ex, validationFailures);
                            continue;
                        }
                    }
                }
            }
 
            if (principal != null && validatedToken != null)
            {
                Logger.TokenValidationSucceeded();
 
                var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                {
                    Principal = principal
                };
 
                tokenValidatedContext.SecurityToken = validatedToken;
                tokenValidatedContext.Properties.ExpiresUtc = GetSafeDateTime(validatedToken.ValidTo);
                tokenValidatedContext.Properties.IssuedUtc = GetSafeDateTime(validatedToken.ValidFrom);
 
                await Events.TokenValidated(tokenValidatedContext);
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;  // <-------------------------return AuthenticateResult
                }
 
                if (Options.SaveToken)
                {
                    tokenValidatedContext.Properties.StoreTokens(new[]
                    {
                        new AuthenticationToken { Name = "access_token", Value = token }
                    });
                }
 
                tokenValidatedContext.Success();
                return tokenValidatedContext.Result!;
            }
 
            if (validationFailures != null)
            {
                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
                };
 
                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }
 
                return AuthenticateResult.Fail(authenticationFailedContext.Exception);
            }
 
            if (!Options.UseSecurityTokenValidators)
            {
                return AuthenticateResults.TokenHandlerUnableToValidate;
            }
 
            return AuthenticateResults.ValidatorNotFound;
        }
        catch (Exception ex)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Exception = ex
            };
 
            await Events.AuthenticationFailed(authenticationFailedContext);
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }
 
            throw;
        }
    }

    private void RecordTokenValidationError(Exception exception, List<Exception> exceptions)
    {
        if (exception != null)
        {
            Logger.TokenValidationFailed(exception);
            exceptions.Add(exception);
        }
 
        // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
        // Refreshing on SecurityTokenSignatureKeyNotFound may be redundant if Last-Known-Good is enabled, it won't do much harm, most likely will be a nop.
        if (Options.RefreshOnIssuerKeyNotFound && Options.ConfigurationManager != null
            && exception is SecurityTokenSignatureKeyNotFoundException)
        {
            Options.ConfigurationManager.RequestRefresh();
        }
    }

    private async Task<TokenValidationParameters> SetupTokenValidationParametersAsync()
    {
        // Clone to avoid cross request race conditions for updated configurations.
        var tokenValidationParameters = Options.TokenValidationParameters.Clone();
 
        // Options is JwtBearerOptions
        if (Options.ConfigurationManager is BaseConfigurationManager baseConfigurationManager)  // non-IdentityServer4 doesn't go this path, Options.ConfigurationManager is null
        {
            tokenValidationParameters.ConfigurationManager = baseConfigurationManager;
        }
        else
        {
            if (Options.ConfigurationManager != null)
            {
                // GetConfigurationAsync has a time interval that must pass before new http request will be issued.
                var configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);  // <--------------------------i1
                /* i1
                    1. ConfigurationManager.GetConfigurationAsync() invoke, which calls await _configRetriever.GetConfigurationAsync(_metadataAddress, _docRetriever, ...)
                       where _metadataAddress is "https://localhost:5005/.well-known/openid-configuration", 
                       and _docRetriever is OpenIdConnectConfigurationRetriever
                    
                    2. OpenIdConnectConfigurationRetriever.GetAsync(string address, IDocumentRetriever retriever, ...) invoke,  retriever is HttpDocumentRetriever
                    
                    3. HttpDocumentRetriever.GetDocumentAsync(string address, CancellationToken cancel) invoke which calls `var response = await httpClient.GetAsync(uri, cancel)`
                       this is how the the address is `opts.Authority = "https://localhost:5005"` is called

                    now the configuration contains the result from calling https://localhost:5005/.well-known/openid-configuration , full json, check i2:
                    
                    {
                        "issuer": "https://localhost:5005",
                        "scopes_supported": [
                            "movieAPI",
                            "offline_access"
                        ],
                        // ...
                    }
                    
                */
                var issuers = new[] { configuration.Issuer };
                tokenValidationParameters.ValidIssuers = (tokenValidationParameters.ValidIssuers == null ? issuers : tokenValidationParameters.ValidIssuers.Concat(issuers));
                tokenValidationParameters.IssuerSigningKeys = (tokenValidationParameters.IssuerSigningKeys == null ? configuration.SigningKeys : tokenValidationParameters.IssuerSigningKeys.Concat(configuration.SigningKeys));
            }
        }
 
        return tokenValidationParameters;
    }

    private static DateTime? GetSafeDateTime(DateTime dateTime)
    {
        // Assigning DateTime.MinValue or default(DateTime) to a DateTimeOffset when in a UTC+X timezone will throw
        // Since we don't really care about DateTime.MinValue in this case let's just set the field to null
        if (dateTime == DateTime.MinValue)
        {
            return null;
        }
        return dateTime;
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var authResult = await HandleAuthenticateOnceSafeAsync();
        var eventContext = new JwtBearerChallengeContext(Context, Scheme, Options, properties)
        {
            AuthenticateFailure = authResult?.Failure
        };
 
        // Avoid returning error=invalid_token if the error is not caused by an authentication failure (e.g missing token).
        if (Options.IncludeErrorDetails && eventContext.AuthenticateFailure != null)
        {
            eventContext.Error = "invalid_token";
            eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticateFailure);
        }
 
        await Events.Challenge(eventContext);
        if (eventContext.Handled)
        {
            return;
        }
 
        Response.StatusCode = 401;
 
        if (string.IsNullOrEmpty(eventContext.Error) &&
            string.IsNullOrEmpty(eventContext.ErrorDescription) &&
            string.IsNullOrEmpty(eventContext.ErrorUri))
        {
            Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
        }
        else
        {
            // https://tools.ietf.org/html/rfc6750#section-3.1
            // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
            var builder = new StringBuilder(Options.Challenge);
            if (Options.Challenge.IndexOf(' ') > 0)
            {
                // Only add a comma after the first param, if any
                builder.Append(',');
            }
            if (!string.IsNullOrEmpty(eventContext.Error))
            {
                builder.Append(" error=\"");
                builder.Append(eventContext.Error);
                builder.Append('\"');
            }
            if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
            {
                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(',');
                }
 
                builder.Append(" error_description=\"");
                builder.Append(eventContext.ErrorDescription);
                builder.Append('\"');
            }
            if (!string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                if (!string.IsNullOrEmpty(eventContext.Error) ||
                    !string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    builder.Append(',');
                }
 
                builder.Append(" error_uri=\"");
                builder.Append(eventContext.ErrorUri);
                builder.Append('\"');
            }
 
            Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
        }
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);
 
        if (Response.StatusCode == 403)
        {
            // No-op
        }
        else if (Response.HasStarted)
        {
            Logger.ForbiddenResponseHasStarted();
        }
        else
        {
            Response.StatusCode = 403;
        }
 
        return Events.Forbidden(forbiddenContext);
    }

    private static string CreateErrorDescription(Exception authFailure)
    {
        IReadOnlyCollection<Exception> exceptions;
        if (authFailure is AggregateException agEx)
        {
            exceptions = agEx.InnerExceptions;
        }
        else
        {
            exceptions = new[] { authFailure };
        }
 
        var messages = new List<string>(exceptions.Count);
 
        foreach (var ex in exceptions)
        {
            // Order sensitive, some of these exceptions derive from others
            // and we want to display the most specific message possible.
            string? message = ex switch
            {
                SecurityTokenInvalidAudienceException stia => $"The audience '{stia.InvalidAudience ?? "(null)"}' is invalid",
                SecurityTokenInvalidIssuerException stii => $"The issuer '{stii.InvalidIssuer ?? "(null)"}' is invalid",
                SecurityTokenNoExpirationException _ => "The token has no expiration",
                SecurityTokenInvalidLifetimeException stil => "The token lifetime is invalid; NotBefore: "
                    + $"'{stil.NotBefore?.ToString(CultureInfo.InvariantCulture) ?? "(null)"}'"
                    + $", Expires: '{stil.Expires?.ToString(CultureInfo.InvariantCulture) ?? "(null)"}'",
                SecurityTokenNotYetValidException stnyv => $"The token is not valid before '{stnyv.NotBefore.ToString(CultureInfo.InvariantCulture)}'",
                SecurityTokenExpiredException ste => $"The token expired at '{ste.Expires.ToString(CultureInfo.InvariantCulture)}'",
                SecurityTokenSignatureKeyNotFoundException _ => "The signature key was not found",
                SecurityTokenInvalidSignatureException _ => "The signature is invalid",
                _ => null,
            };
 
            if (message is not null)
            {
                messages.Add(message);
            }
        }
 
        return string.Join("; ", messages);
    }
}
//---------------------------Ʌ

//--------------------------V
public class JwtBearerEvents
{
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;
 
    public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;

    public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

    public Func<JwtBearerChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

    public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);
 
    public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);
 
    public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);
 
    public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

    public virtual Task Challenge(JwtBearerChallengeContext context) => OnChallenge(context);
}
//--------------------------Ʌ
```

```C#
//--------------------------------------V
public partial class JsonWebTokenHandler : TokenHandler
{
    private IDictionary<string, string> _inboundClaimTypeMap;
    private const string _namespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties";
    private static string _shortClaimType = _namespace + "/ShortTypeName";
    private bool _mapInboundClaims = DefaultMapInboundClaims;

    public static IDictionary<string, string> DefaultInboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.InboundClaimTypeMap);

    public static bool DefaultMapInboundClaims = false;

    public const string Base64UrlEncodedUnsignedJWSHeader = "eyJhbGciOiJub25lIn0";

    public JsonWebTokenHandler()
    {
        if (_mapInboundClaims)
            _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
        else
            _inboundClaimTypeMap = new Dictionary<string, string>();
    }

    public Type TokenType
    {
        get { return typeof(JsonWebToken); }
    }

    public static string ShortClaimTypeProperty
    {
        get
        {
            return _shortClaimType;
        }

        set
        {
            if (string.IsNullOrWhiteSpace(value))
                throw LogHelper.LogArgumentNullException(nameof(value));

            _shortClaimType = value;
        }
    }

    public bool MapInboundClaims
    {
        get
        {
            return _mapInboundClaims;
        }
        set
        {
            if (!_mapInboundClaims && value && _inboundClaimTypeMap.Count == 0)
                _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
            _mapInboundClaims = value;
        }
    }

    public IDictionary<string, string> InboundClaimTypeMap
    {
        get
        {
            return _inboundClaimTypeMap;
        }

        set
        {
            _inboundClaimTypeMap = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }
    }

    public virtual bool CanReadToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        if (token.Length > MaximumTokenSizeInBytes)
        {
            if (LogHelper.IsEnabled(EventLogLevel.Informational))
                LogHelper.LogInformation(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes));

            return false;
        }

        // Count the number of segments, which is the number of periods + 1. We can stop when we've encountered
        // more segments than the maximum we know how to handle.
        int pos = 0;
        int segmentCount = 1;
        while (segmentCount <= JwtConstants.MaxJwtSegmentCount && ((pos = token.IndexOf('.', pos)) >= 0))
        {
            pos++;
            segmentCount++;
        }

        switch (segmentCount)
        {
            case JwtConstants.JwsSegmentCount:
                return JwtTokenUtilities.RegexJws.IsMatch(token);

            case JwtConstants.JweSegmentCount:
                return JwtTokenUtilities.RegexJwe.IsMatch(token);

            default:
                LogHelper.LogInformation(LogMessages.IDX14107);
                return false;
        }
    }

    public virtual bool CanValidateToken
    {
        get { return true; }
    }

    private static StringComparison GetStringComparisonRuleIf509(SecurityKey securityKey) => (securityKey is X509SecurityKey)
                        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static StringComparison GetStringComparisonRuleIf509OrECDsa(SecurityKey securityKey) => (securityKey is X509SecurityKey
                        || securityKey is ECDsaSecurityKey)
                        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    protected virtual ClaimsIdentity CreateClaimsIdentity(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
    {
        _ = jwtToken ?? throw LogHelper.LogArgumentNullException(nameof(jwtToken));

        return CreateClaimsIdentityPrivate(jwtToken, validationParameters, GetActualIssuer(jwtToken));
    }

    protected virtual ClaimsIdentity CreateClaimsIdentity(JsonWebToken jwtToken, TokenValidationParameters validationParameters, string issuer)
    {
        _ = jwtToken ?? throw LogHelper.LogArgumentNullException(nameof(jwtToken));

        if (string.IsNullOrWhiteSpace(issuer))
            issuer = GetActualIssuer(jwtToken);

        if (MapInboundClaims)
            return CreateClaimsIdentityWithMapping(jwtToken, validationParameters, issuer);

        return CreateClaimsIdentityPrivate(jwtToken, validationParameters, issuer);
    }

    private ClaimsIdentity CreateClaimsIdentityWithMapping(JsonWebToken jwtToken, TokenValidationParameters validationParameters, string issuer)
    {
        _ = validationParameters ?? throw LogHelper.LogArgumentNullException(nameof(validationParameters));

        ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwtToken, issuer);
        foreach (Claim jwtClaim in jwtToken.Claims)
        {
            bool wasMapped = _inboundClaimTypeMap.TryGetValue(jwtClaim.Type, out string claimType);

            if (!wasMapped)
                claimType = jwtClaim.Type;

            if (claimType == ClaimTypes.Actor)
            {
                if (identity.Actor != null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(
                                LogMessages.IDX14112,
                                LogHelper.MarkAsNonPII(JwtRegisteredClaimNames.Actort),
                                jwtClaim.Value)));

                if (CanReadToken(jwtClaim.Value))
                {
                    JsonWebToken actor = ReadToken(jwtClaim.Value) as JsonWebToken;
                    identity.Actor = CreateClaimsIdentity(actor, validationParameters);
                }
            }

            if (wasMapped)
            {
                Claim claim = new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity);
                if (jwtClaim.Properties.Count > 0)
                {
                    foreach (var kv in jwtClaim.Properties)
                    {
                        claim.Properties[kv.Key] = kv.Value;
                    }
                }

                claim.Properties[ShortClaimTypeProperty] = jwtClaim.Type;
                identity.AddClaim(claim);
            }
            else
            {
                identity.AddClaim(jwtClaim);
            }
        }

        return identity;
    }

    internal override ClaimsIdentity CreateClaimsIdentityInternal(SecurityToken securityToken, TokenValidationParameters tokenValidationParameters, string issuer)
    {
        return CreateClaimsIdentity(securityToken as JsonWebToken, tokenValidationParameters, issuer);
    }

    private static string GetActualIssuer(JsonWebToken jwtToken)
    {
        string actualIssuer = jwtToken.Issuer;
        if (string.IsNullOrWhiteSpace(actualIssuer))
        {
            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                LogHelper.LogVerbose(TokenLogMessages.IDX10244, ClaimsIdentity.DefaultIssuer);

            actualIssuer = ClaimsIdentity.DefaultIssuer;
        }

        return actualIssuer;
    }

    private ClaimsIdentity CreateClaimsIdentityPrivate(JsonWebToken jwtToken, TokenValidationParameters validationParameters, string issuer)
    {
        _ = validationParameters ?? throw LogHelper.LogArgumentNullException(nameof(validationParameters));

        ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwtToken, issuer);
        foreach (Claim jwtClaim in jwtToken.Claims)
        {
            string claimType = jwtClaim.Type;
            if (claimType == ClaimTypes.Actor)
            {
                if (identity.Actor != null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX14112, LogHelper.MarkAsNonPII(JwtRegisteredClaimNames.Actort), jwtClaim.Value)));

                if (CanReadToken(jwtClaim.Value))
                {
                    JsonWebToken actor = ReadToken(jwtClaim.Value) as JsonWebToken;
                    identity.Actor = CreateClaimsIdentity(actor, validationParameters, issuer);
                }
            }

            if (jwtClaim.Properties.Count == 0)
            {
                identity.AddClaim(new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity));
            }
            else
            {
                Claim claim = new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity);

                foreach (var kv in jwtClaim.Properties)
                    claim.Properties[kv.Key] = kv.Value;

                identity.AddClaim(claim);
            }
        }

        return identity;
    }

    public string DecryptToken(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
    {
        return DecryptToken(jwtToken, validationParameters, null);
    }

    private string DecryptToken(JsonWebToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        if (jwtToken == null)
            throw LogHelper.LogArgumentNullException(nameof(jwtToken));

        if (validationParameters == null)
            throw LogHelper.LogArgumentNullException(nameof(validationParameters));

        if (string.IsNullOrEmpty(jwtToken.Enc))
            throw LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TokenLogMessages.IDX10612)));

        var keys = GetContentEncryptionKeys(jwtToken, validationParameters, configuration);
        return JwtTokenUtilities.DecryptJwtToken(
            jwtToken,
            validationParameters,
            new JwtTokenDecryptionParameters
            {
                DecompressionFunction = JwtTokenUtilities.DecompressToken,
                Keys = keys,
                MaximumDeflateSize = MaximumTokenSizeInBytes
            });
    }

    private static SecurityKey ResolveTokenDecryptionKeyFromConfig(JsonWebToken jwtToken, BaseConfiguration configuration)
    {
        if (jwtToken == null)
            throw LogHelper.LogArgumentNullException(nameof(jwtToken));

        if (!string.IsNullOrEmpty(jwtToken.Kid) && configuration.TokenDecryptionKeys != null)
        {
            foreach (var key in configuration.TokenDecryptionKeys)
            {
                if (key != null && string.Equals(key.KeyId, jwtToken.Kid, GetStringComparisonRuleIf509OrECDsa(key)))
                    return key;
            }
        }

        if (!string.IsNullOrEmpty(jwtToken.X5t) && configuration.TokenDecryptionKeys != null)
        {
            foreach (var key in configuration.TokenDecryptionKeys)
            {
                if (key != null && string.Equals(key.KeyId, jwtToken.X5t, GetStringComparisonRuleIf509(key)))
                    return key;

                var x509Key = key as X509SecurityKey;
                if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                    return key;
            }
        }

        return null;
    }

    protected virtual SecurityKey ResolveTokenDecryptionKey(string token, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
    {
        if (jwtToken == null)
            throw LogHelper.LogArgumentNullException(nameof(jwtToken));

        if (validationParameters == null)
            throw LogHelper.LogArgumentNullException(nameof(validationParameters));

        StringComparison stringComparison = GetStringComparisonRuleIf509OrECDsa(validationParameters.TokenDecryptionKey);
        if (!string.IsNullOrEmpty(jwtToken.Kid))
        {
            if (validationParameters.TokenDecryptionKey != null
                && string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.Kid, stringComparison))
                return validationParameters.TokenDecryptionKey;

            if (validationParameters.TokenDecryptionKeys != null)
            {
                foreach (var key in validationParameters.TokenDecryptionKeys)
                {
                    if (key != null && string.Equals(key.KeyId, jwtToken.Kid, GetStringComparisonRuleIf509OrECDsa(key)))
                        return key;
                }
            }
        }

        if (!string.IsNullOrEmpty(jwtToken.X5t))
        {
            if (validationParameters.TokenDecryptionKey != null)
            {
                if (string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.X5t, stringComparison))
                    return validationParameters.TokenDecryptionKey;

                var x509Key = validationParameters.TokenDecryptionKey as X509SecurityKey;
                if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                    return validationParameters.TokenDecryptionKey;
            }

            if (validationParameters.TokenDecryptionKeys != null)
            {
                foreach (var key in validationParameters.TokenDecryptionKeys)
                {
                    if (key != null && string.Equals(key.KeyId, jwtToken.X5t, GetStringComparisonRuleIf509(key)))
                        return key;

                    var x509Key = key as X509SecurityKey;
                    if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                        return key;
                }
            }
        }

        return null;
    }

    public virtual JsonWebToken ReadJsonWebToken(string token)
    {
        if (string.IsNullOrEmpty(token))
            throw LogHelper.LogArgumentNullException(nameof(token));

        if (token.Length > MaximumTokenSizeInBytes)
            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes))));

        return new JsonWebToken(token);
    }

    public override SecurityToken ReadToken(string token)
    {
        return ReadJsonWebToken(token);
    }
   
    public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
    {
        return ValidateTokenAsync(token, validationParameters).ConfigureAwait(false).GetAwaiter().GetResult();
    }

    public override async Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
    {
        if (string.IsNullOrEmpty(token))
            return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(token)), IsValid = false };

        if (validationParameters == null)
            return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

        if (token.Length > MaximumTokenSizeInBytes)
            return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)))), IsValid = false };

        try
        {
            TokenValidationResult result = ReadToken(token, validationParameters);
            if (result.IsValid)
                return await ValidateTokenAsync(result.SecurityToken, validationParameters).ConfigureAwait(false);

            return result;
        }
        catch (Exception ex)
        {
            return new TokenValidationResult
            {
                Exception = ex,
                IsValid = false
            };
        }
    }

    public override async Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token, TokenValidationParameters validationParameters)
    {
        if (token == null)
            throw LogHelper.LogArgumentNullException(nameof(token));

        if (validationParameters == null)
            return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

        var jwt = token as JsonWebToken;
        if (jwt == null)
            return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogMessages.IDX14100)), IsValid = false };

        try
        {
            return await ValidateTokenAsync(jwt, validationParameters).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new TokenValidationResult
            {
                Exception = ex,
                IsValid = false
            };
        }
    }

    private static TokenValidationResult ReadToken(string token, TokenValidationParameters validationParameters)
    {
        JsonWebToken jsonWebToken = null;
        if (validationParameters.TokenReader != null)
        {
            var securityToken = validationParameters.TokenReader(token, validationParameters);
            if (securityToken == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10510, LogHelper.MarkAsSecurityArtifact(token, JwtTokenUtilities.SafeLogJwtToken))));

            jsonWebToken = securityToken as JsonWebToken;
            if (jsonWebToken == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10509, typeof(JsonWebToken), securityToken.GetType(), LogHelper.MarkAsSecurityArtifact(token, JwtTokenUtilities.SafeLogJwtToken))));
        }
        else
        {
            try
            {
                jsonWebToken = new JsonWebToken(token);
            }
            catch (Exception ex)
            {
                return new TokenValidationResult
                {
                    Exception = LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogMessages.IDX14100, ex)),
                    IsValid = false
                };
            }
        }

        return new TokenValidationResult
        {
            SecurityToken = jsonWebToken,
            IsValid = true
        };
    }
>
    private async ValueTask<TokenValidationResult> ValidateTokenAsync(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters)
    {
        BaseConfiguration currentConfiguration = null;
        if (validationParameters.ConfigurationManager != null)
        {
            try
            {
                currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // The exception is not re-thrown as the TokenValidationParameters may have the issuer and signing key set
                // directly on them, allowing the library to continue with token validation.
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                    LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
            }
        }

        TokenValidationResult tokenValidationResult = await ValidateTokenAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false);
        if (validationParameters.ConfigurationManager != null)
        {
            if (tokenValidationResult.IsValid)
            {
                // Set current configuration as LKG if it exists.
                if (currentConfiguration != null)
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                return tokenValidationResult;
            }
            else if (TokenUtilities.IsRecoverableException(tokenValidationResult.Exception))
            {
                // If we were still unable to validate, attempt to refresh the configuration and validate using it
                // but ONLY if the currentConfiguration is not null. We want to avoid refreshing the configuration on
                // retrieval error as this case should have already been hit before. This refresh handles the case
                // where a new valid configuration was somehow published during validation time.
                if (currentConfiguration != null)
                {
                    validationParameters.ConfigurationManager.RequestRefresh();
                    validationParameters.RefreshBeforeValidation = true;
                    var lastConfig = currentConfiguration;
                    currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                    // Only try to re-validate using the newly obtained config if it doesn't reference equal the previously used configuration.
                    if (lastConfig != currentConfiguration)
                    {
                        tokenValidationResult = await ValidateTokenAsync(jsonWebToken, validationParameters, currentConfiguration).ConfigureAwait(false);

                        if (tokenValidationResult.IsValid)
                        {
                            validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;
                            return tokenValidationResult;
                        }
                    }
                }

                if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                {
                    validationParameters.RefreshBeforeValidation = false;
                    validationParameters.ValidateWithLKG = true;
                    var recoverableException = tokenValidationResult.Exception;

                    foreach (BaseConfiguration lkgConfiguration in validationParameters.ConfigurationManager.GetValidLkgConfigurations())
                    {
                        if (!lkgConfiguration.Equals(currentConfiguration) && TokenUtilities.IsRecoverableConfiguration(jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableException))
                        {
                            tokenValidationResult = await ValidateTokenAsync(jsonWebToken, validationParameters, lkgConfiguration).ConfigureAwait(false);

                            if (tokenValidationResult.IsValid)
                                return tokenValidationResult;
                        }
                    }
                }
            }
        }

        return tokenValidationResult;
    }

    private ValueTask<TokenValidationResult> ValidateTokenAsync(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        return jsonWebToken.IsEncrypted ?
            ValidateJWEAsync(jsonWebToken, validationParameters, configuration) :
            ValidateJWSAsync(jsonWebToken, validationParameters, configuration);
    }

    private async ValueTask<TokenValidationResult> ValidateJWSAsync(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        try
        {
            TokenValidationResult tokenValidationResult;
            if (validationParameters.TransformBeforeSignatureValidation != null)
                jsonWebToken = validationParameters.TransformBeforeSignatureValidation(jsonWebToken, validationParameters) as JsonWebToken;

            if (validationParameters.SignatureValidator != null || validationParameters.SignatureValidatorUsingConfiguration != null)
            {
                var validatedToken = ValidateSignatureUsingDelegates(jsonWebToken, validationParameters, configuration);
                tokenValidationResult = await ValidateTokenPayloadAsync(validatedToken, validationParameters, configuration).ConfigureAwait(false);
                Validators.ValidateIssuerSecurityKey(validatedToken.SigningKey, validatedToken, validationParameters, configuration);
            }
            else
            {
                if (validationParameters.ValidateSignatureLast)
                {
                    tokenValidationResult = await ValidateTokenPayloadAsync(jsonWebToken, validationParameters, configuration).ConfigureAwait(false);
                    if (tokenValidationResult.IsValid)
                        tokenValidationResult.SecurityToken = ValidateSignatureAndIssuerSecurityKey(jsonWebToken, validationParameters, configuration);
                }
                else
                {
                    var validatedToken = ValidateSignatureAndIssuerSecurityKey(jsonWebToken, validationParameters, configuration);
                    tokenValidationResult = await ValidateTokenPayloadAsync(validatedToken, validationParameters, configuration).ConfigureAwait(false);
                }
            }

            return tokenValidationResult;
        }
        catch (Exception ex)
        {
            return new TokenValidationResult
            {
                Exception = ex,
                IsValid = false,
                TokenOnFailedValidation = validationParameters.IncludeTokenOnFailedValidation ? jsonWebToken : null
            };
        }
    }

    private async ValueTask<TokenValidationResult> ValidateJWEAsync(JsonWebToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        try
        {
            TokenValidationResult tokenValidationResult = ReadToken(DecryptToken(jwtToken, validationParameters, configuration), validationParameters);
            if (!tokenValidationResult.IsValid)
                return tokenValidationResult;

            tokenValidationResult = await ValidateJWSAsync(tokenValidationResult.SecurityToken as JsonWebToken, validationParameters, configuration).ConfigureAwait(false);
            if (!tokenValidationResult.IsValid)
                return tokenValidationResult;

            jwtToken.InnerToken = tokenValidationResult.SecurityToken as JsonWebToken;
            jwtToken.Payload = (tokenValidationResult.SecurityToken as JsonWebToken).Payload;
            return new TokenValidationResult
            {
                SecurityToken = jwtToken,
                ClaimsIdentityNoLocking = tokenValidationResult.ClaimsIdentityNoLocking,
                IsValid = true,
                TokenType = tokenValidationResult.TokenType
            };
        }
        catch (Exception ex)
        {
            return new TokenValidationResult
            {
                Exception = ex,
                IsValid = false,
                TokenOnFailedValidation = validationParameters.IncludeTokenOnFailedValidation ? jwtToken : null
            };
        }
    }

    private static JsonWebToken ValidateSignatureUsingDelegates(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        if (validationParameters.SignatureValidatorUsingConfiguration != null)
        {
            var validatedToken = validationParameters.SignatureValidatorUsingConfiguration(jsonWebToken.EncodedToken, validationParameters, configuration);
            if (validatedToken == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, jsonWebToken)));

            if (!(validatedToken is JsonWebToken validatedJsonWebToken))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10506, LogHelper.MarkAsNonPII(typeof(JsonWebToken)), LogHelper.MarkAsNonPII(validatedToken.GetType()), jsonWebToken)));

            return validatedJsonWebToken;
        }
        else if (validationParameters.SignatureValidator != null)
        {
            var validatedToken = validationParameters.SignatureValidator(jsonWebToken.EncodedToken, validationParameters);
            if (validatedToken == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, jsonWebToken)));

            if (!(validatedToken is JsonWebToken validatedJsonWebToken))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10506, LogHelper.MarkAsNonPII(typeof(JsonWebToken)), LogHelper.MarkAsNonPII(validatedToken.GetType()), jsonWebToken)));

            return validatedJsonWebToken;
        }

        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, jsonWebToken)));
    }

    private static JsonWebToken ValidateSignatureAndIssuerSecurityKey(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        JsonWebToken validatedToken = ValidateSignature(jsonWebToken, validationParameters, configuration);
        Validators.ValidateIssuerSecurityKey(validatedToken.SigningKey, jsonWebToken, validationParameters, configuration);

        return validatedToken;
    }

    private async ValueTask<TokenValidationResult> ValidateTokenPayloadAsync(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        var expires = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Exp) ? (DateTime?)jsonWebToken.ValidTo : null;  // <----------------jwt's expiry time will be checked
        var notBefore = jsonWebToken.HasPayloadClaim(JwtRegisteredClaimNames.Nbf) ? (DateTime?)jsonWebToken.ValidFrom : null;

        Validators.ValidateLifetime(notBefore, expires, jsonWebToken, validationParameters);
        Validators.ValidateAudience(jsonWebToken.Audiences, jsonWebToken, validationParameters);
        string issuer = await Validators.ValidateIssuerAsync(jsonWebToken.Issuer, jsonWebToken, validationParameters, configuration).ConfigureAwait(false);

        Validators.ValidateTokenReplay(expires, jsonWebToken.EncodedToken, validationParameters);
        if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
        {
            // Infinite recursion should not occur here, as the JsonWebToken passed into this method is (1) constructed from a string
            // AND (2) the signature is successfully validated on it. (1) implies that even if there are nested actor tokens,
            // they must end at some point since they cannot reference one another. (2) means that the token has a valid signature
            // and (since issuer validation occurs first) came from a trusted authority.
            // NOTE: More than one nested actor token should not be considered a valid token, but if we somehow encounter one,
            // this code will still work properly.
            TokenValidationResult tokenValidationResult =
                await ValidateTokenAsync(jsonWebToken.Actor, validationParameters.ActorValidationParameters ?? validationParameters).ConfigureAwait(false);

            if (!tokenValidationResult.IsValid)
                return tokenValidationResult;
        }

        string tokenType = Validators.ValidateTokenType(jsonWebToken.Typ, jsonWebToken, validationParameters);
        return new TokenValidationResult(jsonWebToken, this, validationParameters.Clone(), issuer)
        {
            IsValid = true,
            TokenType = tokenType
        };
    }

    private static JsonWebToken ValidateSignature(JsonWebToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        bool kidMatched = false;
        IEnumerable<SecurityKey> keys = null;

        if (!jwtToken.IsSigned)
        {
            if (validationParameters.RequireSignedTokens)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10504, jwtToken)));
            else
                return jwtToken;
        }

        if (validationParameters.IssuerSigningKeyResolverUsingConfiguration != null)
        {
            keys = validationParameters.IssuerSigningKeyResolverUsingConfiguration(jwtToken.EncodedToken, jwtToken, jwtToken.Kid, validationParameters, configuration);
        }
        else if (validationParameters.IssuerSigningKeyResolver != null)
        {
            keys = validationParameters.IssuerSigningKeyResolver(jwtToken.EncodedToken, jwtToken, jwtToken.Kid, validationParameters);
        }
        else
        {
            var key = JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Kid, jwtToken.X5t, validationParameters, configuration);
            if (key != null)
            {
                kidMatched = true;
                keys = new List<SecurityKey> { key };
            }
        }

        if (validationParameters.TryAllIssuerSigningKeys && keys.IsNullOrEmpty())
        {
            // control gets here if:
            // 1. User specified delegate: IssuerSigningKeyResolver returned null
            // 2. ResolveIssuerSigningKey returned null
            // Try all the keys. This is the degenerate case, not concerned about perf.
            keys = TokenUtilities.GetAllSigningKeys(configuration, validationParameters);
        }

        // keep track of exceptions thrown, keys that were tried
        StringBuilder exceptionStrings = null;
        StringBuilder keysAttempted = null;
        var kidExists = !string.IsNullOrEmpty(jwtToken.Kid);

        if (keys != null)
        {
            foreach (var key in keys)
            {
                try
                {
                    if (ValidateSignature(jwtToken, key, validationParameters))
                    {
                        if (LogHelper.IsEnabled(EventLogLevel.Informational))
                            LogHelper.LogInformation(TokenLogMessages.IDX10242, jwtToken);

                        jwtToken.SigningKey = key;
                        return jwtToken;
                    }
                }
                catch (Exception ex)
                {
                    (exceptionStrings ??= new StringBuilder()).AppendLine(ex.ToString());
                }

                if (key != null)
                {
                    (keysAttempted ??= new StringBuilder()).Append(key.ToString()).Append(" , KeyId: ").AppendLine(key.KeyId);
                    if (kidExists && !kidMatched && key.KeyId != null)
                        kidMatched = jwtToken.Kid.Equals(key.KeyId, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                }
            }
        }

        // Get information on where keys used during token validation came from for debugging purposes.
        var keysInTokenValidationParameters = TokenUtilities.GetAllSigningKeys(validationParameters: validationParameters);
        var keysInConfiguration = TokenUtilities.GetAllSigningKeys(configuration);
        var numKeysInTokenValidationParameters = keysInTokenValidationParameters.Count();
        var numKeysInConfiguration = keysInConfiguration.Count();

        if (kidExists)
        {
            if (kidMatched)
            {
                JsonWebToken localJwtToken = jwtToken; // avoid closure on non-exceptional path
                var isKidInTVP = keysInTokenValidationParameters.Any(x => x.KeyId.Equals(localJwtToken.Kid));
                var keyLocation = isKidInTVP ? "TokenValidationParameters" : "Configuration";
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10511,
                    LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    LogHelper.MarkAsNonPII(keyLocation),
                    LogHelper.MarkAsNonPII(jwtToken.Kid),
                    (object)exceptionStrings ?? "",
                    jwtToken)));
            }

            if (!validationParameters.ValidateSignatureLast)
            {
                InternalValidators.ValidateAfterSignatureFailed(
                    jwtToken,
                    jwtToken.ValidFromNullable,
                    jwtToken.ValidToNullable,
                    jwtToken.Audiences,
                    validationParameters,
                    configuration);
            }
        }

        if (keysAttempted is not null)
        {
            if (kidExists)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10503,
                    LogHelper.MarkAsNonPII(jwtToken.Kid),
                    LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    (object)exceptionStrings ?? "",
                    jwtToken)));
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10517,
                    LogHelper.MarkAsNonPII((object)keysAttempted ?? ""),
                    LogHelper.MarkAsNonPII(numKeysInTokenValidationParameters),
                    LogHelper.MarkAsNonPII(numKeysInConfiguration),
                    (object)exceptionStrings ?? "",
                    jwtToken)));
            }
        }

        throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(TokenLogMessages.IDX10500));
    }

    internal static bool IsSignatureValid(byte[] signatureBytes, int signatureBytesLength, SignatureProvider signatureProvider, byte[] dataToVerify, int dataToVerifyLength)
    {
        if (signatureProvider is SymmetricSignatureProvider)
        {
            return signatureProvider.Verify(dataToVerify, 0, dataToVerifyLength, signatureBytes, 0, signatureBytesLength);
        }
        else
        {
            if (signatureBytes.Length == signatureBytesLength)
            {
                return signatureProvider.Verify(dataToVerify, 0, dataToVerifyLength, signatureBytes, 0, signatureBytesLength);
            }
            else
            {
                byte[] sigBytes = new byte[signatureBytesLength];
                Array.Copy(signatureBytes, 0, sigBytes, 0, signatureBytesLength);
                return signatureProvider.Verify(dataToVerify, 0, dataToVerifyLength, sigBytes, 0, signatureBytesLength);
            }
        }
    }

    internal static bool ValidateSignature(byte[] bytes, int len, string stringWithSignature, int signatureStartIndex, SignatureProvider signatureProvider)
    {
        return Base64UrlEncoding.Decode<bool, SignatureProvider, byte[], int>(
                stringWithSignature,
                signatureStartIndex + 1,
                stringWithSignature.Length - signatureStartIndex - 1,
                signatureProvider,
                bytes,
                len,
                IsSignatureValid);
    }

    internal static bool ValidateSignature(JsonWebToken jsonWebToken, SecurityKey key, TokenValidationParameters validationParameters)
    {
        var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
        if (!cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Alg, key))
        {
            if (LogHelper.IsEnabled(EventLogLevel.Informational))
                LogHelper.LogInformation(LogMessages.IDX14000, LogHelper.MarkAsNonPII(jsonWebToken.Alg), key);

            return false;
        }

        Validators.ValidateAlgorithm(jsonWebToken.Alg, key, jsonWebToken, validationParameters);
        var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, jsonWebToken.Alg);
        try
        {
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10636, key == null ? "Null" : key.ToString(), LogHelper.MarkAsNonPII(jsonWebToken.Alg))));

            return EncodingUtils.PerformEncodingDependentOperation<bool, string, int, SignatureProvider>(
                jsonWebToken.EncodedToken,
                0,
                jsonWebToken.Dot2,
                Encoding.UTF8,
                jsonWebToken.EncodedToken,
                jsonWebToken.Dot2,
                signatureProvider,
                ValidateSignature);
        }
        finally
        {
            cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
        }
    }
}
//--------------------------------------Ʌ
```

```C#
//----------------------------------------V
public class JwtBearerPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        if (string.IsNullOrEmpty(options.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.Audience))
        {
            options.TokenValidationParameters.ValidAudience = options.Audience;
        }
 
        if (options.ConfigurationManager == null)
        {
            if (options.Configuration != null)  // <---------------non IdentityServer4 doesn't go this path
            {
                options.ConfigurationManager 
                    =  new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration); // <-------StaticConfigurationManager inherits BaseConfigurationManager
                                                                                                                                
            }
            else if (!(string.IsNullOrEmpty(options.MetadataAddress) && string.IsNullOrEmpty(options.Authority)))  // <---------------IdentityServer4 goes this path
            {
                if (string.IsNullOrEmpty(options.MetadataAddress) && !string.IsNullOrEmpty(options.Authority))
                {
                    options.MetadataAddress = options.Authority;
                    if (!options.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
                    {
                        options.MetadataAddress += "/";
                    }
 
                    options.MetadataAddress += ".well-known/openid-configuration";  // <---------------------------------
                }
 
                if (options.RequireHttpsMetadata && !options.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
                }
 
                if (options.Backchannel == null)
                {
                    options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                    options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core JwtBearer handler");
                    options.Backchannel.Timeout = options.BackchannelTimeout;
                    options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
                }
 
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(options.Backchannel) { RequireHttps = options.RequireHttpsMetadata })
                {
                    RefreshInterval = options.RefreshInterval,
                    AutomaticRefreshInterval = options.AutomaticRefreshInterval,
                };
            }
        }
    }
}
//----------------------------------------Ʌ
```

```C#
//----------------------------------V
public abstract class TokenHandler
{
    private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
    private int _maximumTokenSizeInBytes = 256000;
    public static readonly int DefaultTokenLifetimeInMinutes = 60;
    public virtual int MaximumTokenSizeInBytes => _=> { get; set; };  //maximumTokenSizeInBytes;
    public bool SetDefaultTimesOnTokenCreation { get; set; } = true;
    public int TokenLifetimeInMinutes => { get; set; }  // on _defaultTokenLifetimeInMinutes
}

public interface ISecurityTokenValidator
{
    bool CanValidateToken { get; }
    int MaximumTokenSizeInBytes { get; set; }
    bool CanReadToken(string securityToken);
    ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken);
}
//----------------------------------Ʌ

//----------------------------------------V
public abstract class SecurityTokenHandler : TokenHandler, ISecurityTokenValidator
{
    protected SecurityTokenHandler() { }

    public virtual SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached) => throw new NotImplementedException();
    
    public virtual SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor) => throw new NotImplementedException();
    
    public virtual bool CanValidateToken => false;
    public virtual bool CanWriteToken => false;
    public abstract Type TokenType { get; }

    public virtual bool CanReadToken(XmlReader reader) => false;
    public virtual bool CanReadToken(string tokenString) => false; 
    public virtual SecurityToken ReadToken(XmlReader reader) => null;
    public virtual string WriteToken(SecurityToken token)  => null;

    public abstract void WriteToken(XmlWriter writer, SecurityToken token);
    public abstract SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters);

    public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        => throw new NotImplementedException();

    public virtual ClaimsPrincipal ValidateToken(XmlReader reader, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        => throw new NotImplementedException();
}
//----------------------------------------Ʌ

//----------------------------------V
public class JwtSecurityTokenHandler : SecurityTokenHandler
{
    // ...
    public override bool CanReadToken(string token);
    public override bool CanValidateToken => true;
    public override bool CanWriteToken => true;

    public override Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
    {
        var claimsPrincipal = ValidateToken(token, validationParameters, out var validatedToken);
        
        return Task.FromResult(new TokenValidationResult
        {
            SecurityToken = validatedToken,
            ClaimsIdentity = claimsPrincipal?.Identity as ClaimsIdentity,
            IsValid = true,
        });
    }

    public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
    {
        int tokenPartCount = JwtTokenUtilities.CountJwtTokenPart(token, JwtConstants.MaxJwtSegmentCount + 1);

        if (tokenPartCount == JwtConstants.JweSegmentCount)
        {
            var jwtToken = ReadJwtToken(token);
            var decryptedJwt = DecryptToken(jwtToken, validationParameters);
            return ValidateToken(decryptedJwt, jwtToken, validationParameters, out validatedToken);
        }
        else
        {
            return ValidateToken(token, null, validationParameters, out validatedToken);
        }
    }

    private ClaimsPrincipal ValidateToken(string token, JwtSecurityToken outerToken, TokenValidationParameters validationParameters, out SecurityToken signatureValidatedToken)
    {
        // return the claimsPrincipal by using private methods such as ValidateJWE, ValidateJWS                             
    }
}
//----------------------------------Ʌ

//-------------------------------------->>
public interface IConfigurationManager<T> where T : class
{
    Task<T> GetConfigurationAsync(CancellationToken cancel);    
    void RequestRefresh();
}
//--------------------------------------<<


//--------------------------------------------V
public abstract class BaseConfigurationManager
{
    private TimeSpan _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
    private TimeSpan _refreshInterval = DefaultRefreshInterval;
    private TimeSpan _lastKnownGoodLifetime = DefaultLastKnownGoodConfigurationLifetime;
    private BaseConfiguration _lastKnownGoodConfiguration;
    private DateTime? _lastKnownGoodConfigFirstUse = null;

    internal EventBasedLRUCache<BaseConfiguration, DateTime> _lastKnownGoodConfigurationCache;

    /// <summary>
    /// Gets or sets the <see cref="TimeSpan"/> that controls how often an automatic metadata refresh should occur.
    /// </summary>
    public TimeSpan AutomaticRefreshInterval
    {
        get { return _automaticRefreshInterval; }
        set
        {
            if (value < MinimumAutomaticRefreshInterval)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), LogHelper.FormatInvariant(LogMessages.IDX10108, LogHelper.MarkAsNonPII(MinimumAutomaticRefreshInterval), LogHelper.MarkAsNonPII(value))));

            _automaticRefreshInterval = value;
        }
    }

    public static readonly TimeSpan DefaultAutomaticRefreshInterval = new TimeSpan(0, 12, 0, 0);

    public static readonly TimeSpan DefaultLastKnownGoodConfigurationLifetime = new TimeSpan(0, 1, 0, 0);

    public static readonly TimeSpan DefaultRefreshInterval = new TimeSpan(0, 0, 5, 0);

    public BaseConfigurationManager()
        : this(new LKGConfigurationCacheOptions())
    {
    }

    public BaseConfigurationManager(LKGConfigurationCacheOptions options)
    {
        if (options == null)
            throw LogHelper.LogArgumentNullException(nameof(options));

        _lastKnownGoodConfigurationCache = new EventBasedLRUCache<BaseConfiguration, DateTime>(
            options.LastKnownGoodConfigurationSizeLimit,
            options.TaskCreationOptions,
            options.BaseConfigurationComparer,
            options.RemoveExpiredValues);
    }

    public virtual Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
    {
        throw  new NotImplementedException(...);
    }

    internal BaseConfiguration[] GetValidLkgConfigurations()
    {
        return _lastKnownGoodConfigurationCache.ToArray().Where(x => x.Value.Value > DateTime.UtcNow).Select(x => x.Key).ToArray();
    }

    public BaseConfiguration LastKnownGoodConfiguration
    {
        get {
            return _lastKnownGoodConfiguration;
        }
        set
        {
            _lastKnownGoodConfiguration = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
            _lastKnownGoodConfigFirstUse = DateTime.UtcNow;

            // LRU cache will remove the expired configuration
            _lastKnownGoodConfigurationCache.SetValue(_lastKnownGoodConfiguration, DateTime.UtcNow + LastKnownGoodLifetime, DateTime.UtcNow + LastKnownGoodLifetime);
        }
    }

    public TimeSpan LastKnownGoodLifetime => { get; set; };  // on _lastKnownGoodLifetime
   
    public string MetadataAddress { get; set; }

    public static readonly TimeSpan MinimumAutomaticRefreshInterval = new TimeSpan(0, 0, 5, 0);

    public static readonly TimeSpan MinimumRefreshInterval = new TimeSpan(0, 0, 0, 1);

    public TimeSpan RefreshInterval => { get; set; };  // on _refreshInterval
    
    public bool UseLastKnownGoodConfiguration { get; set; } = true;

    public bool IsLastKnownGoodValid => _lastKnownGoodConfiguration != null && (_lastKnownGoodConfigFirstUse == null || DateTime.UtcNow < _lastKnownGoodConfigFirstUse + LastKnownGoodLifetime);

    public abstract void RequestRefresh();
}
//--------------------------------------------Ʌ

//----------------------------------V
public class ConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T> where T : class
{
    private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;
    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
    private bool _isFirstRefreshRequest = true;

    private readonly SemaphoreSlim _refreshLock;
    private readonly IDocumentRetriever _docRetriever;
    private readonly IConfigurationRetriever<T> _configRetriever;
    private readonly IConfigurationValidator<T> _configValidator;
    private T _currentConfiguration;
    private Exception _fetchMetadataFailure;
    private TimeSpan _bootstrapRefreshInterval = TimeSpan.FromSeconds(1);
 
    public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
        : base(lkgCacheOptions)
    {
        MetadataAddress = metadataAddress;
        _docRetriever = docRetriever;
        _configRetriever = configRetriever;
        _refreshLock = new SemaphoreSlim(1);
    }

    public async Task<T> GetConfigurationAsync()
    {
        return await GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
    }

    public async Task<T> GetConfigurationAsync(CancellationToken cancel)
    {
        if (_currentConfiguration != null && _syncAfter > DateTimeOffset.UtcNow)
        {
            return _currentConfiguration;
        }

        await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);
        try
        {
            if (_syncAfter <= DateTimeOffset.UtcNow)
            {
                try
                {
                    var configuration = await _configRetriever.GetConfigurationAsync(MetadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);
                    if (_configValidator != null)
                    {
                        ConfigurationValidationResult result = _configValidator.Validate(configuration);
                        if (!result.Succeeded)
                            throw LogHelper.LogExceptionMessage(new InvalidConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, result.ErrorMessage)));
                    }

                    _lastRefresh = DateTimeOffset.UtcNow;
                    // Add a random amount between 0 and 5% of AutomaticRefreshInterval jitter to avoid spike traffic to IdentityProvider.
                    _syncAfter = DateTimeUtil.Add(DateTime.UtcNow, AutomaticRefreshInterval + TimeSpan.FromSeconds(new Random().Next((int)AutomaticRefreshInterval.TotalSeconds / 20)));
                    _currentConfiguration = configuration;
                }
                catch (Exception ex)
                {
                   // ...
                }
            }

            // Stale metadata is better than no metadata
            if (_currentConfiguration != null)
                return _currentConfiguration;
            else
               throw ...;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public override async Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
    {
        var obj = await GetConfigurationAsync(cancel).ConfigureAwait(false);
        if (obj is BaseConfiguration)
            return obj as BaseConfiguration;
        return null;
    }

    public override void RequestRefresh()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (_isFirstRefreshRequest)
        {
            _syncAfter = now;
            _isFirstRefreshRequest = false;
        }
        else if (now >= DateTimeUtil.Add(_lastRefresh.UtcDateTime, RefreshInterval))
        {
            _syncAfter = now;
        }
    }

    public new static readonly TimeSpan DefaultAutomaticRefreshInterval = BaseConfigurationManager.DefaultAutomaticRefreshInterval;
    public new static readonly TimeSpan DefaultRefreshInterval = BaseConfigurationManager.DefaultRefreshInterval;
    public new static readonly TimeSpan MinimumAutomaticRefreshInterval = BaseConfigurationManager.MinimumAutomaticRefreshInterval;
    public new static readonly TimeSpan MinimumRefreshInterval = BaseConfigurationManager.MinimumRefreshInterval;
}
//----------------------------------Ʌ

//--------------------------------V
public class HttpDocumentRetriever : IDocumentRetriever
{
    private HttpClient _httpClient;
    private static readonly HttpClient _defaultHttpClient = new HttpClient();

    public const string StatusCode = "status_code";
    public const string ResponseContent = "response_content";
    public static bool DefaultSendAdditionalHeaderData { get; set; } = true;

    private bool _sendAdditionalHeaderData = DefaultSendAdditionalHeaderData;

    public bool SendAdditionalHeaderData { get; set; } = true;  // on _sendAdditionalHeaderData
    
    internal IDictionary<string, string> AdditionalHeaderData { get; set; }

    public HttpDocumentRetriever() { }

    public HttpDocumentRetriever(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public bool RequireHttps { get; set; } = true;

    public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
    {       
        // ...
        try
        {
            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
                LogHelper.LogVerbose(LogMessages.IDX20805, address);

            var httpClient = _httpClient ?? _defaultHttpClient;
            var uri = new Uri(address, UriKind.RelativeOrAbsolute);
            response = await SendAndRetryOnNetworkErrorAsync(httpClient, uri).ConfigureAwait(false);

            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
                return responseContent;      
        } 
        // ...
    }

    private async Task<HttpResponseMessage> SendAndRetryOnNetworkErrorAsync(HttpClient httpClient, Uri uri);
}
//--------------------------------Ʌ

//----------------------------------------------V
public class OpenIdConnectConfigurationRetriever : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    public static Task<OpenIdConnectConfiguration> GetAsync(string address, CancellationToken cancel)
    {
        return GetAsync(address, new HttpDocumentRetriever(), cancel);
    }

    public static Task<OpenIdConnectConfiguration> GetAsync(string address, HttpClient httpClient, CancellationToken cancel)
    {
        return GetAsync(address, new HttpDocumentRetriever(httpClient), cancel);
    }

    Task<OpenIdConnectConfiguration> IConfigurationRetriever<OpenIdConnectConfiguration>.GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        return GetAsync(address, retriever, cancel);
    }

    public static async Task<OpenIdConnectConfiguration> GetAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        string doc = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);

        OpenIdConnectConfiguration openIdConnectConfiguration = OpenIdConnectConfigurationSerializer.Read(doc);
        if (!string.IsNullOrEmpty(openIdConnectConfiguration.JwksUri))
        {
            string keys = await retriever.GetDocumentAsync(openIdConnectConfiguration.JwksUri, cancel).ConfigureAwait(false);

            openIdConnectConfiguration.JsonWebKeySet = new JsonWebKeySet(keys);
            foreach (SecurityKey key in openIdConnectConfiguration.JsonWebKeySet.GetSigningKeys())
            {
                openIdConnectConfiguration.SigningKeys.Add(key);
            }
        }

        return openIdConnectConfiguration;
    }
}
//----------------------------------------------Ʌ
```

