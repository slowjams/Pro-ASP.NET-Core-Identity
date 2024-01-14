## .NET Identity Source Code

* CookieAuthenticationHandler

* JwtBearer


#### Cookie Authentication-----------------------------------------------------------------------------------------------------------------------V

When user signs in (or is signed in using for example OpenIdConnect) or simply by calling `HttpContext.Authentication.SignInAsync`, a ticket (`AuthenticationTicket`), containing specified claims, properties and some more info is created, serialized, encrypted, split into multiple cookies and sent to the client.

When a ticket `AuthenticationTicket` is serialized and encrypted, it is then by default passed into `ChunkingCookieManager` which then splits the encrypted and serialized ticket into multiple parts (chunks, each is a single cookie) so we don’t hit the cookie limits in browsers and appends it as a cookie to the response.

`CookieAuthenticationOptions` have a property called `SessionStore`. It allows you to implement `ITicketStore` interface and then stores the actual ticket into it while sending only a "session id" to the client in an encrypted cookie.

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {      
        services.AddAuthentication(opts => {  // opts is AuthenticationOptions
            opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;   // DefaultScheme is ""Cookies"
        }).AddCookie(opts => {
            opts.LoginPath = "/signin";
            opts.AccessDeniedPath = "/signin/403";
        });

        // ...
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseRouting();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => {
           // ...
        });
    }
}
//------------------Ʌ
```

```C#
//----------------------------------------------<<
public static class CookieAuthenticationDefaults
{
   public const string AuthenticationScheme = "Cookies";
   public static readonly string CookiePrefix = ".AspNetCore.";
   public static readonly PathString LoginPath = new PathString("/Account/Login");  // <------------------------
   public static readonly PathString LogoutPath = new PathString("/Account/Logout");
   public static readonly PathString AccessDeniedPath = new PathString("/Account/AccessDenied");
   public static readonly string ReturnUrlParameter = "ReturnUrl";
}
//---------------------------------------------->>

//--------------------------------------V
public class CookieAuthenticationOptions : AuthenticationSchemeOptions
{
   private CookieBuilder _cookieBuilder = new RequestPathBaseCookieBuilder
   {
      // the default name is configured in PostConfigureCookieAuthenticationOptions
 
      // To support OAuth authentication, a lax mode is required, see https://github.com/aspnet/Security/issues/1231.
      SameSite = SameSiteMode.Lax,
      HttpOnly = true,
      SecurePolicy = CookieSecurePolicy.SameAsRequest,
      IsEssential = true,
   };

   public CookieAuthenticationOptions()
   {
      ExpireTimeSpan = TimeSpan.FromDays(14);  // <---------------------------------so default expire time is two weeks
      ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;   // <----------------------------------------
      SlidingExpiration = true;
      Events = new CookieAuthenticationEvents();
   }

   public CookieBuilder Cookie
   {
      get => _cookieBuilder;
      set => _cookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
   }

   public IDataProtectionProvider? DataProtectionProvider { get; set; }
   public bool SlidingExpiration { get; set; }
   public PathString LoginPath { get; set; }
   public PathString LogoutPath { get; set; }
   public PathString AccessDeniedPath { get; set; }
   public string ReturnUrlParameter { get; set; }

   public new CookieAuthenticationEvents Events
   {
      get => (CookieAuthenticationEvents)base.Events!;
      set => base.Events = value;
   }

   public ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; set; } = default!;
   public ICookieManager CookieManager { get; set; } = default!;   // ChunkingCookieManager will be used as default
   public ITicketStore? SessionStore { get; set; }  // <------------------------------
   public TimeSpan ExpireTimeSpan { get; set; }
}
//--------------------------------------Ʌ
```

```C#
//----------------------------------V
public static class CookieExtensions
{
   public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, Action<CookieAuthenticationOptions> configureOptions)
      => builder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, configureOptions);    
   // ...
   public static AuthenticationBuilder AddCookie(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<CookieAuthenticationOptions> configureOptions)
   {
      builder.Services
          .TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureCookieAuthenticationOptions>());
      
      builder.Services.   // <--------------------authenticationScheme will be used as "cookie name" check PostConfigureCookieAuthenticationOptions
          AddOptions<CookieAuthenticationOptions>(authenticationScheme).Validate(o => o.Cookie.Expiration == null, "Cookie.Expiration is ignored, ...");

      return builder.AddScheme<CookieAuthenticationOptions, CookieAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
   }
}
//----------------------------------Ʌ

//--------------------------------------V
public class CookieAuthenticationHandler : SignInAuthenticationHandler<CookieAuthenticationOptions>
{
   private const string HeaderValueNoCache = "no-cache";
   private const string HeaderValueNoCacheNoStore = "no-cache,no-store";
   private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";
   private const string SessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
 
   private bool _shouldRefresh;
   private bool _signInCalled;
   private bool _signOutCalled;
 
   private DateTimeOffset? _refreshIssuedUtc;
   private DateTimeOffset? _refreshExpiresUtc;
   private string? _sessionKey;
   private Task<AuthenticateResult>? _readCookieTask;
   private AuthenticationTicket? _refreshTicket;

   public CookieAuthenticationHandler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

   protected new CookieAuthenticationEvents Events
   {
      get { return (CookieAuthenticationEvents)base.Events!; }
      set { base.Events = value; }
   }

   protected override Task InitializeHandlerAsync()
   {
      // Cookies needs to finish the response
      Context.Response.OnStarting(FinishResponseAsync);
      return Task.CompletedTask;
   }

   protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new CookieAuthenticationEvents());

   private Task<AuthenticateResult> EnsureCookieTicket()
   {
      // We only need to read the ticket once
      if (_readCookieTask == null)
      {
         _readCookieTask = ReadCookieTicket();
      }
      return _readCookieTask;
   }

   private async Task CheckForRefreshAsync(AuthenticationTicket ticket)
   {
      var currentUtc = TimeProvider.GetUtcNow();
      var issuedUtc = ticket.Properties.IssuedUtc;
      var expiresUtc = ticket.Properties.ExpiresUtc;
      var allowRefresh = ticket.Properties.AllowRefresh ?? true;
      if (issuedUtc != null && expiresUtc != null && Options.SlidingExpiration && allowRefresh)
      {
         var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
         var timeRemaining = expiresUtc.Value.Subtract(currentUtc);
 
         var eventContext = new CookieSlidingExpirationContext(Context, Scheme, Options, ticket, timeElapsed, timeRemaining)
         {
            ShouldRenew = timeRemaining < timeElapsed,
         };
         await Events.CheckSlidingExpiration(eventContext);
 
         if (eventContext.ShouldRenew)
         {
            RequestRefresh(ticket);
         }
      }
   }

   private void RequestRefresh(AuthenticationTicket ticket, ClaimsPrincipal? replacedPrincipal = null)
   {
      var issuedUtc = ticket.Properties.IssuedUtc;
      var expiresUtc = ticket.Properties.ExpiresUtc;
 
      if (issuedUtc != null && expiresUtc != null)
      {
         _shouldRefresh = true;
         var currentUtc = TimeProvider.GetUtcNow();
         _refreshIssuedUtc = currentUtc;
         var timeSpan = expiresUtc.Value.Subtract(issuedUtc.Value);
         _refreshExpiresUtc = currentUtc.Add(timeSpan);
         _refreshTicket = CloneTicket(ticket, replacedPrincipal);
      }
   }

   private static AuthenticationTicket CloneTicket(AuthenticationTicket ticket, ClaimsPrincipal? replacedPrincipal)
   {
      var principal = replacedPrincipal ?? ticket.Principal;
      var newPrincipal = new ClaimsPrincipal();
      foreach (var identity in principal.Identities)
      {
         newPrincipal.AddIdentity(identity.Clone());
      }
 
      var newProperties = new AuthenticationProperties();
      foreach (var item in ticket.Properties.Items)
      {
         newProperties.Items[item.Key] = item.Value;
      }
 
      return new AuthenticationTicket(newPrincipal, newProperties, ticket.AuthenticationScheme);
   }

   private async Task<AuthenticateResult> ReadCookieTicket()
   {
      var cookie = Options.CookieManager.GetRequestCookie(Context, Options.Cookie.Name!);  // <--------------------------------------------
                                                                                           // Options.Cookie.Name make the reading of cookie that's assoicated with the scheme
      if (string.IsNullOrEmpty(cookie)) 
         return AuthenticateResult.NoResult();
 
      AuthenticationTicket ticket = Options.TicketDataFormat.Unprotect(cookie, GetTlsTokenBinding());  // <----------------retireve ticket from cookie
      
      if (ticket == null) 
          return AuthenticateResults.FailedUnprotectingTicket;
 
      if (Options.SessionStore != null)
      {
         var claim = ticket.Principal.Claims.FirstOrDefault(c => c.Type.Equals(SessionIdClaim));
         if (claim == null)
         {
            return AuthenticateResults.MissingSessionId;
         }
         // Only store _sessionKey if it matches an existing session. Otherwise we'll create a new one.
         ticket = await Options.SessionStore.RetrieveAsync(claim.Value, Context, Context.RequestAborted);
         if (ticket == null)
         {
            return AuthenticateResults.MissingIdentityInSession;
         }
         _sessionKey = claim.Value;
      }
 
      var currentUtc = TimeProvider.GetUtcNow();
      var expiresUtc = ticket.Properties.ExpiresUtc;
 
      if (expiresUtc != null && expiresUtc.Value < currentUtc)
      {
         if (Options.SessionStore != null)
         {
            await Options.SessionStore.RemoveAsync(_sessionKey!, Context, Context.RequestAborted);
 
            // Clear out the session key if its expired, so renew doesn't try to use it
            _sessionKey = null;
         }
         return AuthenticateResults.ExpiredTicket;
      }
 
      // Finally we have a valid ticket
      return AuthenticateResult.Success(ticket);
   }

   protected override async Task<AuthenticateResult> HandleAuthenticateAsync()  // <----------------invoke for a non-SignIn requests to read cookies sent from client to server
   {                                                                            // note that this method will still be invoked for SignIn request because of the redirection
      var result = await EnsureCookieTicket();
      if (!result.Succeeded)
      {
         return result;
      }
 
      // We check this before the ValidatePrincipal event because we want to make sure we capture a clean clone
      // without picking up any per-request modifications to the principal.
      await CheckForRefreshAsync(result.Ticket);
 
      var context = new CookieValidatePrincipalContext(Context, Scheme, Options, result.Ticket);
      await Events.ValidatePrincipal(context);
 
      if (context.Principal == null)
      {
         return AuthenticateResults.NoPrincipal;
      }
 
      if (context.ShouldRenew)
      {
         RequestRefresh(result.Ticket, context.Principal);
      }
 
      return AuthenticateResult.Success(new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name));
   }

   private CookieOptions BuildCookieOptions()
   {
      var cookieOptions = Options.Cookie.Build(Context);
      // ignore the 'Expires' value as this will be computed elsewhere
      cookieOptions.Expires = null;
 
      return cookieOptions;
   }

   protected virtual async Task FinishResponseAsync()
   {
      // Only renew if requested, and neither sign in or sign out was called
      if (!_shouldRefresh || _signInCalled || _signOutCalled)
      {
         return;
      }
 
      var ticket = _refreshTicket;
      if (ticket != null)
      {
         var properties = ticket.Properties;
 
         if (_refreshIssuedUtc.HasValue)
         {
            properties.IssuedUtc = _refreshIssuedUtc;
         }
 
         if (_refreshExpiresUtc.HasValue)
         {
            properties.ExpiresUtc = _refreshExpiresUtc;
         }
 
         if (Options.SessionStore != null && _sessionKey != null)
         {
            await Options.SessionStore.RenewAsync(_sessionKey, ticket, Context, Context.RequestAborted);
            var principal = new ClaimsPrincipal(
               new ClaimsIdentity( new[] { new Claim(SessionIdClaim, _sessionKey, ClaimValueTypes.String, Options.ClaimsIssuer) }, Scheme.Name));
            ticket = new AuthenticationTicket(principal, null, Scheme.Name);
         }
 
         var cookieValue = Options.TicketDataFormat.Protect(ticket, GetTlsTokenBinding());
 
         var cookieOptions = BuildCookieOptions();
         if (properties.IsPersistent && _refreshExpiresUtc.HasValue)
         {
            cookieOptions.Expires = _refreshExpiresUtc.Value.ToUniversalTime();
         }
 
         Options.CookieManager.AppendResponseCookie(Context, Options.Cookie.Name!, cookieValue, cookieOptions);
 
         await ApplyHeaders(shouldRedirect: false, shouldHonorReturnUrlParameter: false, properties: properties);
      }    
   }

   protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)  // invoke for SignIn requests to serializate AuthenticationTicket
   {                                                                                                            // into cookies, note that the ticket contians ClaimsPrincipal
      properties = properties ?? new AuthenticationProperties();
 
      _signInCalled = true;
 
      // Process the request cookie to initialize members like _sessionKey.
      await EnsureCookieTicket();
      var cookieOptions = BuildCookieOptions();
 
      var signInContext = new CookieSigningInContext(Context, Scheme, Options, user, properties, cookieOptions);
 
      DateTimeOffset issuedUtc;
      if (signInContext.Properties.IssuedUtc.HasValue)
      {
         issuedUtc = signInContext.Properties.IssuedUtc.Value;
      }
      else
      {
         issuedUtc = TimeProvider.GetUtcNow();
         signInContext.Properties.IssuedUtc = issuedUtc;  // <-----------add an entry [.issued, 01 Jan 2024 02:00:46] to AuthenticationProperties.Items 
      }
 
      if (!signInContext.Properties.ExpiresUtc.HasValue)
      {
         signInContext.Properties.ExpiresUtc = issuedUtc.Add(Options.ExpireTimeSpan); // <---------add an entry [.expires, 15 Jan 2024 02:00:46] to AuthenticationProperties.Items 
      }
 
      await Events.SigningIn(signInContext);
 
      if (signInContext.Properties.IsPersistent)
      {
         var expiresUtc = signInContext.Properties.ExpiresUtc ?? issuedUtc.Add(Options.ExpireTimeSpan);
         signInContext.CookieOptions.Expires = expiresUtc.ToUniversalTime();
 
      var ticket = new AuthenticationTicket(signInContext.Principal!, 
                                            signInContext.Properties,  // AuthenticationProperties htat contains .redirect, .issued .expires etc are baked into ticket
                                            signInContext.Scheme.Name);
 
      if (Options.SessionStore != null)
      {
         if (_sessionKey != null)
         {
            // Renew the ticket in cases of multiple requests see: https://github.com/dotnet/aspnetcore/issues/22135
            await Options.SessionStore.RenewAsync(_sessionKey, ticket, Context, Context.RequestAborted);
         }
         else
         {
            _sessionKey = await Options.SessionStore.StoreAsync(ticket, Context, Context.RequestAborted);
         }
 
         var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
            new[] { new Claim(SessionIdClaim, _sessionKey, ClaimValueTypes.String, Options.ClaimsIssuer) },
            Options.ClaimsIssuer));
            
         ticket = new AuthenticationTicket(principal, null, Scheme.Name);
      }
 
      var cookieValue = Options.TicketDataFormat.Protect(ticket, GetTlsTokenBinding());  // <------------------serilize the AuthenticationTicket into cookie string value
 
      Options.CookieManager.AppendResponseCookie(   // <---------------------------------------------------------------append cookie
         Context,
         Options.Cookie.Name!,  // Name can be IdentityConstants.TwoFactorUserIdScheme etc, so that cookies will be assoicated to the Name
         cookieValue,  // <-----------------------------cookieValue contains the AuthenticationTicket
         signInContext.CookieOptions);
 
      var signedInContext = new CookieSignedInContext(
         Context,
         Scheme,
         signInContext.Principal!,
         signInContext.Properties,
         Options);
 
      await Events.SignedIn(signedInContext);
 
      // Only honor the ReturnUrl query string parameter on the login path
      var shouldHonorReturnUrlParameter = Options.LoginPath.HasValue && OriginalPath == Options.LoginPath;
      await ApplyHeaders(shouldRedirect: true, shouldHonorReturnUrlParameter, signedInContext.Properties);
 
      Logger.AuthenticationSchemeSignedIn(Scheme.Name);
   }

   protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
   {
      properties = properties ?? new AuthenticationProperties();
 
      _signOutCalled = true;
 
      // Process the request cookie to initialize members like _sessionKey.
      await EnsureCookieTicket();
      var cookieOptions = BuildCookieOptions();
      if (Options.SessionStore != null && _sessionKey != null)
      {
         await Options.SessionStore.RemoveAsync(_sessionKey, Context, Context.RequestAborted);
      }
 
      var context = new CookieSigningOutContext(
         Context,
         Scheme,
         Options,
         properties,
         cookieOptions);
 
      await Events.SigningOut(context);
 
      Options.CookieManager.DeleteCookie(  // <-------------------remove cookies
         Context,
         Options.Cookie.Name!,   // <-----------------------------------------Name can be IdentityConstants.TwoFactorUserIdScheme etc,
                                 // this is important because only cookies related to the Name will be deleted, NOT all client cookies are deleted
         context.CookieOptions);
 
      // Only honor the ReturnUrl query string parameter on the logout path
      var shouldHonorReturnUrlParameter = Options.LogoutPath.HasValue && OriginalPath == Options.LogoutPath;
      await ApplyHeaders(shouldRedirect: true, shouldHonorReturnUrlParameter, context.Properties);
   }

   private async Task ApplyHeaders(bool shouldRedirect, bool shouldHonorReturnUrlParameter, AuthenticationProperties properties)
   {
      Response.Headers.CacheControl = HeaderValueNoCacheNoStore;
      Response.Headers.Pragma = HeaderValueNoCache;
      Response.Headers.Expires = HeaderValueEpocDate;
 
      if (shouldRedirect && Response.StatusCode == 200)
      {
         // set redirect uri in order:
         // 1. properties.RedirectUri
         // 2. query parameter ReturnUrlParameter (if the request path matches the path set in the options)
         //
         // Absolute uri is not allowed if it is from query string as query string is not
         // a trusted source.
         var redirectUri = properties.RedirectUri;
         if (shouldHonorReturnUrlParameter && string.IsNullOrEmpty(redirectUri))
         {
            redirectUri = Request.Query[Options.ReturnUrlParameter];
            if (string.IsNullOrEmpty(redirectUri) || !IsHostRelative(redirectUri))
            {
               redirectUri = null;
            }
         }
 
         if (redirectUri != null)
         {
            await Events.RedirectToReturnUrl(new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, redirectUri));
         }
      }
   }

   private static bool IsHostRelative(string path)
   {
      if (string.IsNullOrEmpty(path))
      {
         return false;
      }
      if (path.Length == 1)
      {
         return path[0] == '/';
      }
      return path[0] == '/' && path[1] != '/' && path[1] != '\\';
   }

   protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
   {
      var returnUrl = properties.RedirectUri;
      if (string.IsNullOrEmpty(returnUrl))
      {
         returnUrl = OriginalPathBase + OriginalPath + Request.QueryString;
      }
      var accessDeniedUri = Options.AccessDeniedPath + QueryString.Create(Options.ReturnUrlParameter, returnUrl);
      var redirectContext = new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, BuildRedirectUri(accessDeniedUri));
      await Events.RedirectToAccessDenied(redirectContext);
   }

   protected override async Task HandleChallengeAsync(AuthenticationProperties properties)  // <---------------------------
   {
      var redirectUri = properties.RedirectUri;  // <-----------------redirect client to return url
      if (string.IsNullOrEmpty(redirectUri))
      {
         redirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
      }
 
      var loginUri = Options.LoginPath + QueryString.Create(Options.ReturnUrlParameter, redirectUri);   // <----------------------------------------
      var redirectContext = new RedirectContext<CookieAuthenticationOptions>(Context, Scheme, Options, properties, BuildRedirectUri(loginUri));
      await Events.RedirectToLogin(redirectContext);
   }

   private string? GetTlsTokenBinding()
   {
      var binding = Context.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
      return binding == null ? null : Convert.ToBase64String(binding);
   }
}}
//--------------------------------------Ʌ

//-------------------------------------V
public class CookieAuthenticationEvents
{
    public Func<CookieValidatePrincipalContext, Task> OnValidatePrincipal { get; set; } = context => Task.CompletedTask;
 
    public Func<CookieSlidingExpirationContext, Task> OnCheckSlidingExpiration { get; set; } = context => Task.CompletedTask;
 
    public Func<CookieSigningInContext, Task> OnSigningIn { get; set; } = context => Task.CompletedTask;
 
    public Func<CookieSignedInContext, Task> OnSignedIn { get; set; } = context => Task.CompletedTask;
 
    public Func<CookieSigningOutContext, Task> OnSigningOut { get; set; } = context => Task.CompletedTask;

    public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToLogin { get; set; } = context =>
    {
        if (IsAjaxRequest(context.Request))
        {
            context.Response.Headers.Location = context.RedirectUri;
            context.Response.StatusCode = 401;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }
        return Task.CompletedTask;
    };

    public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToAccessDenied { get; set; } = context =>
    {
        if (IsAjaxRequest(context.Request))
        {
            context.Response.Headers.Location = context.RedirectUri;
            context.Response.StatusCode = 403;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }
        return Task.CompletedTask;
    };
 
    public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToLogout { get; set; } = context =>
    {
        if (IsAjaxRequest(context.Request))
        {
            context.Response.Headers.Location = context.RedirectUri;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }
        return Task.CompletedTask;
    };
 
    public Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToReturnUrl { get; set; } = context =>
    {
        if (IsAjaxRequest(context.Request))
        {
            context.Response.Headers.Location = context.RedirectUri;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }
        return Task.CompletedTask;
    };
 
    private static bool IsAjaxRequest(HttpRequest request)
    {
        return string.Equals(request.Query[HeaderNames.XRequestedWith], "XMLHttpRequest", StringComparison.Ordinal) ||
            string.Equals(request.Headers.XRequestedWith, "XMLHttpRequest", StringComparison.Ordinal);
    }

    public virtual Task ValidatePrincipal(CookieValidatePrincipalContext context) => OnValidatePrincipal(context);
 
    public virtual Task CheckSlidingExpiration(CookieSlidingExpirationContext context) => OnCheckSlidingExpiration(context);

    public virtual Task SigningIn(CookieSigningInContext context) => OnSigningIn(context);
 
    public virtual Task SignedIn(CookieSignedInContext context) => OnSignedIn(context);
 
    public virtual Task SigningOut(CookieSigningOutContext context) => OnSigningOut(context);
 
    public virtual Task RedirectToLogout(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToLogout(context);

    public virtual Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToLogin(context);
 
    public virtual Task RedirectToReturnUrl(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToReturnUrl(context);
 
    public virtual Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToAccessDenied(context);
}
//-------------------------------------Ʌ
```

#### Cookie Authentication end-----------------------------------------------------------------------------------------------------------------Ʌ


#### JwtBearer --------------------------------------------------------------------------------------------------------------------------------V

```C#
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
    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();
    private readonly JsonWebTokenHandler _defaultTokenHandler = new JsonWebTokenHandler
    {
        MapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims
    };
 
    private bool _mapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims;

    public JwtBearerOptions()
    {
        SecurityTokenValidators = new List<ISecurityTokenValidator> { _defaultHandler };
        TokenHandlers = new List<TokenHandler> { _defaultTokenHandler };
    }

    public bool RequireHttpsMetadata { get; set; } = true;
    public string MetadataAddress { get; set; } = default!;
    public string? Authority { get; set; }
    public string? Audience { get; set; }
    public string Challenge { get; set; } = JwtBearerDefaults.AuthenticationScheme;
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }
    public HttpClient Backchannel { get; set; } = default!;
    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromMinutes(1);
    public OpenIdConnectConfiguration? Configuration { get; set; }
    public IConfigurationManager<OpenIdConnectConfiguration>? ConfigurationManager { get; set; }
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
 
            var tvp = await SetupTokenValidationParametersAsync();
            List<Exception>? validationFailures = null;
            SecurityToken? validatedToken = null;
            ClaimsPrincipal? principal = null;  // <----------------------
 
            if (!Options.UseSecurityTokenValidators)
            {
                foreach (var tokenHandler in Options.TokenHandlers)
                {
                    try
                    {
                        var tokenValidationResult = await tokenHandler.ValidateTokenAsync(token, tvp);
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
 
        if (Options.ConfigurationManager is BaseConfigurationManager baseConfigurationManager)
        {
            tokenValidationParameters.ConfigurationManager = baseConfigurationManager;
        }
        else
        {
            if (Options.ConfigurationManager != null)
            {
                // GetConfigurationAsync has a time interval that must pass before new http request will be issued.
                var configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
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

#### JwtBearer --------------------------------------------------------------------------------------------------------------------------------Ʌ

