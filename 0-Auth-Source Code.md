.NET Identity Source Code
==============================

```C#
//------------------>>
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(opts =>
        {
            opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;   // DefaultScheme is ""Cookies"
        }).AddCookie(opts =>
        {   // AddCookie uses CookieAuthenticationHandler internally
            opts.LoginPath = "/signin";
            opts.AccessDeniedPath = "/signin/403";
        });

        services.AddAuthorization(opts =>
        {
            opts.AddPolicy("UsersExceptBob", builder =>
               builder.RequireRole("User")
                      .AddRequirements(new AssertionRequirement(context => !string.Equals(context.User.Identity.Name, "Bob"))));
            //.AddAuthenticationSchemes("OtherScheme"));

            opts.AddPolicy("NotAdmins",
                builder => builder.AddRequirements(new AssertionRequirement(context => !context.User.IsInRole("Administrator"))));
        });

        // ...
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseStaticFiles();
        
        app.UseAuthentication();  // <--------------------UseAuthentication() can appear before UseRouting(), although grouping authn/authz together makes perfect sense 
                                  // from an organizational standpoint. But UseAuthorization() has to appear after UseRouting()
                                  // https://weblog.west-wind.com/posts/2021/Mar/09/Role-based-JWT-Tokens-in-ASPNET-Core    
        app.UseRouting();  

        app.UseAuthorization();
        
        app.UseEndpoints(endpoints =>
        {
           // ...
        });
    }
}
//------------------<<
```

**Authentication**

```C#
//-----------------------------------------------------------V
public static class AuthenticationServiceCollectionExtensions
{
   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
   { 
      services.AddAuthenticationCore();
      services.AddDataProtection();  // store encrypted keys at Users\xxx\AppData\Local\ASP.NET\DataProtection-Keys
      services.AddWebEncoders();
      services.TryAddSingleton(TimeProvider.System);
      #pragma warning disable CS0618 // Type or member is obsolete
      services.TryAddSingleton<ISystemClock, SystemClock>();
      #pragma warning restore CS0618 // Type or member is obsolete
      services.TryAddSingleton<IAuthenticationConfigurationProvider, DefaultAuthenticationConfigurationProvider>();
 
      return new AuthenticationBuilder(services);
   }

   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, string defaultScheme)
      => services.AddAuthentication(o => o.DefaultScheme = defaultScheme);
   
   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
   { 
      var builder = services.AddAuthentication();
      services.Configure(configureOptions);
      return builder;
   }
}
//-----------------------------------------------------------Ʌ

//---------------------------------------------------------------V
public static class AuthenticationCoreServiceCollectionExtensions
{
   public static IServiceCollection AddAuthenticationCore(this IServiceCollection services)
   { 
      services.TryAddScoped<IAuthenticationService, AuthenticationService>();
      services.TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>(); // Can be replaced with scoped ones that use DbContext
      services.TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>();
      services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
      return services;
   }

   public static IServiceCollection AddAuthenticationCore(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
   {
      services.AddAuthenticationCore();
      services.Configure(configureOptions);
      return services;
   }
}
//---------------------------------------------------------------Ʌ

//-----------------------------------------------------V
public static class AuthenticationHttpContextExtensions
{
   public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context) => context.AuthenticateAsync(scheme: null);
   public static Task<AuthenticateResult> AuthenticateAsync(this HttpContext context, string? scheme) => GetAuthenticationService(context).AuthenticateAsync(context, scheme);

   //
   public static Task SignInAsync(this HttpContext context, string? scheme, ClaimsPrincipal principal) => context.SignInAsync(scheme, principal, properties: null);
   public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal) => context.SignInAsync(scheme: null, principal: principal, properties: null);
   public static Task SignInAsync(this HttpContext context, ClaimsPrincipal principal, AuthenticationProperties? properties) => ...;
   public static Task SignInAsync(this HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) 
      => GetAuthenticationService(context).SignInAsync(context, scheme, principal, properties);
   //

   // ... SignOutAsync, ChallengeAsync, ForbidAsync
   
   public static Task ChallengeAsync(this HttpContext context, string? scheme, AuthenticationProperties? properties) =>
      GetAuthenticationService(context).ChallengeAsync(context, scheme, properties);

   public static Task ForbidAsync(this HttpContext context, string? scheme, AuthenticationProperties? properties) =>
      GetAuthenticationService(context).ForbidAsync(context, scheme, properties);

   public static Task<string?> GetTokenAsync(this HttpContext context, string tokenName) => GetAuthenticationService(context).GetTokenAsync(context, tokenName);

   private static IAuthenticationService GetAuthenticationService(HttpContext context) =>
      context.RequestServices.GetService<IAuthenticationService>() ?? throw new InvalidOperationException("...");
}
//-----------------------------------------------------Ʌ
```

```C#
//------------------------------------------>>
public static class AuthAppBuilderExtensions
{
   internal const string AuthenticationMiddlewareSetKey = "__AuthenticationMiddlewareSet";

   public static IApplicationBuilder UseAuthentication(this IApplicationBuilder app)
   {
      app.Properties[AuthenticationMiddlewareSetKey] = true;
      return app.UseMiddleware<AuthenticationMiddleware>();     // <------------------------------a0
   }
}
//------------------------------------------<<

//-----------------------------------V
public class AuthenticationMiddleware
{
   private readonly RequestDelegate _next;

   public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes)
   {
      _next = next;
      Schemes = schemes;
   }

   public IAuthenticationSchemeProvider Schemes { get; set; }

   public async Task Invoke(HttpContext context)    // // <------------------------------a1
   {
      context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
      {
         OriginalPath = context.Request.Path,
         OriginalPathBase = context.Request.PathBase
      });

      // Give any IAuthenticationRequestHandler schemes a chance to handle the request
      var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
      foreach (AuthenticationScheme scheme in await Schemes.GetRequestHandlerSchemesAsync())  // GetRequestHandlerSchemesAsync returns all scheme registered by AddScheme()
      {
         var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
         
         if (handler != null && await handler.HandleRequestAsync())  // <---------------------for external auth service, check ExternalAuthHandler example in chapter23
            return;
      }
 
      AuthenticationScheme defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();  // use AuthenticationOptions.DefaultAuthenticateScheme if it exsits
                                                                                                     // if not then AuthenticationOptions.DefaultScheme
      if (defaultAuthenticate != null)                                             
      {  
         // result contains an AuthenticationTicket that can be queried further like result?.Principal
         AuthenticateResult result = await context.AuthenticateAsync(defaultAuthenticate.Name);   // <----------a2.0 internally call AuthenticationHandlerProvider  
                                                                                                  // which in turn create your own IAuthenticationHandler and call it
                                                                                                  // via AuthenticationService
         if (result?.Principal != null)  // query from the wrapped AuthenticationTicket in AuthenticateResult
         {
            context.User = result.Principal;   // <--------------------------------------a3 important! that's the main purpose of AuthenticationMiddleware whihc is to set a
                                               // ClaimsPrincipal on HttpContext.User, note that it is not and should not be set in IAuthenticationHandler.AuthenticateAsync()
         }
         if (result?.Succeeded ?? false)
         {
            var authFeatures = new AuthenticationFeatures(result);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);  // <------------cache the result so that it could be used by PolicyEvaluator later when there is no
                                                                             // AuthenticationScheme specified in the  [Authorize( AuthenticationSchemes = "xxx, yyy")]
         }
      }

      await _next(context);
   }
}
//-----------------------------------Ʌ
```

```C#
//-------------------------------------V
public interface IAuthenticationHandler
{
   Task InitializeAsync(AuthenticationScheme scheme, HttpContext context);
   Task<AuthenticateResult> AuthenticateAsync();
   Task ChallengeAsync(AuthenticationProperties? properties);
   Task ForbidAsync(AuthenticationProperties? properties);
}
//-------------------------------------Ʌ

//-------------------------------------------V
public interface IAuthenticationSignInHandler : IAuthenticationSignOutHandler
{
   Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties);
}

public interface IAuthenticationSignOutHandler : IAuthenticationHandler
{
   Task SignOutAsync(AuthenticationProperties? properties);
}
//-------------------------------------------Ʌ

//-------------------------------------------V
public interface IAuthenticationRequestHandler : IAuthenticationHandler // Uuually implementation of this interface are remote auth implementation like Google, Facebook etc
{
   Task<bool> HandleRequestAsync();
}
//-------------------------------------------Ʌ

//---------------------------------------------------V
public abstract class AuthenticationHandler<TOptions> : IAuthenticationHandler
{
   private Task<AuthenticateResult>? _authenticateTask;
   public AuthenticationScheme Scheme { get; private set; } = default!;
   public TOptions Options { get; private set; } = default!;
   protected HttpContext Context { get; private set; } = default!;
   
   protected AuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder);

   protected HttpRequest Request {
        get => Context.Request;
   }

   protected HttpResponse Response {
      get => Context.Response;
   }

   protected PathString OriginalPath => Context.Features.Get<IAuthenticationFeature>()?.OriginalPath ?? Request.Path;
   protected PathString OriginalPathBase => Context.Features.Get<IAuthenticationFeature>()?.OriginalPathBase ?? Request.PathBase;
   protected ILogger Logger { get; };
   protected UrlEncoder UrlEncoder { get; };
   protected TimeProvider TimeProvider { get; private set; } = TimeProvider.System;
   protected IOptionsMonitor<TOptions> OptionsMonitor { get; }
   protected virtual object? Events { get; set; }
   protected virtual string ClaimsIssuer => Options.ClaimsIssuer ?? Scheme.Name;  // <---------------
   protected string CurrentUri
   {
      get => Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase + Request.Path + Request.QueryString;
   }

   public async Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
   {
      Scheme = scheme;
      Context = context;
 
      Options = OptionsMonitor.Get(Scheme.Name);
      TimeProvider = Options.TimeProvider ?? TimeProvider.System;

      await InitializeEventsAsync();
      await InitializeHandlerAsync();
   }

   protected virtual async Task InitializeEventsAsync()
   {
      Events = Options.Events;
      if (Options.EventsType != null)
      {
         Events = Context.RequestServices.GetRequiredService(Options.EventsType);
      }
      Events ??= await CreateEventsAsync();
   }

   protected virtual Task<object> CreateEventsAsync() => Task.FromResult(new object());
   protected virtual Task InitializeHandlerAsync() => Task.CompletedTask;
   protected string BuildRedirectUri(string targetPath) => Request.Scheme + Uri.SchemeDelimiter + Request.Host + OriginalPathBase + targetPath;

   protected virtual string? ResolveTarget(string? scheme)
   {
      var target = scheme ?? Options.ForwardDefaultSelector?.Invoke(Context) ?? Options.ForwardDefault;
 
      // Prevent self targetting
      return string.Equals(target, Scheme.Name, StringComparison.Ordinal) ? null : target;
   }

   public async Task<AuthenticateResult> AuthenticateAsync()
   {
      var target = ResolveTarget(Options.ForwardAuthenticate);
      if (target != null)
      {
         return await Context.AuthenticateAsync(target);
      }
 
      // Calling Authenticate more than once should always return the original value.
      var result = await HandleAuthenticateOnceAsync() ?? AuthenticateResult.NoResult();
      if (result.Failure == null)
      {
         var ticket = result.Ticket;
         if (ticket?.Principal != null)
         {
            Logger.AuthenticationSchemeAuthenticated(Scheme.Name);
         }
         else
         {
            Logger.AuthenticationSchemeNotAuthenticated(Scheme.Name);
         }
      }
      else
      {
         Logger.AuthenticationSchemeNotAuthenticatedWithFailure(Scheme.Name, result.Failure.Message);
      }
      return result;
   }

   protected Task<AuthenticateResult> HandleAuthenticateOnceAsync()
   {
      if (_authenticateTask == null)
      {
         _authenticateTask = HandleAuthenticateAsync();
      }
 
      return _authenticateTask;
   }

   protected async Task<AuthenticateResult> HandleAuthenticateOnceSafeAsync()
   {
      try
      {
         return await HandleAuthenticateOnceAsync();
      }
      catch (Exception ex)
      {
         return AuthenticateResult.Fail(ex);
      }
   }

   protected abstract Task<AuthenticateResult> HandleAuthenticateAsync();

   protected virtual Task HandleForbiddenAsync(AuthenticationProperties properties)
   {
      Response.StatusCode = 403;
      return Task.CompletedTask;
   }

   protected virtual Task HandleChallengeAsync(AuthenticationProperties properties)
   {
      Response.StatusCode = 401;
      return Task.CompletedTask;
   }

   public async Task ChallengeAsync(AuthenticationProperties? properties)
   {
      var target = ResolveTarget(Options.ForwardChallenge);
      if (target != null)
      {
         await Context.ChallengeAsync(target, properties);
         return;
      }
 
      properties ??= new AuthenticationProperties();
      await HandleChallengeAsync(properties);
      Logger.AuthenticationSchemeChallenged(Scheme.Name);
   }

   public async Task ForbidAsync(AuthenticationProperties? properties)
   {
      var target = ResolveTarget(Options.ForwardForbid);
      if (target != null)
      {
         await Context.ForbidAsync(target, properties);
         return;
      }
 
      properties ??= new AuthenticationProperties();
      await HandleForbiddenAsync(properties);
      Logger.AuthenticationSchemeForbidden(Scheme.Name);
   }
}
//---------------------------------------------------Ʌ

//---------------------------------------------------------V
public abstract class SignInAuthenticationHandler<TOptions> : SignOutAuthenticationHandler<TOptions>, IAuthenticationSignInHandler
{
   public SignInAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) { }
   public SignInAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

   public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
   {
      var target = ResolveTarget(Options.ForwardSignIn);
      return (target != null) ? Context.SignInAsync(target, user, properties) : HandleSignInAsync(user, properties ?? new AuthenticationProperties());
   }

   protected abstract Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties);
}

public abstract class SignOutAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationSignOutHandler
{
   // ...
}
//---------------------------------------------------------Ʌ

//-------------------------------V
public class AuthenticationScheme
{
   public AuthenticationScheme(string name, string? displayName, Type handlerType)
   {
      if (!typeof(IAuthenticationHandler).IsAssignableFrom(handlerType))
         throw new ArgumentException("handlerType must implement IAuthenticationHandler.");
 
      Name = name;
      HandlerType = handlerType;
      DisplayName = displayName;
   }

   public string Name { get; }
   public string? DisplayName { get; }
   public Type HandlerType { get; }
}
//-------------------------------Ʌ

//--------------------------------------V
public class AuthenticationSchemeBuilder
{
   public AuthenticationSchemeBuilder(string name)
   {
      Name = name;
   }

   public string Name { get; }
   public string? DisplayName { get; set; }
   public Type? HandlerType { get; set; }

   public AuthenticationScheme Build()
   {
      if (HandlerType is null)
      {
         throw new InvalidOperationException($"{nameof(HandlerType)} must be configured to build an {nameof(AuthenticationScheme)}.");
      }
 
      return new AuthenticationScheme(Name, DisplayName, HandlerType);
   }
}
//--------------------------------------Ʌ

//-----------------------------------V
public class AuthenticationProperties
{
   internal const string IssuedUtcKey = ".issued";
   internal const string ExpiresUtcKey = ".expires";
   internal const string IsPersistentKey = ".persistent";
   internal const string RedirectUriKey = ".redirect";
   internal const string RefreshKey = ".refresh";
   internal const string UtcDateTimeFormat = "r";

   public AuthenticationProperties() : this(items: null, parameters: null) { }
   public AuthenticationProperties(IDictionary<string, string?> items) : this(items, parameters: null) { }

   public AuthenticationProperties(IDictionary<string, string?>? items, IDictionary<string, object?>? parameters)
   {
      Items = items ?? new Dictionary<string, string?>(StringComparer.Ordinal);
      Parameters = parameters ?? new Dictionary<string, object?>(StringComparer.Ordinal);
   }

   public DateTimeOffset? IssuedUtc { get; set; }
   public string? RedirectUri { get; set; }            // <----------------------
   public bool IsPersistent { get; set; }   
   public IDictionary<string, object?> Parameters { get; }
   public IDictionary<string, string?> Items { get; }  // <----------------------
   public DateTimeOffset? ExpiresUtc { get; set; }
   public bool? AllowRefresh { get; set; }

   public AuthenticationProperties Clone();
   public T? GetParameter<T>(string key);
   public string? GetString(string key);
   public void SetParameter<T>(string key, T value);
   public void SetString(string key, string? value);
   protected bool? GetBool(string key);
   protected DateTimeOffset? GetDateTimeOffset(string key);
   protected void SetBool(string key, bool? value);
   protected void SetDateTimeOffset(string key, DateTimeOffset? value);
}
//-----------------------------------Ʌ

//-----------------------------V
public class AuthenticateResult
{
   private static readonly AuthenticateResult _noResult = new() { None = true };
   
   protected AuthenticateResult() { }

   public bool Succeeded => Ticket != null;   // <-----------------succeeded if it has a Ticket

   public AuthenticationTicket? Ticket { get; protected set; }

   public ClaimsPrincipal? Principal => Ticket?.Principal;  // <---------------------

   public AuthenticationProperties? Properties { get; protected set; }

   public Exception? Failure { get; protected set; }

   public bool None { get; protected set; }

   public AuthenticateResult Clone();

   public static AuthenticateResult Success(AuthenticationTicket ticket)  // <---------------------------
   {
      return new AuthenticateResult() { Ticket = ticket, Properties = ticket.Properties };  // <----------AuthenticationProperties are retrieved from ticket
   }

   public static AuthenticateResult NoResult() => _noResult;

   public static AuthenticateResult Fail(Exception failure)
   {
      return new AuthenticateResult() { Failure = failure };
   }

   public static AuthenticateResult Fail(Exception failure, AuthenticationProperties? properties)
   {
      return new AuthenticateResult() { Failure = failure, Properties = properties };
   }

   public static AuthenticateResult Fail(string failureMessage)
      => Fail(new AuthenticationFailureException(failureMessage));

   public static AuthenticateResult Fail(string failureMessage, AuthenticationProperties? properties)
      => Fail(new AuthenticationFailureException(failureMessage), properties);
}
//-----------------------------Ʌ

//-------------------------------V
public class AuthenticationTicket
{
   public AuthenticationTicket(ClaimsPrincipal principal, AuthenticationProperties? properties, string authenticationScheme)
   { 
      AuthenticationScheme = authenticationScheme;
      Principal = principal;
      Properties = properties ?? new AuthenticationProperties();
   }

   public AuthenticationTicket(ClaimsPrincipal principal, string authenticationScheme)
      : this(principal, properties: null, authenticationScheme: authenticationScheme) { }
   
   public string AuthenticationScheme { get; }

   public ClaimsPrincipal Principal { get; }

   public AuthenticationProperties Properties { get; }  // <-----------------------will be passed to AuthenticateResult

   public AuthenticationTicket Clone()
   {
      var principal = new ClaimsPrincipal();
      foreach (var identity in Principal.Identities)
      {
         principal.AddIdentity(identity.Clone());
      }
      return new AuthenticationTicket(principal, Properties.Clone(), AuthenticationScheme);
   }
}
//-------------------------------Ʌ

//--------------------------------V
public class AuthenticationOptions
{
   private readonly IList<AuthenticationSchemeBuilder> _schemes = new List<AuthenticationSchemeBuilder>();

   public IEnumerable<AuthenticationSchemeBuilder> Schemes => _schemes;

   public IDictionary<string, AuthenticationSchemeBuilder> SchemeMap { get; } = new Dictionary<string, AuthenticationSchemeBuilder>(StringComparer.Ordinal);

   public void AddScheme(string name, Action<AuthenticationSchemeBuilder> configureBuilder)
   {
      if (SchemeMap.ContainsKey(name))
         throw new InvalidOperationException("Scheme already exists: " + name);
 
      var builder = new AuthenticationSchemeBuilder(name);
      configureBuilder(builder);
      _schemes.Add(builder);
      SchemeMap[name] = builder;
   }

   public void AddScheme<THandler>(string name, string? displayName) where THandler : IAuthenticationHandler
   {
      AddScheme(name, b =>
      {
         b.DisplayName = displayName;
         b.HandlerType = typeof(THandler);
      });
   }

   //
   public string? DefaultScheme { get; set; }
   public string? DefaultAuthenticateScheme { get; set; }

   /* difference between DefaultAuthenticateScheme and DefaultScheme

   Authenticate: DefaultAuthenticateScheme, or DefaultScheme
   Challenge: DefaultChallengeScheme, or DefaultScheme
   Forbid: DefaultForbidScheme, or DefaultChallengeScheme, or DefaultScheme
   Sign-in: DefaultSignInScheme, or DefaultScheme
   Sign-out: DefaultSignOutScheme, or DefaultScheme
   
   */
   //
   public string? DefaultSignInScheme { get; set; }
   public string? DefaultSignOutScheme { get; set; }
   public string? DefaultChallengeScheme { get; set; }
   public string? DefaultForbidScheme { get; set; }
   public bool RequireAuthenticatedSignIn { get; set; } = true;

   private bool? _disableAutoDefaultScheme;
   internal bool DisableAutoDefaultScheme
   {
      get
      {
         if (!_disableAutoDefaultScheme.HasValue)
            _disableAutoDefaultScheme = AppContext.TryGetSwitch("Microsoft.AspNetCore.Authentication.SuppressAutoDefaultScheme", out var enabled) && enabled;
 
         return _disableAutoDefaultScheme.Value;
      }
      set => _disableAutoDefaultScheme = value;
   }
}
//--------------------------------Ʌ

//--------------------------------------------------------------V
internal sealed class DefaultAuthenticationConfigurationProvider : IAuthenticationConfigurationProvider
{
   private readonly IConfiguration _configuration;
   private const string AuthenticationKey = "Authentication";

   public DefaultAuthenticationConfigurationProvider() : this(new ConfigurationManager()) { }

   public DefaultAuthenticationConfigurationProvider(IConfiguration configuration)
      => _configuration = configuration;

   public IConfiguration AuthenticationConfiguration => _configuration.GetSection(AuthenticationKey);
}
//--------------------------------------------------------------Ʌ

//--------------------------------V
public class AuthenticationBuilder
{
   public AuthenticationBuilder(IServiceCollection services)
   {
      Services = services;
   }

   public virtual IServiceCollection Services { get; }

   private AuthenticationBuilder AddSchemeHelper<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : class, IAuthenticationHandler
   {
      Services.Configure<AuthenticationOptions>(o =>
      {
         o.AddScheme(authenticationScheme, scheme =>
         {
            scheme.HandlerType = typeof(THandler);
            scheme.DisplayName = displayName;
         });
      });

      if (configureOptions != null)
      {
         Services.Configure(authenticationScheme, configureOptions);
      }

      Services.AddOptions<TOptions>(authenticationScheme).Validate(o =>
      {
         o.Validate(authenticationScheme);
         return true;
      });

      Services.AddTransient<THandler>();
      Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, PostConfigureAuthenticationSchemeOptions<TOptions>>());
      
      return this;
   }

   public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : AuthenticationHandler<TOptions>
      => AddSchemeHelper<TOptions, THandler>(authenticationScheme, displayName, configureOptions);

   public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : AuthenticationHandler<TOptions>
      => AddScheme<TOptions, THandler>(authenticationScheme, displayName: null, configureOptions: configureOptions);
   
   public virtual AuthenticationBuilder AddRemoteScheme<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : RemoteAuthenticationOptions, new()
      where THandler : RemoteAuthenticationHandler<TOptions>
   {
      Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, EnsureSignInScheme<TOptions>>());
      return AddScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions: configureOptions);
   }

   public virtual AuthenticationBuilder AddPolicyScheme(string authenticationScheme, string? displayName, Action<PolicySchemeOptions> configureOptions)
      => AddSchemeHelper<PolicySchemeOptions, PolicySchemeHandler>(authenticationScheme, displayName, configureOptions);

   private sealed class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
   {
      private readonly AuthenticationOptions _authOptions;
 
      public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
      {
         _authOptions = authOptions.Value;
      }
 
      public void PostConfigure(string? name, TOptions options)
      {
         options.SignInScheme ??= _authOptions.DefaultSignInScheme ?? _authOptions.DefaultScheme;
      }
   }
 
   // Set TimeProvider from DI on all options instances, if not already set by tests.
   private sealed class PostConfigureAuthenticationSchemeOptions<TOptions> : IPostConfigureOptions<TOptions>
      where TOptions : AuthenticationSchemeOptions
   {
      public PostConfigureAuthenticationSchemeOptions(TimeProvider timeProvider)
      {
            TimeProvider = timeProvider;
      }
 
      private TimeProvider TimeProvider { get; }
 
      public void PostConfigure(string? name, TOptions options)
      {
         options.TimeProvider ??= TimeProvider;
      }
   }
}
//--------------------------------Ʌ

//--------------------------------V
public class AuthenticationService : IAuthenticationService
{
   private HashSet<ClaimsPrincipal>? _transformCache;

   public AuthenticationService(IAuthenticationSchemeProvider schemes, IAuthenticationHandlerProvider handlers, IClaimsTransformation transform, IOptions<AuthenticationOptions> options)
   {
      Schemes = schemes;
      Handlers = handlers;
      Transform = transform;
      Options = options.Value;
   }

   public IAuthenticationSchemeProvider Schemes { get; }  // <-------------

   public IAuthenticationHandlerProvider Handlers { get; }

   public IClaimsTransformation Transform { get; }

   public AuthenticationOptions Options { get; }

   // this method is called during authentication process (when default scheme applies, otherwise AuthenticateAsync() will still be called multiple times when multiple scheme 
   // applies which are specified via policy), others like ChallengeAsync() is called by AuthorizationMiddleware
   public virtual async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)   // <------------------------a2.0
   {
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultAuthenticateSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }

      IAuthenticationHandler handler = await Handlers.GetHandlerAsync(context, scheme);  // Handlers is AuthenticationHandlerProvider, GetHandlerAsync
                                                                                         // creates your IAuthenticationHandler and call its InitializeAsync
                                                                                         // <------------------------------------------------a2.1
      if (handler == null)
         throw await CreateMissingHandlerException(scheme);     // <------------------this makes browser display 500 status code when the policy's authentication scheme
                                                                // is not registered in AddAuthentication() when authorization middleware is running
 
      AuthenticateResult result = 
         (await handler.AuthenticateAsync()) ?? AuthenticateResult.NoResult();  // <----------------a2.2! important!call user defined IAuthenticationHandler.AuthenticateAsync() 
                                                                                // which create a new AuthenticationTicket(new ClaimsPrincipal(xxx),scheme.Name) if successful
                                                                                // then set this ticket in AuthenticateResult
      if (result.Succeeded)  // it has the Ticket
      {
         var principal = result.Principal!;
         var doTransform = true;
         _transformCache ??= new HashSet<ClaimsPrincipal>();
         if (_transformCache.Contains(principal))
            doTransform = false;
 
         if (doTransform)
         {
            principal = await Transform.TransformAsync(principal);  // <----------------! figure it out later
            _transformCache.Add(principal);
         }
         return AuthenticateResult.Success(new AuthenticationTicket(principal, result.Properties, result.Ticket!.AuthenticationScheme));
      }
      return result;
   }

   // when HttpContext.SignInAsync() is called normally in signin page
   public virtual async Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
   {
      if (Options.RequireAuthenticatedSignIn)
      {
         if (principal.Identity == null)
                throw new InvalidOperationException("SignInAsync when principal.Identity == null is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
            
         if (!principal.Identity.IsAuthenticated)
                throw new InvalidOperationException("SignInAsync when principal.Identity.IsAuthenticated is false is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
      }
 
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultSignInSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignInScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      IAuthenticationHandler handler = await Handlers.GetHandlerAsync(context, scheme); // Handlers is AuthenticationHandlerProvider, GetHandlerAsync
                                                                                         // creates your IAuthenticationHandler and call its InitializeAsync
                                                                                         // <------------------------------------------------a2.1
      if (handler == null)
      {
         throw await CreateMissingSignInHandlerException(scheme);
      }
 
      var signInHandler = handler as IAuthenticationSignInHandler;
      if (signInHandler == null)
      {
         throw await CreateMismatchedSignInHandlerException(scheme, handler);
      }
 
      await signInHandler.SignInAsync(principal, properties);
   }

   public virtual async Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
   {
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultSignOutSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignOutScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingSignOutHandlerException(scheme);
      }
 
      var signOutHandler = handler as IAuthenticationSignOutHandler;
      if (signOutHandler == null)
      {
         throw await CreateMismatchedSignOutHandlerException(scheme, handler);
      }
 
      await signOutHandler.SignOutAsync(properties);
   }

   public virtual async Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)  // properties normally contains the return url
   {
      if (scheme == null)
      {
         var defaultChallengeScheme = await Schemes.GetDefaultChallengeSchemeAsync();
         scheme = defaultChallengeScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultChallengeScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      IAuthenticationHandler handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingHandlerException(scheme);
      }
 
      await handler.ChallengeAsync(properties);
   }

   public virtual async Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
   {
      if (scheme == null)
      {
         var defaultForbidScheme = await Schemes.GetDefaultForbidSchemeAsync();
         scheme = defaultForbidScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultForbidScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      IAuthenticationHandler handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingHandlerException(scheme);
      }
 
      await handler.ForbidAsync(properties);
   }

   private async Task<Exception> CreateMissingHandlerException(string scheme)
   {
      var schemes = string.Join(", ", (await Schemes.GetAllSchemesAsync()).Select(sch => sch.Name));
 
      var footer = $" Did you forget to call AddAuthentication().Add[SomeAuthHandler](\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
            return new InvalidOperationException($"No authentication handlers are registered." + footer);
 
      return new InvalidOperationException($"No authentication handler is registered for the scheme '{scheme}'. The registered schemes are: {schemes}." + footer);
   }

   private async Task<string> GetAllSignInSchemeNames()
   {
      return string.Join(", ", (await Schemes.GetAllSchemesAsync())
         .Where(sch => typeof(IAuthenticationSignInHandler).IsAssignableFrom(sch.HandlerType))
         .Select(sch => sch.Name));
   }
 
   private async Task<Exception> CreateMissingSignInHandlerException(string scheme)
   {
      var schemes = await GetAllSignInSchemeNames();
 
      // CookieAuth is the only implementation of sign-in.
      var footer = $" Did you forget to call AddAuthentication().AddCookie(\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
      {
         return new InvalidOperationException($"No sign-in authentication handlers are registered." + footer);
      }
 
      return new InvalidOperationException($"No sign-in authentication handler is registered for the scheme '{scheme}'. The registered sign-in schemes are: {schemes}." + footer);
   }

   private async Task<Exception> CreateMismatchedSignInHandlerException(string scheme, IAuthenticationHandler handler)
   {
      var schemes = await GetAllSignInSchemeNames();
 
      var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for SignInAsync. ";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the only implementation of sign-in.
         return new InvalidOperationException(mismatchError + $"Did you forget to call AddAuthentication().AddCookie(\"Cookies\") and SignInAsync(\"Cookies\",...)?");
      }
 
      return new InvalidOperationException(mismatchError + $"The registered sign-in schemes are: {schemes}.");
   }
 
   private async Task<string> GetAllSignOutSchemeNames()
   {
      return string.Join(", ", (await Schemes.GetAllSchemesAsync())
         .Where(sch => typeof(IAuthenticationSignOutHandler).IsAssignableFrom(sch.HandlerType))
         .Select(sch => sch.Name));
   }

   private async Task<Exception> CreateMissingSignOutHandlerException(string scheme)
   {
      var schemes = await GetAllSignOutSchemeNames();
 
      var footer = $" Did you forget to call AddAuthentication().AddCookie(\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
         return new InvalidOperationException($"No sign-out authentication handlers are registered." + footer);
      }
 
      return new InvalidOperationException( $"No sign-out authentication handler is registered for the scheme '{scheme}'. The registered sign-out schemes are: {schemes}." + footer);
   }
 
   private async Task<Exception> CreateMismatchedSignOutHandlerException(string scheme, IAuthenticationHandler handler)
   {
      var schemes = await GetAllSignOutSchemeNames();
 
      var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for {nameof(SignOutAsync)}. ";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
         return new InvalidOperationException(mismatchError + $"Did you forget to call AddAuthentication().AddCookie(\"Cookies\") and {nameof(SignOutAsync)}(\"Cookies\",...)?");
      }
 
      return new InvalidOperationException(mismatchError + $"The registered sign-out schemes are: {schemes}.");
   }
}
//--------------------------------Ʌ

//-----------------------------------V
public class NoopClaimsTransformation : IClaimsTransformation
{
    public virtual Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        return Task.FromResult(principal);
    }
}
//-----------------------------------Ʌ

//----------------------------------------V
public class AuthenticationHandlerProvider : IAuthenticationHandlerProvider
{
   public IAuthenticationSchemeProvider Schemes { get; }

   private readonly Dictionary<string, IAuthenticationHandler> _handlerMap = new Dictionary<string, IAuthenticationHandler>(StringComparer.Ordinal);

   public AuthenticationHandlerProvider(IAuthenticationSchemeProvider schemes)
   {
      Schemes = schemes;
   }

   public async Task<IAuthenticationHandler?> GetHandlerAsync(HttpContext context, string authenticationScheme)  // <------------------a2.1.0
   {
      if (_handlerMap.TryGetValue(authenticationScheme, out var value))
         return value;
 
      AuthenticationScheme scheme = await Schemes.GetSchemeAsync(authenticationScheme);  // <-----------------use AuthenticationSchemeProvider to get scheme
      if (scheme == null)
         return null;

      var handler = (context.RequestServices.GetService(scheme.HandlerType) ?? 
         ActivatorUtilities.CreateInstance(context.RequestServices, scheme.HandlerType)) as IAuthenticationHandler;  // <----! create your IAuthenticationHandler
                                                                                                                     // <--------------a2.1.1
      if (handler != null)
      {
         await handler.InitializeAsync(scheme, context);   // <------------------a2.1.2 calls your IAuthenticationHandler.InitializeAsync() and pass AuthenticationScheme
         _handlerMap[authenticationScheme] = handler;
      }

      return handler;
   }
}
//----------------------------------------Ʌ

//---------------------------------------V
public class AuthenticationSchemeProvider : IAuthenticationSchemeProvider
{
   private readonly AuthenticationOptions _options;
   private readonly object _lock = new object();
 
   private readonly IDictionary<string, AuthenticationScheme> _schemes;  // <----------------
   private readonly List<AuthenticationScheme> _requestHandlers;
   private static readonly Task<AuthenticationScheme?> _nullScheme = Task.FromResult<AuthenticationScheme?>(null);
   private Task<AuthenticationScheme?> _autoDefaultScheme = _nullScheme;
   
   public AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options) : this(options, new Dictionary<string, AuthenticationScheme>(StringComparer.Ordinal)) { }

   protected AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options, IDictionary<string, AuthenticationScheme> schemes)
   {
      _options = options.Value;
 
      _schemes = schemes ?? throw new ArgumentNullException(nameof(schemes));
      _requestHandlers = new List<AuthenticationScheme>();
 
      foreach (AuthenticationSchemeBuilder builder in _options.Schemes)
      {
         var scheme = builder.Build();
         AddScheme(scheme);
      }
   }

   // Used as a safe return value for enumeration apis
   private IEnumerable<AuthenticationScheme> _schemesCopy = Array.Empty<AuthenticationScheme>();
   private IEnumerable<AuthenticationScheme> _requestHandlersCopy = Array.Empty<AuthenticationScheme>();

   private Task<AuthenticationScheme?> GetDefaultSchemeAsync()
      => _options.DefaultScheme != null ? GetSchemeAsync(_options.DefaultScheme) : _autoDefaultScheme;

   public virtual Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync()
      => _options.DefaultAuthenticateScheme != null ? GetSchemeAsync(_options.DefaultAuthenticateScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync()
      => _options.DefaultChallengeScheme != null ? GetSchemeAsync(_options.DefaultChallengeScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync()
      => _options.DefaultForbidScheme != null ? GetSchemeAsync(_options.DefaultForbidScheme) : GetDefaultChallengeSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync()
      => _options.DefaultSignInScheme != null ? GetSchemeAsync(_options.DefaultSignInScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync()
      => _options.DefaultSignOutScheme != null ? GetSchemeAsync(_options.DefaultSignOutScheme) : GetDefaultSignInSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetSchemeAsync(string name)
      => Task.FromResult(_schemes.TryGetValue(name, out var scheme) ? scheme : null);
   
   public virtual Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync()
      => Task.FromResult(_requestHandlersCopy);
   
   public virtual bool TryAddScheme(AuthenticationScheme scheme)
   {
      if (_schemes.ContainsKey(scheme.Name))
         return false;

      lock (_lock)
      {
         if (_schemes.ContainsKey(scheme.Name))
            return false;

         if (typeof(IAuthenticationRequestHandler).IsAssignableFrom(scheme.HandlerType))
         {
            _requestHandlers.Add(scheme);
            _requestHandlersCopy = _requestHandlers.ToArray();
         }
         _schemes[scheme.Name] = scheme;
         _schemesCopy = _schemes.Values.ToArray();
         CheckAutoDefaultScheme();
 
         return true;
      }
   }

   public virtual void AddScheme(AuthenticationScheme scheme)
   {
      if (_schemes.ContainsKey(scheme.Name))
         throw new InvalidOperationException("Scheme already exists: " + scheme.Name);

      lock (_lock)
      {
         if (!TryAddScheme(scheme))
            throw new InvalidOperationException("Scheme already exists: " + scheme.Name);
      }
   }

   public virtual void RemoveScheme(string name)
   {
      if (!_schemes.TryGetValue(name, out _))      
         return;
        
      lock (_lock)
      {
         if (_schemes.TryGetValue(name, out var scheme))
         {
            if (_requestHandlers.Remove(scheme))      
               _requestHandlersCopy = _requestHandlers.ToArray();
            
            _schemes.Remove(name);
            _schemesCopy = _schemes.Values.ToArray();
            CheckAutoDefaultScheme();
         }
      }
   }

   public virtual Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult(_schemesCopy);

   private void CheckAutoDefaultScheme()
   {
      if (!_options.DisableAutoDefaultScheme)
      {
         if (_schemes.Count == 1)
            _autoDefaultScheme = Task.FromResult<AuthenticationScheme?>(_schemesCopy.First());   
         else
            _autoDefaultScheme = _nullScheme;
      }
   }
}
//---------------------------------------Ʌ

//--------------------------------------V
public class AuthenticationSchemeOptions
{
   public virtual void Validate() { }
   public virtual void Validate(string scheme) => Validate();
   public string? ClaimsIssuer { get; set; }
   public object? Events { get; set; }
   public Type? EventsType { get; set; }
   public string? ForwardDefault { get; set; }
   public string? ForwardAuthenticate { get; set; }
   public string? ForwardChallenge { get; set; }
   public string? ForwardForbid { get; set; }
   public string? ForwardSignIn { get; set; }
   public string? ForwardSignOut { get; set; }
   public Func<HttpContext, string?>? ForwardDefaultSelector { get; set; }
   public TimeProvider? TimeProvider { get; set; }
}
//--------------------------------------Ʌ
```

=================================================================================================================================================================

**Authorization**

```C#
//---------------------------------------------------V
public static class PolicyServiceCollectionExtensions
{
   public static AuthorizationBuilder AddAuthorizationBuilder(this IServiceCollection services)
      => new AuthorizationBuilder(services.AddAuthorization());

   public static IServiceCollection AddAuthorizationPolicyEvaluator(this IServiceCollection services)
   {
      services.TryAddSingleton<AuthorizationPolicyMarkerService>();
      services.TryAddTransient<IPolicyEvaluator, PolicyEvaluator>();
      services.TryAddTransient<IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
      return services;
   }

   public static IServiceCollection AddAuthorization(this IServiceCollection services)
   { 
      services.AddAuthorizationCore();
      services.AddAuthorizationPolicyEvaluator();
      services.TryAddSingleton<AuthorizationPolicyCache>();
      return services;
   }

   public static IServiceCollection AddAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configure)
   { 
      services.AddAuthorizationCore(configure);
      services.AddAuthorizationPolicyEvaluator();
      services.TryAddSingleton<AuthorizationPolicyCache>();
      return services;
   }
}
//---------------------------------------------------Ʌ

//----------------------------------------------------------V
public static class AuthorizationServiceCollectionExtensions
{
   public static IServiceCollection AddAuthorizationCore(this IServiceCollection services)
   {
      // These services depend on options, and they are used in Blazor WASM, where options aren't included by default.
      services.AddOptions();
 
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationService, DefaultAuthorizationService>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationPolicyProvider, DefaultAuthorizationPolicyProvider>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerProvider, DefaultAuthorizationHandlerProvider>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationEvaluator, DefaultAuthorizationEvaluator>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerContextFactory, DefaultAuthorizationHandlerContextFactory>());
      
      // allows an IAuthorizationRequirement be its own IAuthorizationHandler, see `RolesAuthorizationRequirement` source code
      services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>());   // <-----------------------!important
      
      return services;
   }

   public static IServiceCollection AddAuthorizationCore(this IServiceCollection services, Action<AuthorizationOptions> configure)
   { 
      services.Configure(configure);
      return services.AddAuthorizationCore();
   }
}
//----------------------------------------------------------Ʌ

//---------------------------------------------------V
public static class AuthorizationAppBuilderExtensions
{
   internal const string AuthorizationMiddlewareSetKey = "__AuthorizationMiddlewareSet";

   public static IApplicationBuilder UseAuthorization(this IApplicationBuilder app)
   { 
      VerifyServicesRegistered(app);
 
      app.Properties[AuthorizationMiddlewareSetKey] = true;
      return app.UseMiddleware<AuthorizationMiddleware>();   // <--------------------------------b0
   }

   private static void VerifyServicesRegistered(IApplicationBuilder app)
    {
        // Verify that AddAuthorizationPolicy was called before calling UseAuthorization. We use the AuthorizationPolicyMarkerService to ensure all the services were added.
        if (app.ApplicationServices.GetService(typeof(AuthorizationPolicyMarkerService)) == null)
        {
            throw new InvalidOperationException(Resources.FormatException_UnableToFindServices(nameof(IServiceCollection), nameof(PolicyServiceCollectionExtensions.AddAuthorization)));
        }
    }
}
//---------------------------------------------------Ʌ

//------------------------------------------------V
public static class AuthorizationServiceExtensions
{
   // only this method will be called eventually
   public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object? resource, IAuthorizationRequirement requirement)
   {
      return service.AuthorizeAsync(user, resource, new IAuthorizationRequirement[] { requirement });
   }
   //
  
   public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object? resource, AuthorizationPolicy policy)
   { 
      return service.AuthorizeAsync(user, resource, policy.Requirements);   // <-------------------b4.1.1 only IAuthorizationRequirement[] is passed to DefaultAuthorizationService
                                                                            // no policy name or authentication scheme is needed, which makes sense
   }

   public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, AuthorizationPolicy policy)
   {   
      return service.AuthorizeAsync(user, resource: null, policy: policy);
   }

   public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, string policyName)
   {
      return service.AuthorizeAsync(user, resource: null, policyName: policyName);
   }
   
}
//------------------------------------------------Ʌ

//----------------------------------V
public class AuthorizationMiddleware
{
   private const string SuppressUseHttpContextAsAuthorizationResource = "Microsoft.AspNetCore.Authorization.SuppressUseHttpContextAsAuthorizationResource";
 
   // Property key is used by Endpoint routing to determine if Authorization has run
   private const string AuthorizationMiddlewareInvokedWithEndpointKey = "__AuthorizationMiddlewareWithEndpointInvoked";
   private static readonly object AuthorizationMiddlewareWithEndpointInvokedValue = new object();
 
   private readonly RequestDelegate _next;
   private readonly IAuthorizationPolicyProvider _policyProvider;
   private readonly bool _canCache;
   private readonly AuthorizationPolicyCache? _policyCache;
   private readonly ILogger<AuthorizationMiddleware>? _logger;

   public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
   {
      _next = next ?? throw new ArgumentNullException(nameof(next));
      _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
      _canCache = false;
   }

   public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider, IServiceProvider services, ILogger<AuthorizationMiddleware> logger) 
      : this(next, policyProvider, services)
   {
      _logger = logger;
   }

   public AuthorizationMiddleware(RequestDelegate next, IServiceProvider services) : this(next, policyProvider)
   { 
      if (_policyProvider.AllowsCachingPolicies)
      {
         _policyCache = services.GetService<AuthorizationPolicyCache>();
         _canCache = _policyCache != null;
      }
   }

   public async Task Invoke(HttpContext context)   // <--------------------------------b1
   {
      var endpoint = context.GetEndpoint();
      if (endpoint != null)
      {
         // EndpointRoutingMiddleware uses this flag to check if the Authorization middleware processed auth metadata on the endpoint.
         // The Authorization middleware can only make this claim if it observes an actual endpoint.
         context.Items[AuthorizationMiddlewareInvokedWithEndpointKey] = AuthorizationMiddlewareWithEndpointInvokedValue;
      }

      // Use the computed policy for this endpoint if we can
      AuthorizationPolicy? policy = null;
      var canCachePolicy = _canCache && endpoint != null;
      if (canCachePolicy)
      {
         policy = _policyCache!.Lookup(endpoint!);
      }

      if (policy == null)
      {
         var authorizeData = // <------this must be when you use [Authorize(Policy = "xxx") or use RequireAuthorization() and routing middleware set it into endpoint's Metadata
            endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? Array.Empty<IAuthorizeData>();   // <---------------AuthorizeAttribute inherits IAuthorizeData
 
         var policies =  
            endpoint?.Metadata.GetOrderedMetadata<AuthorizationPolicy>() ?? Array.Empty<AuthorizationPolicy>();  // not sure what's this for
 
         // this `policy` is a new AuthorizationPolicy(...) instance generated by via AuthorizationPolicy.CombineAsync (via AuthorizationPolicyBuilder internally)
         policy = await AuthorizationPolicy.CombineAsync(_policyProvider, authorizeData, policies);   // <--------------------------------b2
                                                                                                      // return fallbackPolicy if no [Authorize(Policy = "xxx")] used
 
         var requirementData = endpoint?.Metadata?.GetOrderedMetadata<IAuthorizationRequirementData>() ?? Array.Empty<IAuthorizationRequirementData>();
         if (requirementData.Count > 0)
         {
            var reqPolicy = new AuthorizationPolicyBuilder();
            foreach (var rd in requirementData)
            {
               foreach (var r in rd.GetRequirements())
               {
                  reqPolicy.AddRequirements(r);
               }
            }
 
            // Combine policy with requirements or just use requirements if no policy
            policy = policy is null ? reqPolicy.Build() : AuthorizationPolicy.Combine(policy, reqPolicy.Build());
         }
 
         // Cache the computed policy
         if (policy != null && canCachePolicy)
         {
            _policyCache!.Store(endpoint!, policy);
         }      
      }

      // if you use [Authorize] even though there is no any arguemnt being used then policy will not be null
      if (policy == null)   // <-----------that's why default project template can only have app.UseAuthorization() not app.UseAuthentication() in the startup.cs
      {
         await _next(context);
         return;
      }

      var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

      AuthenticateResult authenticateResult =                       
         await policyEvaluator.AuthenticateAsync(policy, context);  // <-------------------------------b3!, counter intuitive, AuthorizationMiddleware does Authenticate process
                                                                    // This is when non-default scheme's handler, defined in Authorization process gets called
      if (authenticateResult?.Succeeded ?? false)
      {
         if (context.Features.Get<IAuthenticateResultFeature>() is IAuthenticateResultFeature authenticateResultFeature)
         {
            authenticateResultFeature.AuthenticateResult = authenticateResult;
         }
         else
         {
            var authFeatures = new AuthenticationFeatures(authenticateResult);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);
         }
      }

      // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
      if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
      {
         await _next(context);
         return;
      }
 
      if (authenticateResult != null && !authenticateResult.Succeeded && _logger is ILogger log && log.IsEnabled(LogLevel.Debug))
      {
         log.LogDebug("Policy authentication schemes {policyName} did not succeed", String.Join(", ", policy.AuthenticationSchemes));
      }

      object? resource;
      if (AppContext.TryGetSwitch(SuppressUseHttpContextAsAuthorizationResource, out var useEndpointAsResource) && useEndpointAsResource)
      {
         resource = endpoint;
      }
      else
      {
         resource = context;
      }
 
      // this is important, authorization process will actually invoke authentication process, the authentication process in the AuthenticationMiddleware only
      // invoke authentication process for default auth scheme, but authorization process in AuthenticationMiddlwarfe will do authentication process for each
      // auth scheme specified in e.g [Authorize(AuthenticationSchemes = "Foo, Bar")]
      var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult!, context, resource);  // <----------------------b4
      // look like we can check authenticateResult here and return 401, but the idea is authorize the request to see if it is 403 then see whether to return 401 or 403
      var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
      
      await authorizationMiddlewareResultHandler.HandleAsync(_next, context, policy, authorizeResult); // <---------------------b5, call IAuthenticationHandler.ChallengeAsync()
                                                                                                       //  or IAuthenticationHandler.ForbidAsync() if authorization fails
   }
}
//----------------------------------Ʌ

//--------------------------------------------Ʌ

public interface IAuthorizationRequirementData
{
   IEnumerable<IAuthorizationRequirement> GetRequirements();
}

// marker interface
public interface IAuthorizationRequirement { }
//--------------------------------------------Ʌ
```

```C#
public class AuthorizeAttribute : Attribute, IAuthorizeData
{
   public AuthorizeAttribute() { }

   public AuthorizeAttribute(string policy)
   {
      Policy = policy;
   }

   public string? Policy { get; set; }
   public string? Roles { get; set; }
   public string? AuthenticationSchemes { get; set; }
   public override string ToString()
   {
      return DebuggerHelpers.GetDebugText(nameof(Policy), Policy, nameof(Roles), Roles, nameof(AuthenticationSchemes), AuthenticationSchemes, includeNullValues: false, prefix: "Authorize");
   }
}
```

```C#
//------------------------------------V
public interface IAuthorizationHandler
{
   Task HandleAsync(AuthorizationHandlerContext context);
}
//------------------------------------Ʌ

//--------------------------------------V
public class AuthorizationHandlerContext
{
   private readonly HashSet<IAuthorizationRequirement> _pendingRequirements;
   private List<AuthorizationFailureReason>? _failedReasons;
   private bool _failCalled;
   private bool _succeedCalled;

   public AuthorizationHandlerContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
   {
      Requirements = requirements;
      User = user;
      Resource = resource;
      _pendingRequirements = new HashSet<IAuthorizationRequirement>(requirements);
   }

   public virtual IEnumerable<IAuthorizationRequirement> Requirements { get; }
   public virtual ClaimsPrincipal User { get; }
   public virtual object? Resource { get; }
   public virtual IEnumerable<IAuthorizationRequirement> PendingRequirements { get { return _pendingRequirements; } }

   public virtual IEnumerable<AuthorizationFailureReason> FailureReasons
      => (IEnumerable<AuthorizationFailureReason>?)_failedReasons ?? Array.Empty<AuthorizationFailureReason>();

   public virtual bool HasFailed { get { return _failCalled; } }
   public virtual bool HasSucceeded
   {
      get {
         return !_failCalled && _succeedCalled && !PendingRequirements.Any();
      }
   }

   public virtual void Fail()
   {
      _failCalled = true;
   }

   public virtual void Fail(AuthorizationFailureReason reason)
   {
      Fail();
      if (reason != null)
      {
         if (_failedReasons == null)
         {
            _failedReasons = new List<AuthorizationFailureReason>();
         }
 
         _failedReasons.Add(reason);
      }
   }

   public virtual void Succeed(IAuthorizationRequirement requirement)  // <------------------------
   {
      _succeedCalled = true;
      _pendingRequirements.Remove(requirement);
   }
}
//--------------------------------------Ʌ

//------------------------------------------------------V
public abstract class AuthorizationHandler<TRequirement> : IAuthorizationHandler where TRequirement : IAuthorizationRequirement
{
   public virtual async Task HandleAsync(AuthorizationHandlerContext context)
   {
      foreach (var req in context.Requirements.OfType<TRequirement>())
      {
         await HandleRequirementAsync(context, req).ConfigureAwait(false);
      }
   }

   protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement);
}
//------------------------------------------------------Ʌ
```

```C#
//-----------------------------V
public interface IAuthorizeData
{
   string? Policy { get; set; }
   string? Roles { get; set; }
   string? AuthenticationSchemes { get; set; }
}
//-----------------------------Ʌ

//------------------------------V
public class AuthorizationPolicy
{
   public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements, IEnumerable<string> authenticationSchemes)
   {
      if (!requirements.Any())
      {
         throw new InvalidOperationException(Resources.Exception_AuthorizationPolicyEmpty);
      }
        
      Requirements = new List<IAuthorizationRequirement>(requirements).AsReadOnly();
      AuthenticationSchemes = new List<string>(authenticationSchemes).AsReadOnly();
   }

   public IReadOnlyList<IAuthorizationRequirement> Requirements { get; }

   public IReadOnlyList<string> AuthenticationSchemes { get; }

   public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
   { 
      return Combine((IEnumerable<AuthorizationPolicy>)policies);
   }

   public static AuthorizationPolicy Combine(IEnumerable<AuthorizationPolicy> policies)
   { 
      var builder = new AuthorizationPolicyBuilder();
      foreach (var policy in policies)
      {
         builder.Combine(policy);
      }
      return builder.Build();
   }

   public static Task<AuthorizationPolicy?> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData) 
   {
      CombineAsync(policyProvider, authorizeData, Enumerable.Empty<AuthorizationPolicy>());
   }

   public static async Task<AuthorizationPolicy?> CombineAsync(IAuthorizationPolicyProvider policyProvider, 
                                                               IEnumerable<IAuthorizeData> authorizeData 
                                                               IEnumerable<AuthorizationPolicy> policies)
   {
      var anyPolicies = policies.Any();

      // Avoid allocating enumerator if the data is known to be empty
      var skipEnumeratingData = false;
      if (authorizeData is IList<IAuthorizeData> dataList)   // <---------------------------------b2.1
      {
         skipEnumeratingData = dataList.Count == 0;
      }

      AuthorizationPolicyBuilder? policyBuilder = null;
      if (!skipEnumeratingData)
      {
         foreach (var authorizeDatum in authorizeData)
         {
            if (policyBuilder == null)
            {
               policyBuilder = new AuthorizationPolicyBuilder();
            }

            var useDefaultPolicy = !(anyPolicies);
            if (!string.IsNullOrWhiteSpace(authorizeDatum.Policy))  // <----------------------from [Authorize(Policy = "xxx")]
            {
               var policy = await policyProvider.GetPolicyAsync(authorizeDatum.Policy).ConfigureAwait(false);
               if (policy == null)
               {
                  throw new InvalidOperationException(Resources.FormatException_AuthorizationPolicyNotFound(authorizeDatum.Policy));
               }
               policyBuilder.Combine(policy);
               useDefaultPolicy = false;
            }

            var rolesSplit = authorizeDatum.Roles?.Split(',');   // <----------------------from [Authorize(Role = "xxx, yyy")]
            if (rolesSplit?.Length > 0)
            {
               var trimmedRolesSplit = rolesSplit.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim());
               policyBuilder.RequireRole(trimmedRolesSplit);   // <-------------------------------------b2.2
               useDefaultPolicy = false;
            }

            var authTypesSplit = authorizeDatum.AuthenticationSchemes?.Split(',');  // <--------------------from [Authorize(AuthenticationSchemes = "OtherScheme")]
            if (authTypesSplit?.Length > 0)
            {
               foreach (var authType in authTypesSplit)
               {
                  if (!string.IsNullOrWhiteSpace(authType))
                  {
                     policyBuilder.AuthenticationSchemes.Add(authType.Trim());
                  }
               }
            }

            if (useDefaultPolicy)
            {
               policyBuilder.Combine(await policyProvider.GetDefaultPolicyAsync().ConfigureAwait(false));
            }
         }
      }

      if (anyPolicies)
      {
         policyBuilder ??= new();
 
         foreach (var policy in policies)
         {
            policyBuilder.Combine(policy);
         }
      }

      // If we have no policy by now, use the fallback policy if we have one
      if (policyBuilder == null)
      {
         var fallbackPolicy = await policyProvider.GetFallbackPolicyAsync().ConfigureAwait(false);
         if (fallbackPolicy != null)
         {
            return fallbackPolicy;
         }
      }

      return policyBuilder?.Build();
   }
}
//------------------------------Ʌ

//-------------------------------------V
public class AuthorizationPolicyBuilder
{
   private static readonly DenyAnonymousAuthorizationRequirement _denyAnonymousAuthorizationRequirement = new();  // <---------------------default policy

   public AuthorizationPolicyBuilder(params string[] authenticationSchemes)
   {
      AddAuthenticationSchemes(authenticationSchemes);
   }

   public AuthorizationPolicyBuilder(AuthorizationPolicy policy)
   {
      Combine(policy);
   }

   public IList<IAuthorizationRequirement> Requirements { get; set; } = new List<IAuthorizationRequirement>();
   public IList<string> AuthenticationSchemes { get; set; } = new List<string>();
   public AuthorizationPolicyBuilder AddAuthenticationSchemes(params string[] schemes) => AddAuthenticationSchemesCore(schemes);

   private AuthorizationPolicyBuilder AddAuthenticationSchemesCore(IEnumerable<string> schemes)
   {
      foreach (var authType in schemes)
      {
         AuthenticationSchemes.Add(authType);
      }
      return this;
   }

   public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements) => AddRequirementsCore(requirements);

   private AuthorizationPolicyBuilder AddRequirementsCore(IEnumerable<IAuthorizationRequirement> requirements)
   {
      foreach (var req in requirements)
      {
         Requirements.Add(req);
      }
      return this;
   }

   public AuthorizationPolicyBuilder Combine(AuthorizationPolicy policy)
   { 
      AddAuthenticationSchemesCore(policy.AuthenticationSchemes);
      AddRequirementsCore(policy.Requirements);
      return this;
   }

   public AuthorizationPolicyBuilder RequireClaim(string claimType, params string[] allowedValues)
   { 
      return RequireClaim(claimType, (IEnumerable<string>)allowedValues);
   }

   public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
   { 
      Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues));
      return this;
   }

   public AuthorizationPolicyBuilder RequireClaim(string claimType)
   { 
      Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues: null));
      return this;
   }

   public AuthorizationPolicyBuilder RequireRole(params string[] roles)
   { 
      return RequireRole((IEnumerable<string>)roles);
   }

   public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
   { 
      Requirements.Add(new RolesAuthorizationRequirement(roles));    // <------------------------------b2.3.
      return this;
   }

   public AuthorizationPolicyBuilder RequireUserName(string userName)
   { 
      Requirements.Add(new NameAuthorizationRequirement(userName));
      return this;
   }

   public AuthorizationPolicyBuilder RequireAuthenticatedUser()   // <-----------------check AuthorizationOptions.DefaultPolicy
   {
      Requirements.Add(_denyAnonymousAuthorizationRequirement);
      return this;
   }

   public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, bool> handler)
   { 
      Requirements.Add(new AssertionRequirement(handler));
      return this;
   }

   public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, Task<bool>> handler)
   { 
      Requirements.Add(new AssertionRequirement(handler));
      return this;
   }

   public AuthorizationPolicy Build()
   {
      return new AuthorizationPolicy(Requirements, AuthenticationSchemes.Distinct());
   }
}
//-------------------------------------Ʌ

//------------------------------->>
public interface IPolicyEvaluator  // base class for authorization handlers that need to be called for a specific requirement type
{
   Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context);
   Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource);
}
//-------------------------------<<

//--------------------------V
public class PolicyEvaluator : IPolicyEvaluator
{
   private readonly IAuthorizationService _authorization;

   public PolicyEvaluator(IAuthorizationService authorization)
   {
      _authorization = authorization;
   }

   public virtual async Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
   {
      if (policy.AuthenticationSchemes != null && policy.AuthenticationSchemes.Count > 0)  // if users doesn't specify AuthenticationSchemes in a policy, that means 
      {                                                                                    // we can jump to context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult
         ClaimsPrincipal? newPrincipal = null;                                             // which is set by AuthenticationMiddleware in the first place
         DateTimeOffset? minExpiresUtc = null;
         foreach (var scheme in policy.AuthenticationSchemes)  // <----------as long as one authenticates, all success
         {
            var result = await context.AuthenticateAsync(scheme); //<-------------------b3.1 important! called each scheme's handler IAuthenticationHandler.AuthenticateAsync()
                                                                  // schemes are specified in AddAuthorization() or AddPolicy() e.g
                                                                  // new AuthorizationPolicy(new IAuthorizationRequirement[] { ... }, new string[] { "SchemeXX1", "SchemeXX2" })
                    
            if (result != null && result.Succeeded)
            {
               newPrincipal = SecurityHelper.MergeUserPrincipal(newPrincipal, result.Principal);  // <-------------b3.2 get AuthenticationTicket.Principal
 
               if (minExpiresUtc is null || result.Properties?.ExpiresUtc < minExpiresUtc)
                  minExpiresUtc = result.Properties?.ExpiresUtc;
            }
         }

         if (newPrincipal != null)
         {
            context.User = newPrincipal;   // <------------------------------------------------b3.3. set the mergered ClaimsPrincipal on HttpContext.User
            var ticket = new AuthenticationTicket(newPrincipal, string.Join(";", policy.AuthenticationSchemes));  //<-----------emmm, looks like failed scheme is included ticket
                                                                                                                  // along with successful scheme
            // ExpiresUtc is the easiest property to reason about when dealing with multiple schemes
            // SignalR will use this property to evaluate auth expiration for long running connections
            ticket.Properties.ExpiresUtc = minExpiresUtc;
            return AuthenticateResult.Success(ticket);
         }
         else
         {
            context.User = new ClaimsPrincipal(new ClaimsIdentity());  // <-------------------------that's how you set a unauthenticated user
            return AuthenticateResult.NoResult();
         }
      }

      return context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult ?? DefaultAuthenticateResult(context);

      static AuthenticateResult DefaultAuthenticateResult(HttpContext context)
      {
         return (context.User?.Identity?.IsAuthenticated ?? false)
            ? AuthenticateResult.Success(new AuthenticationTicket(context.User, "context.User")) : AuthenticateResult.NoResult();
      }
   }

   public virtual async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource)
   { 
      var result = await _authorization.AuthorizeAsync(context.User, resource, policy);   // <------------------------b4.1  via extension method on IAuthorizationService
      if (result.Succeeded)
         return PolicyAuthorizationResult.Success();
 
      // If authentication was successful, return forbidden, otherwise challenge
      return (authenticationResult.Succeeded) ?   // <--------------------------------- authenticationResult is used here to differentiate Forbid or Challenge result
         PolicyAuthorizationResult.Forbid(result.Failure) : PolicyAuthorizationResult.Challenge();  // <-------------------b4.2 that's how 401 and 403 result get determined
    }
}
//--------------------------Ʌ
```

```C#
//--------------------------------------------V
internal sealed class AuthorizationPolicyCache : IDisposable
{
   private readonly DataSourceDependentCache<ConcurrentDictionary<Endpoint, AuthorizationPolicy>> _policyCache;

   public AuthorizationPolicyCache(EndpointDataSource dataSource)
   {
      // We cache AuthorizationPolicy instances per-Endpoint for performance, but we want to wipe out
      // that cache if the endpoints change so that we don't allow unbounded memory growth.
      _policyCache = new DataSourceDependentCache<ConcurrentDictionary<Endpoint, AuthorizationPolicy>>(dataSource, (_) =>
      {
         // We don't eagerly fill this cache because there's no real reason to.
         eturn new ConcurrentDictionary<Endpoint, AuthorizationPolicy>();
      });
      _policyCache.EnsureInitialized();
   }

   public AuthorizationPolicy? Lookup(Endpoint endpoint)
   {
      _policyCache.Value!.TryGetValue(endpoint, out var policy);
      return policy;
   }
 
   public void Store(Endpoint endpoint, AuthorizationPolicy policy)
   {
      _policyCache.Value![endpoint] = policy;
   }
 
   public void Dispose()
   {
       _policyCache.Dispose();
   }
}
//--------------------------------------------Ʌ

//--------------------------------------V
public class DefaultAuthorizationService : IAuthorizationService
{
   private readonly AuthorizationOptions _options;
   private readonly IAuthorizationHandlerContextFactory _contextFactory;
   private readonly IAuthorizationHandlerProvider _handlers;
   private readonly IAuthorizationEvaluator _evaluator;
   private readonly IAuthorizationPolicyProvider _policyProvider;
   private readonly ILogger _logger;

   public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
   {
      _options = options.Value;
      _handlers = handlers;
      _policyProvider = policyProvider;
      _logger = logger;
      _evaluator = evaluator;
      _contextFactory = contextFactory;
   }

   public virtual async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
   {
      AuthorizationHandlerContext authContext =                        // <-------------------------------------------------------------b4.1.2
         _contextFactory.CreateContext(requirements, user, resource);  // IAuthorizationRequirement/s is injected into authContext
                                                                       // which will be passed to each IAuthorizationHandler
      IEnumerable<IAuthorizationHandler> handlers = 
         await _handlers.GetHandlersAsync(authContext).ConfigureAwait(false); // <--------get all user-defined IAuthorizationHandler and default PassThroughAuthorizationHandler 
                                                                              
      foreach (var handler in handlers)
      {
         await handler.HandleAsync(authContext).ConfigureAwait(false);   // <-----------------------------b4.1.3. call user-defined IAuthorizationHandler
         if (!_options.InvokeHandlersAfterFailure && authContext.HasFailed)
         {
            break;
         }
      }
 
      AuthorizationResult result = _evaluator.Evaluate(authContext);
      if (result.Succeeded)
      {
         _logger.UserAuthorizationSucceeded();
      }
      else
      {
         _logger.UserAuthorizationFailed(result.Failure);
      }
      
      return result;
   }

   public virtual async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName)
   { 
      AuthorizationPolicy policy = await _policyProvider.GetPolicyAsync(policyName).ConfigureAwait(false);
      if (policy == null)
         throw new InvalidOperationException($"No policy found: {policyName}.");

      return await this.AuthorizeAsync(user, resource, policy).ConfigureAwait(false);
   }
}
//--------------------------------------Ʌ

//---------------------------------------------------->>
public interface IAuthorizationMiddlewareResultHandler   // allow custom handling of authorization and handling of the authorization response
{
   Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult);
}
//----------------------------------------------------<<

//-----------------------------------------------V
public class AuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
   public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)  // <---------b5.1.
   {
      if (authorizeResult.Succeeded)
      {
         return next(context);
      }

      return Handle();

      async Task Handle()
      {
         if (authorizeResult.Challenged)
         {
            if (policy.AuthenticationSchemes.Count > 0)
            {
               foreach (var scheme in policy.AuthenticationSchemes)
               {
                  await context.ChallengeAsync(scheme); // <---------call IAuthenticationService.ChallengeAsync() which calls user-defined IAuthenticationHandler.ChallengeAsync()
               }
            }
            else
            {
               await context.ChallengeAsync();
            }
         }
         else if (authorizeResult.Forbidden)
         {
            if (policy.AuthenticationSchemes.Count > 0)
            {
               foreach (var scheme in policy.AuthenticationSchemes)
               {
                  await context.ForbidAsync(scheme);  // <---------call IAuthenticationService.ForbidAsync() which calls user-defined IAuthenticationHandler.ForbidAsync()
               }
            }
            else
            {
               await context.ForbidAsync();
            }
         }
      }
   }
}  // now you see how AuthorizationMiddleware actually calls IAuthenticationHandler which are not being called during authentication process
//-----------------------------------------------Ʌ

//---------------------------------------------V
public class DefaultAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
   private readonly AuthorizationOptions _options;
   private Task<AuthorizationPolicy>? _cachedDefaultPolicy;
   private Task<AuthorizationPolicy?>? _cachedFallbackPolicy;

   public DefaultAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options)
   {
      _options = options.Value;
   }

   public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
   {
      if (_cachedDefaultPolicy == null || _cachedDefaultPolicy.Result != _options.DefaultPolicy)
      {
         _cachedDefaultPolicy = Task.FromResult(_options.DefaultPolicy);
      }
 
      return _cachedDefaultPolicy;
   }

   public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
   {
      if (_cachedFallbackPolicy == null || _cachedFallbackPolicy.Result != _options.FallbackPolicy)
      {
         _cachedFallbackPolicy = Task.FromResult(_options.FallbackPolicy);
      }
 
      return _cachedFallbackPolicy;
   }

   public virtual Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
   {
      // MVC caches policies specifically for this class, so this method MUST return the same policy per
      // policyName for every request or it could allow undesired access. It also must return synchronously.
      // A change to either of these behaviors would require shipping a patch of MVC as well.
      return _options.GetPolicyTask(policyName);
   }

   public virtual bool AllowsCachingPolicies => GetType() == typeof(DefaultAuthorizationPolicyProvider);
}
//---------------------------------------------Ʌ

//-------------------------------V
public class AuthorizationOptions
{
   private static readonly Task<AuthorizationPolicy?> _nullPolicyTask = Task.FromResult<AuthorizationPolicy?>(null);

   private Dictionary<string, Task<AuthorizationPolicy?>> PolicyMap { get; } = new Dictionary<string, Task<AuthorizationPolicy?>>(StringComparer.OrdinalIgnoreCase);

   public bool InvokeHandlersAfterFailure { get; set; } = true;

   public AuthorizationPolicy DefaultPolicy { get; set; } = 
      new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();  // <------------------------use DenyAnonymousAuthorization as default policy

   public AuthorizationPolicy? FallbackPolicy { get; set; }

   public void AddPolicy(string name, AuthorizationPolicy policy)
   { 
      PolicyMap[name] = Task.FromResult<AuthorizationPolicy?>(policy);
   }

   public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
   {
      var policyBuilder = new AuthorizationPolicyBuilder();
      configurePolicy(policyBuilder);
      PolicyMap[name] = Task.FromResult<AuthorizationPolicy?>(policyBuilder.Build());
   }

   public AuthorizationPolicy? GetPolicy(string name)
   { 
      if (PolicyMap.TryGetValue(name, out var value))
      {
         return value.Result;
      }
 
      return null;
   }

   internal Task<AuthorizationPolicy?> GetPolicyTask(string name)
   { 
      if (PolicyMap.TryGetValue(name, out var value))
      {
         return value;
      }
 
      return _nullPolicyTask;
   }
}
//-------------------------------Ʌ

//-----------------------------------------V
public class ClaimsAuthorizationRequirement : AuthorizationHandler<ClaimsAuthorizationRequirement>, IAuthorizationRequirement
{
   private readonly bool _emptyAllowedValues;

   public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string>? allowedValues)
   { 
      ClaimType = claimType;
      AllowedValues = allowedValues;
      _emptyAllowedValues = AllowedValues == null || !AllowedValues.Any();
   }

   public string ClaimType { get; }
   public IEnumerable<string>? AllowedValues { get; }
   
   protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
   {
      if (context.User != null)
      {
         var found = false;
         if (requirement._emptyAllowedValues)
         {
            foreach (var claim in context.User.Claims)
            {
               if (string.Equals(claim.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase))
               {
                  found = true;
                  break;
               }
            }
         }
         else
         {
            foreach (var claim in context.User.Claims)
            {
               if (string.Equals(claim.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase) && requirement.AllowedValues!.Contains(claim.Value, StringComparer.Ordinal))
               {
                  found = true;
                  break;
               }
            }
         }
         if (found)
         {
            context.Succeed(requirement);
         }
      }

      return Task.CompletedTask;
   }
}
//-----------------------------------------Ʌ

//----------------------------------------V
public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
{
    public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
    {
        ArgumentNullThrowHelper.ThrowIfNull(allowedRoles);
 
        if (!allowedRoles.Any())
        {
            throw new InvalidOperationException(Resources.Exception_RoleRequirementEmpty);
        }
        AllowedRoles = allowedRoles;
    }

    public IEnumerable<string> AllowedRoles { get; }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
    {
        if (context.User != null)
        {
            var found = false;
 
            foreach (var role in requirement.AllowedRoles)
            {
                if (context.User.IsInRole(role))
                {
                    found = true;
                    break;
                }
            }
 
            if (found)
            {
                context.Succeed(requirement);
            }
        }
        return Task.CompletedTask;
    }
}
//----------------------------------------Ʌ

//-------------------------------V
public class AssertionRequirement : IAuthorizationHandler, IAuthorizationRequirement
{
    public Func<AuthorizationHandlerContext, Task<bool>> Handler { get; }

    public AssertionRequirement(Func<AuthorizationHandlerContext, bool> handler)
    { 
        Handler = context => Task.FromResult(handler(context));
    }

    public AssertionRequirement(Func<AuthorizationHandlerContext, Task<bool>> handler)
    { 
        Handler = handler;
    }

    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        if (await Handler(context).ConfigureAwait(false))
        {
            context.Succeed(this);
        }
    }
}
//-------------------------------Ʌ

//------------------------------------------V
public class PassThroughAuthorizationHandler : IAuthorizationHandler
{
   private readonly AuthorizationOptions _options;

   public PassThroughAuthorizationHandler() : this(Options.Create(new AuthorizationOptions())) { }

   public PassThroughAuthorizationHandler(IOptions<AuthorizationOptions> options) => _options = options.Value;

   public async Task HandleAsync(AuthorizationHandlerContext context)
   {
      foreach (var handler in context.Requirements.OfType<IAuthorizationHandler>())
      {
         await handler.HandleAsync(context).ConfigureAwait(false);
         if (!_options.InvokeHandlersAfterFailure && context.HasFailed)
         {
            break;
         }
      }
   }
}
//------------------------------------------Ʌ

//----------------------------------------------V
public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
{
   private readonly Task<IEnumerable<IAuthorizationHandler>> _handlersTask;

   public DefaultAuthorizationHandlerProvider(IEnumerable<IAuthorizationHandler> handlers)
   { 
      _handlersTask = Task.FromResult(handlers);
   }

   public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(AuthorizationHandlerContext context)
      => _handlersTask;
}
//----------------------------------------------Ʌ

//----------------------------------------V
public class DefaultAuthorizationEvaluator : IAuthorizationEvaluator
{
   public AuthorizationResult Evaluate(AuthorizationHandlerContext context)
      => context.HasSucceeded
         ? AuthorizationResult.Success()
         : AuthorizationResult.Failed(context.HasFailed
            ? AuthorizationFailure.Failed(context.FailureReasons)
            : AuthorizationFailure.Failed(context.PendingRequirements));
}
//----------------------------------------Ʌ

//----------------------------------------------------V
public class DefaultAuthorizationHandlerContextFactory : IAuthorizationHandlerContextFactory
{
   public virtual AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
   {
      return new AuthorizationHandlerContext(requirements, user, resource);
   }
}
//----------------------------------------------------Ʌ

//------------------------------------------V
public class PassThroughAuthorizationHandler : IAuthorizationHandler
{
   private readonly AuthorizationOptions _options;

   public PassThroughAuthorizationHandler() : this(Options.Create(new AuthorizationOptions())) { }

   public PassThroughAuthorizationHandler(IOptions<AuthorizationOptions> options)
      => _options = options.Value;

   public async Task HandleAsync(AuthorizationHandlerContext context)
   {
      foreach (var handler in context.Requirements.OfType<IAuthorizationHandler>())
      {
         await handler.HandleAsync(context).ConfigureAwait(false);
         if (!_options.InvokeHandlersAfterFailure && context.HasFailed)
         {
            break;
         }
      }
   }
}
//------------------------------------------Ʌ

//-------------------------------------V
public class AuthorizationFailureReason
{
   public AuthorizationFailureReason(IAuthorizationHandler handler, string message)
   {
      Handler = handler;
      Message = message;
   }

   public string Message { get; }
   public IAuthorizationHandler Handler { get; }
}
//-------------------------------------Ʌ

//----------------------------------V
public class AllowAnonymousAttribute : Attribute, IAllowAnonymous
{
   public override string ToString()
   {
      return "AllowAnonymous";
   }
}
//----------------------------------Ʌ

//---------------------------------------V
public class NameAuthorizationRequirement : AuthorizationHandler<NameAuthorizationRequirement>, IAuthorizationRequirement
{
   public NameAuthorizationRequirement(string requiredName)
   { 
      RequiredName = requiredName;
   }

   public string RequiredName { get; }

   protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NameAuthorizationRequirement requirement)
   {
      if (context.User != null)
      {
         var succeed = false;
 
         foreach (var identity in context.User.Identities)
         {
            if (string.Equals(identity.Name, requirement.RequiredName, StringComparison.Ordinal))
            {
               succeed = true;
               break;
            }
         }
 
         if (succeed)
         {
            context.Succeed(requirement);
         }
      }
      return Task.CompletedTask;
   }
}
//---------------------------------------Ʌ

//------------------------------------------------V
public class DenyAnonymousAuthorizationRequirement : AuthorizationHandler<DenyAnonymousAuthorizationRequirement>, IAuthorizationRequirement
{
   protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
   {
      var user = context.User;
      var userIsAnonymous = user?.Identity == null || !user.Identities.Any(i => i.IsAuthenticated);
      
      if (!userIsAnonymous)
      {
         context.Succeed(requirement);
      }

      return Task.CompletedTask;
   }
}
//------------------------------------------------Ʌ
```

```C#
//-----------------------------------------V
public interface IHttpAuthenticationFeature
{
   ClaimsPrincipal? User { get; set; }
}
//-----------------------------------------Ʌ

//-----------------------------------------V
public interface IAuthenticateResultFeature
{
   AuthenticateResult? AuthenticateResult { get; set; }
}
//-----------------------------------------Ʌ

//------------------------------------------V
internal sealed class AuthenticationFeatures : IAuthenticateResultFeature, IHttpAuthenticationFeature
{
   private ClaimsPrincipal? _user;
   private AuthenticateResult? _result;

   public AuthenticationFeatures(AuthenticateResult result)
   {
      AuthenticateResult = result;
   }

   public AuthenticateResult? AuthenticateResult
   {
      get => _result;
      set
      {
         _result = value;
         _user = _result?.Principal;
      }
   }

   public ClaimsPrincipal? User
   {
      get => _user;
      set
      {
         _user = value;
         _result = null;
      }
   }
}
//------------------------------------------Ʌ
```

========================================================================================================

```C#
/*
public static class ClaimTypes
{
   public const string Actor = "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor";
   public const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
   public const string Rsa = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa";
   public const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
   public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
   public const string Gender = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";
   public const string GivenName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
   // ...
}
*/

//----------------V
public class Claim
{
   private enum SerializationMask
   {
      None = 0,
      NameClaimType = 1,
      RoleClaimType = 2,
      StringType = 4,
      Issuer = 8,
      OriginalIssuerEqualsIssuer = 16,
      OriginalIssuer = 32,
      HasProperties = 64,
      UserData = 128,
   }
   
   private readonly byte[] _userSerializationData;
 
   private readonly string _issuer;
   private readonly string _originalIssuer;
   private Dictionary<string, string> _properties;
 
   private readonly ClaimsIdentity _subject;  // <---------------------
   private readonly string _type;
   private readonly string _value;
   private readonly string _valueType;

   public Claim(BinaryReader reader) : this(reader, null) { }

   public Claim(BinaryReader reader, ClaimsIdentity subject)
   {
      _subject = subject;

      SerializationMask mask = (SerializationMask)reader.ReadInt32();
      int numPropertiesRead = 1;
      int numPropertiesToRead = reader.ReadInt32();
      _value = reader.ReadString();

      if ((mask & SerializationMask.NameClaimType) == SerializationMask.NameClaimType) {
         _type = ClaimsIdentity.DefaultNameClaimType;
      }
      else if ((mask & SerializationMask.RoleClaimType) == SerializationMask.RoleClaimType) {
         _type = ClaimsIdentity.DefaultRoleClaimType;
      }
      else {
         _type = reader.ReadString();
      }

      // ...
   }

   public Claim(string type, string value) : this(type, value, ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultIssuer, (ClaimsIdentity?)null) { }

   public Claim(string type, string value, string? valueType) : this(type, value, valueType, ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultIssuer, (ClaimsIdentity?)null) { }

   protected Claim(Claim other) : this(other, (other == null ? (ClaimsIdentity)null : other._subject)) { }

   protected Claim(Claim other, ClaimsIdentity? subject) {
       // ...
   }

   public Claim(string type, string value) : this(type, value, ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultIssuer, (ClaimsIdentity?)null) { }

   internal Claim(string type, string value, string valueType, string issuer, string originalIssuer, ClaimsIdentity subject, string propertyKey, string propertyValue)
   {
      _type = type;
      _value = value;
      _valueType = string.IsNullOrEmpty(valueType) ? ClaimValueTypes.String : valueType;
      _issuer = string.IsNullOrEmpty(issuer) ? ClaimsIdentity.DefaultIssuer : issuer;
      _originalIssuer = string.IsNullOrEmpty(originalIssuer) ? _issuer : originalIssuer;
      _subject = subject;
 
      if (propertyKey != null)
      {
         _properties = new Dictionary<string, string>();
         _properties[propertyKey] = propertyValue!;
      }
   }

   protected virtual byte[] CustomSerializationData => _userSerializationData;

   //
   public string Issuer => _issuer;

   public string OriginalIssuer => _originalIssuer;

   public IDictionary<string, string> Properties => _properties ??= new Dictionary<string, string>();

   public ClaimsIdentity Subject => _subject;

   public string Type => _type;

   public string Value => _value;

   public string ValueType => _valueType;
   //

   public virtual Claim Clone()
   {
      return Clone((ClaimsIdentity)null);
   }

   public virtual Claim Clone(ClaimsIdentity identity)
   {
      return new Claim(this, identity);
   }

   public virtual void WriteTo(BinaryWriter writer)
   {
      WriteTo(writer, null);
   }

   protected virtual void WriteTo(BinaryWriter writer, byte[] userData)
   {
      // ...
   }
   public override string ToString()
   {
      return _type + ": " + _value;
   }
}
//----------------Ʌ

//------------------------>>
public interface IIdentity
{
   string AuthenticationType { get; }
   bool IsAuthenticated { get; }
   string Name { get; }
}
//------------------------<<

//-------------------------V
public class ClaimsIdentity : IIdentity
{
   private enum SerializationMask
   {
      None = 0,
      AuthenticationType = 1,
      BootstrapConext = 2,
      NameClaimType = 4,
      RoleClaimType = 8,
      HasClaims = 16,
      HasLabel = 32,
      Actor = 64,
      UserData = 128,
   }

   private byte[]? _userSerializationData;
   private ClaimsIdentity? _actor;   // <--------------------
   private string? _authenticationType;
   private object? _bootstrapContext;
   private List<List<Claim>>? _externalClaims;
   private string? _label;
   private readonly List<Claim> _instanceClaims = new List<Claim>();   // <--------------------
   private string _nameClaimType = DefaultNameClaimType;   // <-------
   private string _roleClaimType = DefaultRoleClaimType;
 
   public const string DefaultIssuer = @"LOCAL AUTHORITY";
   public const string DefaultNameClaimType = ClaimTypes.Name;
   public const string DefaultRoleClaimType = ClaimTypes.Role;

   public ClaimsIdentity() : this((IIdentity?)null, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity identity) : this(identity, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType) : this((IIdentity?)null, (IEnumerable<Claim>?)null, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType) : this((IIdentity?)null, claims, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims) : this(identity, claims, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType)
   {
      ClaimsIdentity? claimsIdentity = identity as ClaimsIdentity;

      _authenticationType = (identity != null && string.IsNullOrEmpty(authenticationType)) ? identity.AuthenticationType : authenticationType;
      _nameClaimType = !string.IsNullOrEmpty(nameType) ? nameType : (claimsIdentity != null ? claimsIdentity._nameClaimType : DefaultNameClaimType);
      _roleClaimType = !string.IsNullOrEmpty(roleType) ? roleType : (claimsIdentity != null ? claimsIdentity._roleClaimType : DefaultRoleClaimType);

      if (claimsIdentity != null)
      {
         _label = claimsIdentity._label;
         _bootstrapContext = claimsIdentity._bootstrapContext;

         if (claimsIdentity.Actor != null)
         {
            if (!IsCircular(claimsIdentity.Actor))
            {
               _actor = claimsIdentity.Actor;
            }
            else
            {
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);
            }
         }
         SafeAddClaims(claimsIdentity._instanceClaims);
      }
      else {
         if (identity != null && !string.IsNullOrEmpty(identity.Name))
         {
            SafeAddClaim(new Claim(_nameClaimType, identity.Name, ClaimValueTypes.String, DefaultIssuer, DefaultIssuer, this));
         }
      }

      if (claims != null)
      {
         SafeAddClaims(claims);
      }
   }

   public ClaimsIdentity(BinaryReader reader) 
   {
      Initialize(reader);
   }

   protected ClaimsIdentity(ClaimsIdentity other)
   {
      if (other._actor != null)
      {
         _actor = other._actor.Clone();
      }
 
      _authenticationType = other._authenticationType;
      _bootstrapContext = other._bootstrapContext;
      _label = other._label;
      _nameClaimType = other._nameClaimType;
      _roleClaimType = other._roleClaimType;
      if (other._userSerializationData != null)
      {
         _userSerializationData = other._userSerializationData.Clone() as byte[];
      }
 
      SafeAddClaims(other._instanceClaims);
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;

   internal List<List<Claim>> ExternalClaims => _externalClaims ??= new List<List<Claim>>();

   public string? Label { get { return _label; } set { _label = value; } }

   public string NameClaimType => _nameClaimType;   // <------------ClaimTypes.Name;

   public string RoleClaimType => _roleClaimType;   // <------------ClaimTypes.Role;
  
   public virtual string? AuthenticationType => _authenticationType;  // <-------------

   public virtual bool IsAuthenticated => !string.IsNullOrEmpty(_authenticationType);  // <----------        

   public virtual string? Name {   // <--------------------------! ClaimsIdentity.Name is the value of first matching claim, not the "name" of ClaimsIdentity like passport
      get {
         Claim? claim = FindFirst(_nameClaimType);   // _nameClaimType is ClaimTypes.Name
         if (claim != null)
            return claim.Value;
 
         return null;
      }      
   }

   public virtual Claim? FindFirst(string type)
   {
      foreach (Claim claim in Claims)
      {
         if (claim != null)
         {
            if (string.Equals(claim.Type, type, StringComparison.OrdinalIgnoreCase))
            {
               return claim;
            }
         }
      }
 
      return null;
   }

   public ClaimsIdentity? Actor
   {
      get { return _actor; }
      set {
         if (value != null) 
         {
            if (IsCircular(value))
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);                  
         }
         _actor = value;
      }
   } 

   public object? BootstrapContext
   {
      get { return _bootstrapContext; }
      set { _bootstrapContext = value; }
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         if (_externalClaims == null)
             return _instanceClaims;
 
         return CombinedClaimsIterator();
      }
   }

   private IEnumerable<Claim> CombinedClaimsIterator()
   {
      for (int i = 0; i < _instanceClaims.Count; i++)
         yield return _instanceClaims[i];
 
      for (int j = 0; j < _externalClaims!.Count; j++)
      {
         if (_externalClaims[j] != null)
         {
            foreach (Claim claim in _externalClaims[j])
               yield return claim;
         }
      }
   }

   public virtual void AddClaim(Claim claim)
   {
      if (object.ReferenceEquals(claim.Subject, this))
         _instanceClaims.Add(claim);
      else
         _instanceClaims.Add(claim.Clone(this));
   }

   public virtual void AddClaims(IEnumerable<Claim?> claims)
   {
      foreach (Claim? claim in claims)
      {
         if (claim == null)
            continue;

         if (object.ReferenceEquals(claim.Subject, this))
         {
            _instanceClaims.Add(claim);
         }
         else
         {
            _instanceClaims.Add(claim.Clone(this));
         }
      }
   }

   // no ArgumentNullException.ThrowIfNull(claims);
   private void SafeAddClaim(Claim? claim);
   private void SafeAddClaims(IEnumerable<Claim?> claims);
   //

   public virtual bool TryRemoveClaim(Claim? claim)
   {
      if (claim == null)
         return false;
 
      bool removed = false;
 
      for (int i = 0; i < _instanceClaims.Count; i++)
      {
         if (object.ReferenceEquals(_instanceClaims[i], claim))
         {
            _instanceClaims.RemoveAt(i);
            removed = true;
            break;
         }
      }
      return removed;
   }

   public virtual void RemoveClaim(Claim? claim)
   {
      if (!TryRemoveClaim(claim))
         throw new InvalidOperationException(SR.Format(SR.InvalidOperation_ClaimCannotBeRemoved, claim));
            
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (Claim claim in Claims)
         {
            if (match(claim))
               yield return claim;
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type);

   public virtual bool HasClaim(Predicate<Claim> match);

   public virtual bool HasClaim(string type, string value)
   {
      foreach (Claim claim in Claims)
      {
         if (claim != null && string.Equals(claim.Type, type, StringComparison.OrdinalIgnoreCase) && string.Equals(claim.Value, value, StringComparison.Ordinal))
         {
            return true;
         }
      }
 
      return false;
   }

   private bool IsCircular(ClaimsIdentity subject)
   {
      if (ReferenceEquals(this, subject))
         return true;
 
      ClaimsIdentity currSubject = subject;
 
      while (currSubject.Actor != null)
      {
         if (ReferenceEquals(this, currSubject.Actor))
            return true;
 
         currSubject = currSubject.Actor;
      }
 
      return false;
   }

   // ...  BinaryWriter related methods leaved out

   public virtual ClaimsIdentity Clone()
   {
      return new ClaimsIdentity(this);
   }
}
//-------------------------Ʌ

//------------------------->>
public interface IPrincipal
{
   IIdentity Identity { get; }
   bool IsInRole(string role);
}
//-------------------------<<

//--------------------------V
public class ClaimsPrincipal : IPrincipal
{
   private enum SerializationMask
   {
      None = 0,
      HasIdentities = 1,
      UserData = 2
   }

   private readonly List<ClaimsIdentity> _identities = new List<ClaimsIdentity>();  //<--------------------------

   private readonly byte[]? _userSerializationData;
 
   private static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> s_identitySelector = SelectPrimaryIdentity;
   private static Func<ClaimsPrincipal> s_principalSelector = ClaimsPrincipalSelector;
 
   public ClaimsPrincipal() { }

   public ClaimsPrincipal(IEnumerable<ClaimsIdentity> identities)
   {
      _identities.AddRange(identities);
   }

   public ClaimsPrincipal(IIdentity identity)
   { 
      if (identity is ClaimsIdentity ci)
         identities.Add(ci);
      else
         _identities.Add(new ClaimsIdentity(identity));
   }

   public ClaimsPrincipal(IPrincipal principal)
   {
      ClaimsPrincipal? cp = principal as ClaimsPrincipal;
      if (null == cp)
         _identities.Add(new ClaimsIdentity(principal.Identity));
      else
         if (null != cp.Identities)
            _identities.AddRange(cp.Identities);          
   }

   private static ClaimsPrincipal? SelectClaimsPrincipal()
   {
      IPrincipal? threadPrincipal = Thread.CurrentPrincipal;
 
      return threadPrincipal switch {
         ClaimsPrincipal claimsPrincipal => claimsPrincipal, not null => new ClaimsPrincipal(threadPrincipal), null => null
      };
   }

   private static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)   // <-----------------------
   { 
      foreach (ClaimsIdentity identity in identities)
      {
         if (identity != null)        
            return identity;              
      }
 
      return null;
   }

   public static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> PrimaryIdentitySelector
   {
      get {
         return s_identitySelector;
      }
      set {
         s_identitySelector = value;
      }
   }

   public static Func<ClaimsPrincipal> ClaimsPrincipalSelector
   {
      get {
         return s_principalSelector;
      }
      set {
         s_principalSelector = value;
      }
   }

   public virtual void AddIdentity(ClaimsIdentity identity)
   { 
      _identities.Add(identity);
   }

   public virtual void AddIdentities(IEnumerable<ClaimsIdentity> identities)
   { 
      _identities.AddRange(identities);
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         foreach (ClaimsIdentity identity in Identities) {
            foreach (Claim claim in identity.Claims) {
               yield return claim;
            }
         }
      }
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;
  
   public virtual ClaimsPrincipal Clone() => new ClaimsPrincipal(this);

   public static ClaimsPrincipal? Current
   {
      get {
         return s_principalSelector is not null ? s_principalSelector() : SelectClaimsPrincipal();
      }
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (ClaimsIdentity identity in Identities)
         {
            if (identity != null)
            {
               foreach (Claim claim in identity.FindAll(match))                 
                  yield return claim;                       
            }
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type)
   {
      Claim? claim = null;
 
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            claim = _identities[i].FindFirst(type);
            if (claim != null)
            {
               return claim;
            }
         }
      }
 
      return claim;
   }

   public virtual bool HasClaim(Predicate<Claim> match)
   { 
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(match))                   
               return true;                  
         }
      }
 
      return false;
   }

   public virtual bool HasClaim(string type, string value);

   public virtual IEnumerable<ClaimsIdentity> Identities => _identities;  // <-----------------

   public virtual System.Security.Principal.IIdentity? Identity {  // <-----------------
      get {
         if (s_identitySelector != null)                
            return s_identitySelector(_identities);               
         else               
            return SelectPrimaryIdentity(_identities);               
      }
   }

   public virtual bool IsInRole(string role)
   {
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(_identities[i].RoleClaimType, role))             
               return true;                  
         }
      }
 
      return false;
   }
}
//--------------------------Ʌ

//------------------------------------->>
public static class PrincipalExtensions
{
    public static string? FindFirstValue(this ClaimsPrincipal principal, string claimType)
    {
        var claim = principal.FindFirst(claimType);
        return claim?.Value;
    }
}
//-------------------------------------<<

//----------------------------------V
internal static class SecurityHelper
{
   public static ClaimsPrincipal MergeUserPrincipal(ClaimsPrincipal? existingPrincipal, ClaimsPrincipal? additionalPrincipal)
   {
      if (existingPrincipal == null && additionalPrincipal != null)
      {
         return additionalPrincipal;
      }

      var newPrincipal = new ClaimsPrincipal();

      // new principal identities go first
      if (additionalPrincipal != null)
      {
         newPrincipal.AddIdentities(additionalPrincipal.Identities);
      }

      // then add any existing non empty or authenticated identities
      if (existingPrincipal != null)
      {
         newPrincipal.AddIdentities(existingPrincipal.Identities.Where(i => i.IsAuthenticated || i.Claims.Any()));
      }

      return newPrincipal;

   }
}
//----------------------------------Ʌ

//------------------------------------V
public class PolicyAuthorizationResult
{
   private static readonly PolicyAuthorizationResult _challengedResult = new() { Challenged = true };
   private static readonly PolicyAuthorizationResult _forbiddenResult = new() { Forbidden = true };
   private static readonly PolicyAuthorizationResult _succeededResult = new() { Succeeded = true };

   private PolicyAuthorizationResult() { }

   public bool Challenged { get; private set; }
   public bool Forbidden { get; private set; }
   public bool Succeeded { get; private set; }

   public static PolicyAuthorizationResult Challenge() => _challengedResult;
   public static PolicyAuthorizationResult Forbid() => _forbiddenResult;
   public static PolicyAuthorizationResult Success() => _succeededResult;

   public AuthorizationFailure? AuthorizationFailure { get; private set; }

   public static PolicyAuthorizationResult Forbid(AuthorizationFailure? authorizationFailure)
      => authorizationFailure is null ? _forbiddenResult : new PolicyAuthorizationResult { Forbidden = true, AuthorizationFailure = authorizationFailure };
}
//------------------------------------Ʌ
```

##

```C#
//---------------------------V
public interface ITicketStore
{
   Task<string> StoreAsync(AuthenticationTicket ticket);
   Task<string> StoreAsync(AuthenticationTicket ticket, CancellationToken cancellationToken) => StoreAsync(ticket);
   Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken) => StoreAsync(ticket, cancellationToken);
   Task RenewAsync(string key, AuthenticationTicket ticket);
   Task RenewAsync(string key, AuthenticationTicket ticket, CancellationToken cancellationToken) => RenewAsync(key, ticket);
   Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken) => RenewAsync(key, ticket, cancellationToken);
   Task<AuthenticationTicket?> RetrieveAsync(string key);
   Task<AuthenticationTicket?> RetrieveAsync(string key, CancellationToken cancellationToken) => RetrieveAsync(key);
   Task<AuthenticationTicket?> RetrieveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken) => RetrieveAsync(key, cancellationToken);
   Task RemoveAsync(string key);
   Task RemoveAsync(string key, CancellationToken cancellationToken) => RemoveAsync(key);
   Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken) => RemoveAsync(key, cancellationToken);
}
//---------------------------Ʌ

//------------------------------V
public class AuthenticationToken
{
    public string Name { get; set; } = default!;
    public string Value { get; set; } = default!;
}
//------------------------------Ʌ

//-----------------------------------------------V
public static class AuthenticationTokenExtensions
{
    private const string TokenNamesKey = ".TokenNames";
    private const string TokenKeyPrefix = ".Token.";

    public static void StoreTokens(this AuthenticationProperties properties, IEnumerable<AuthenticationToken> tokens)  // <----------------
    {
        // Clear old tokens first
        var oldTokens = properties.GetTokens();
        foreach (var t in oldTokens)
        {
            properties.Items.Remove(TokenKeyPrefix + t.Name);
        }
        properties.Items.Remove(TokenNamesKey);
 
        var tokenNames = new List<string>();
        foreach (var token in tokens)
        {
            if (token.Name is null)
            {
                throw new ArgumentException("Token name cannot be null for any token.", nameof(tokens));
            }
 
            // REVIEW: should probably check that there are no ; in the token name and throw or encode
            tokenNames.Add(token.Name);
            properties.Items[TokenKeyPrefix + token.Name] = token.Value;
        }
 
        if (tokenNames.Count > 0)
        {
            properties.Items[TokenNamesKey] = string.Join(";", tokenNames);
        }
    }

    public static string? GetTokenValue(this AuthenticationProperties properties, string tokenName)
    {
        var tokenKey = TokenKeyPrefix + tokenName;
 
        return properties.Items.TryGetValue(tokenKey, out var value) ? value : null;
    }

    public static bool UpdateTokenValue(this AuthenticationProperties properties, string tokenName, string tokenValue)
    {
        var tokenKey = TokenKeyPrefix + tokenName;
        if (!properties.Items.ContainsKey(tokenKey))
        {
            return false;
        }
        properties.Items[tokenKey] = tokenValue;
        return true;
    }

    public static IEnumerable<AuthenticationToken> GetTokens(this AuthenticationProperties properties)
    { 
        var tokens = new List<AuthenticationToken>();
        if (properties.Items.TryGetValue(TokenNamesKey, out var value) && !string.IsNullOrEmpty(value))
        {
            var tokenNames = value.Split(';');
            foreach (var name in tokenNames)
            {
                var token = properties.GetTokenValue(name);
                if (token != null)
                {
                    tokens.Add(new AuthenticationToken { Name = name, Value = token });
                }
            }
        }
 
        return tokens;
    }

    public static Task<string?> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string tokenName)
        => auth.GetTokenAsync(context, scheme: null, tokenName: tokenName);

    public static async Task<string?> GetTokenAsync(this IAuthenticationService auth, HttpContext context, string? scheme, string tokenName)
    {
        var result = await auth.AuthenticateAsync(context, scheme);
        return result?.Properties?.GetTokenValue(tokenName);
    }
}
//-----------------------------------------------Ʌ
```

