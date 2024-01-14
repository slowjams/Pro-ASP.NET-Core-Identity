Project with Source Code
==============================

```C#
public class Startup
{
    public Startup(IConfiguration config) => Configuration = config;

    private IConfiguration Configuration { get; set; }

    public void ConfigureServices(IServiceCollection services)
    {
        // ...
        services.AddDbContext<IdentityDbContext>(opts =>
        {
            opts.UseSqlServer(Configuration["ConnectionStrings:IdentityConnection"], opts => opts.MigrationsAssembly("IdentityApp"));
        });

        services
           .AddDefaultIdentity<IdentityUser>()              // <---------------dotnet add package Microsoft.Extensions.Identity.Core --version 5.0.0
           .AddEntityFrameworkStores<IdentityDbContext>();  // <---------------dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 5.0.0
    }

    // ...
}
```

Note that compiled razor pages are in https://github.com/dotnet/aspnetcore/tree/main/src/Identity/UI/src/Areas/Identity/Pages

```sql
CREATE TABLE [dbo].[AspNetUsers] (
    [Id]                   NVARCHAR (450)     NOT NULL,
    [UserName]             NVARCHAR (256)     NULL,
    [NormalizedUserName]   NVARCHAR (256)     NULL,
    [Email]                NVARCHAR (256)     NULL,
    [NormalizedEmail]      NVARCHAR (256)     NULL,
    [EmailConfirmed]       BIT                NOT NULL,
    [PasswordHash]         NVARCHAR (MAX)     NULL,
    [SecurityStamp]        NVARCHAR (MAX)     NULL,
    [ConcurrencyStamp]     NVARCHAR (MAX)     NULL,
    [PhoneNumber]          NVARCHAR (MAX)     NULL,
    [PhoneNumberConfirmed] BIT                NOT NULL,
    [TwoFactorEnabled]     BIT                NOT NULL,
    [LockoutEnd]           DATETIMEOFFSET (7) NULL,
    [LockoutEnabled]       BIT                NOT NULL,
    [AccessFailedCount]    INT                NOT NULL
);

CREATE TABLE [dbo].[AspNetUserClaims] (
    [Id]         INT            IDENTITY (1, 1) NOT NULL,
    [UserId]     NVARCHAR (450) NOT NULL,
    [ClaimType]  NVARCHAR (MAX) NULL,
    [ClaimValue] NVARCHAR (MAX) NULL
);

CREATE TABLE [dbo].[AspNetRoles] (
    [Id]               NVARCHAR (450) NOT NULL,
    [Name]             NVARCHAR (256) NULL,
    [NormalizedName]   NVARCHAR (256) NULL,
    [ConcurrencyStamp] NVARCHAR (MAX) NULL
);

CREATE TABLE [dbo].[AspNetUserRoles] (
    [UserId] NVARCHAR (450) NOT NULL,
    [RoleId] NVARCHAR (450) NOT NULL
);

CREATE TABLE [dbo].[AspNetRoleClaims] (
    [Id]         INT            IDENTITY (1, 1) NOT NULL,
    [RoleId]     NVARCHAR (450) NOT NULL,
    [ClaimType]  NVARCHAR (MAX) NULL,
    [ClaimValue] NVARCHAR (MAX) NULL
);

CREATE TABLE [dbo].[AspNetUserLogins] (
    [LoginProvider]       NVARCHAR (128) NOT NULL,
    [ProviderKey]         NVARCHAR (128) NOT NULL,
    [ProviderDisplayName] NVARCHAR (MAX) NULL,
    [UserId]              NVARCHAR (450) NOT NULL
);

CREATE TABLE [dbo].[AspNetUserTokens] (
    [UserId]        NVARCHAR (450) NOT NULL,
    [LoginProvider] NVARCHAR (128) NOT NULL,
    [Name]          NVARCHAR (128) NOT NULL,
    [Value]         NVARCHAR (MAX) NULL
);
```

## Source Code 

```C#
//-------------------------------------------------------V
public static class IdentityServiceCollectionUIExtensions
{
    public static IdentityBuilder AddDefaultIdentity<TUser>(this IServiceCollection services)
        => services.AddDefaultIdentity<TUser>(_ => { });

    public static IdentityBuilder AddDefaultIdentity<TUser>(this IServiceCollection services, Action<IdentityOptions> configureOptions) where TUser : class
    {
        services.AddAuthentication(o =>
        {
            o.DefaultScheme = IdentityConstants.ApplicationScheme;
            o.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        })
        .AddIdentityCookies(o => { });
 
        return 
            services.AddIdentityCore<TUser>(o =>
            {
                o.Stores.MaxLengthForKeys = 128;
                configureOptions?.Invoke(o);
            })
            .AddDefaultUI()  // <----------------------------------
            .AddDefaultTokenProviders();
    }
}
//-------------------------------------------------------Ʌ

//---------------------------------------------V
public static class IdentityBuilderUIExtensions
{
    public static IdentityBuilder AddDefaultUI(this IdentityBuilder builder)
    {
        builder.AddSignInManager();
        builder.Services
            .AddMvc()
            .ConfigureApplicationPartManager(apm =>
            {
                // We try to resolve the UI framework that was used by looking at the entry assembly.
                // When an app runs, the entry assembly will point to the built app. In some rare cases
                // (functional testing) the app assembly will be different, and we'll try to locate it through
                // the same mechanism that MVC uses today.
                // Finally, if for some reason we aren't able to find the assembly, we'll use our default value
                // (Bootstrap5)
                if (!TryResolveUIFramework(Assembly.GetEntryAssembly(), out var framework) &&
                    !TryResolveUIFramework(GetApplicationAssembly(builder), out framework))
                {
                    framework = default;
                }
 
                var parts = new ConsolidatedAssemblyApplicationPartFactory().GetApplicationParts(typeof(IdentityBuilderUIExtensions).Assembly);
                foreach (var part in parts)
                {
                    apm.ApplicationParts.Add(part);
                }
                apm.FeatureProviders.Add(new ViewVersionFeatureProvider(framework));
            });
 
        builder.Services.ConfigureOptions(typeof(IdentityDefaultUIConfigureOptions<>).MakeGenericType(builder.UserType));
        builder.Services.TryAddTransient<IEmailSender, NoOpEmailSender>();
        builder.Services.TryAddTransient(typeof(IEmailSender<>), typeof(DefaultMessageEmailSender<>));
 
        return builder;
    }

    private static Assembly? GetApplicationAssembly(IdentityBuilder builder)
    {
        // This is the same logic that MVC follows to find the application assembly.
        var environment = builder.Services.Where(d => d.ServiceType == typeof(IWebHostEnvironment)).ToArray();
        var applicationName = ((IWebHostEnvironment?)environment.LastOrDefault()?.ImplementationInstance)
            ?.ApplicationName;
 
        if (applicationName == null)
        {
            return null;
        }
        var appAssembly = Assembly.Load(applicationName);
        return appAssembly;
    }
 
    private static bool TryResolveUIFramework(Assembly? assembly, out UIFramework uiFramework)
    {
        uiFramework = default;
 
        var metadata = assembly?.GetCustomAttributes<UIFrameworkAttribute>()
            .SingleOrDefault()?.UIFramework; // Bootstrap5 is the default
        if (metadata == null)
        {
            return false;
        }
 
        // If we find the metadata there must be a valid framework here.
        if (!Enum.TryParse(metadata, ignoreCase: true, out uiFramework))
        {
            var enumValues = string.Join(", ", Enum.GetNames(typeof(UIFramework)).Select(v => $"'{v}'"));
            throw new InvalidOperationException(
                $"Found an invalid value for the 'IdentityUIFrameworkVersion'. Valid values are {enumValues}");
        }
 
        return true;
    }

    internal sealed class ViewVersionFeatureProvider : IApplicationFeatureProvider<ViewsFeature>
    {
        private readonly UIFramework _framework;
 
        public ViewVersionFeatureProvider(UIFramework framework) => _framework = framework;
 
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ViewsFeature feature)  // <--------use compiled view from Microsoft.AspNetCore.Identity.UI package that
        {                                                                                      // contains e.g src/Identity/UI/src/Areas/Identity/Pages/V5/Account/Login.cshtml
            var viewsToRemove = new List<CompiledViewDescriptor>();
            foreach (var descriptor in feature.ViewDescriptors)
            {
                if (IsIdentityUIView(descriptor))
                {
                    switch (_framework)
                    {
                        case UIFramework.Bootstrap4:
                            if (descriptor.Type?.FullName?.Contains("V5", StringComparison.Ordinal) is true)
                            {
                                // Remove V5 views
                                viewsToRemove.Add(descriptor);
                            }
                            else
                            {
                                // Fix up paths to eliminate version subdir
                                descriptor.RelativePath = descriptor.RelativePath.Replace("V4/", "");
                            }
                            break;
                        case UIFramework.Bootstrap5:
                            if (descriptor.Type?.FullName?.Contains("V4", StringComparison.Ordinal) is true)
                            {
                                // Remove V4 views
                                viewsToRemove.Add(descriptor);
                            }
                            else
                            {
                                // Fix up paths to eliminate version subdir
                                descriptor.RelativePath = descriptor.RelativePath.Replace("V5/", "");
                            }
                            break;
                        default:
                            throw new InvalidOperationException($"Unknown framework: {_framework}");
                    }
                }
            }
 
            foreach (var descriptorToRemove in viewsToRemove)
            {
                feature.ViewDescriptors.Remove(descriptorToRemove);
            }
        }
 
        private static bool IsIdentityUIView(CompiledViewDescriptor desc) 
            => desc.RelativePath.StartsWith("/Areas/Identity", StringComparison.OrdinalIgnoreCase) && desc.Type?.Assembly == typeof(IdentityBuilderUIExtensions).Assembly;
    }
}
//---------------------------------------------Ʌ

//-------------------------------------------V
public static class IdentityBuilderExtensions
{
    public static IdentityBuilder AddDefaultTokenProviders(this IdentityBuilder builder)
    {
        var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(builder.UserType);
        var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(builder.UserType);
        var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(builder.UserType);
        var authenticatorProviderType = typeof(AuthenticatorTokenProvider<>).MakeGenericType(builder.UserType);
        return builder.AddTokenProvider(TokenOptions.DefaultProvider, dataProtectionProviderType)
            .AddTokenProvider(TokenOptions.DefaultEmailProvider, emailTokenProviderType)
            .AddTokenProvider(TokenOptions.DefaultPhoneProvider, phoneNumberProviderType)
            .AddTokenProvider(TokenOptions.DefaultAuthenticatorProvider, authenticatorProviderType);
    }

    private static void AddSignInManagerDeps(this IdentityBuilder builder)
    {
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped(typeof(ISecurityStampValidator), typeof(SecurityStampValidator<>).MakeGenericType(builder.UserType));
        builder.Services.AddScoped(typeof(ITwoFactorSecurityStampValidator), typeof(TwoFactorSecurityStampValidator<>).MakeGenericType(builder.UserType));
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SecurityStampValidatorOptions>, PostConfigureSecurityStampValidatorOptions>());
    }

    public static IdentityBuilder AddSignInManager(this IdentityBuilder builder)
    {
        builder.AddSignInManagerDeps();
        var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);
        builder.Services.AddScoped(managerType);
        return builder;
    }

    public static IdentityBuilder AddSignInManager<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TSignInManager>(this IdentityBuilder builder) 
    {
        builder.AddSignInManagerDeps();
        var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);
        var customType = typeof(TSignInManager);
        if (!managerType.IsAssignableFrom(customType))
        {
            throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "SignInManager", builder.UserType.Name));
        }
        if (managerType != customType)
        {
            builder.Services.AddScoped(typeof(TSignInManager), services => services.GetRequiredService(managerType));
        }
        builder.Services.AddScoped(managerType, typeof(TSignInManager));
        return builder;
    }

    public static IdentityBuilder AddApiEndpoints(this IdentityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
 
        builder.AddSignInManager();
        builder.AddDefaultTokenProviders();
        builder.Services.TryAddTransient(typeof(IEmailSender<>), typeof(DefaultMessageEmailSender<>));
        builder.Services.TryAddTransient<IEmailSender, NoOpEmailSender>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JsonOptions>, IdentityEndpointsJsonOptionsSetup>());
        return builder;
    }

    private sealed class PostConfigureSecurityStampValidatorOptions : IPostConfigureOptions<SecurityStampValidatorOptions>
    {
        public PostConfigureSecurityStampValidatorOptions(TimeProvider timeProvider)
        {
            TimeProvider = timeProvider;
        }
 
        private TimeProvider TimeProvider { get; }
 
        public void PostConfigure(string? name, SecurityStampValidatorOptions options)
        {
            options.TimeProvider ??= TimeProvider;
        }
    }
}
//-------------------------------------------Ʌ

//---------------------------------------------------------------V
public static class IdentityCookieAuthenticationBuilderExtensions
{
    public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder)
        => builder.AddIdentityCookies(o => { });

    public static IdentityCookiesBuilder AddIdentityCookies(this AuthenticationBuilder builder, Action<IdentityCookiesBuilder> configureCookies)
    {
        var cookieBuilder = new IdentityCookiesBuilder();
        cookieBuilder.ApplicationCookie = builder.AddApplicationCookie();
        cookieBuilder.ExternalCookie = builder.AddExternalCookie();
        cookieBuilder.TwoFactorRememberMeCookie = builder.AddTwoFactorRememberMeCookie();
        cookieBuilder.TwoFactorUserIdCookie = builder.AddTwoFactorUserIdCookie();
        configureCookies?.Invoke(cookieBuilder);
        return cookieBuilder;
    }

    public static OptionsBuilder<CookieAuthenticationOptions> AddApplicationCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(IdentityConstants.ApplicationScheme, o =>  // <-------------calls builder.AddScheme<CookieAuthenticationOptions, CookieAuthenticationHandler>(...)
        {
            o.LoginPath = new PathString("/Account/Login");
            o.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
            };
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.ApplicationScheme);
    }

    public static OptionsBuilder<CookieAuthenticationOptions> AddExternalCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(IdentityConstants.ExternalScheme, o =>  // <-------------------------
        {
            o.Cookie.Name = IdentityConstants.ExternalScheme;
            o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.ExternalScheme);
    }

    public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorRememberMeCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(IdentityConstants.TwoFactorRememberMeScheme, o =>
        {
            o.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme;
            o.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = SecurityStampValidator.ValidateAsync<ITwoFactorSecurityStampValidator>
            };
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorRememberMeScheme);
    }

    public static OptionsBuilder<CookieAuthenticationOptions> AddTwoFactorUserIdCookie(this AuthenticationBuilder builder)
    {
        builder.AddCookie(IdentityConstants.TwoFactorUserIdScheme, o =>
        {
            o.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
            o.Events = new CookieAuthenticationEvents
            {
                OnRedirectToReturnUrl = _ => Task.CompletedTask
            };
            o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        });
        return new OptionsBuilder<CookieAuthenticationOptions>(builder.Services, IdentityConstants.TwoFactorUserIdScheme);
    }
}
//---------------------------------------------------------------Ʌ

//----------------------------------------------------------V
public static class IdentityEntityFrameworkBuilderExtensions
{
    public static IdentityBuilder AddEntityFrameworkStores<TContext>(this IdentityBuilder builder)  // <------------add IUserStore and/or IRoleStore based on TContext
    {
        AddStores(builder.Services, builder.UserType, builder.RoleType, typeof(TContext));
        return builder;
    }

    private static void AddStores(IServiceCollection services, Type userType, Type? roleType, Type contextType)
    {
        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>));
        if (identityUserType == null)
        {
            throw new InvalidOperationException(Resources.NotIdentityUser);
        }
 
        var keyType = identityUserType.GenericTypeArguments[0];
 
        if (roleType != null)
        {
            var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole<>));
            if (identityRoleType == null)
            {
                throw new InvalidOperationException(Resources.NotIdentityRole);
            }
 
            Type userStoreType;
            Type roleStoreType;
            var identityContext = FindGenericBaseType(contextType, typeof(IdentityDbContext<,,,,,,,>));
            if (identityContext == null)
            {
                // If its a custom DbContext, we can only add the default POCOs
                userStoreType = typeof(UserStore<,,,>).MakeGenericType(userType, roleType, contextType, keyType);
                roleStoreType = typeof(RoleStore<,,>).MakeGenericType(roleType, contextType, keyType);
            }
            else
            {
                userStoreType = typeof(UserStore<,,,,,,,,>).MakeGenericType(userType, roleType, contextType,  // UserStore is the IUserStore that wrapps a DbContext
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[3],
                    identityContext.GenericTypeArguments[4],
                    identityContext.GenericTypeArguments[5],
                    identityContext.GenericTypeArguments[7],
                    identityContext.GenericTypeArguments[6]);
                roleStoreType = typeof(RoleStore<,,,,>).MakeGenericType(roleType, contextType,
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[4],
                    identityContext.GenericTypeArguments[6]);
            }
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);  // <---------------------------
            services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);  // <---------------------------
        }
        else
        {   // No Roles
            Type userStoreType;
            var identityContext = FindGenericBaseType(contextType, typeof(IdentityUserContext<,,,,>));
            if (identityContext == null)
            {
                // If its a custom DbContext, we can only add the default POCOs
                userStoreType = typeof(UserOnlyStore<,,>).MakeGenericType(userType, contextType, keyType);
            }
            else
            {
                userStoreType = typeof(UserOnlyStore<,,,,,>).MakeGenericType(userType, contextType,
                    identityContext.GenericTypeArguments[1],
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[3],
                    identityContext.GenericTypeArguments[4]);
            }
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
        }
    }

    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
//----------------------------------------------------------Ʌ

//------------------------------------------------------------V
internal sealed class IdentityDefaultUIConfigureOptions<TUser> : IPostConfigureOptions<RazorPagesOptions>, IConfigureNamedOptions<CookieAuthenticationOptions>
{
    private const string IdentityUIDefaultAreaName = "Identity";
 
    public IdentityDefaultUIConfigureOptions(
        IWebHostEnvironment environment)
    {
        Environment = environment;
    }
 
    public IWebHostEnvironment Environment { get; }
 
    public void PostConfigure(string? name, RazorPagesOptions options)
    {
        options = options ?? throw new ArgumentNullException(nameof(options));
 
        options.Conventions.AuthorizeAreaFolder(IdentityUIDefaultAreaName, "/Account/Manage");
        options.Conventions.AuthorizeAreaPage(IdentityUIDefaultAreaName, "/Account/Logout");
        var convention = new IdentityPageModelConvention<TUser>();
        options.Conventions.AddAreaFolderApplicationModelConvention(IdentityUIDefaultAreaName, "/", convention.Apply);
        options.Conventions.AddAreaFolderApplicationModelConvention(IdentityUIDefaultAreaName, "/Account/Manage", pam => pam.Filters.Add(new ExternalLoginsPageFilter<TUser>()));
    }

    public void Configure(CookieAuthenticationOptions options) {
        // Nothing to do here as Configure(string name, CookieAuthenticationOptions options) is the one setting things up.
    }
 
    public void Configure(string? name, CookieAuthenticationOptions options)
    {
        options = options ?? throw new ArgumentNullException(nameof(options));
 
        if (string.Equals(IdentityConstants.ApplicationScheme, name, StringComparison.Ordinal))
        {
            options.LoginPath = $"/{IdentityUIDefaultAreaName}/Account/Login";  // <----------------------------------
            options.LogoutPath = $"/{IdentityUIDefaultAreaName}/Account/Logout";
            options.AccessDeniedPath = $"/{IdentityUIDefaultAreaName}/Account/AccessDenied";
        }
    }
}
//------------------------------------------------------------Ʌ
```

```C#
//----------------------------------V
public class IdentityUserClaim<TKey>
{
    public virtual int Id { get; set; } = default!;
    public virtual TKey UserId { get; set; } = default!;
    public virtual string? ClaimType { get; set; }
    public virtual string? ClaimValue { get; set; }
    
    public virtual Claim ToClaim()
    {
        return new Claim(ClaimType!, ClaimValue!);
    }

    public virtual void InitializeFromClaim(Claim claim)  // <--------------------
    {
        ClaimType = claim.Type;
        ClaimValue = claim.Value;
    }
}
//----------------------------------Ʌ

//---------------------------------------------V
public class IdentityUserLogin<TKey> where TKey : IEquatable<TKey>
{
    public virtual string LoginProvider { get; set; } = default!;  // Gets or sets the login provider for the login (e.g. facebook, google)
    public virtual string ProviderKey { get; set; } = default!;
    public virtual string? ProviderDisplayName { get; set; }
    public virtual TKey UserId { get; set; } = default!;
}
//---------------------------------------------Ʌ

//---------------------------------------------V
public class IdentityUserToken<TKey> where TKey : IEquatable<TKey>
{
    public virtual TKey UserId { get; set; } = default!;
    public virtual string LoginProvider { get; set; } = default!;
    public virtual string Name { get; set; } = default!;
    public virtual string? Value { get; set; }
}
//---------------------------------------------Ʌ

//-----------------------------V
public class IdentityRole<TKey> where TKey : IEquatable<TKey>
{
    public IdentityRole() { }

    public IdentityRole(string roleName) : this()
    {
        Name = roleName;
    }

    public virtual TKey Id { get; set; } = default!;
    public virtual string? Name { get; set; }
    public virtual string? NormalizedName { get; set; }
    public virtual string? ConcurrencyStamp { get; set; }
}
//-----------------------------Ʌ

//-----------------------V
public class IdentityRole : IdentityRole<string>
{
    public IdentityRole()
    {
        Id = Guid.NewGuid().ToString();
    }

    public IdentityRole(string roleName) : this()
    {
        Name = roleName;
    }
}
//-----------------------Ʌ

//----------------------------------------V
public class IdentityUser<TKey> where TKey : IEquatable<TKey>
{
    public IdentityUser() { }

    public IdentityUser(string userName) : this()
    {
        UserName = userName;
    }

    public virtual TKey Id { get; set; } = default!;
    public virtual string? UserName { get; set; }
    public virtual string? NormalizedUserName { get; set; }
    public virtual string? Email { get; set; }
    public virtual string? NormalizedEmail { get; set; }
    public virtual bool EmailConfirmed { get; set; }
    public virtual string? PasswordHash { get; set; }
    public virtual string? SecurityStamp { get; set; }
    public virtual string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
    public virtual string? PhoneNumber { get; set; }
    public virtual bool PhoneNumberConfirmed { get; set; }
    public virtual bool TwoFactorEnabled { get; set; }
    public virtual DateTimeOffset? LockoutEnd { get; set; }
    public virtual bool LockoutEnabled { get; set; }
    public virtual int AccessFailedCount { get; set; }
}
//----------------------------------------Ʌ

//-----------------------V
public class IdentityUser : IdentityUser<string>
{
    public IdentityUser()
    {
        Id = Guid.NewGuid().ToString();
        SecurityStamp = Guid.NewGuid().ToString();
    }

    public IdentityUser(string userName) : this()
    {
        UserName = userName;
    }
}
//-----------------------Ʌ

//--------------------V
public class UserStore : UserStore<IdentityUser<string>>
{
    public UserStore(DbContext context, IdentityErrorDescriber? describer = null) : base(context, describer) { }
}
//--------------------Ʌ

//---------------------------V
public class UserStore<TUser> : UserStore<TUser, IdentityRole, DbContext, string>
{
    public UserStore(DbContext context, IdentityErrorDescriber? describer = null) : base(context, describer) { }

}
//---------------------------Ʌ

//--------------------------------------------V
public class UserStore<TUser, TRole, TContext> : UserStore<TUser, TRole, TContext, string>
{
    public UserStore(TContext context, IdentityErrorDescriber? describer = null) : base(context, describer) { }
}
//--------------------------------------------Ʌ

//-------------------------------------------------------------------------------------------------------------V
public class UserStore<TUser, TRole, TContext, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
    UserStoreBase<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>,
    IProtectedUserStore<TUser>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TContext : DbContext
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>, new()
    where TUserRole : IdentityUserRole<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : IdentityUserToken<TKey>, new()
    where TRoleClaim : IdentityRoleClaim<TKey>, new()
{
    public UserStore(TContext context, IdentityErrorDescriber? describer = null) : base(describer ?? new IdentityErrorDescriber())
    {
        Context = context;
    }

    public virtual TContext Context { get; private set; }
 
    private DbSet<TUser> UsersSet { get { return Context.Set<TUser>(); } }
    private DbSet<TRole> Roles { get { return Context.Set<TRole>(); } }
    private DbSet<TUserClaim> UserClaims { get { return Context.Set<TUserClaim>(); } }
    private DbSet<TUserRole> UserRoles { get { return Context.Set<TUserRole>(); } }
    private DbSet<TUserLogin> UserLogins { get { return Context.Set<TUserLogin>(); } }
    private DbSet<TUserToken> UserTokens { get { return Context.Set<TUserToken>(); } }

    public bool AutoSaveChanges { get; set; } = true;

    protected Task SaveChanges(CancellationToken cancellationToken)
    {
        return AutoSaveChanges ? Context.SaveChangesAsync(cancellationToken) : Task.CompletedTask;
    }

    public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        Context.Add(user);
        await SaveChanges(cancellationToken);  // <---------------------
        return IdentityResult.Success;
    }

    public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
 
        Context.Attach(user);
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        Context.Update(user);
        try
        {
            await SaveChanges(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    // ...
}  
//-------------------------------------------------------------------------------------------------------------Ʌ

//----------------------------------------------------------------------------------V
public abstract class UserStoreBase<TUser, TKey, TUserClaim, TUserLogin, TUserToken> :
    IUserLoginStore<TUser>,
    IUserClaimStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserEmailStore<TUser>,
    IUserLockoutStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IQueryableUserStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserAuthenticationTokenStore<TUser>,
    IUserAuthenticatorKeyStore<TUser>,
    IUserTwoFactorRecoveryCodeStore<TUser>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : IdentityUserToken<TKey>, new()
{
    private const string InternalLoginProvider = "[AspNetUserStore]";
    private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
    private const string RecoveryCodeTokenName = "RecoveryCodes";
    
    public UserStoreBase(IdentityErrorDescriber describer)
    { 
        ErrorDescriber = describer;
    }

    public IdentityErrorDescriber ErrorDescriber { get; set; }
    //
    public abstract IQueryable<TUser> Users { get; }
    public abstract Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default);
    public abstract Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default);
    public abstract Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default);
    public abstract Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default);
    public abstract Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default);
    protected abstract Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken);
    public abstract Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);
    public abstract Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default);
    public abstract Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default);
    public abstract Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default);
    public abstract Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default);
    public abstract Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default);
    public abstract Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default);
    public abstract Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default);
    protected abstract Task AddUserTokenAsync(TUserToken token);
    protected abstract Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
    protected abstract Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken);
    protected abstract Task<TUserLogin> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken);
    protected abstract Task RemoveUserTokenAsync(TUserToken token);
    //

    //
    public virtual TKey ConvertIdFromString(string id);
    public virtual string ConvertIdToString(TKey id);
    public virtual Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken);
    public virtual Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default);
    public abstract Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default);
    public virtual Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken);
    public virtual Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
    public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken);
    public virtual Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
    public virtual Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken);
    public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default);
    public virtual Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken);
    public virtual Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default);
    public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default);
    public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default);
    public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default);
    public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default);
    public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default);
    public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default);
    public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default);
    public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default);
    public virtual Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default);
    public virtual Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken);
    public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default);
    public virtual Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default);
    protected virtual TUserClaim CreateUserClaim(TUser user, Claim claim);
    protected virtual TUserLogin CreateUserLogin(TUser user, UserLoginInfo login);
    protected virtual TUserToken CreateUserToken(TUser user, string loginProvider, string name, string value);
    //

    protected virtual TUserClaim CreateUserClaim(TUser user, Claim claim)
    {
        var userClaim = new TUserClaim { UserId = user.Id };
        userClaim.InitializeFromClaim(claim);
        return userClaim;
    }

    protected virtual TUserLogin CreateUserLogin(TUser user, UserLoginInfo login)
    {
        return new TUserLogin
        {
            UserId = user.Id,
            ProviderKey = login.ProviderKey,
            LoginProvider = login.LoginProvider,
            ProviderDisplayName = login.ProviderDisplayName
        };
    }

    protected virtual TUserToken CreateUserToken(TUser user, string loginProvider, string name, string? value)
    {
        return new TUserToken
        {
            UserId = user.Id,
            LoginProvider = loginProvider,
            Name = name,
            Value = value
        };
    }
}
//----------------------------------------------------------------------------------Ʌ

//----------------------------------------------------------------------------------------------------------------V
public abstract class UserStoreBase<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
    UserStoreBase<TUser, TKey, TUserClaim, TUserLogin, TUserToken>,
    IUserRoleStore<TUser>  // <--------------------------------
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>, new()
    where TUserRole : IdentityUserRole<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : IdentityUserToken<TKey>, new()
    where TRoleClaim : IdentityRoleClaim<TKey>, new()
//----------------------------------------------------------------------------------------------------------------Ʌ

//-------------------------------------------------------------------------------------------------------------V
public class UserStore<TUser, TRole, TContext, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
    UserStoreBase<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>,
    IProtectedUserStore<TUser>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TContext : DbContext
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>, new()
    where TUserRole : IdentityUserRole<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : IdentityUserToken<TKey>, new()
    where TRoleClaim : IdentityRoleClaim<TKey>, new()
{
    public UserStoreBase(IdentityErrorDescriber describer) : base(describer) { }

    protected virtual TUserRole CreateUserRole(TUser user, TRole role)
    {
        return new TUserRole()
        {
            UserId = user.Id,
            RoleId = role.Id
        };
    }

    public abstract Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken));
    public abstract Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken));
    public abstract Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken));
    public abstract Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken));
    public abstract Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken));
    protected abstract Task<TRole?> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken);
    protected abstract Task<TUserRole?> FindUserRoleAsync(TKey userId, TKey roleId, CancellationToken cancellationToken);
}
//-------------------------------------------------------------------------------------------------------------Ʌ
```

```C#
//---------------------------------V
public static class OAuthExtensions
{
    public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<OAuthOptions> configureOptions)
        => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, configureOptions);

    public static AuthenticationBuilder AddOAuth(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OAuthOptions> configureOptions)
        => builder.AddOAuth<OAuthOptions, OAuthHandler<OAuthOptions>>(authenticationScheme, displayName, configureOptions); 
    
    public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, Action<TOptions> configureOptions)
        where TOptions : OAuthOptions, new()
        where THandler : OAuthHandler<TOptions>
        => builder.AddOAuth<TOptions, THandler>(authenticationScheme, OAuthDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddOAuth<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TOptions> configureOptions)
        where TOptions : OAuthOptions, new()
        where THandler : OAuthHandler<TOptions>
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, OAuthPostConfigureOptions<TOptions, THandler>>());
        return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
    }
}
//---------------------------------Ʌ

//--------------------------------------V
public class RemoteAuthenticationOptions : AuthenticationSchemeOptions
{
    private const string CorrelationPrefix = ".AspNetCore.Correlation.";
 
    private CookieBuilder _correlationCookieBuilder;

    public RemoteAuthenticationOptions()
    {
        _correlationCookieBuilder = new CorrelationCookieBuilder(this)
        {
            Name = CorrelationPrefix,
            HttpOnly = true,
            SameSite = SameSiteMode.None,
            SecurePolicy = CookieSecurePolicy.Always,
            IsEssential = true,
        };
    }

    public override void Validate(string scheme)
    {
        base.Validate(scheme);
        if (string.Equals(scheme, SignInScheme, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(Resources.Exception_RemoteSignInSchemeCannotBeSelf);
        }
    }

    public override void Validate()
    {
        base.Validate();
        if (CallbackPath == null || !CallbackPath.HasValue)
        {
            throw new ArgumentException(Resources.FormatException_OptionMustBeProvided(nameof(CallbackPath)), nameof(CallbackPath));
        }
    }

    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }
    public HttpClient Backchannel { get; set; } = default!;
    public IDataProtectionProvider? DataProtectionProvider { get; set; }
    public PathString CallbackPath { get; set; }
    public PathString AccessDeniedPath { get; set; }
    public string ReturnUrlParameter { get; set; } = "ReturnUrl";
    public string? SignInScheme { get; set; }
    public TimeSpan RemoteAuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(15);
    public bool SaveTokens { get; set; }
    
    public new RemoteAuthenticationEvents Events
    {
        get => (RemoteAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }

    public CookieBuilder CorrelationCookie
    {
        get => _correlationCookieBuilder;
        set => _correlationCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
    }

    private sealed class CorrelationCookieBuilder : RequestPathBaseCookieBuilder
    {
        private readonly RemoteAuthenticationOptions _options;
 
        public CorrelationCookieBuilder(RemoteAuthenticationOptions remoteAuthenticationOptions)
        {
            _options = remoteAuthenticationOptions;
        }
 
        protected override string AdditionalPath => _options.CallbackPath;
 
        public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
        {
            var cookieOptions = base.Build(context, expiresFrom);
 
            if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
            {
                cookieOptions.Expires = expiresFrom.Add(_options.RemoteAuthenticationTimeout);
            }
 
            return cookieOptions;
        }
    }
}
//--------------------------------------Ʌ

//-----------------------V
public class OAuthOptions : RemoteAuthenticationOptions
{
    public OAuthOptions()
    {
        Events = new OAuthEvents();
    }

    public override void Validate()
    {
        base.Validate();
 
        if (string.IsNullOrEmpty(ClientId))
            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientId)), nameof(ClientId));
 
        if (string.IsNullOrEmpty(ClientSecret))
            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, nameof(ClientSecret)), nameof(ClientSecret));
        
        // ...
    }

    public string ClientId { get; set; } = default!;
    public string ClientSecret { get; set; } = default!;
    public string AuthorizationEndpoint { get; set; } = default!;
    public string TokenEndpoint { get; set; } = default!;
    public string UserInformationEndpoint { get; set; } = default!;
    public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();
    public ICollection<string> Scope { get; } = new HashSet<string>();
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;
    public bool UsePkce { get; set; }

    public new OAuthEvents Events
    {
        get { return (OAuthEvents)base.Events; }
        set { base.Events = value; }
    }
}
//-----------------------Ʌ

//------------------------V
public class GoogleOptions : OAuthOptions
{
    public GoogleOptions()
    {
        CallbackPath = new PathString("/signin-google");               // <------------------------------
        AuthorizationEndpoint = GoogleDefaults.AuthorizationEndpoint;  // <------------------------------
        TokenEndpoint = GoogleDefaults.TokenEndpoint;
        UserInformationEndpoint = GoogleDefaults.UserInformationEndpoint;
        UsePkce = true;
        Scope.Add("openid");
        Scope.Add("profile");
        Scope.Add("email");
 
        ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id"); // v2
        ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub"); // v3
        ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
        ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
        ClaimActions.MapJsonKey("urn:google:profile", "link");
        ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
    }

    public string? AccessType { get; set; }
}
//------------------------Ʌ

//---------------------------------------------------------V
public abstract class RemoteAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationRequestHandler where TOptions : RemoteAuthenticationOptions, new()
{
    private const string CorrelationProperty = ".xsrf";
    private const string CorrelationMarker = "N";
    private const string AuthSchemeKey = ".AuthScheme";

    protected string? SignInScheme => Options.SignInScheme;

    protected new RemoteAuthenticationEvents Events
    {
        get { return (RemoteAuthenticationEvents)base.Events!; }
        set { base.Events = value; }
    }

    protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock) { }
    
    protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }
    
    protected override Task<object> CreateEventsAsync()
        => Task.FromResult<object>(new RemoteAuthenticationEvents());

    public virtual Task<bool> ShouldHandleRequestAsync()
        => Task.FromResult(Options.CallbackPath == Request.Path);   // CallbackPath is "signin-google"

    public virtual async Task<bool> HandleRequestAsync()  //<-------------------------------e2, intercept the request after users sign in
    {
        if (!await ShouldHandleRequestAsync())  // <--------------------------e2.1
            return false;
 
        AuthenticationTicket? ticket = null;
        Exception? exception = null;
        AuthenticationProperties? properties = null;

        try {
            AuthenticateResult authResult = await HandleRemoteAuthenticateAsync();  // <--------------------------e2.2.
            /* authResult.Properties.Items contains:
               [.redirect, /Identity/Account/ExternalLogin?returnUrl=%2F&handler=Callback]
               [LoginProvider, Google]
            */

            if (authResult == null)
                exception = new InvalidOperationException("Invalid return state, unable to redirect.");
            else if (authResult.Handled)
                return true;
            else if (authResult.Skipped || authResult.None)
                return false;
            else if (!authResult.Succeeded)
            {
                exception = authResult.Failure ?? new InvalidOperationException("Invalid return state, unable to redirect.");
                properties = authResult.Properties;
            }
            ticket = authResult?.Ticket;
        }
        catch (Exception ex) {
            exception = ex;
        }
 
        if (exception != null)
        {
            var errorContext = new RemoteFailureContext(Context, Scheme, Options, exception)
            {
                Properties = properties
            };
            await Events.RemoteFailure(errorContext);
 
            if (errorContext.Result != null)
            {
                if (errorContext.Result.Handled)
                    return true;
                else if (errorContext.Result.Skipped)
                    return false;
                else if (errorContext.Result.Failure != null)
                    throw new AuthenticationFailureException("An error was returned from the RemoteFailure event.", errorContext.Result.Failure);
            }
 
            if (errorContext.Failure != null)
                throw new AuthenticationFailureException("An error was encountered while handling the remote login.", errorContext.Failure);
        }
 
        // We have a ticket if we get here
        var ticketContext = new TicketReceivedContext(Context, Scheme, Options, ticket)
        {
            ReturnUri = ticket.Properties.RedirectUri
        };
 
        ticket.Properties.RedirectUri = null;
 
        // Mark which provider produced this identity so we can cross-check later in HandleAuthenticateAsync
        ticketContext.Properties!.Items[AuthSchemeKey] = Scheme.Name;  // <----------------------------------
 
        await Events.TicketReceived(ticketContext);
 
        if (ticketContext.Result != null)
        {
            if (ticketContext.Result.Handled)
            {
                Logger.SignInHandled();
                return true;
            }
            else if (ticketContext.Result.Skipped)
            {
                Logger.SignInSkipped();
                return false;
            }
        }
 
        // SignInScheme is "Identity.External" which will be handled by cookie handler which serilize the ticket into cookie for the next redirect request
        await Context.SignInAsync(SignInScheme, ticketContext.Principal!, ticketContext.Properties);  // <------------------e4
        /* ticketContext.Properties.Properties.Items contains:       
            [LoginProvider, Google]
            [.AuthScheme, Google]
            [.issued, Sun, 07 Jan 2024 06:39:09 GMT]
            [.expires, Sun, 07 Jan 2024 06:44:09 GMT]

        Note that [.redirect, /Identity/Account/ExternalLogin?returnUrl=%2F&handler=Callback] is not there as it is "moved" to ticketContext.ReturnUri
        Also there's no LoginProviderKey/user id Entry at the moment. This entry will be added when the e5.0 is called        
        */

        // Default redirect path is the base path
        if (string.IsNullOrEmpty(ticketContext.ReturnUri))
        {
            ticketContext.ReturnUri = "/";
        }
 
        Response.Redirect(ticketContext.ReturnUri);  // <-----------------e5.0, ReturnUri is /Identity/Account/ExternalLogin?returnUrl=%2F&handler=Callback
        return true;
    }   

    protected abstract Task<HandleRequestResult> HandleRemoteAuthenticateAsync();

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await Context.AuthenticateAsync(SignInScheme);
        if (result != null)
        {
            if (result.Failure != null)
                return result;
 
            // The SignInScheme may be shared with multiple providers, make sure this provider issued the identity.
            var ticket = result.Ticket;
            if (ticket != null && ticket.Principal != null && ticket.Properties != null && ticket.Properties.Items.TryGetValue(AuthSchemeKey, out var authenticatedScheme)
                && string.Equals(Scheme.Name, authenticatedScheme, StringComparison.Ordinal))
            {
                return AuthenticateResult.Success(new AuthenticationTicket(ticket.Principal, ticket.Properties, Scheme.Name));
            }

            return AuthenticateResult.NoResult();
        }

        return AuthenticateResult.Fail("Remote authentication does not directly support AuthenticateAsync");
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        => Context.ForbidAsync(SignInScheme);

    protected virtual void GenerateCorrelationId(AuthenticationProperties properties)
    { 
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var correlationId = Base64UrlTextEncoder.Encode(bytes);
 
        var cookieOptions = Options.CorrelationCookie.Build(Context, TimeProvider.GetUtcNow());
 
        properties.Items[CorrelationProperty] = correlationId;
 
        var cookieName = Options.CorrelationCookie.Name + correlationId;
 
        Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
    }

    protected virtual bool ValidateCorrelationId(AuthenticationProperties properties)
    { 
        if (!properties.Items.TryGetValue(CorrelationProperty, out var correlationId))
        {
            Logger.CorrelationPropertyNotFound(Options.CorrelationCookie.Name!);
            return false;
        }
 
        properties.Items.Remove(CorrelationProperty);
 
        var cookieName = Options.CorrelationCookie.Name + correlationId;
 
        var correlationCookie = Request.Cookies[cookieName];
        if (string.IsNullOrEmpty(correlationCookie))
        {
            Logger.CorrelationCookieNotFound(cookieName);
            return false;
        }
 
        var cookieOptions = Options.CorrelationCookie.Build(Context, TimeProvider.GetUtcNow());
 
        Response.Cookies.Delete(cookieName, cookieOptions);
 
        if (!string.Equals(correlationCookie, CorrelationMarker, StringComparison.Ordinal))
        {
            Logger.UnexpectedCorrelationCookieValue(cookieName, correlationCookie);
            return false;
        }
 
        return true;
    }

    protected virtual async Task<HandleRequestResult> HandleAccessDeniedErrorAsync(AuthenticationProperties properties)
    {
        var context = new AccessDeniedContext(Context, Scheme, Options)
        {
            AccessDeniedPath = Options.AccessDeniedPath,
            Properties = properties,
            ReturnUrl = properties?.RedirectUri,
            ReturnUrlParameter = Options.ReturnUrlParameter
        };
        await Events.AccessDenied(context);
 
        if (context.Result != null)
        {
            if (context.Result.Handled)
                Logger.AccessDeniedContextHandled();
            else if (context.Result.Skipped)
                Logger.AccessDeniedContextSkipped();
 
            return context.Result;
        }
 
        // If an access denied endpoint was specified, redirect the user agent.
        // Otherwise, invoke the RemoteFailure event for further processing.
        if (context.AccessDeniedPath.HasValue)
        {
            string uri = context.AccessDeniedPath;
            if (!string.IsNullOrEmpty(context.ReturnUrlParameter) && !string.IsNullOrEmpty(context.ReturnUrl))
            {
                uri = QueryHelpers.AddQueryString(uri, context.ReturnUrlParameter, context.ReturnUrl);
            }
            Response.Redirect(BuildRedirectUri(uri));
 
            return HandleRequestResult.Handle();
        }
 
        return HandleRequestResult.NoResult();
    }
}
//---------------------------------------------------------Ʌ

//---------------------------------V
public class OAuthHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : OAuthOptions, new()
{
    protected HttpClient Backchannel => Options.Backchannel;

    protected new OAuthEvents Events
    {
        get { return (OAuthEvents)base.Events; }
        set { base.Events = value; }
    }

    public OAuthHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OAuthEvents());

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()  // <------------------------e3.0
    {
        var query = Request.Query;
 
        var state = query["state"];  // <------------------------------e3.1
        var properties = Options.StateDataFormat.Unprotect(state);
 
        if (properties == null)
            return HandleRequestResults.InvalidState;
 
        // OAuth2 10.12 CSRF
        if (!ValidateCorrelationId(properties))
            return HandleRequestResult.Fail("Correlation failed.", properties);
 
        var error = query["error"];  // <------------------------------e3.2
        if (!StringValues.IsNullOrEmpty(error))
        {
            // Note: access_denied errors are special protocol errors indicating the user didn't approve the authorization demand requested by the remote authorization server.
            // Since it's a frequent scenario (that is not caused by incorrect configuration), denied errors are handled differently using HandleAccessDeniedErrorAsync().
            var errorDescription = query["error_description"];
            var errorUri = query["error_uri"];
            if (StringValues.Equals(error, "access_denied"))
            {
                var result = await HandleAccessDeniedErrorAsync(properties);
                if (!result.None)
                    return result;
                var deniedEx = new AuthenticationFailureException("Access was denied by the resource owner or by the remote server.");
                deniedEx.Data["error"] = error.ToString();
                deniedEx.Data["error_description"] = errorDescription.ToString();
                deniedEx.Data["error_uri"] = errorUri.ToString();
 
                return HandleRequestResult.Fail(deniedEx, properties);
            }
 
            var failureMessage = new StringBuilder();
            failureMessage.Append(error);
            if (!StringValues.IsNullOrEmpty(errorDescription))
                failureMessage.Append(";Description=").Append(errorDescription);
            if (!StringValues.IsNullOrEmpty(errorUri))
                failureMessage.Append(";Uri=").Append(errorUri);
 
            var ex = new AuthenticationFailureException(failureMessage.ToString());
            ex.Data["error"] = error.ToString();
            ex.Data["error_description"] = errorDescription.ToString();
            ex.Data["error_uri"] = errorUri.ToString();
 
            return HandleRequestResult.Fail(ex, properties);
        }
 
        var code = query["code"];   // <------------------------------e3.3
 
        if (StringValues.IsNullOrEmpty(code))
            return HandleRequestResult.Fail("Code was not found.", properties);
 
        var codeExchangeContext = new OAuthCodeExchangeContext(properties, code.ToString(), BuildRedirectUri(Options.CallbackPath));
        using var tokens = await ExchangeCodeAsync(codeExchangeContext);  // <------------------------------e3.4, pass code (authCode) to get token
 
        if (tokens.Error != null)
            return HandleRequestResult.Fail(tokens.Error, properties);
 
        if (string.IsNullOrEmpty(tokens.AccessToken))
            return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
 
        var identity = new ClaimsIdentity(ClaimsIssuer);  // <-----------------ClaimsIssuer is "Google" and is set at AuthenticationHandler
 
        if (Options.SaveTokens)
        {
            var authTokens = new List<AuthenticationToken>();
 
            authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
            if (!string.IsNullOrEmpty(tokens.RefreshToken))
                authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
 
            if (!string.IsNullOrEmpty(tokens.TokenType))
                authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
 
            if (!string.IsNullOrEmpty(tokens.ExpiresIn))
            {
                int value;
                if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                {                   
                    var expiresAt = TimeProvider.GetUtcNow() + TimeSpan.FromSeconds(value);
                    authTokens.Add(new AuthenticationToken
                    {
                        Name = "expires_at",
                        Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                    });
                }
            }
 
            properties.StoreTokens(authTokens);
        }
 
        AuthenticationTicket ticket = await CreateTicketAsync(identity, properties, tokens);  // <--------------------------e3.6 pass token to get user data
        if (ticket != null)
        {
            return HandleRequestResult.Success(ticket);
        }
        else
        {
            return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
        }
    }

    protected virtual async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)  // <------------------------------e3.4
    {
        var tokenRequestParameters = new Dictionary<string, string>()
        {
            { "client_id", Options.ClientId },
            { "redirect_uri", context.RedirectUri },
            { "client_secret", Options.ClientSecret },   // <---------------pass secret now
            { "code", context.Code },
            { "grant_type", "authorization_code" },
        };
 
        // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
        if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
        {
            tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier!);
            context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
        }
 
        var requestContent = new FormUrlEncodedContent(tokenRequestParameters!);
 
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
        requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        requestMessage.Content = requestContent;
        requestMessage.Version = Backchannel.DefaultRequestVersion;
        var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);  // <------------------------------e3.5
        var body = await response.Content.ReadAsStringAsync(Context.RequestAborted);
 
        return response.IsSuccessStatusCode switch
        {
            true => OAuthTokenResponse.Success(JsonDocument.Parse(body)),
            false => PrepareFailedOAuthTokenReponse(response, body)
        };
    }

    private static OAuthTokenResponse PrepareFailedOAuthTokenReponse(HttpResponseMessage response, string body)
    {
        var exception = OAuthTokenResponse.GetStandardErrorException(JsonDocument.Parse(body));
 
        if (exception is null)
        {
            var errorMessage = $"OAuth token endpoint failure: Status: {response.StatusCode};Headers: {response.Headers};Body: {body};";
            return OAuthTokenResponse.Failed(new AuthenticationFailureException(errorMessage));
        }
 
        return OAuthTokenResponse.Failed(exception);
    }

    protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        var user = JsonDocument.Parse("{}{}");  // should be using (var user = JsonDocument.Parse("{}"{}"))
        var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, user.RootElement);
        await Events.CreatingTicket(context);   
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties) // <-------------------------------------------e1, will be called
    {                                                                                       // after default SignIn page generate new ChallengeResult("Google", xxx);
       if (string.IsNullOrEmpty(properties.RedirectUri))
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
 
        // OAuth2 10.12 CSRF
        GenerateCorrelationId(properties);
 
        var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
        var redirectContext = new RedirectContext<OAuthOptions>(Context, Scheme, Options, properties, authorizationEndpoint);
        await Events.RedirectToAuthorizationEndpoint(redirectContext);  // <-----------------e1.1. go to Google's extern SignIn page where users enter credentials
                                                                        // redirect to "https://accounts.google.com/o/oauth2/v2/auth/...."
        var location = Context.Response.Headers.Location;
        if (location == StringValues.Empty)
            location = "(not set)";
 
        var cookie = Context.Response.Headers.SetCookie;
        if (cookie == StringValues.Empty)
            cookie = "(not set)";
    }

    protected virtual string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)  // <---------e1.1, generate Goole's SignIn URL
    {
        var scopeParameter = properties.GetParameter<ICollection<string>>(OAuthChallengeProperties.ScopeKey);
        var scope = scopeParameter != null ? FormatScope(scopeParameter) : FormatScope();
 
        var parameters = new Dictionary<string, string> 
        {
            { "client_id", Options.ClientId },   // <------------------------
            { "scope", scope },
            { "response_type", "code" },
            { "redirect_uri", redirectUri },
        };
 
        if (Options.UsePkce)
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            var codeVerifier = Base64UrlTextEncoder.Encode(bytes);
 
            // Store this for use during the code redemption.
            properties.Items.Add(OAuthConstants.CodeVerifierKey, codeVerifier);
 
            var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
            var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);
 
            parameters[OAuthConstants.CodeChallengeKey] = codeChallenge;
            parameters[OAuthConstants.CodeChallengeMethodKey] = OAuthConstants.CodeChallengeMethodS256;
        }
 
        parameters["state"] = Options.StateDataFormat.Protect(properties);

        // Options.AuthorizationEndpoint is "https://accounts.google.com/o/oauth2/v2/auth"
        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters!);  // <-------------------------------------
    }

    protected virtual string FormatScope(IEnumerable<string> scopes)
        => string.Join(" ", scopes); // OAuth2 3.3 space separated

    protected virtual string FormatScope()
        => FormatScope(Options.Scope);
}
//---------------------------------Ʌ
```

```C#
//------------------------V
public class GoogleHandler : OAuthHandler<GoogleOptions>
{
    public GoogleHandler(IOptionsMonitor<GoogleOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)  // e3.6
    {
         // Get the Google user
        var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);  // <---------------------e3.6.1
 
        var response = await Backchannel.SendAsync(request, Context.RequestAborted);   // <-------------------------e.3.6.2 send token to Google service for user data
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"An error occurred when retrieving Google user information ({response.StatusCode}). Please check ...");
        }
 
        using (var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted)))
        {
            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
            context.RunClaimActions();
            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);  // <---------------------e3.6.3.
        }
    }

    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        // Google Identity Platform Manual:
        // https://developers.google.com/identity/protocols/OAuth2WebServer
 
        // Some query params and features (e.g. PKCE) are handled by the base class but some params have to be modified or added here
        var queryStrings = QueryHelpers.ParseQuery(new Uri(base.BuildChallengeUrl(properties, redirectUri)).Query);
 
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.ScopeKey, FormatScope, Options.Scope);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.AccessTypeKey, Options.AccessType);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.ApprovalPromptKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.PromptParameterKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.LoginHintKey);
        SetQueryParam(queryStrings, properties, GoogleChallengeProperties.IncludeGrantedScopesKey, v => v?.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(), (bool?)null);
 
        // Some properties are removed when setting query params above, so the state has to be reset
        queryStrings["state"] = Options.StateDataFormat.Protect(properties);
 
        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
    }

    private static void SetQueryParam<T>(IDictionary<string, StringValues> queryStrings, AuthenticationProperties properties, 
                                         string name, Func<T, string?> formatter, T defaultValue)
    {
        string? value;
        var parameterValue = properties.GetParameter<T>(name);
        if (parameterValue != null)
        {
            value = formatter(parameterValue);
        }
        else if (!properties.Items.TryGetValue(name, out value))
        {
            value = formatter(defaultValue);
        }
 
        // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
        properties.Items.Remove(name);
 
        if (value != null)
        {
            queryStrings[name] = value;
        }
    }

    private static void SetQueryParam(IDictionary<string, StringValues> queryStrings, AuthenticationProperties properties, string name, string? defaultValue = null)
        => SetQueryParam(queryStrings, properties, name, x => x, defaultValue);
}
//------------------------Ʌ

//----------------------------------V
public static class GoogleExtensions
{
    public static AuthenticationBuilder AddGoogle(this AuthenticationBuilder builder)
        => builder.AddGoogle(GoogleDefaults.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddGoogle(this AuthenticationBuilder builder, Action<GoogleOptions> configureOptions)
        => builder.AddGoogle(GoogleDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddGoogle(this AuthenticationBuilder builder, string authenticationScheme, Action<GoogleOptions> configureOptions)
        => builder.AddGoogle(authenticationScheme, GoogleDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddGoogle(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<GoogleOptions> configureOptions)
        => builder.AddOAuth<GoogleOptions, GoogleHandler>(authenticationScheme, displayName, configureOptions);
}
//----------------------------------Ʌ

//-------------------------------->>
public static class GoogleDefaults
{
    public const string AuthenticationScheme = "Google";
    public static readonly string DisplayName = "Google";
    public static readonly string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    public static readonly string TokenEndpoint = "https://oauth2.googleapis.com/token";
    public static readonly string UserInformationEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";
}
//--------------------------------<<
```


Built-In Razor Pages

```C#
//-------------------------------------------------------------------V
namespace Microsoft.AspNetCore.Identity.UI.V5.Pages.Account.Internal;

[AllowAnonymous]
[IdentityDefaultUI(typeof(ExternalLoginModel<>))]
public class ExternalLoginModel : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = default!;

    public string? ProviderDisplayName { get; set; }

    public string? ReturnUrl { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = default!;
    }

    public virtual IActionResult OnGet() => throw new NotImplementedException();

    public virtual IActionResult OnPost(string provider, [StringSyntax(StringSyntaxAttribute.Uri)] string? returnUrl = null) => throw new NotImplementedException();

    public virtual Task<IActionResult> OnGetCallbackAsync([StringSyntax(StringSyntaxAttribute.Uri)] string? returnUrl = null, string? remoteError = null) => throw new NotImplementedException();

    public virtual Task<IActionResult> OnPostConfirmationAsync([StringSyntax(StringSyntaxAttribute.Uri)] string? returnUrl = null) => throw new NotImplementedException();
}

internal sealed class ExternalLoginModel<TUser> : ExternalLoginModel where TUser : class
{
    private readonly SignInManager<TUser> _signInManager;
    private readonly UserManager<TUser> _userManager;
    private readonly IUserStore<TUser> _userStore;
    private readonly IUserEmailStore<TUser> _emailStore;
    private readonly IEmailSender<TUser> _emailSender;
    private readonly ILogger<ExternalLoginModel> _logger;

    public ExternalLoginModel(
        SignInManager<TUser> signInManager,
        UserManager<TUser> userManager,
        IUserStore<TUser> userStore,
        ILogger<ExternalLoginModel> logger,
        IEmailSender<TUser> emailSender)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _userStore = userStore;
        _emailStore = GetEmailStore();
        _logger = logger;
        _emailSender = emailSender;
    }

    public override IActionResult OnGet() => RedirectToPage("./Login");

    public override IActionResult OnPost(string provider, string? returnUrl = null)
    {
        // Request a redirect to the external login provider.
        var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return new ChallengeResult(provider, properties);
    }

    public override async Task<IActionResult> OnGetCallbackAsync(string? returnUrl = null, string? remoteError = null)  // <----------------e5.1, it is like OnGetCorrelate
    {
        returnUrl = returnUrl ?? Url.Content("~/");
        if (remoteError != null)
        {
            ErrorMessage = $"Error from external provider: {remoteError}";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }
        ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();  // <---------------------e5.2
        // info contains ProviderKey now

        if (info == null)
        {
            ErrorMessage = "Error loading external login information.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        // Sign in the user with this external login provider if the user already has a login.
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
        
        if (result.Succeeded)
        {
            return LocalRedirect(returnUrl);
        }
        if (result.IsLockedOut)
        {
            return RedirectToPage("./Lockout");
        }
        else
        {
            // If the user does not have an account, then ask the user to create an account.
            ReturnUrl = returnUrl;
            ProviderDisplayName = info.ProviderDisplayName;
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                Input = new InputModel
                {
                    Email = info.Principal.FindFirstValue(ClaimTypes.Email)!
                };
            }
            return Page();
        }
    }

    public override async Task<IActionResult> OnPostConfirmationAsync(string? returnUrl = null)
    {
        returnUrl = returnUrl ?? Url.Content("~/");
        // Get the information about the user from the external login provider
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ErrorMessage = "Error loading external login information during confirmation.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        if (ModelState.IsValid)
        {
            var user = CreateUser();

            await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

            var result = await _userManager.CreateAsync(user);  // <----------------------------------
            if (result.Succeeded)
            {
                result = await _userManager.AddLoginAsync(user, info);  // <----------------------------------
                if (result.Succeeded)
                {
                    if (_logger.IsEnabled(LogLevel.Information))
                    {
                        _logger.LogInformation(LoggerEventIds.UserCreatedByExternalProvider, "User created an account using {Name} provider.", info.LoginProvider);
                    }

                    var userId = await _userManager.GetUserIdAsync(user);
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId = userId, code = code },
                        protocol: Request.Scheme)!;

                    await _emailSender.SendConfirmationLinkAsync(user, Input.Email, HtmlEncoder.Default.Encode(callbackUrl));

                    // If account confirmation is required, we need to show the link if we don't have a real email sender
                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("./RegisterConfirmation", new { Email = Input.Email });
                    }

                    await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                    return LocalRedirect(returnUrl);
                }
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        ProviderDisplayName = info.ProviderDisplayName;
        ReturnUrl = returnUrl;
        return Page();
    }

    private TUser CreateUser()
    {
        try
        {
            return Activator.CreateInstance<TUser>();
        }
        catch
        {
            throw new InvalidOperationException($"Can't create an instance of '{nameof(TUser)}'. " +
                $"Ensure that '{nameof(TUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                $"override the external login page in /Areas/Identity/Pages/Account/ExternalLogin.cshtml");
        }
    }

    private IUserEmailStore<TUser> GetEmailStore()
    {
        if (!_userManager.SupportsUserEmail)
        {
            throw new NotSupportedException("The default UI requires a user store with email support.");
        }
        return (IUserEmailStore<TUser>)_userStore;
    }
}
//-------------------------------------------------------------------Ʌ
```


## Identity UI Scaffolding

```C# install required packages
dotnet tool install --global dotnet-aspnet-codegenerator --version 5.0.0

dotnet add package Microsoft.VisualStudio.Web.CodeGeneration.Design --version 5.0.0
```

```C# show available Razor pages to overwrite
dotnet aspnet-codegenerator identity --listFiles

...
Account._StatusMessage
Account.AccessDenied
Account.ConfirmEmail
Account.ConfirmEmailChange
Account.ExternalLogin
Account.ForgotPassword
... 
```

```C# Scaffolding an Identity UI Razor Page
// create Login.cshtm under Areas/Identity/Pages/Account so users can overwrite it
dotnet aspnet-codegenerator identity --dbContext Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext --files Account.Login
```