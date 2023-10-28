using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ExampleApp.Custom;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using ExampleApp.Identity.Store;
using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using System;
using ExampleApp.Services;

namespace ExampleApp {
    public class Startup {

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<ILookupNormalizer, Normalizer>();
            services.AddSingleton<IUserStore<AppUser>, UserStore>();
            //services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();
            services.AddSingleton<IPasswordValidator<AppUser>, PasswordValidator>();

            services.AddSingleton<IEmailSender, ConsoleEmailSender>();
            services.AddSingleton<ISMSSender, ConsoleSMSSender>();
            services.AddSingleton<IPasswordHasher<AppUser>, SimplePasswordHasher>();

            //services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>, AppUserClaimsPrincipalFactory>();
            services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
            //services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();
            
            services.AddOptions<ExternalAuthOptions>();
            services.Configure<GoogleOptions>(opts => {
                opts.ClientId = "396623271087-1lvqvq0v71bennoicj3q8ns8l5jk825m.apps.googleusercontent.com";
                opts.ClientSecret = "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";
            });

            services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions
            {
                // opts.Tokens is TokenOptions
                opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
                opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
                opts.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultPhoneProvider;

                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireDigit = false;
                opts.Password.RequiredLength = 8;

                opts.Lockout.MaxFailedAccessAttempts = 30;
                opts.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);  // default is 5 mins
                //opts.SignIn.RequireConfirmedAccount = true;

            })
       
            .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
            .AddTokenProvider<PhoneConfirmationTokenGenerator>(TokenOptions.DefaultPhoneProvider)  // DefaultPhoneProvider = "Phone";
            .AddTokenProvider<TwoFactorSignInTokenGenerator>(IdentityConstants.TwoFactorUserIdScheme)
            .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>(TokenOptions.DefaultAuthenticatorProvider)
            .AddSignInManager()
            .AddRoles<AppRole>();

            services.AddSingleton<IRoleValidator<AppRole>, RoleValidator>();

            services.AddAuthentication(opts => {  // opts is AuthenticationOptions
                opts.DefaultScheme = IdentityConstants.ApplicationScheme;
                opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
                opts.AddScheme<GoogleHandler>("google", "Google");
            })
            .AddCookie(IdentityConstants.ApplicationScheme, opts => {
                opts.LoginPath = "/signin";
                opts.AccessDeniedPath = "/signin/403";
            })
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
            .AddCookie(IdentityConstants.ExternalScheme);

            services.AddAuthorization(opts => 
            {
                opts.AddPolicy("UsersExceptBob", builder =>
                   builder.RequireRole("User")
                          .AddRequirements(new AssertionRequirement(context => !string.Equals(context.User.Identity.Name, "Bob"))));
                //.AddAuthenticationSchemes("OtherScheme"));

                opts.AddPolicy("NotAdmins",
                    builder => builder.AddRequirements(new AssertionRequirement(context => !context.User.IsInRole("Administrator"))));

                opts.AddPolicy("Full2FARequired", builder =>
                {
                    builder.RequireClaim("amr", "mfa");
                });
            });

            services.AddRazorPages();

            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {           
                endpoints.MapRazorPages();
                endpoints.MapDefaultControllerRoute();
                endpoints.MapFallbackToPage("/Secret");
            });
        }
    }
}