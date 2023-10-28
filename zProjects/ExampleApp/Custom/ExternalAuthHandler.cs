using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Text.Json;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using ExampleApp.Custom;

namespace ExampleApp.Custom
{
    public class ExternalAuthOptions
    {
        public string ClientId { get; set; } = "MyClientID";
        public string ClientSecret { get; set; } = "MyClientSecret";

        public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
        public virtual string RedirectPath { get; set; } = "/signin-external";
        public virtual string Scope { get; set; } = "openid email profile";
        public virtual string StateHashSecret { get; set; } = "mysecret";
        public virtual string AuthenticationUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/authenticate";
        public virtual string ExchangeUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/exchange";
        public virtual string ErrorUrlTemplate { get; set; } = "/externalsignin?error={0}";
        public virtual string DataUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/data";
    }
    
    public class ExternalAuthHandler : IAuthenticationRequestHandler
    {
        public ExternalAuthHandler(IOptions<ExternalAuthOptions> options, IDataProtectionProvider dp, ILogger<ExternalAuthHandler> logger)
        {
            Options = options.Value;
            DataProtectionProvider = dp;
            Logger = logger;
        }

        public AuthenticationScheme Scheme { get; set; }
        public HttpContext Context { get; set; }
        public ExternalAuthOptions Options { get; set; }

        public IDataProtectionProvider DataProtectionProvider { get; set; }
        public PropertiesDataFormat PropertiesFormatter { get; set; }
        public ILogger<ExternalAuthHandler> Logger { get; set; }
        public string ErrorMessage { get; set; }


        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            Scheme = scheme;
            Context = context;
            PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName));
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync()  // doesn't do authentication as you want external auth service does the job
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        public async Task ChallengeAsync(AuthenticationProperties properties)  // < ----------ee1.2 note that there are three different "return url" here,  one is "DemoExternalAuth/authenticate?xxx"  
        {                                                                      // that need to be redirected immediately. The other one is AuthenticationProperties.RedirectUri to be used later,
                                                                               // the last one is the return url "secret" route inside as a segment of AuthenticationProperties.RedirectUri                                                                          
            var authenticationUrl = await GetAuthenticationUrl(properties);
            Context.Response.Redirect(authenticationUrl);  // < --------------------------------ee1.3.
            /* redirect to      
            DemoExternalAuth/authenticate?client_id=MyClientID&redirect_uri=localhost:5000/signin-external&scope=openid%20email%20profile&response_type=code&state=xxx
            AuthenticationProperties properties contains return url which is "/ExternalSignIn?returnUrl=secret%2F&handler=Correlate" which is encrypted
            
            For Google:
            https://accounts.google.com/o/oauth2/v2/auth?client_id=396623271087-1lvqvq0v71bennoicj3q8ns8l5jk825m.apps.googleusercontent.com&redirect_uri=localhost%3A5000%2Fsignin-google&scope=openid%20email%20profile&response_type=code&state=xxx
            Google will redirect it to:
            https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=396623271087-1lvqvq0v71bennoicj3q8ns8l5jk825m.apps.googleusercontent.com&redirect_uri=localhost%3A5000%2Fsignin-google&scope=openid%20email%20profile&response_type=code&state=xxx&service=lso&o2v=2&theme=glif&flowName=GeneralOAuthFlow
             */

        }

        protected virtual Task<string> GetAuthenticationUrl(AuthenticationProperties properties)
        {
            Dictionary<string, string> qs = new Dictionary<string, string>();

            qs.Add("client_id", Options.ClientId);
            qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);  // RedirectPath is "signin-external"
            qs.Add("scope", Options.Scope);
            qs.Add("response_type", "code");
            qs.Add("state", PropertiesFormatter.Protect(properties));

            return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
        }

        public virtual async Task<bool> HandleRequestAsync()  // <----------------ee4.0 intercept the "xxx/signin-external" request 
        {
            if (Context.Request.Path.Equals(Options.RedirectPath)) // when RedirectPath is "signin-external"
            {
                string authCode = Context.Request.Query["code"].ToString();  // authCode is sent by externl service
                (string token, string state) = await GetAccessToken(authCode);  // <-----------ee4.1 exchanging the Authorization Code for an Access Token
                if (!string.IsNullOrEmpty(token))
                {
                    IEnumerable<Claim> claims = await GetUserData(token);  // <----------ee5.0 use access token to get user data from external auth service
                    if (claims != null)
                    {
                        ClaimsIdentity identity = new ClaimsIdentity(Scheme.Name);
                        identity.AddClaims(claims);
                        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
                        AuthenticationProperties props = PropertiesFormatter.Unprotect(state);

                        props.StoreTokens(new[] { new AuthenticationToken { Name = "access_token", Value = token } });

                        await Context.SignInAsync(IdentityConstants.ExternalScheme, claimsPrincipal, props);  // <-----------ee6
                        
                        Context.Response.Redirect(props.RedirectUri);  // RedirectUri is "/ExternalSignIn?returnUrl=%2F&handler=Correlate"

                        return true;
                    }
                }
                
                Context.Response.Redirect(string.Format(Options.ErrorUrlTemplate, ErrorMessage));
                
                return true;
            }

            return false;
        }

        protected virtual async Task<(string token, string state)> GetAccessToken(string authCode)
        {
            string state = Context.Request.Query["state"];
            HttpClient httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            HttpResponseMessage response = await httpClient.PostAsJsonAsync(  // <----------------ee4.2 call external service's Exchange handler
                Options.ExchangeUrl, // <-----------                                        
                new 
                {
                    code = authCode,   // <---------------
                    redirect_uri = Options.RedirectRoot + Options.RedirectPath,
                    client_id = Options.ClientId,
                    client_secret = Options.ClientSecret,   // <---------provider secret to get access token, note that secret is not needed in getting user data process                                                 
                    state,
                    grant_type = "authorization_code",
                }
            );

            string jsonData = await response.Content.ReadAsStringAsync();
            JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
            string error = jsonDoc.RootElement.GetString("error");
            
            if (error != null)
            {
                ErrorMessage = "Access Token Error";
                Logger.LogError(ErrorMessage);
                Logger.LogError(jsonData);
            }

            string token = jsonDoc.RootElement.GetString("access_token");    // <----------------ee4.3. get access token
            string jsonState = jsonDoc.RootElement.GetString("state") ?? state;
            
            return error == null ? (token, state) : (null, null);
        }
        
        public Task ForbidAsync(AuthenticationProperties properties)
        {
            return Task.CompletedTask;
        }

        protected virtual async Task<IEnumerable<Claim>>GetUserData(string accessToken)
        {
            HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get, Options.DataUrl);  // <----------invoke external service's Data handler
            msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);  // <----------head will be e.g "Bearer xxx"
            HttpResponseMessage response = await new HttpClient().SendAsync(msg);
           
            string jsonData = await response.Content.ReadAsStringAsync();   // <----------------ee5.1.

            JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
            
            var error = jsonDoc.RootElement.GetString("error");
            if (error != null)
            {
                ErrorMessage = "User Data Error";
                Logger.LogError(ErrorMessage);
                Logger.LogError(jsonData);
                return null;
            }
            else
            {
                return GetClaims(jsonDoc);
            }
        }
       
        protected virtual IEnumerable<Claim> GetClaims(JsonDocument jsonDoc)
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.NameIdentifier, jsonDoc.RootElement.GetString("id")));
            claims.Add(new Claim(ClaimTypes.Name, jsonDoc.RootElement.GetString("name")));
            claims.Add(new Claim(ClaimTypes.Email, jsonDoc.RootElement.GetString("emailAddress")));
            
            return claims;
        }
    }
}