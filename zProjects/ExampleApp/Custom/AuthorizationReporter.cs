using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExampleApp.Custom
{
    public class AuthorizationReporter
    {
        private string[] schemes = new string[] { "TestScheme" };
        private RequestDelegate next;

        private IAuthorizationPolicyProvider policyProvider;  // DefaultAuthorizationPolicyProvider that queries AuthorizationOptions
        private IAuthorizationService authorizationService;

        public AuthorizationReporter(RequestDelegate requestDelegate, IAuthorizationPolicyProvider provider, IAuthorizationService service)
        {
            next = requestDelegate;
            policyProvider = provider;
            authorizationService = service;
        }

        public async Task Invoke(HttpContext context)
        {
            Endpoint ep = context.GetEndpoint();
            if (ep != null)
            {
                IEnumerable<IAuthorizeData> authData = ep.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? Array.Empty<IAuthorizeData>();
                AuthorizationPolicy policy = await AuthorizationPolicy.CombineAsync(policyProvider, authData);

                Dictionary<(string, string), bool> results = new Dictionary<(string, string), bool>();
                bool allowAnon = ep.Metadata.GetMetadata<IAllowAnonymous>() != null;
                
                foreach (ClaimsPrincipal cp in GetUsers())
                {
                    results[(cp.Identity.Name ?? "(No User)", cp.Identity.AuthenticationType)] = 
                        allowAnon || policy == null ||await AuthorizeUser(cp, policy);
                }
                context.Items["authReport"] = results;
                await ep.RequestDelegate(context);
            }
            else
            {
                await next(context);
            }
        }

        private IEnumerable<ClaimsPrincipal> GetUsers() => UsersAndClaims.GetUsers().Concat(new[] { new ClaimsPrincipal(new ClaimsIdentity()) });

        private async Task<bool> AuthorizeUser(ClaimsPrincipal cp, AuthorizationPolicy policy)
        {
            return UserSchemeMatchesPolicySchemes(cp, policy) && (await authorizationService.AuthorizeAsync(cp, policy)).Succeeded;
        }

        private bool UserSchemeMatchesPolicySchemes(ClaimsPrincipal cp, AuthorizationPolicy policy)
        {
            return policy.AuthenticationSchemes?.Count() == 0 || 
                cp.Identities.Select(id => id.AuthenticationType)
                .Any(auth => policy.AuthenticationSchemes.Any(scheme => scheme == auth));
        }
    }
}