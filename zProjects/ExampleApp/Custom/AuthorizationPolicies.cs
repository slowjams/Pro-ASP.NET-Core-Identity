using Microsoft.AspNetCore.Authorization;
using System.Linq;

namespace ExampleApp.Custom
{
    public static class AuthorizationPolicies
    {
        public static void AddPolicies(AuthorizationOptions opts)
        {
            opts.FallbackPolicy = new AuthorizationPolicy(
                new[] { new CustomRequirement() { Name = "Bob" } }, 
                Enumerable.Empty<string>()
            );
        }
    }
}
